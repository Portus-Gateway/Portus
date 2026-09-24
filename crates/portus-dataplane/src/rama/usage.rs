//! Watch an AI route's response go by and record what it cost. The body
//! wrapper feeds every frame to the core's usage tracker and drops one
//! record into the ring when the body ends or is abandoned.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use rama::error::BoxError;
use rama::http::body::{Frame, SizeHint};
use rama::http::{Body, StreamingBody};

use portus_dataplane_core::ai::budget::Reservation;
use portus_dataplane_core::ai::usage::{Dialect, RefusalKind, UsageRecord, UsageRing, UsageTracker};
use portus_dataplane_core::router::{AiBackend, BodyFields};

/// What the handler knows about the request before the response body runs.
pub struct RequestSide<'a> {
    pub ai: &'a AiBackend,
    pub host: &'a str,
    pub body_fields: Option<&'a BodyFields>,
    pub request_bytes: u64,
    pub start: Instant,
    /// The Portus API key that authenticated the request; 0 when none.
    pub key_id: u64,
    /// The subject's tenant and name, when known.
    pub tenant: Option<&'a str>,
    pub subject: Option<&'a str>,
    /// The user a trusted caller acted for (`auth.onBehalfOf`).
    pub on_behalf_of: Option<&'a str>,
    /// The gateway's id for this request, echoed to the client.
    pub request_id: u64,
    /// The client's own `x-portus-request-id`, when it sent one.
    pub client_request_id: Option<&'a str>,
    /// What refused the request (a policy id, `key`, `jwt`); None when forwarded.
    pub rule: Option<&'a str>,
    /// The budget reservation to settle with the response's tokens.
    pub reservation: Option<Reservation>,
}

/// Record a request the gateway refused itself: no tokens, the key when
/// one was recognised, and why.
pub fn record_refusal(status: u16, kind: RefusalKind, req: RequestSide<'_>, ring: &UsageRing) {
    let mut record = base_record(status, &req);
    record.duration_micros = req.start.elapsed().as_micros() as u64;
    record.refusal = Some(kind);
    ring.push(record);
}

fn base_record(status: u16, req: &RequestSide<'_>) -> UsageRecord {
    let field = |key: &str| req.body_fields.and_then(|f| f.iter().find(|(k, _)| *k == key)).map(|(_, v)| v.as_str());
    let stream = field("stream") == Some("true");
    UsageRecord {
        ts_unix_micros: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
            - req.start.elapsed().as_micros() as u64,
        duration_micros: 0,
        status,
        dialect: req.ai.dialect,
        stream,
        provider: UsageRecord::name(&req.ai.provider),
        route_host: UsageRecord::name(req.host),
        // An MCP record carries the JSON-RPC method where an LLM record
        // carries the model, and the tool where the served model would go.
        requested_model: UsageRecord::name(match req.ai.dialect {
            Dialect::Mcp => field("method").unwrap_or(""),
            _ => field("model").unwrap_or(""),
        }),
        served_model: UsageRecord::name(match req.ai.dialect {
            Dialect::Mcp => field("tool").unwrap_or(""),
            _ => "",
        }),
        tokens: None,
        request_bytes: req.request_bytes,
        response_bytes: 0,
        key_id: req.key_id,
        tenant: UsageRecord::name(req.tenant.unwrap_or("")),
        subject: UsageRecord::name(req.subject.unwrap_or("")),
        request_id: req.request_id,
        refusal: None,
        rule: UsageRecord::name(req.rule.unwrap_or("")),
        client_request_id: UsageRecord::name(req.client_request_id.unwrap_or("")),
        first_byte_micros: 0,
        on_behalf_of: UsageRecord::name(req.on_behalf_of.unwrap_or("")),
    }
}

/// Wrap `body` so its usage is recorded into `ring` when it completes.
/// `readable` is false when the provider compressed the body: the record is
/// still written (request, bytes, status) but carries no tokens.
pub fn observe(body: Body, status: u16, req: RequestSide<'_>, ring: Arc<UsageRing>, readable: bool) -> Body {
    let stream = req.body_fields.and_then(|f| f.iter().find(|(k, _)| *k == "stream")).is_some_and(|(_, v)| v == "true");
    let record = base_record(status, &req);
    Body::new(Observed {
        inner: body,
        tracker: readable.then(|| UsageTracker::new(req.ai.dialect, stream)),
        record,
        start: req.start,
        ring,
        reservation: req.reservation,
        finished: false,
    })
}

struct Observed {
    inner: Body,
    tracker: Option<UsageTracker>,
    record: UsageRecord,
    start: Instant,
    ring: Arc<UsageRing>,
    reservation: Option<Reservation>,
    finished: bool,
}

impl Observed {
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let usage = self.tracker.take().map(UsageTracker::finish).unwrap_or_default();
        let mut record = self.record.clone();
        record.duration_micros = self.start.elapsed().as_micros() as u64;
        record.tokens = usage.tokens;
        if let Some(reservation) = self.reservation.take() {
            reservation.settle(usage.tokens.as_ref());
        }
        if let Some(m) = usage.model {
            record.served_model = UsageRecord::name(&m);
        }
        self.ring.push(record);
    }
}

impl StreamingBody for Observed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if self.record.first_byte_micros == 0 {
                        self.record.first_byte_micros = self.start.elapsed().as_micros().max(1) as u64;
                    }
                    self.record.response_bytes += data.len() as u64;
                    if let Some(t) = self.tracker.as_mut() {
                        t.feed(data);
                    }
                }
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => self.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Observed {
    fn drop(&mut self) {
        // A client that went away mid-stream still consumed tokens.
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portus_dataplane_core::ai::usage::{Dialect, Tokens};
    use rama::http::body::util::{BodyExt, Full};

    fn side<'a>(ai: &'a AiBackend, fields: &'a BodyFields) -> RequestSide<'a> {
        RequestSide { ai, host: "llm.bench", body_fields: Some(fields), request_bytes: 321, start: Instant::now(), key_id: 9, tenant: Some("team-a"), subject: Some("ci"), on_behalf_of: None, request_id: 77, client_request_id: Some("turn-3"), rule: None, reservation: None }
    }

    #[tokio::test]
    async fn the_record_carries_the_request_ids_the_first_byte_time_and_the_vouched_user() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::Anthropic, provider: Arc::from("anthropic"), key_required: true, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("model", "claude-opus-5".into())];
        let mut side = side(&ai, &fields);
        side.on_behalf_of = Some("alice@example.com");
        side.subject = Some("alice@example.com");
        let body = Body::new(Full::new(Bytes::from_static(br#"{"usage":{"input_tokens":1,"output_tokens":1}}"#)));
        let _ = observe(body, 200, side, Arc::clone(&ring), true).collect().await.unwrap();
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        let r = &out[0];
        assert_eq!((r.request_id, r.client_request_id.as_str(), r.on_behalf_of.as_str(), r.subject.as_str(), r.key_id), (77, "turn-3", "alice@example.com", "alice@example.com", 9));
        assert!(r.first_byte_micros > 0 && r.first_byte_micros <= r.duration_micros, "{} <= {}", r.first_byte_micros, r.duration_micros);
        assert_eq!(r.rule.as_str(), "");
    }

    #[tokio::test]
    async fn an_mcp_record_carries_the_method_and_tool_and_no_tokens() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::Mcp, provider: Arc::from("github-mcp"), key_required: false, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("method", "tools/call".into()), ("id", "3".into()), ("tool", "github.search".into())];
        let side = RequestSide { ai: &ai, host: "mcp.example.com", body_fields: Some(&fields), request_bytes: 120, start: Instant::now(), key_id: 42, tenant: Some("team-mcp"), subject: Some("agent"), on_behalf_of: None, request_id: 1, client_request_id: None, rule: None, reservation: None };
        let body = observe(Body::from(r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#), 200, side, Arc::clone(&ring), true);
        let _ = body.collect().await.unwrap();
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        let record = &out[0];
        assert_eq!((record.dialect, record.status, record.key_id), (Dialect::Mcp, 200, 42));
        assert_eq!((record.tenant.as_str(), record.subject.as_str()), ("team-mcp", "agent"));
        assert_eq!((record.requested_model.as_str(), record.served_model.as_str()), ("tools/call", "github.search"));
        assert_eq!(record.tokens, None);
        assert!(record.response_bytes > 0);
    }

    #[tokio::test]
    async fn a_compressed_response_is_recorded_without_tokens_instead_of_being_misread() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::Anthropic, provider: Arc::from("anthropic"), key_required: true, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("model", "claude-opus-5".into()), ("stream", "true".into())];
        // What a gzip body looks like to a parser: not SSE, not JSON.
        let body = Body::new(Full::new(Bytes::from_static(b"\x1f\x8b\x08\x00garbage-that-is-not-sse")));
        let observed = observe(body, 200, side(&ai, &fields), Arc::clone(&ring), false);
        let bytes = observed.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 27, "the body still passes through unchanged");
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1, "the request is still recorded");
        assert_eq!((out[0].status, out[0].tokens, out[0].response_bytes), (200, None, 27));
    }

    #[tokio::test]
    async fn a_consumed_anthropic_response_produces_one_record_with_tokens() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::Anthropic, provider: Arc::from("anthropic"), key_required: true, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("model", "claude-opus-5".into())];
        let body = Body::new(Full::new(Bytes::from_static(
            br#"{"id":"m","model":"claude-opus-5-served","usage":{"input_tokens":10,"output_tokens":4}}"#,
        )));
        let observed = observe(body, 200, side(&ai, &fields), Arc::clone(&ring), true);
        let bytes = observed.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 87, "the body passes through unchanged");
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        let r = &out[0];
        assert_eq!((r.status, r.stream, r.provider.as_str(), r.route_host.as_str()), (200, false, "anthropic", "llm.bench"));
        assert_eq!((r.requested_model.as_str(), r.served_model.as_str()), ("claude-opus-5", "claude-opus-5-served"));
        assert_eq!(r.tokens, Some(Tokens { input: 10, output: 4, cache_read: 0, cache_creation: 0 }));
        assert_eq!((r.request_bytes, r.response_bytes), (321, 87));
        assert_eq!(r.key_id, 9);
    }

    #[tokio::test]
    async fn an_abandoned_stream_is_still_recorded_once() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::OpenAi, provider: Arc::from("echo"), key_required: false, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("model", "gpt-5".into()), ("stream", "true".into())];
        let body = Body::new(Full::new(Bytes::from_static(b"data: {\"model\":\"gpt-5\",\"usage\":null}\n\n")));
        let mut observed = observe(body, 200, side(&ai, &fields), Arc::clone(&ring), true);
        let _ = observed.frame().await;
        drop(observed);
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        assert!(out[0].stream);
        assert_eq!(out[0].tokens, None, "no usage chunk was seen");
        assert_eq!(out[0].served_model.as_str(), "gpt-5");
    }

    #[test]
    fn a_refusal_is_recorded_with_its_reason_and_no_tokens() {
        let ring = UsageRing::new(8);
        let ai = AiBackend { dialect: Dialect::Anthropic, provider: Arc::from("anthropic"), key_required: true, budget: None, session_affinity: false, jwt: None, on_behalf_of: None, federation: None };
        let fields: BodyFields = vec![("model", "claude-opus-5".into())];
        let mut refused = side(&ai, &fields);
        refused.rule = Some("llm/daily");
        record_refusal(429, RefusalKind::BudgetExhausted, refused, &ring);
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        let r = &out[0];
        assert_eq!((r.status, r.key_id, r.refusal, r.tokens), (429, 9, Some(RefusalKind::BudgetExhausted), None));
        assert_eq!((r.rule.as_str(), r.first_byte_micros), ("llm/daily", 0));
        assert_eq!((r.requested_model.as_str(), r.provider.as_str()), ("claude-opus-5", "anthropic"));
    }
}
