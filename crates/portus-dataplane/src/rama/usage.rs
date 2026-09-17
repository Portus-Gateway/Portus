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

use portus_dataplane_core::ai::budget::Allowance;
use portus_dataplane_core::ai::usage::{UsageRecord, UsageRing, UsageTracker};
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
    /// The budget allowance to debit with the response's tokens.
    pub allowance: Option<Arc<Allowance>>,
}

/// Wrap `body` so its usage is recorded into `ring` when it completes.
pub fn observe(body: Body, status: u16, req: RequestSide<'_>, ring: Arc<UsageRing>) -> Body {
    let field = |key: &str| req.body_fields.and_then(|f| f.iter().find(|(k, _)| *k == key)).map(|(_, v)| v.as_str());
    let stream = field("stream") == Some("true");
    let record = UsageRecord {
        ts_unix_micros: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
            - req.start.elapsed().as_micros() as u64,
        duration_micros: 0,
        status,
        dialect: req.ai.dialect,
        stream,
        provider: UsageRecord::name(&req.ai.provider),
        route_host: UsageRecord::name(req.host),
        requested_model: UsageRecord::name(field("model").unwrap_or("")),
        served_model: UsageRecord::name(""),
        tokens: None,
        request_bytes: req.request_bytes,
        response_bytes: 0,
        key_id: req.key_id,
        request_id: rand::random(),
    };
    Body::new(Observed {
        inner: body,
        tracker: Some(UsageTracker::new(req.ai.dialect, stream)),
        record,
        start: req.start,
        ring,
        allowance: req.allowance,
    })
}

struct Observed {
    inner: Body,
    tracker: Option<UsageTracker>,
    record: UsageRecord,
    start: Instant,
    ring: Arc<UsageRing>,
    allowance: Option<Arc<Allowance>>,
}

impl Observed {
    fn finish(&mut self) {
        let Some(tracker) = self.tracker.take() else { return };
        let usage = tracker.finish();
        let mut record = self.record.clone();
        record.duration_micros = self.start.elapsed().as_micros() as u64;
        record.tokens = usage.tokens;
        if let (Some(allowance), Some(tokens)) = (&self.allowance, &usage.tokens) {
            allowance.debit(tokens);
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
        RequestSide { ai, host: "llm.bench", body_fields: Some(fields), request_bytes: 321, start: Instant::now(), key_id: 9, allowance: None }
    }

    #[tokio::test]
    async fn a_consumed_anthropic_response_produces_one_record_with_tokens() {
        let ring = Arc::new(UsageRing::new(8));
        let ai = AiBackend { dialect: Dialect::Anthropic, provider: Arc::from("anthropic"), key_required: true, budget: None };
        let fields: BodyFields = vec![("model", "claude-opus-5".into())];
        let body = Body::new(Full::new(Bytes::from_static(
            br#"{"id":"m","model":"claude-opus-5-served","usage":{"input_tokens":10,"output_tokens":4}}"#,
        )));
        let observed = observe(body, 200, side(&ai, &fields), Arc::clone(&ring));
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
        let ai = AiBackend { dialect: Dialect::OpenAi, provider: Arc::from("echo"), key_required: false, budget: None };
        let fields: BodyFields = vec![("model", "gpt-5".into()), ("stream", "true".into())];
        let body = Body::new(Full::new(Bytes::from_static(b"data: {\"model\":\"gpt-5\",\"usage\":null}\n\n")));
        let mut observed = observe(body, 200, side(&ai, &fields), Arc::clone(&ring));
        let _ = observed.frame().await;
        drop(observed);
        let mut out = Vec::new();
        assert_eq!(ring.drain_into(&mut out, 10), 1);
        assert!(out[0].stream);
        assert_eq!(out[0].tokens, None, "no usage chunk was seen");
        assert_eq!(out[0].served_model.as_str(), "gpt-5");
    }
}
