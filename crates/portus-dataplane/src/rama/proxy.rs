//! The Rama request service: the core plans the request, this carries it
//! out with Rama's HTTP client.
//!
//! Rama 0.4 has its own HTTP types (headers, method, URI) rather than the
//! `http` crate's, so the core's header traits are implemented here on thin
//! newtypes and nothing is copied per request beyond what forwarding needs.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::{info, warn};
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::http::body::util::{BodyExt, Full};
use rama::http::io::upgrade::handle_upgrade;
use rama::http::{Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, StreamingBody, Version};
use rama::net::address::{Authority, Host};
use rama::net::Protocol;
use rama::net::uri::Uri;
use rama::net::client::{ConnectionError, ConnectionErrorDomain};
use rama::net::stream::SocketInfo;
use rama::tls::client::{ServerVerifyMode, TlsClientAuth, TlsServerName, TlsServerVerify};
use rama::tls::rustls::client::RustlsServerCertVerifier;
use rama::tls::SecureTransport;
use rama::Service;

use portus_dataplane_core::metrics::ProxyMetrics;
use portus_dataplane_core::outlier::Outliers;
use portus_dataplane_core::plan::{
    apply_cors_response_headers, plan_request, should_retry_connect, Forward, HeaderSink, Plan, Reply,
    RequestFacts,
};
use portus_dataplane_core::router::{access_log_enabled, should_retry_status, BodyFields, RequestHeaders, SnapshotSlot};
use portus_dataplane_core::types::BackendProtocol;

use super::body::scan_body;
use super::client::{Upstream, UpstreamTarget};
use super::usage::{observe, RequestSide};
use portus_dataplane_core::ai::budget::{estimate, exhausted_reply, now_micros, Scope, Verdict, REMAINING_HEADER};
use portus_dataplane_core::ai::keys::{authorize, Refusal};
use portus_dataplane_core::ai::ledger::LedgerReporter;
use super::tls::{client_auth_for, upstream_tls_for};

/// Request bodies up to this size are buffered when the route allows retries,
/// so a failed attempt can be replayed. Larger bodies stream and get one
/// attempt.
const RETRY_BUFFER_MAX: u64 = 64 * 1024;

/// Read view of Rama's header map for the core.
struct Headers<'a>(&'a HeaderMap);

impl RequestHeaders for Headers<'_> {
    fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.get(name).map(|v| v.as_bytes())
    }
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) {
        for (name, value) in self.0.iter() {
            f(name.as_str(), value.as_bytes());
        }
    }
}

/// Write view of Rama's header map for the core's mutations.
struct HeadersMut<'a>(&'a mut HeaderMap);

fn rama_name(name: &http::HeaderName) -> Option<HeaderName> {
    HeaderName::from_bytes(name.as_str().as_bytes()).ok()
}

fn rama_value(value: &http::HeaderValue) -> Option<HeaderValue> {
    HeaderValue::from_bytes(value.as_bytes()).ok()
}

impl HeaderSink for HeadersMut<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&[u8]> {
        self.0.get(name.as_str()).map(|v| v.as_bytes())
    }
    fn insert(&mut self, name: http::HeaderName, value: http::HeaderValue) {
        if let (Some(n), Some(v)) = (rama_name(&name), rama_value(&value)) {
            self.0.insert(n, v);
        }
    }
    fn append(&mut self, name: http::HeaderName, value: http::HeaderValue) {
        if let (Some(n), Some(v)) = (rama_name(&name), rama_value(&value)) {
            self.0.append(n, v);
        }
    }
    fn remove(&mut self, name: &http::HeaderName) {
        self.0.remove(name.as_str());
    }
}

pub struct ProxyService {
    snapshot: SnapshotSlot,
    metrics: Arc<ProxyMetrics>,
    outliers: Arc<Outliers>,
    client: Upstream,
    /// Set when a ledger is configured: AI route responses are recorded.
    ledger: Option<Arc<LedgerReporter>>,
}

impl ProxyService {
    pub fn new(
        snapshot: SnapshotSlot,
        metrics: Arc<ProxyMetrics>,
        outliers: Arc<Outliers>,
        client: Upstream,
        ledger: Option<Arc<LedgerReporter>>,
    ) -> Self {
        Self { snapshot, metrics, outliers, client, ledger }
    }
}

impl Service<Request> for ProxyService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        Ok(self.handle(req).await)
    }
}

/// The parts of the downstream request the upstream attempts are built from.
struct Incoming {
    method: Method,
    version: Version,
    /// The downstream URI; each attempt takes it with the backend as authority.
    uri: Uri,
}

enum AttemptError {
    /// Nothing reached the backend (dial, TLS handshake).
    Connect(String),
    /// Our own deadline fired.
    Timeout,
    /// The exchange failed after the connection was up.
    Exchange(String),
}

impl ProxyService {
    async fn handle(&self, req: Request) -> Response {
        let start = Instant::now();

        let socket = req.extensions().get_ref::<SocketInfo>().map(|s| (s.local_addr(), s.peer_addr()));
        let local_port = socket.and_then(|(local, _)| local).map(|a| a.port).unwrap_or(80);
        let peer_ip: Option<IpAddr> = socket.map(|(_, peer)| peer.ip_addr);
        let sni: Option<String> = req
            .extensions()
            .get_ref::<SecureTransport>()
            .and_then(|s| s.client_hello())
            .and_then(|h| h.ext_server_name())
            .map(|d| d.as_str().to_string());
        let socket_is_tls = req.extensions().contains::<SecureTransport>();

        let raw_host: String = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| req.uri().host().map(|h| h.to_string()))
            .unwrap_or_default();
        let host = raw_host.split(':').next().unwrap_or(&raw_host);

        // Plan, scanning the body first when the host's routes match on
        // body fields. The borrows of `req` end with each pass so the body
        // can be taken and replaced between them.
        let mut req = req;
        let mut body_fields: Option<BodyFields> = None;
        let (plan, logged) = loop {
            let step = {
                let path: std::borrow::Cow<'_, str> =
                    req.uri().path().map(|p| p.as_encoded_str()).unwrap_or(std::borrow::Cow::Borrowed("/"));
                let query: Option<std::borrow::Cow<'_, str>> = req.uri().query().map(|q| q.as_encoded_str());
                let target: std::borrow::Cow<'_, str> = match &query {
                    Some(q) => std::borrow::Cow::Owned(format!("{path}?{q}")),
                    None => std::borrow::Cow::Borrowed(&path),
                };
                let snap = self.snapshot.load();
                let facts = RequestFacts {
                    host,
                    path: &path,
                    path_and_query: &target,
                    query: query.as_deref(),
                    method: req.method().as_str(),
                    headers: &Headers(req.headers()),
                    local_port,
                    socket_is_tls,
                    sni: sni.as_deref(),
                    peer_ip,
                    body_fields: body_fields.as_ref(),
                };
                match plan_request(&snap, facts, &self.metrics).await {
                    Plan::Respond(reply) => {
                        let status = reply.status;
                        self.metrics.request_total.with_label_values(&["no_route", status_label(status).as_str(), "http"]).inc();
                        self.metrics.request_duration.with_label_values(&["no_route", "http"]).observe(start.elapsed().as_secs_f64());
                        access_log(peer_ip, req.method().as_str(), &path, "no_route", status, start);
                        return reply_response(reply);
                    }
                    Plan::Forward(plan) => {
                        let logged = access_log_enabled().then(|| (req.method().as_str().to_string(), path.into_owned()));
                        Ok((plan, logged))
                    }
                    Plan::NeedsBody(need) => Err(need),
                }
            };
            match step {
                Ok(done) => break done,
                Err(need) => {
                    if body_fields.is_some() {
                        // The second pass asked again: the plan is inconsistent.
                        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                    let (parts, body) = req.into_parts();
                    match scan_body(body, need).await {
                        Ok((fields, replay)) => {
                            body_fields = Some(fields);
                            req = Request::from_parts(parts, replay);
                        }
                        Err(status) => return status_response(status),
                    }
                }
            }
        };
        // HTTP/2 carries the authority in `:authority`, not a `Host` header;
        // the backend must still see the client's authority, not ours.
        let authority = if req.headers().contains_key("host") {
            None
        } else {
            req.uri().authority().map(|a| a.to_string())
        };

        let request_bytes: u64 = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        // Portus API key: one hash and one lookup against the ledger's
        // snapshot. The client's credential never reaches the provider; the
        // route's mutations set the provider's own.
        let mut key_id = 0;
        let mut tenant: Option<Arc<str>> = None;
        let model = body_fields.as_ref().and_then(|f| f.iter().find(|(k, _)| *k == "model")).map(|(_, v)| v.as_str());
        if let Some(ai) = plan.ai.as_ref().filter(|ai| ai.key_required) {
            let verdict = match self.ledger.as_ref() {
                Some(ledger) => authorize(&ledger.keys.load(), &Headers(req.headers()), model).map(|k| (k.id, Arc::clone(&k.tenant))),
                None => Err(Refusal::Unauthenticated),
            };
            match verdict {
                Ok((id, t)) => {
                    key_id = id;
                    tenant = Some(t);
                }
                Err(refusal) => {
                    let reply = refusal.reply(ai.dialect, model);
                    let status = reply.status;
                    self.metrics.request_total.with_label_values(&[plan.service_name.as_ref(), status_label(status).as_str(), plan.protocol_label()]).inc();
                    if let Some((method, path)) = &logged {
                        access_log(peer_ip, method, path, plan.service_name.as_ref(), status, start);
                    }
                    return reply_response(reply);
                }
            }
            req.headers_mut().remove("x-api-key");
            req.headers_mut().remove("authorization");
        }
        // Token budget: reserve an estimate against the subject's counter
        // (one atomic), settle to the real count when the response ends. The
        // counter syncs with the ledger in the background.
        let mut reservation = None;
        let mut remaining_header: Option<i64> = None;
        if let (Some(ai), Some(budget)) = (plan.ai.as_ref(), plan.ai.as_ref().and_then(|ai| ai.budget.as_ref())) {
            let subject: Arc<str> = match budget.per {
                Scope::Key if key_id != 0 => Arc::from(key_id.to_string()),
                Scope::Key => Arc::from("anonymous"),
                Scope::Tenant => tenant.clone().unwrap_or_else(|| Arc::from("anonymous")),
                Scope::Route => Arc::from("route"),
            };
            let max_tokens = body_fields
                .as_ref()
                .and_then(|f| f.iter().find(|(k, _)| *k == "max_tokens"))
                .and_then(|(_, v)| v.parse::<u64>().ok());
            let cost = estimate(max_tokens, request_bytes);
            let verdict = match self.ledger.as_ref() {
                Some(ledger) => {
                    let mut v = ledger.budgets.check(budget, &subject, cost, now_micros());
                    if v == Verdict::Unknown {
                        // A subject this pod has not synced in this window:
                        // give the ledger one bounded chance to answer before
                        // the fail-open/closed knob decides.
                        ledger.budgets.counter(budget, &subject).wait_for_sync(Duration::from_millis(250)).await;
                        v = ledger.budgets.check(budget, &subject, cost, now_micros());
                    }
                    v
                }
                None => Verdict::Unknown,
            };
            let refuse = match verdict {
                Verdict::Allow(r) => {
                    remaining_header = Some(r.remaining());
                    reservation = Some(r);
                    None
                }
                Verdict::Exhausted { retry_after_secs, remaining, needed } => Some((retry_after_secs, remaining, needed)),
                Verdict::Unknown if budget.fail_open => None,
                Verdict::Unknown => Some((1, 0, cost)),
            };
            if let Some((retry, remaining, needed)) = refuse {
                let reply = exhausted_reply(ai.dialect, retry, remaining, needed);
                let status = reply.status;
                self.metrics.request_total.with_label_values(&[plan.service_name.as_ref(), status_label(status).as_str(), plan.protocol_label()]).inc();
                if let Some((method, path)) = &logged {
                    access_log(peer_ip, method, path, plan.service_name.as_ref(), status, start);
                }
                return reply_response(reply);
            }
        }
        let mut response = self.forward(req, &plan, peer_ip, authority).await;

        let status = response.status().as_u16();
        if let Some(remaining) = remaining_header
            && let Some(n) = rama_name(&REMAINING_HEADER)
        {
            response.headers_mut().insert(n, HeaderValue::from(remaining.max(0)));
        }
        if let (Some(ai), Some(ledger)) = (plan.ai.as_ref(), self.ledger.as_ref()) {
            let side = RequestSide { ai, host, body_fields: body_fields.as_ref(), request_bytes, start, key_id, reservation };
            let body = std::mem::replace(response.body_mut(), Body::empty());
            *response.body_mut() = observe(body, status, side, Arc::clone(&ledger.ring));
        }
        let host_label = plan.service_name.as_ref();
        self.metrics.request_total.with_label_values(&[host_label, status_label(status).as_str(), plan.protocol_label()]).inc();
        plan.duration_histogram.observe(start.elapsed().as_secs_f64());
        if let Some(cb) = &plan.circuit_breaker {
            if status >= 500 {
                cb.record_failure();
            } else {
                cb.record_success();
            }
            self.metrics.circuit_breaker_state.with_label_values(&[host_label]).set(cb.current_state() as i64);
        }
        if let Some(cl) = &plan.connection_limiter {
            cl.release();
        }
        if let Some((method, path)) = &logged {
            access_log(peer_ip, method, path, host_label, status, start);
        }
        response
    }

    async fn forward(
        &self,
        req: Request,
        plan: &Forward,
        peer_ip: Option<IpAddr>,
        authority: Option<String>,
    ) -> Response {
        let Some(pool) = plan.pool.as_ref() else {
            return status_response(StatusCode::INTERNAL_SERVER_ERROR);
        };

        // An HTTP/1 upgrade (WebSocket): once the backend answers 101 the two
        // upgraded byte streams are joined. The downstream half is only
        // available after the 101 has been written, so it is taken as a future
        // now and awaited in a spawned task.
        let is_upgrade = req.version() <= Version::HTTP_11
            && req
                .headers()
                .get("connection")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
            && req.headers().contains_key("upgrade");
        let downstream_upgrade = is_upgrade.then(|| handle_upgrade(&req));

        let (parts, body) = req.into_parts();
        let method = parts.method;
        let version = parts.version;
        let uri = parts.uri;
        let mut headers = parts.headers;
        if let Some(authority) = authority
            && !headers.contains_key("host")
            && let Ok(v) = HeaderValue::from_str(&authority)
        {
            headers.insert("host", v);
        }

        // Headers the backend sees: forwarded-for, host rewrite and the
        // route's mutations, applied once; retries reuse the result.
        if let Some(ip) = peer_ip
            && let Ok(ip_value) = HeaderValue::from_str(&ip.to_string())
        {
            let xff = match headers.get("x-forwarded-for") {
                Some(existing) => {
                    let mut merged = existing.as_bytes().to_vec();
                    merged.extend_from_slice(b", ");
                    merged.extend_from_slice(ip_value.as_bytes());
                    HeaderValue::from_bytes(&merged).unwrap_or_else(|_| ip_value.clone())
                }
                None => ip_value.clone(),
            };
            headers.insert("x-forwarded-for", xff);
            headers.insert("x-real-ip", ip_value);
        }
        if let Some(new_host) = &plan.rewrite_hostname
            && let Ok(v) = HeaderValue::from_str(new_host)
        {
            headers.insert("host", v);
        }
        plan.request_headers.apply(&mut HeadersMut(&mut headers));

        // Bodies are buffered for replay only when the route retries and the
        // body is small; otherwise the body streams once and there is no retry.
        let mut streaming: Option<Body> = None;
        let mut buffered: Option<Bytes> = None;
        let small = StreamingBody::size_hint(&body).exact().is_some_and(|n| n <= RETRY_BUFFER_MAX);
        if plan.max_retries > 0 && small {
            match body.collect().await {
                Ok(collected) => buffered = Some(collected.to_bytes()),
                Err(_) => return status_response(StatusCode::BAD_REQUEST),
            }
        } else {
            streaming = Some(body);
        }
        let retrying = buffered.is_some();
        let mut retries_left = if retrying { plan.max_retries } else { 0 };
        let incoming = Incoming { method, version, uri };

        let mut response = loop {
            let Some(backend) = pool.select() else {
                return status_response(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let body = match (&buffered, streaming.take()) {
                (Some(b), _) => Body::new(Full::new(b.clone())),
                (None, Some(b)) => b,
                (None, None) => return status_response(StatusCode::BAD_GATEWAY),
            };
            // The single-attempt path moves the headers; only a retrying
            // request pays for a clone.
            let attempt_headers = if retrying { headers.clone() } else { std::mem::take(&mut headers) };
            let upstream = self.upstream_request(&incoming, attempt_headers, plan, backend, body);
            // One deadline for the whole exchange: the route's request timeout,
            // else its backend-request (read) timeout, else the connect timeout.
            let deadline = plan.request_timeout.or(plan.read_timeout).or(plan.connect_timeout);
            match self.attempt(upstream, deadline).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if let Some(out) = self.outliers.responded(pool, &backend, status) {
                        self.note_ejection(plan, &backend, out, &format!("{status} responses in a row"));
                    }
                    if should_retry_status(status, &plan.retry_codes, retries_left) {
                        retries_left -= 1;
                        info!("upstream {} answered {status}, retrying ({retries_left} left)", plan.service_name);
                        continue;
                    }
                    break resp;
                }
                Err(AttemptError::Connect(why)) => {
                    self.metrics.upstream_connect_errors_total.with_label_values(&[plan.service_name.as_ref()]).inc();
                    if let Some(out) = self.outliers.connect_failed(pool, &backend) {
                        self.note_ejection(plan, &backend, out, "a connect failure");
                    }
                    if should_retry_connect(&plan.retry_on, retries_left) {
                        retries_left -= 1;
                        warn!("upstream connect failed for {} ({why}), retrying ({retries_left} left)", plan.service_name);
                        continue;
                    }
                    warn!("upstream connect failed for {}: {why}", plan.service_name);
                    break status_response(StatusCode::BAD_GATEWAY);
                }
                Err(AttemptError::Timeout) => {
                    break status_response(if plan.has_timeout {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::BAD_GATEWAY
                    });
                }
                Err(AttemptError::Exchange(why)) => {
                    warn!("upstream exchange with {} failed: {why}", plan.service_name);
                    break status_response(StatusCode::BAD_GATEWAY);
                }
            }
        };

        if response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(downstream) = downstream_upgrade
        {
            let upstream = handle_upgrade(&response);
            let service = plan.service_name.clone();
            tokio::spawn(async move {
                match tokio::join!(downstream, upstream) {
                    (Ok(mut down), Ok(mut up)) => {
                        if let Err(e) = tokio::io::copy_bidirectional(&mut down, &mut up).await {
                            log::debug!("upgraded connection to {service} ended: {e}");
                        }
                    }
                    (d, u) => warn!(
                        "upgrade to {service} not completed: downstream {:?}, upstream {:?}",
                        d.err().map(|e| e.to_string()),
                        u.err().map(|e| e.to_string())
                    ),
                }
            });
            return response;
        }

        let mut sink = HeadersMut(response.headers_mut());
        plan.response_headers.apply(&mut sink);
        if let Some((origin, cors, has_credentials)) = &plan.cors {
            apply_cors_response_headers(&mut sink, origin, cors, *has_credentials);
        }
        response
    }

    async fn attempt(&self, req: Request, deadline: Option<Duration>) -> Result<Response, AttemptError> {
        let fut = self.client.serve(req);
        let result = match deadline {
            Some(d) => match tokio::time::timeout(d, fut).await {
                Ok(r) => r,
                Err(_) => return Err(AttemptError::Timeout),
            },
            None => fut.await,
        };
        result.map_err(|e| classify(&e))
    }

    /// The request one attempt sends: same method and target, the backend as
    /// the URI authority (Rama dials the URI), the prepared headers, and the
    /// TLS and HTTP/2 parameters as request extensions.
    fn upstream_request(
        &self,
        incoming: &Incoming,
        headers: HeaderMap,
        plan: &Forward,
        backend: SocketAddr,
        body: Body,
    ) -> Request {
        let use_tls = plan.backend_tls.is_some() || plan.upstream_tls;
        // The downstream URI with the backend as authority: path and query
        // pass through untouched, no string round-trip. A URL rewrite is the
        // one case that re-parses.
        let mut uri = match &plan.rewrite_path {
            Some(path) => format!("http://{backend}{path}").parse().unwrap_or_else(|_| incoming.uri.clone()),
            None => incoming.uri.clone(),
        };
        uri.set_scheme(if use_tls { Protocol::HTTPS } else { Protocol::HTTP });
        uri.set_authority(Authority::from(backend));
        let h2 = matches!(plan.protocol, BackendProtocol::Grpc | BackendProtocol::H2c);
        let version = if h2 {
            Version::HTTP_2
        } else if incoming.version == Version::HTTP_2 {
            Version::HTTP_11
        } else {
            incoming.version
        };

        let mut req = Request::new(body);
        *req.method_mut() = incoming.method.clone();
        *req.uri_mut() = uri;
        *req.version_mut() = version;
        *req.headers_mut() = headers;

        let ext = req.extensions();
        let mut tls_key: u64 = 0;
        if use_tls {
            let sni = plan.backend_tls.as_ref().map(|b| b.hostname.as_ref()).unwrap_or(plan.upstream_sni.as_ref());
            if !sni.is_empty()
                && let Ok(host) = Host::try_from(sni)
            {
                ext.insert(TlsServerName(host));
            }
            match plan.backend_tls.as_deref() {
                Some(btls) => {
                    let view = upstream_tls_for(btls);
                    ext.insert(view.trust.clone());
                    if let Some(verifier) = &view.verifier {
                        ext.insert(RustlsServerCertVerifier(Arc::clone(verifier)));
                    }
                    tls_key ^= view.key;
                }
                None if !plan.upstream_verify => {
                    ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
                    tls_key ^= 1;
                }
                None => {}
            }
            if let Some(identity) = plan.client_identity.as_ref() {
                if let Some(auth) = client_auth_for(identity).as_ref() {
                    ext.insert(TlsClientAuth(auth.clone()));
                }
                tls_key ^= (Arc::as_ptr(identity) as usize as u64).rotate_left(17);
            }
            // Plaintext and TLS never share a key even when nothing else differs.
            tls_key |= 1 << 63;
        }
        ext.insert(UpstreamTarget { addr: backend, tls: use_tls, tls_key, h2 });
        req
    }

    fn note_ejection(&self, plan: &Forward, addr: &SocketAddr, out: Duration, why: &str) {
        let svc = plan.service_name.as_ref();
        self.metrics.upstream_ejections_total.with_label_values(&[svc]).inc();
        warn!("ejected {addr} from {svc}:{} for {out:?} after {why}", plan.port);
    }
}

/// Status code as a metrics label without a heap allocation.
fn status_label(status: u16) -> arrayvec::ArrayString<4> {
    let mut buf = arrayvec::ArrayString::<4>::new();
    let _ = std::fmt::Write::write_fmt(&mut buf, format_args!("{status}"));
    buf
}

fn access_log(peer_ip: Option<IpAddr>, method: &str, path: &str, host: &str, status: u16, start: Instant) {
    if access_log_enabled() {
        info!(
            target: "portus_dataplane::access",
            "{} {} {} {} {} {:.3}s",
            peer_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "-".into()),
            method,
            path,
            host,
            status,
            start.elapsed().as_secs_f64()
        );
    }
}

/// Connection-phase failures (dial, TLS) are distinguished from failures of
/// an established exchange so retries and outlier ejection only fire when
/// the backend never answered.
fn classify(err: &BoxError) -> AttemptError {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err.as_ref());
    while let Some(e) = cur {
        if let Some(ce) = e.downcast_ref::<ConnectionError>() {
            return match ce.domain() {
                ConnectionErrorDomain::Transport | ConnectionErrorDomain::Application => AttemptError::Connect(ce.to_string()),
                _ => AttemptError::Exchange(ce.to_string()),
            };
        }
        if e.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
            return AttemptError::Timeout;
        }
        cur = e.source();
    }
    AttemptError::Exchange(err.to_string())
}

fn reply_response(reply: Reply) -> Response {
    let mut resp = Response::new(Body::new(Full::new(reply.body)));
    *resp.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in &reply.headers {
        if let (Some(n), Some(v)) = (rama_name(name), rama_value(value)) {
            resp.headers_mut().insert(n, v);
        }
    }
    if !reply.keepalive {
        resp.headers_mut().insert("connection", HeaderValue::from_static("close"));
    }
    resp
}

fn status_response(status: StatusCode) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = status;
    resp.headers_mut().insert("content-length", HeaderValue::from_static("0"));
    resp
}
