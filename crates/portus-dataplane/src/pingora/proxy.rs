//! The Pingora `ProxyHttp` implementation: the core plans the request, this
//! carries it out on Pingora's session and peer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log::{info, warn};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use portus_dataplane_core::h2::{UPSTREAM_H2_CONNECTION_WINDOW, UPSTREAM_H2_STREAM_WINDOW};
use portus_dataplane_core::metrics::ProxyMetrics;
use portus_dataplane_core::outlier::Outliers;
use portus_dataplane_core::plan::{
    apply_cors_response_headers, plan_request, should_retry_connect, Forward, HeaderSink, Plan,
    Reply, RequestFacts,
};
use portus_dataplane_core::router::{access_log_enabled, should_retry_status, SnapshotSlot};
use portus_dataplane_core::types::BackendProtocol;

use super::tls::{ca_type_for, cert_key_for};

/// Per-request state: the core's plan plus what Pingora's hooks track.
pub struct RouterCtx {
    plan: Option<Box<Forward>>,
    retries_left: u32,
    request_start: Instant,
    body_bytes_received: u64,
    /// The endpoint the last upstream attempt went to, for outlier ejection.
    upstream_addr: Option<SocketAddr>,
}

/// Maps a Pingora error to the appropriate HTTP status code for Gateway API compliance.
///
/// When a route has timeouts configured (`has_timeout` is true):
/// - `ReadTimedout` or `ConnectTimedout` from upstream → **504** Gateway Timeout
///
/// Without timeouts, falls through to Pingora's default behavior:
/// - Upstream errors → 502
/// - Downstream read/write/close errors → 0 (connection dead)
/// - Other downstream errors → 400
/// - Internal/unset errors → 500
fn timeout_error_to_status_code(e: &pingora_core::Error, has_timeout: bool) -> u16 {
    use pingora_core::ErrorType::*;

    if let HTTPStatus(code) = e.etype() {
        return *code;
    }
    if has_timeout {
        match e.etype() {
            ReadTimedout | ConnectTimedout => return 504,
            _ => {}
        }
    }
    match e.esource() {
        pingora_core::ErrorSource::Upstream => 502,
        pingora_core::ErrorSource::Downstream => match e.etype() {
            WriteError | ReadError | ConnectionClosed => 0,
            _ => 400,
        },
        pingora_core::ErrorSource::Internal | pingora_core::ErrorSource::Unset => match e.etype() {
            ReadTimedout | ConnectTimedout => 502,
            _ => 500,
        },
    }
}

/// Pingora keeps original header casing beside its `HeaderMap`, so its
/// header objects are mutated through their own methods rather than the map.
struct PingoraHeaders<'a, T>(&'a mut T);

macro_rules! header_sink_for {
    ($ty:ty) => {
        impl HeaderSink for PingoraHeaders<'_, $ty> {
            fn get(&self, name: &http::HeaderName) -> Option<&[u8]> {
                self.0.headers.get(name).map(|v| v.as_bytes())
            }
            fn insert(&mut self, name: http::HeaderName, value: http::HeaderValue) {
                // Only fails on an invalid name, which a parsed `HeaderName` never is.
                let _ = self.0.insert_header(name, value);
            }
            fn append(&mut self, name: http::HeaderName, value: http::HeaderValue) {
                let _ = self.0.append_header(name, value);
            }
            fn remove(&mut self, name: &http::HeaderName) {
                self.0.remove_header(name);
            }
        }
    };
}
header_sink_for!(pingora_http::RequestHeader);
header_sink_for!(pingora_http::ResponseHeader);

/// Write a core [`Reply`] to the downstream session.
async fn respond(session: &mut Session, reply: Reply) -> Result<()> {
    if !reply.keepalive {
        session.set_keepalive(None);
    }
    let mut header = pingora_http::ResponseHeader::build(reply.status, Some(reply.headers.len()))?;
    for (name, value) in reply.headers {
        header.insert_header(name, value)?;
    }
    session.write_response_header(Box::new(header), false).await?;
    session.write_response_body(Some(reply.body), true).await?;
    Ok(())
}

pub struct Router {
    pub snapshot: SnapshotSlot,
    pub metrics: Arc<ProxyMetrics>,
    /// Passive outlier ejection state, shared by the HTTP and HTTPS services.
    pub outliers: Arc<Outliers>,
}

impl Router {
    fn note_ejection(&self, plan: &Forward, addr: &SocketAddr, out: Duration, why: &str) {
        let svc = plan.service_name.as_ref();
        self.metrics.upstream_ejections_total.with_label_values(&[svc]).inc();
        warn!("ejected {addr} from {svc}:{} for {out:?} after {why}", plan.port);
    }
}

#[async_trait]
impl ProxyHttp for Router {
    type CTX = RouterCtx;

    fn new_ctx(&self) -> Self::CTX {
        RouterCtx {
            plan: None,
            retries_left: 0,
            request_start: Instant::now(),
            body_bytes_received: 0,
            upstream_addr: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let raw_host: String = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| req.uri.authority().map(|a| a.as_str()))
            .unwrap_or("")
            .to_string();
        let host = raw_host.split(':').next().unwrap_or(&raw_host);
        let local_port: u16 = session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.local_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.port())
            .unwrap_or(80);
        let ssl = session.digest().and_then(|d| d.ssl_digest.as_ref());
        let socket_is_tls = ssl.is_some();
        let sni = ssl.and_then(|s| s.sni.as_deref());
        let peer_ip = session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.peer_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip());

        let snap = self.snapshot.load();
        let facts = RequestFacts {
            host,
            path: req.uri.path(),
            path_and_query: req.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(req.uri.path()),
            query: req.uri.query(),
            method: req.method.as_str(),
            headers: &req.headers,
            local_port,
            socket_is_tls,
            sni,
            peer_ip,
        };
        match plan_request(&snap, facts, &self.metrics).await {
            Plan::Respond(reply) => {
                respond(session, reply).await?;
                Ok(true)
            }
            Plan::Forward(plan) => {
                ctx.retries_left = plan.max_retries;
                ctx.plan = Some(plan);
                session.set_keepalive(Some(60));
                Ok(false)
            }
        }
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Content-Length requests were checked when planning; this bounds
        // chunked/streamed bodies.
        if let (Some(plan), Some(data)) = (ctx.plan.as_ref(), body.as_ref()) {
            ctx.body_bytes_received += data.len() as u64;
            if ctx.body_bytes_received > plan.max_request_body_bytes {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "request body exceeds size limit",
                ));
            }
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // X-Forwarded-For / X-Real-IP from the downstream client address.
        if let Some(addr) = session.downstream_session.client_addr() {
            use std::fmt::Write;
            let mut ip_buf = arrayvec::ArrayString::<64>::new();
            match addr.as_inet() {
                Some(inet) => {
                    let _ = write!(&mut ip_buf, "{}", inet.ip());
                }
                None => {
                    let _ = write!(&mut ip_buf, "{}", addr);
                }
            }
            let ip = ip_buf.as_str();
            let xff = match upstream_request.headers.get("x-forwarded-for") {
                Some(existing) => format!("{}, {}", existing.to_str().unwrap_or(""), ip),
                None => ip.to_owned(),
            };
            upstream_request.insert_header("x-forwarded-for", &xff)?;
            upstream_request.insert_header("x-real-ip", ip)?;
        }

        let Some(plan) = ctx.plan.as_ref() else { return Ok(()) };
        if let Some(new_path) = &plan.rewrite_path
            && let Ok(uri) = new_path.parse::<http::Uri>()
        {
            upstream_request.set_uri(uri);
        }
        if let Some(new_host) = &plan.rewrite_hostname {
            upstream_request.insert_header("host", new_host.as_ref())?;
        }
        plan.request_headers.apply(&mut PingoraHeaders(upstream_request));
        Ok(())
    }

    /// HTTPRoute rule-level retry (`retry.codes`): an upstream response with
    /// one of the configured statuses is discarded and the request replayed
    /// while attempts remain. Returning a retryable error here re-enters
    /// Pingora's upstream loop before anything reaches the client; the last
    /// attempt's response passes through unchanged.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(plan) = ctx.plan.as_ref() else { return Ok(()) };
        let status = upstream_response.status.as_u16();
        if let (Some(pool), Some(addr)) = (plan.pool.as_ref(), ctx.upstream_addr.as_ref())
            && let Some(out) = self.outliers.responded(pool, addr, status)
        {
            self.note_ejection(plan, addr, out, &format!("{status} responses in a row"));
        }
        if should_retry_status(status, &plan.retry_codes, ctx.retries_left) {
            ctx.retries_left -= 1;
            info!("upstream {} answered {status}, retrying ({} left)", plan.service_name, ctx.retries_left);
            let mut e = pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "retrying on upstream response status",
            );
            e.set_retry(true);
            return Err(e);
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(plan) = ctx.plan.as_ref() else { return Ok(()) };
        let mut headers = PingoraHeaders(upstream_response);
        plan.response_headers.apply(&mut headers);
        if let Some((origin, cors, has_credentials)) = &plan.cors {
            apply_cors_response_headers(&mut headers, origin, cors, *has_credentials);
        }
        Ok(())
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let Some(plan) = ctx.plan.as_ref() else {
            let host = session.req_header().headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("<unknown>");
            let path = session.req_header().uri.path();
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(404),
                format!("no route for {host}{path}"),
            ));
        };
        let pool = plan.pool.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(500),
                format!("no endpoints for {}:{}", plan.service_name, plan.port),
            )
        })?;
        let backend = pool.select().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(500),
                format!("no ready endpoints for {}:{}", plan.service_name, plan.port),
            )
        })?;

        // BackendTLSPolicy overrides the route-level upstream_tls.
        let (use_tls, sni) = match (&plan.backend_tls, plan.upstream_tls) {
            (Some(btls), _) => (true, btls.hostname.to_string()),
            (None, true) => (true, plan.upstream_sni.to_string()),
            (None, false) => (false, String::new()),
        };

        ctx.upstream_addr = Some(backend);
        let mut peer = HttpPeer::new(backend, use_tls, sni);
        if use_tls {
            // Gateway spec.tls.backend.clientCertificateRef (mTLS). Part of the
            // peer's reuse hash, so pooled connections never mix identities.
            peer.client_cert_key = plan.client_identity.as_deref().map(cert_key_for);
            match &plan.backend_tls {
                Some(btls) => {
                    peer.options.verify_cert = true;
                    peer.options.ca = Some(ca_type_for(btls));
                    if !btls.subject_alt_names.is_empty() {
                        peer.options.required_sans = Some(Arc::clone(&btls.subject_alt_names));
                    }
                }
                None => peer.options.verify_cert = plan.upstream_verify,
            }
        }
        if let Some(t) = plan.connect_timeout {
            peer.options.connection_timeout = Some(t);
        }
        if let Some(t) = plan.read_timeout {
            peer.options.read_timeout = Some(t);
        }
        if let Some(t) = plan.write_timeout {
            peer.options.write_timeout = Some(t);
        }

        // Keep idle upstream connections for 60s; without this Pingora uses no
        // idle timeout and connections may be evicted prematurely.
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        // TCP keepalive: Kubernetes services and cloud LBs silently drop idle
        // TCP connections; probes keep requests off dead sockets.
        peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(0),
        });

        // gRPC needs HTTP/2 with concurrent streams; set_http_version(2, 2)
        // forces h2 (h2c for plaintext, ALPN h2 on TLS).
        if plan.protocol == BackendProtocol::Grpc {
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = 200;
            // Periodic PINGs detect dead connections quickly on long-lived
            // gRPC streams behind load balancers that drop idle connections.
            peer.options.h2_ping_interval = Some(Duration::from_secs(30));
        }
        if plan.protocol == BackendProtocol::Grpc || plan.protocol == BackendProtocol::H2c {
            peer.options.h2_stream_window_size = Some(UPSTREAM_H2_STREAM_WINDOW);
            peer.options.h2_connection_window_size = Some(UPSTREAM_H2_CONNECTION_WINDOW);
        }
        // appProtocol kubernetes.io/h2c: HTTP/2 prior knowledge, no upgrade.
        if plan.protocol == BackendProtocol::H2c {
            peer.options.set_http_version(2, 2);
        }
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        let Some(plan) = ctx.plan.as_ref() else { return e };
        self.metrics.upstream_connect_errors_total.with_label_values(&[plan.service_name.as_ref()]).inc();
        if let (Some(pool), Some(addr)) = (plan.pool.as_ref(), ctx.upstream_addr.as_ref())
            && let Some(out) = self.outliers.connect_failed(pool, addr)
        {
            self.note_ejection(plan, addr, out, "a connect failure");
        }
        if should_retry_connect(&plan.retry_on, ctx.retries_left) {
            ctx.retries_left -= 1;
            e.set_retry(true);
            warn!("upstream connect failed for {}, retrying ({} left)", plan.service_name, ctx.retries_left);
        }
        e
    }

    /// Gateway API status codes for failures: with a route timeout configured,
    /// upstream read/connect timeouts are 504; everything else follows
    /// Pingora's defaults.
    async fn fail_to_proxy(&self, session: &mut Session, e: &pingora_core::Error, ctx: &mut Self::CTX) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let has_timeout = ctx.plan.as_ref().is_some_and(|p| p.has_timeout);
        let code = timeout_error_to_status_code(e, has_timeout);
        if code > 0 {
            session.respond_error(code).await.unwrap_or_else(|e| {
                warn!("failed to send error response to downstream: {e}");
            });
        }
        FailToProxy { error_code: code, can_reuse_downstream: false }
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        let duration = ctx.request_start.elapsed().as_secs_f64();
        let status_u16 = session.response_written().map_or(0u16, |resp| resp.status.as_u16());
        let mut status_buf = arrayvec::ArrayString::<4>::new();
        let _ = std::fmt::Write::write_fmt(&mut status_buf, format_args!("{}", status_u16));
        let status = status_buf.as_str();

        let (host, proto) = match ctx.plan.as_ref() {
            Some(plan) => (plan.service_name.as_ref(), plan.protocol_label()),
            None => ("no_route", "http"),
        };
        self.metrics.request_total.with_label_values(&[host, status, proto]).inc();
        match ctx.plan.as_ref() {
            Some(plan) => plan.duration_histogram.observe(duration),
            None => self.metrics.request_duration.with_label_values(&[host, proto]).observe(duration),
        }

        if let Some(plan) = ctx.plan.as_ref() {
            // Circuit breaker: only the final outcome counts, after retries.
            if let Some(cb) = &plan.circuit_breaker {
                if status_u16 >= 500 || status_u16 == 0 {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
                self.metrics.circuit_breaker_state.with_label_values(&[host]).set(cb.current_state() as i64);
            }
            // Connection limiter release: logging() runs after every
            // request_filter(), including early returns, so the slot never leaks.
            if let Some(cl) = &plan.connection_limiter {
                cl.release();
            }
        }

        if access_log_enabled() {
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            let client = session
                .downstream_session
                .client_addr()
                .map(|a| a.as_inet().map(|inet| inet.to_string()).unwrap_or_else(|| a.to_string()))
                .unwrap_or_else(|| "-".to_string());
            info!(
                target: "portus_dataplane::access",
                "{} {} {} {} {} {:.3}s",
                client, method, path, host, status, duration
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_error_read_timedout_with_timeout_returns_504() {
        let err = pingora_core::Error::explain(pingora_core::ErrorType::ReadTimedout, "while reading response header");
        assert_eq!(timeout_error_to_status_code(&err, true), 504);
    }

    #[test]
    fn timeout_error_connect_timedout_with_timeout_returns_504() {
        let err = pingora_core::Error::explain(pingora_core::ErrorType::ConnectTimedout, "connecting to upstream");
        assert_eq!(timeout_error_to_status_code(&err, true), 504);
    }

    #[test]
    fn timeout_error_read_timedout_without_timeout_returns_502() {
        let err = pingora_core::Error::explain(pingora_core::ErrorType::ReadTimedout, "while reading response header");
        assert_eq!(timeout_error_to_status_code(&err, false), 502);
    }

    #[test]
    fn timeout_error_http_status_passthrough() {
        let err = pingora_core::Error::explain(pingora_core::ErrorType::HTTPStatus(404), "no route");
        assert_eq!(timeout_error_to_status_code(&err, true), 404);
    }

    #[test]
    fn timeout_error_upstream_non_timeout_returns_502() {
        let err = pingora_core::Error::new_up(pingora_core::ErrorType::ConnectError);
        assert_eq!(timeout_error_to_status_code(&err, true), 502);
    }
}
