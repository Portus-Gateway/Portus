//! The Pingora `ProxyHttp` implementation: one request through the core's
//! route match and policies, then to the endpoint the pool picked.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use log::{info, warn};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use portus_dataplane_core::circuit_breaker::{CircuitBreaker, ConnectionLimiter};
use portus_dataplane_core::h2::{UPSTREAM_H2_CONNECTION_WINDOW, UPSTREAM_H2_STREAM_WINDOW};
use portus_dataplane_core::metrics::ProxyMetrics;
use portus_dataplane_core::outlier::Outliers;
use portus_dataplane_core::pool::Pool;
use portus_dataplane_core::router::{
    access_log_enabled, cors_allow_origin_value, cors_headers_value, cors_methods_value,
    cors_origin_matches, detect_misdirected_request, extract_client_ip, listener_scheme_and_port,
    lookup_domain_wildcard_bucket, select_listener_bucket, select_weighted_backend,
    should_retry_status, spawn_mirror_request, BackendTlsInfo, ClientIdentity, CorsConfig,
    ListenerBucket, SnapshotSlot, DEFAULT_MAX_REQUEST_BODY_BYTES, EMPTY_CODES, EMPTY_HEADER_VEC,
    EMPTY_NAME_VEC, EMPTY_SNI, EMPTY_STRING_VEC,
};
use portus_dataplane_core::types::BackendProtocol;

use super::tls::{ca_type_for, cert_key_for};

/// Per-request context for retry tracking and cached route info.
pub struct RouterCtx {
    retries_left: u32,
    service_name: Option<Arc<str>>,
    port: u16,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    upstream_tls: bool,
    upstream_sni: Arc<str>,
    upstream_verify: bool,
    protocol: BackendProtocol,
    request_start: Instant,
    request_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    request_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    request_headers_remove: Arc<Vec<HeaderName>>,
    response_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    response_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    response_headers_remove: Arc<Vec<HeaderName>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    connection_acquired: bool,
    connection_limiter: Option<Arc<ConnectionLimiter>>,
    // URL rewrite support
    rewrite_path: Option<String>,
    rewrite_hostname: Option<Arc<str>>,
    // Extended HTTPRoute: per-route request timeout (overall deadline)
    request_timeout: Option<Duration>,
    // Tracks which timeout type is active, so fail_to_proxy returns the correct status code.
    // When backend_request_timeout is active, read timeouts are 504 (Gateway Timeout).
    // When request_timeout is active (overall deadline), read timeouts are also 504.
    has_timeout: bool,
    // CORS: If Origin matches, store (origin, cors_config) to apply response headers.
    cors_origin: Option<http::HeaderValue>,
    cors_config: Option<Arc<CorsConfig>>,
    has_credentials: bool,
    // Phase 11: retry conditions (connect-failure, 5xx, gateway-error)
    // Empty means retry on connect-failure only (backward compat).
    retry_on: Arc<Vec<String>>,
    // HTTPRouteRetry: upstream statuses that are retried.
    retry_codes: Arc<Vec<u16>>,
    // Phase 11: request body size tracking for chunked encoding
    max_request_body_bytes: u64,
    body_bytes_received: u64,
    // PERF-7: Cached Prometheus histogram handle to avoid per-request HashMap lookup
    // in logging(). Populated in request_filter() after route match.
    cached_duration: Option<prometheus::Histogram>,
    // PERF-9: Cached load balancer from snapshot, avoids re-loading ArcSwap in upstream_peer.
    cached_lb: Option<Arc<Pool>>,
    // The endpoint the last upstream attempt went to, for outlier ejection.
    upstream_addr: Option<std::net::SocketAddr>,
    // BackendTLSPolicy config for the selected backend, resolved in request_filter
    // from the same snapshot load as `cached_lb`.
    cached_backend_tls: Option<Arc<BackendTlsInfo>>,
    // Client certificate this Gateway presents to TLS backends
    // (Gateway spec.tls.backend.clientCertificateRef), same snapshot load.
    cached_client_cert: Option<Arc<ClientIdentity>>,
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

    // Check for explicit HTTPStatus first (e.g., our 404/500 for no-route)
    if let HTTPStatus(code) = e.etype() {
        return *code;
    }

    // When timeouts are configured, timeout errors become 504 Gateway Timeout
    // regardless of error source (Pingora may set Upstream or Unset depending
    // on where the timeout occurs).
    if has_timeout {
        match e.etype() {
            ReadTimedout | ConnectTimedout => return 504,
            _ => {}
        }
    }

    // Default Pingora behavior for other errors
    match e.esource() {
        pingora_core::ErrorSource::Upstream => 502,
        pingora_core::ErrorSource::Downstream => {
            match e.etype() {
                WriteError | ReadError | ConnectionClosed => 0,
                _ => 400,
            }
        }
        pingora_core::ErrorSource::Internal | pingora_core::ErrorSource::Unset => {
            // Timeout errors from upstream are 502 even if source is Unset
            match e.etype() {
                ReadTimedout | ConnectTimedout => 502,
                _ => 500,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Router: the Pingora ProxyHttp implementation over the core's decisions
// ---------------------------------------------------------------------------

pub struct Router {
    /// PERF-9: Single atomic snapshot for all per-request config maps.
    /// One ArcSwap::load() replaces 4+ separate loads per request.
    pub snapshot: SnapshotSlot,
    pub metrics: Arc<ProxyMetrics>,
    /// Passive outlier ejection state, shared by the HTTP and HTTPS services.
    pub outliers: Arc<Outliers>,
}

impl Router {
    fn note_ejection(&self, ctx: &RouterCtx, addr: &std::net::SocketAddr, out: Duration, why: &str) {
        let svc = ctx.service_name.as_deref().unwrap_or("unknown");
        self.metrics.upstream_ejections_total.with_label_values(&[svc]).inc();
        warn!("ejected {addr} from {svc}:{} for {out:?} after {why}", ctx.port);
    }
}

#[async_trait]
impl ProxyHttp for Router {
    type CTX = RouterCtx;

    fn new_ctx(&self) -> Self::CTX {
        RouterCtx {
            retries_left: 0,
            service_name: None,
            port: 0,
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            upstream_tls: false,
            upstream_sni: Arc::clone(&EMPTY_SNI),
            upstream_verify: true,
            protocol: BackendProtocol::Http,
            request_start: Instant::now(),
            request_headers_add: Arc::clone(&EMPTY_HEADER_VEC),
            request_headers_set: Arc::clone(&EMPTY_HEADER_VEC),
            request_headers_remove: Arc::clone(&EMPTY_NAME_VEC),
            response_headers_add: Arc::clone(&EMPTY_HEADER_VEC),
            response_headers_set: Arc::clone(&EMPTY_HEADER_VEC),
            response_headers_remove: Arc::clone(&EMPTY_NAME_VEC),
            circuit_breaker: None,
            connection_acquired: false,
            connection_limiter: None,
            rewrite_path: None,
            rewrite_hostname: None,
            request_timeout: None,
            has_timeout: false,
            cors_origin: None,
            cors_config: None,
            has_credentials: false,
            retry_on: Arc::clone(&EMPTY_STRING_VEC),
            retry_codes: Arc::clone(&EMPTY_CODES),
            max_request_body_bytes: 0,
            body_bytes_received: 0,
            cached_duration: None,
            cached_lb: None,
            upstream_addr: None,
            cached_backend_tls: None,
            cached_client_cert: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // PERF-2: TODO — ideally this would borrow from session to avoid a heap
        // allocation, but the borrow checker requires an owned String because
        // `host` is used after mutable borrows on `session` (e.g., rate limiter
        // response, redirect response). Pingora would need to expose the request
        // header through a separate borrow scope to fix this.
        let raw_host: String = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                session
                    .req_header()
                    .uri
                    .authority()
                    .map(|a| a.as_str())
            })
            .unwrap_or("")
            .to_string();
        let host = raw_host.split(':').next().unwrap_or(&raw_host);
        let path = session.req_header().uri.path();
        let method = &session.req_header().method;
        let query = session.req_header().uri.query();

        // The local listener port drives port-specific route matching.
        let raw_local_port: u16 = session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.local_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.port())
            .unwrap_or(80);
        let socket_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let (original_scheme, local_port) = listener_scheme_and_port(raw_local_port, socket_is_tls);

        // PERF-9: One atomic load for all per-request config maps.
        let snap = self.snapshot.load();

        // HTTPRouteHTTPSListenerDetectMisdirectedRequests (GEP-1486): on HTTPS,
        // compare the listener that the TLS handshake selected (by SNI) with
        // the listener that the HTTP Host header claims. If they differ, emit
        // 421 Misdirected Request before any routing.
        if socket_is_tls {
            let misdirected = {
                let sni = session
                    .digest()
                    .and_then(|d| d.ssl_digest.as_ref())
                    .and_then(|s| s.sni.as_deref())
                    .map(|s| s.trim_end_matches('.'));
                let port_buckets: &[ListenerBucket] = snap
                    .listeners_by_port
                    .get(&local_port)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let hit = detect_misdirected_request(sni, host, port_buckets);
                if hit {
                    log::debug!("421 Misdirected: sni={sni:?} host={host} port={local_port}");
                }
                hit
            };
            if misdirected {
                let mut header = pingora_http::ResponseHeader::build(421, None)?;
                header.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                return Ok(true);
            }
        }

        // GatewayHTTPListenerIsolation: resolve the listener claiming this
        // request first (most-specific listener hostname on the matching port),
        // then match routes only within that listener. A catch-all listener
        // on the same port does not rescue a request that a more-specific
        // listener already claims.
        let bucket = snap
            .listeners_by_port
            .get(&local_port)
            .and_then(|bs| select_listener_bucket(host, bs))
            .or_else(|| select_listener_bucket(host, &snap.any_port_listeners));

        log::debug!(
            "route lookup: host={} local_port={} chosen_listener={:?}",
            host, local_port,
            bucket.map(|b| b.listener_hostname.as_ref())
        );

        let host_routes_opt = bucket.and_then(|b| {
            b.exact
                .get(host)
                .or_else(|| lookup_domain_wildcard_bucket(host, &b.domain_wildcards))
                .or(b.catch_all.as_ref())
        });
        let matched = if let Some(host_routes) = host_routes_opt {
            if let Some(pr) = host_routes.match_request(path, method, &session.req_header().headers, query) {
                log::debug!(
                    "matched route: listener={} path={} backend={}:{}",
                    pr.listener_name, pr.path, pr.service_name, pr.port
                );
                // Handle redirect routes: return 3xx response immediately
                if let Some(ref redirect) = pr.redirect {
                    let status = redirect.status_code;
                    let mut location = String::new();

                    // Scheme and port of the listener the request arrived on.
                    let original_port: u16 = local_port;

                    // Build Location header from redirect config
                    let effective_scheme = redirect.scheme.as_deref().unwrap_or(original_scheme);
                    location.push_str(effective_scheme);
                    location.push_str("://");

                    if let Some(ref hostname) = redirect.hostname {
                        location.push_str(hostname);
                    } else {
                        location.push_str(host);
                    }

                    // Determine effective port:
                    // - If redirect specifies a port, use it
                    // - If redirect changes the scheme (explicit scheme), default to the new scheme's port
                    // - If redirect keeps the same scheme (no explicit scheme), preserve original listener port
                    let effective_port = if let Some(p) = redirect.port {
                        Some(p)
                    } else if redirect.scheme.is_some() {
                        // Scheme is changing: default to new scheme's standard port (omitted)
                        None
                    } else {
                        // Scheme preserved: carry original listener port
                        Some(original_port)
                    };
                    if let Some(port) = effective_port {
                        let is_default_port = (effective_scheme == "http" && port == 80)
                            || (effective_scheme == "https" && port == 443);
                        if !is_default_port {
                            location.push(':');
                            location.push_str(&port.to_string());
                        }
                    }

                    if let Some(ref redir_path) = redirect.path {
                        match redirect.path_type.as_str() {
                            "ReplaceFullPath" => location.push_str(redir_path),
                            "ReplacePrefixMatch" => {
                                let prefix = pr.path.as_ref();
                                if let Some(suffix) = path.strip_prefix(prefix) {
                                    location.push_str(redir_path);
                                    if !redir_path.ends_with('/') && !suffix.starts_with('/') && !suffix.is_empty() {
                                        location.push('/');
                                    }
                                    // Avoid double slash when replacement ends with '/' and suffix starts with '/'
                                    if redir_path.ends_with('/') && suffix.starts_with('/') {
                                        location.push_str(&suffix[1..]);
                                    } else {
                                        location.push_str(suffix);
                                    }
                                } else {
                                    location.push_str(redir_path);
                                }
                            }
                            _ => location.push_str(path),
                        }
                    } else {
                        location.push_str(path);
                    }

                    let mut header = pingora_http::ResponseHeader::build(status, None)?;
                    header.insert_header("Location", &location)?;
                    header.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(header), false).await?;
                    session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                    return Ok(true);
                }
                // CORS handling: check Origin against allow_origins
                if let Some(ref cors) = pr.cors {
                    let origin_hv = session.req_header().headers.get("origin").cloned();
                    let origin_str = origin_hv.as_ref().and_then(|v| v.to_str().ok());

                    if let Some(origin_str) = origin_str {
                        let origin_matched = cors_origin_matches(&cors.allow_origins, origin_str);
                        let is_preflight = *method == http::Method::OPTIONS
                            && session.req_header().headers.get("access-control-request-method").is_some();

                        // Non-matching origin preflight: return 403 with no CORS headers.
                        // Browser blocks the request; 403 makes rejection explicit in logs.
                        if !origin_matched && is_preflight {
                            let mut header = pingora_http::ResponseHeader::build(403, None)?;
                            header.insert_header("Content-Length", "0")?;
                            session.write_response_header(Box::new(header), false).await?;
                            session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                            return Ok(true);
                        }

                        if origin_matched {
                            if is_preflight {
                                // Preflight: return 200 immediately with CORS headers
                                let mut header = pingora_http::ResponseHeader::build(200, None)?;
                                // Determine allowed origin header value
                                let has_creds = session.req_header().headers.get("cookie").is_some()
                                    || session.req_header().headers.get("authorization").is_some();
                                let acao = cors_allow_origin_value(cors, origin_str, has_creds);
                                header.insert_header("access-control-allow-origin", acao.as_ref())?;
                                if acao != "*" {
                                    header.insert_header("vary", "Origin")?;
                                }

                                // Allow-Methods: echo requested method or list configured
                                let requested_method = session.req_header().headers.get("access-control-request-method")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("");
                                let methods_value = cors_methods_value(&cors.allow_methods, &cors.allow_methods_joined, requested_method);
                                if !methods_value.is_empty() {
                                    header.insert_header("access-control-allow-methods", methods_value)?;
                                }

                                // Allow-Headers: echo requested headers or list configured
                                let requested_headers = session.req_header().headers.get("access-control-request-headers")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("");
                                let headers_value = cors_headers_value(&cors.allow_headers, &cors.allow_headers_joined, requested_headers);
                                if !headers_value.is_empty() {
                                    header.insert_header("access-control-allow-headers", headers_value)?;
                                }

                                // Expose-Headers
                                if !cors.expose_headers.is_empty() {
                                    header.insert_header("access-control-expose-headers", cors.expose_headers_joined.as_ref())?;
                                }

                                // Max-Age
                                if cors.max_age > 0 {
                                    header.insert_header("access-control-max-age", cors.max_age_str.as_ref())?;
                                }

                                // Allow-Credentials: only if true AND origin is not literal "*"
                                if cors.allow_credentials && acao != "*" {
                                    header.insert_header("access-control-allow-credentials", "true")?;
                                }

                                header.insert_header("Content-Length", "0")?;
                                session.write_response_header(Box::new(header), false).await?;
                                session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                                return Ok(true);
                            } else {
                                // Simple/actual request: store for response filtering
                                ctx.cors_origin = origin_hv.clone();
                                ctx.cors_config = Some(Arc::clone(cors));
                                ctx.has_credentials = session.req_header().headers.get("cookie").is_some()
                                    || session.req_header().headers.get("authorization").is_some();
                            }
                        }
                    }
                }

                // Extract client IP once — used for IP allowlist and per-IP rate limiting.
                // SEC-11: When trusted proxy CIDRs are configured, extract the real
                // client IP from XFF. Otherwise use the peer address directly.
                let client_ip: Option<std::net::IpAddr> = session
                    .digest()
                    .and_then(|d| d.socket_digest.as_ref())
                    .and_then(|sd| sd.peer_addr())
                    .and_then(|addr| addr.as_inet())
                    .map(|sock_addr| {
                        let peer = sock_addr.ip();
                        if pr.ip_trusted_proxy_cidrs.is_empty() {
                            peer
                        } else {
                            let xff = session.req_header().headers.get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            extract_client_ip(xff, peer, &pr.ip_trusted_proxy_cidrs)
                        }
                    });

                // IP allowlist check
                if !pr.ip_allow_cidrs.is_empty() || !pr.ip_deny_cidrs.is_empty() {
                    let denied = if let Some(ip) = client_ip {
                        if pr.ip_deny_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                            true
                        } else if !pr.ip_allow_cidrs.is_empty() {
                            !pr.ip_allow_cidrs.iter().any(|cidr| cidr.contains(&ip))
                        } else {
                            false
                        }
                    } else {
                        !pr.ip_allow_cidrs.is_empty()
                    };

                    if denied {
                        let resp = pingora_http::ResponseHeader::build(403, None)?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session.write_response_body(Some(bytes::Bytes::from_static(b"Forbidden")), true).await?;
                        return Ok(true);
                    }
                }

                // Request body size limit check (SEC-4: use global default when no policy)
                let effective_body_limit = if pr.max_request_body_bytes > 0 {
                    pr.max_request_body_bytes
                } else {
                    DEFAULT_MAX_REQUEST_BODY_BYTES
                };
                if let Some(cl) = session.req_header().headers.get("content-length")
                    && let Ok(len) = cl.to_str().unwrap_or("0").parse::<u64>()
                        && len > effective_body_limit {
                            let resp = pingora_http::ResponseHeader::build(413, None)?;
                            session.write_response_header(Box::new(resp), false).await?;
                            session.write_response_body(Some(bytes::Bytes::from_static(b"Request Entity Too Large")), true).await?;
                            return Ok(true);
                        }

                // Auth check -- before rate limiting so unauthenticated requests don't consume tokens
                if let Some(ref auth_config) = pr.auth_config {
                    use portus_dataplane_core::auth::{validate_basic_auth, validate_api_key};
                    use portus_dataplane_core::types::AuthConfig;
                    match auth_config {
                        AuthConfig::BasicAuth { credentials, realm } => {
                            let auth_header = session.req_header().headers.get("authorization");
                            if let Err(status) = validate_basic_auth(auth_header, credentials).await {
                                let mut resp = pingora_http::ResponseHeader::build(status, None)?;
                                // SEC-10: Sanitize realm to prevent header injection via CRD field
                                let safe_realm: String = realm.chars().filter(|c| *c != '"' && *c != '\r' && *c != '\n').collect();
                                resp.insert_header("WWW-Authenticate", format!("Basic realm=\"{}\"", safe_realm))?;
                                resp.insert_header("Content-Length", "0")?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                                return Ok(true);
                            }
                        }
                        AuthConfig::ApiKey { valid_keys, header_name } => {
                            let key_header = session.req_header().headers.get(header_name.as_str());
                            if let Err(status) = validate_api_key(key_header, valid_keys) {
                                let mut resp = pingora_http::ResponseHeader::build(status, None)?;
                                resp.insert_header("Content-Length", "0")?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                                return Ok(true);
                            }
                        }
                    }
                }

                // Weighted backend selection: override primary backend if weights configured
                if let Some(selected) = select_weighted_backend(&pr.weighted_backends, pr.total_weight) {
                    ctx.service_name = Some(Arc::clone(&selected.service_name));
                    ctx.port = selected.port;
                    // Per-backend headers override rule-level headers when present
                    if !selected.request_headers_add.is_empty()
                        || !selected.request_headers_set.is_empty()
                        || !selected.request_headers_remove.is_empty()
                    {
                        ctx.request_headers_add = Arc::clone(&selected.request_headers_add);
                        ctx.request_headers_set = Arc::clone(&selected.request_headers_set);
                        ctx.request_headers_remove = Arc::clone(&selected.request_headers_remove);
                    } else {
                        ctx.request_headers_add = Arc::clone(&pr.request_headers_add);
                        ctx.request_headers_set = Arc::clone(&pr.request_headers_set);
                        ctx.request_headers_remove = Arc::clone(&pr.request_headers_remove);
                    }
                } else {
                    ctx.service_name = Some(Arc::clone(&pr.service_name));
                    ctx.port = pr.port;
                    ctx.request_headers_add = Arc::clone(&pr.request_headers_add);
                    ctx.request_headers_set = Arc::clone(&pr.request_headers_set);
                    ctx.request_headers_remove = Arc::clone(&pr.request_headers_remove);
                }
                ctx.connect_timeout = pr.connect_timeout;
                ctx.read_timeout = pr.read_timeout;
                ctx.write_timeout = pr.write_timeout;
                ctx.retries_left = pr.max_retries;
                ctx.retry_on = Arc::clone(&pr.retry_on);
                ctx.retry_codes = Arc::clone(&pr.retry_codes);
                ctx.max_request_body_bytes = effective_body_limit;
                ctx.upstream_tls = pr.upstream_tls;
                ctx.upstream_sni = Arc::clone(&pr.upstream_sni);
                ctx.upstream_verify = pr.upstream_verify;
                ctx.protocol = pr.protocol;
                ctx.response_headers_add = Arc::clone(&pr.response_headers_add);
                ctx.response_headers_set = Arc::clone(&pr.response_headers_set);
                ctx.response_headers_remove = Arc::clone(&pr.response_headers_remove);

                // Gateway API conformance: when a route has no valid backends
                // (e.g., invalid cross-namespace ref without ReferenceGrant),
                // the compiled route has an empty service_name. Return 500.
                if ctx.service_name.as_deref().is_some_and(|s| s.is_empty()) {
                    let mut header = pingora_http::ResponseHeader::build(500, None)?;
                    header.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(header), false).await?;
                    session.write_response_body(Some(bytes::Bytes::new()), true).await?;
                    return Ok(true);
                }

                // PERF-9: Cache the LB from the snapshot so upstream_peer() doesn't
                // need another ArcSwap load.
                if let Some(sn) = ctx.service_name.as_ref() {
                    let lb_key = (sn.clone(), ctx.port);
                    ctx.cached_lb = snap.lbs.get(&lb_key).cloned();
                    ctx.cached_backend_tls = snap.backend_tls.get(&lb_key).cloned();
                    ctx.cached_client_cert = snap.backend_client_cert.clone();
                }

                // PERF-7: Cache the duration histogram handle now that host/proto
                // labels are known. Avoids a HashMap lookup + Vec<String> alloc
                // per request in logging().
                {
                    let host_label = ctx.service_name.as_deref().unwrap_or("no_route");
                    let proto_label = match ctx.protocol {
                        BackendProtocol::Http => "http",
                        BackendProtocol::Grpc => "grpc",
                        BackendProtocol::H2c => "h2c",
                        BackendProtocol::WebSocket => "ws",
                    };
                    ctx.cached_duration = Some(
                        self.metrics
                            .request_duration
                            .with_label_values(&[host_label, proto_label]),
                    );
                }

                // Per-route timeout: backend_request_timeout overrides read_timeout
                if let Some(t) = pr.backend_request_timeout {
                    ctx.read_timeout = Some(t);
                    ctx.has_timeout = true;
                }
                // request_timeout sets overall deadline. If no backend_request_timeout
                // is set, use request_timeout as the read_timeout so Pingora enforces it.
                // If both are set, use the smaller of the two.
                if let Some(t) = pr.request_timeout {
                    ctx.request_timeout = Some(t);
                    ctx.has_timeout = true;
                    match ctx.read_timeout {
                        Some(existing) if existing <= t => {
                            // backend_request_timeout is tighter, keep it
                        }
                        _ => {
                            ctx.read_timeout = Some(t);
                        }
                    }
                }

                // URL rewrite: store rewritten path/hostname for upstream_request_filter
                ctx.rewrite_path = pr.rewrite_path(path);
                ctx.rewrite_hostname = pr.rewrite_hostname().cloned();

                // Fire-and-forget mirror requests (multiple mirrors supported)
                for (mirror_svc, mirror_port, mirror_percent) in &pr.mirror_backends {
                    // percent=0 means mirror all; otherwise check random sample
                    if *mirror_percent > 0 && *mirror_percent < 100 {
                        let roll: f64 = rand::random::<f64>() * 100.0;
                        if roll >= *mirror_percent as f64 {
                            continue;
                        }
                    }
                    // Forward key request headers to mirror backend
                    let req_headers = session.req_header();
                    let mirror_headers: Vec<(String, String)> = req_headers.headers
                        .iter()
                        .filter(|(name, _)| {
                            let n = name.as_str();
                            // Forward content and application headers, skip hop-by-hop
                            n.starts_with("content-") || n.starts_with("x-") ||
                            n == "accept" || n == "user-agent"
                        })
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    // Mirror the request line verbatim (path *and* query): the
                    // Gateway API suite keys its mirror check on the full
                    // request target, and a mirror that drops the query is not
                    // a faithful copy.
                    let mirror_target = session
                        .req_header()
                        .uri
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or(path);
                    spawn_mirror_request(
                        mirror_svc,
                        *mirror_port,
                        method,
                        mirror_target,
                        host,
                        &mirror_headers,
                        &snap.lbs,
                    );
                }

                session.set_keepalive(Some(60));

                if let Some(ref limiter) = pr.rate_limiter {
                    use portus_dataplane_core::rate_limiter::RateLimiterMode;
                    let allowed = match limiter {
                        RateLimiterMode::Shared(bucket) => bucket.try_acquire(),
                        RateLimiterMode::PerIp(per_ip) => {
                            client_ip.is_some_and(|ip| per_ip.try_acquire(ip))
                        }
                    };
                    if !allowed {
                        let mut header = pingora_http::ResponseHeader::build(429, None)?;
                        header.insert_header("Content-Length", "19")?;
                        session
                            .write_response_header(Box::new(header), false)
                            .await?;
                        session
                            .write_response_body(
                                Some(bytes::Bytes::from_static(b"rate limit exceeded")),
                                true,
                            )
                            .await?;
                        self.metrics
                            .rate_limit_rejected_total
                            .with_label_values(&[pr.service_name.as_ref()])
                            .inc();
                        return Ok(true);
                    }
                }

                // PERF-8: Circuit breaker and connection limiter are embedded
                // directly in PathRoute — no per-request map lookups needed.
                if let Some(ref cb) = pr.circuit_breaker {
                    if !cb.allow_request() {
                        let mut header = pingora_http::ResponseHeader::build(503, None)?;
                        header.insert_header("Content-Length", "15")?;
                        session.write_response_header(Box::new(header), false).await?;
                        session.write_response_body(
                            Some(bytes::Bytes::from_static(b"circuit is open")),
                            true,
                        ).await?;
                        return Ok(true);
                    }
                    ctx.circuit_breaker = Some(Arc::clone(cb));
                }
                if let Some(ref cl) = pr.connection_limiter {
                    if !cl.try_acquire() {
                        let mut header = pingora_http::ResponseHeader::build(503, None)?;
                        header.insert_header("Content-Length", "24")?;
                        session.write_response_header(Box::new(header), false).await?;
                        session.write_response_body(
                            Some(bytes::Bytes::from_static(b"connection limit reached")),
                            true,
                        ).await?;
                        return Ok(true);
                    }
                    ctx.connection_acquired = true;
                    ctx.connection_limiter = Some(Arc::clone(cl));
                }

                true
            } else {
                false
            }
        } else {
            false
        };

        if !matched {
            session.set_keepalive(None);
            let mut header = pingora_http::ResponseHeader::build(404, None)?;
            header.insert_header("Content-Length", "8")?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(
                    Some(bytes::Bytes::from_static(b"no route")),
                    true,
                )
                .await?;
            return Ok(true);
        }

        Ok(false)
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
        // Enforce body size limit for chunked requests (no Content-Length header).
        // Content-Length requests are checked in request_filter; this handles streaming.
        if ctx.max_request_body_bytes > 0
            && let Some(data) = body {
                ctx.body_bytes_received += data.len() as u64;
                if ctx.body_bytes_received > ctx.max_request_body_bytes {
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
        // Inject X-Forwarded-For and X-Real-IP from downstream client address
        // PERF-3: Use stack buffer for IP string to avoid heap allocation per request.
        if let Some(addr) = session.downstream_session.client_addr() {
            use std::fmt::Write;
            let mut ip_buf = arrayvec::ArrayString::<64>::new();
            if let Some(inet) = addr.as_inet() {
                let _ = write!(&mut ip_buf, "{}", inet.ip());
            } else {
                let _ = write!(&mut ip_buf, "{}", addr);
            }
            let ip = ip_buf.as_str();
            // Append to existing X-Forwarded-For if present, otherwise set
            let xff = if let Some(existing) = upstream_request.headers.get("x-forwarded-for") {
                format!("{}, {}", existing.to_str().unwrap_or(""), ip)
            } else {
                ip.to_owned()
            };
            upstream_request.insert_header("x-forwarded-for", &xff)?;
            upstream_request.insert_header("x-real-ip", ip)?;
        }

        // URL rewrite: modify path and/or host before proxying
        if let Some(ref new_path) = ctx.rewrite_path
            && let Ok(uri) = new_path.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
        if let Some(ref new_host) = ctx.rewrite_hostname {
            upstream_request.insert_header("host", new_host.as_ref())?;
        }

        // CRD header mutations: removes first, then sets (overwrite), then adds (comma-append)
        for name in ctx.request_headers_remove.iter() {
            upstream_request.remove_header(name);
        }
        for (name, value) in ctx.request_headers_set.iter() {
            upstream_request.insert_header(name.clone(), value)?;
        }
        for (name, value) in ctx.request_headers_add.iter() {
            // Gateway API: add = append with comma separator if header exists
            if let Some(existing) = upstream_request.headers.get(name) {
                // PERF-17: Stack buffer for small header appends to avoid heap allocation
                let existing_str = existing.to_str().unwrap_or("");
                let value_str = value.to_str().unwrap_or("");
                if existing_str.len() + 1 + value_str.len() < 128 {
                    use std::fmt::Write;
                    let mut buf = arrayvec::ArrayString::<128>::new();
                    let _ = write!(&mut buf, "{},{}", existing_str, value_str);
                    upstream_request.insert_header(name.clone(), buf.as_str())?;
                } else {
                    let new_val = format!("{},{}", existing_str, value_str);
                    upstream_request.insert_header(name.clone(), &new_val)?;
                }
            } else {
                upstream_request.insert_header(name.clone(), value)?;
            }
        }
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
        let status = upstream_response.status.as_u16();
        if let (Some(lb), Some(addr)) = (ctx.cached_lb.as_ref(), ctx.upstream_addr.as_ref())
            && let Some(out) = self.outliers.responded(lb, addr, status)
        {
            self.note_ejection(ctx, addr, out, &format!("{status} responses in a row"));
        }
        if should_retry_status(status, &ctx.retry_codes, ctx.retries_left) {
            ctx.retries_left -= 1;
            info!(
                "upstream {:?} answered {status}, retrying ({} left)",
                ctx.service_name, ctx.retries_left
            );
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
        // Removes first, then sets (overwrite), then adds (comma-append)
        for name in ctx.response_headers_remove.iter() {
            upstream_response.remove_header(name);
        }
        for (name, value) in ctx.response_headers_set.iter() {
            upstream_response.insert_header(name.clone(), value)?;
        }
        for (name, value) in ctx.response_headers_add.iter() {
            // Gateway API: add = append with comma separator if header exists
            if let Some(existing) = upstream_response.headers.get(name) {
                // PERF-17: Stack buffer for small header appends to avoid heap allocation
                let existing_str = existing.to_str().unwrap_or("");
                let value_str = value.to_str().unwrap_or("");
                if existing_str.len() + 1 + value_str.len() < 128 {
                    use std::fmt::Write;
                    let mut buf = arrayvec::ArrayString::<128>::new();
                    let _ = write!(&mut buf, "{},{}", existing_str, value_str);
                    upstream_response.insert_header(name.clone(), buf.as_str())?;
                } else {
                    let new_val = format!("{},{}", existing_str, value_str);
                    upstream_response.insert_header(name.clone(), &new_val)?;
                }
            } else {
                upstream_response.insert_header(name.clone(), value)?;
            }
        }

        // CORS: add response headers for simple/actual requests
        if let (Some(origin_hv), Some(cors)) = (&ctx.cors_origin, &ctx.cors_config) {
            let origin = origin_hv.to_str().unwrap_or("");
            let has_creds = ctx.has_credentials;
            let acao = cors_allow_origin_value(cors, origin, has_creds);
            upstream_response.insert_header("access-control-allow-origin", acao.as_ref())?;
            if acao != "*" {
                upstream_response.append_header("vary", "Origin")?;
            }
            if cors.allow_credentials && acao != "*" {
                upstream_response.insert_header("access-control-allow-credentials", "true")?;
            }
            if !cors.expose_headers.is_empty() {
                upstream_response.insert_header("access-control-expose-headers", cors.expose_headers_joined.as_ref())?;
            }
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let service_name = ctx.service_name.as_ref().ok_or_else(|| {
            let host = session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<unknown>");
            let path = session.req_header().uri.path();
            pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(404),
                format!("no route for {host}{path}"),
            )
        })?;

        // PERF-9: Use the LB cached in request_filter to avoid a second ArcSwap load.
        let lb = ctx.cached_lb.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(500),
                format!("no endpoints for {}:{}", service_name, ctx.port),
            )
        })?;

        let backend = lb.select().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(500),
                format!("no ready endpoints for {}:{}", service_name, ctx.port),
            )
        })?;

        // BackendTLSPolicy: resolved in request_filter from the same snapshot as
        // the LB, so no second ArcSwap load or key allocation here. A policy
        // overrides the route-level upstream_tls.
        let backend_tls_info = ctx.cached_backend_tls.as_deref();

        let (use_tls, sni) = if let Some(btls) = backend_tls_info {
            // BackendTLSPolicy provides TLS config for this backend
            (true, btls.hostname.to_string())
        } else if ctx.upstream_tls {
            // Route-level TLS (e.g., appProtocol: kubernetes.io/h2c or existing upstream_tls)
            (true, ctx.upstream_sni.to_string())
        } else {
            (false, String::new())
        };

        ctx.upstream_addr = Some(backend);
        let mut peer = HttpPeer::new(backend, use_tls, sni);
        if use_tls {
            // Gateway spec.tls.backend.clientCertificateRef: present the
            // Gateway's client certificate to the backend (mTLS). Part of the
            // peer's reuse hash, so pooled connections never mix identities.
            peer.client_cert_key = ctx.cached_client_cert.as_deref().map(cert_key_for);
            if let Some(btls) = backend_tls_info {
                // BackendTLSPolicy: verify cert against the policy's custom CA certs
                peer.options.verify_cert = true;
                peer.options.ca = Some(ca_type_for(btls));
                if !btls.subject_alt_names.is_empty() {
                    peer.options.required_sans = Some(Arc::clone(&btls.subject_alt_names));
                }
            } else {
                peer.options.verify_cert = ctx.upstream_verify;
            }
        }
        if let Some(t) = ctx.connect_timeout {
            peer.options.connection_timeout = Some(t);
        }
        if let Some(t) = ctx.read_timeout {
            peer.options.read_timeout = Some(t);
        }
        if let Some(t) = ctx.write_timeout {
            peer.options.write_timeout = Some(t);
        }

        // Connection pooling: keep idle upstream connections alive for 60s.
        // Without this, Pingora uses no idle timeout and connections may be
        // evicted from the pool prematurely by the OS or intermediate LBs.
        peer.options.idle_timeout = Some(Duration::from_secs(60));

        // TCP keepalive: detect dead connections quickly. Kubernetes services
        // and cloud LBs may silently drop idle TCP connections; keepalive
        // probes prevent the proxy from sending requests on dead sockets.
        peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(0),
        });

        // gRPC requires HTTP/2 with concurrent stream support.
        // set_http_version(2, 2) forces HTTP/2 minimum, which makes Pingora
        // use h2c for plaintext upstreams. ALPN::H2 handles TLS negotiation.
        if ctx.protocol == BackendProtocol::Grpc {
            peer.options.set_http_version(2, 2);
            // Allow many concurrent streams per connection for multiplexed RPCs.
            // Typical gRPC servers advertise 100+ concurrent streams; 200 is a
            // safe default that avoids under-utilization without hitting common
            // server-side limits.
            peer.options.max_h2_streams = 200;
            // Periodic HTTP/2 PING frames detect dead connections quickly,
            // critical for long-lived gRPC streams behind load balancers that
            // silently drop idle connections.
            peer.options.h2_ping_interval = Some(Duration::from_secs(30));
        }
        if ctx.protocol == BackendProtocol::Grpc || ctx.protocol == BackendProtocol::H2c {
            peer.options.h2_stream_window_size = Some(UPSTREAM_H2_STREAM_WINDOW);
            peer.options.h2_connection_window_size = Some(UPSTREAM_H2_CONNECTION_WINDOW);
        }

        // H2C (HTTP/2 cleartext) for backends with appProtocol: kubernetes.io/h2c.
        // Uses HTTP/2 prior knowledge (no upgrade), matching the conformance test
        // which sends H2CPriorKnowledgeProtocol requests.
        if ctx.protocol == BackendProtocol::H2c {
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
        let svc = ctx.service_name.as_deref().unwrap_or("unknown");
        self.metrics
            .upstream_connect_errors_total
            .with_label_values(&[svc])
            .inc();
        if let (Some(lb), Some(addr)) = (ctx.cached_lb.as_ref(), ctx.upstream_addr.as_ref())
            && let Some(out) = self.outliers.connect_failed(lb, addr)
        {
            self.note_ejection(ctx, addr, out, "a connect failure");
        }
        // Retry on connect failure if retries_left > 0 AND retry_on allows it.
        // Empty retry_on = retry on connect-failure (backward compat).
        // Non-empty retry_on = must contain "connect-failure" or "gateway-error".
        let should_retry = ctx.retries_left > 0
            && (ctx.retry_on.is_empty()
                || ctx.retry_on.iter().any(|c| c == "connect-failure" || c == "gateway-error"));
        if should_retry {
            ctx.retries_left -= 1;
            e.set_retry(true);
            warn!(
                "upstream connect failed for {:?}, retrying ({} left)",
                ctx.service_name, ctx.retries_left
            );
        }
        e
    }

    /// Override default error handling to return Gateway API-compliant status codes.
    ///
    /// When a route has request_timeout or backend_request_timeout configured:
    /// - ReadTimedout from upstream -> 504 Gateway Timeout (not default 502)
    /// - ConnectTimedout from upstream -> 504 Gateway Timeout (not default 502)
    ///
    /// All other errors fall through to Pingora's default behavior.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = timeout_error_to_status_code(e, ctx.has_timeout);
        if code > 0 {
            session.respond_error(code).await.unwrap_or_else(|e| {
                warn!("failed to send error response to downstream: {e}");
            });
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        let duration = ctx.request_start.elapsed().as_secs_f64();

        // PERF-4: Stack buffer for status code avoids heap allocation per request.
        let status_u16 = session
            .response_written()
            .map_or(0u16, |resp| resp.status.as_u16());
        let mut status_buf = arrayvec::ArrayString::<4>::new();
        let _ = std::fmt::Write::write_fmt(&mut status_buf, format_args!("{}", status_u16));
        let status = status_buf.as_str();

        let host = ctx
            .service_name
            .as_deref()
            .unwrap_or("no_route");

        let proto = match ctx.protocol {
            BackendProtocol::Http => "http",
            BackendProtocol::Grpc => "grpc",
            BackendProtocol::H2c => "h2c",
            BackendProtocol::WebSocket => "ws",
        };

        self.metrics
            .request_total
            .with_label_values(&[host, status, proto])
            .inc();

        // PERF-7: Use cached histogram handle when available (populated in
        // request_filter after route match), avoiding a HashMap lookup per request.
        if let Some(ref h) = ctx.cached_duration {
            h.observe(duration);
        } else {
            self.metrics
                .request_duration
                .with_label_values(&[host, proto])
                .observe(duration);
        }

        // Circuit breaker recording -- record only in logging()
        // so retries are exhausted first and only the final outcome counts.
        if let Some(ref cb) = ctx.circuit_breaker {
            let status_code = session.response_written()
                .map_or(0u16, |resp| resp.status.as_u16());
            if status_code >= 500 || status_code == 0 {
                cb.record_failure();
            } else {
                cb.record_success();
            }
            // Update metric
            let svc = ctx.service_name.as_deref().unwrap_or("unknown");
            self.metrics.circuit_breaker_state
                .with_label_values(&[svc])
                .set(cb.current_state() as i64);
        }

        // Connection limiter release -- MUST always execute to prevent slot leak.
        // Pingora guarantees logging() is called after every request_filter(),
        // including early returns (auth failures, redirects, circuit breaker open).
        if ctx.connection_acquired
            && let Some(ref cl) = ctx.connection_limiter {
                cl.release();
            }

        // Access log: off by default, `PORTUS_ACCESS_LOG=true` turns it on
        // (`dataplane.accessLog` in the chart).
        if access_log_enabled() {
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            let client = session
                .downstream_session
                .client_addr()
                .map(|a| {
                    a.as_inet()
                        .map(|inet| inet.to_string())
                        .unwrap_or_else(|| a.to_string())
                })
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

    // -----------------------------------------------------------------------
    // Timeout error → status code mapping tests (Gateway API conformance)
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_error_read_timedout_with_timeout_returns_504() {
        // When backend_request_timeout or request_timeout is configured,
        // a ReadTimedout error should produce 504 Gateway Timeout.
        let err = pingora_core::Error::explain(
            pingora_core::ErrorType::ReadTimedout,
            "while reading response header",
        );
        assert_eq!(
            timeout_error_to_status_code(&err, true),
            504,
            "ReadTimedout with has_timeout should return 504"
        );
    }

    #[test]
    fn timeout_error_connect_timedout_with_timeout_returns_504() {
        let err = pingora_core::Error::explain(
            pingora_core::ErrorType::ConnectTimedout,
            "connecting to upstream",
        );
        assert_eq!(
            timeout_error_to_status_code(&err, true),
            504,
            "ConnectTimedout with has_timeout should return 504"
        );
    }

    #[test]
    fn timeout_error_read_timedout_without_timeout_returns_502() {
        // Without timeouts configured, ReadTimedout should fall through
        // to default upstream error handling (502).
        let err = pingora_core::Error::explain(
            pingora_core::ErrorType::ReadTimedout,
            "while reading response header",
        );
        assert_eq!(
            timeout_error_to_status_code(&err, false),
            502,
            "ReadTimedout without has_timeout should return 502 (default upstream)"
        );
    }

    #[test]
    fn timeout_error_http_status_passthrough() {
        // Explicit HTTPStatus errors should pass through unchanged.
        let err = pingora_core::Error::explain(
            pingora_core::ErrorType::HTTPStatus(404),
            "no route",
        );
        assert_eq!(
            timeout_error_to_status_code(&err, true),
            404,
            "HTTPStatus(404) should return 404 regardless of timeout flag"
        );
    }

    #[test]
    fn timeout_error_upstream_non_timeout_returns_502() {
        // Other upstream errors (non-timeout) should still return 502.
        // Use new_up() to properly set ErrorSource::Upstream.
        let err = pingora_core::Error::new_up(pingora_core::ErrorType::ConnectError);
        assert_eq!(
            timeout_error_to_status_code(&err, true),
            502,
            "ConnectError from upstream should return 502 even with timeout flag"
        );
    }

}
