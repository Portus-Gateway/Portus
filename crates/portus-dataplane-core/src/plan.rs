//! One request's decisions, independent of the network stack.
//!
//! A stack adapter extracts [`RequestFacts`] from its own request object, calls
//! [`plan_request`] once per request and then either writes the [`Reply`] or
//! forwards the request as the [`Forward`] plan says. Everything the Gateway
//! API decides before a byte reaches a backend lives here: listener
//! isolation, misdirected-request detection, redirects, CORS, IP filtering,
//! body limits, authentication, weighted backend choice, timeouts, URL
//! rewrites, mirrors, rate limits, circuit breakers and connection limits.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::auth::{validate_api_key, validate_basic_auth};
use crate::circuit_breaker::{CircuitBreaker, ConnectionLimiter};
use crate::metrics::ProxyMetrics;
use crate::pool::Pool;
use crate::rate_limiter::RateLimiterMode;
use crate::router::{
    cors_allow_origin_value, cors_headers_value, cors_methods_value, cors_origin_matches,
    detect_misdirected_request, extract_client_ip, header_str, listener_scheme_and_port,
    lookup_domain_wildcard_bucket, select_listener_bucket, select_weighted_backend,
    spawn_mirror_request, BackendTlsInfo, BodyFields, ClientIdentity, CorsConfig, ListenerBucket,
    PathRoute, ProxySnapshot, RequestHeaders, DEFAULT_MAX_REQUEST_BODY_BYTES,
};
use crate::types::{AuthConfig, BackendProtocol};

/// What the stack knows about a request before routing.
pub struct RequestFacts<'a, H: RequestHeaders + ?Sized> {
    /// Request host without a port (from `Host`, else the URI authority).
    pub host: &'a str,
    pub path: &'a str,
    /// Path plus query as it appeared on the request line.
    pub path_and_query: &'a str,
    pub query: Option<&'a str>,
    /// Method name as it appeared on the request line (`GET`, `POST`, ...).
    pub method: &'a str,
    pub headers: &'a H,
    /// Port of the listener socket the connection arrived on.
    pub local_port: u16,
    /// The connection is TLS-terminated by this data plane.
    pub socket_is_tls: bool,
    /// SNI from the TLS handshake, if any.
    pub sni: Option<&'a str>,
    /// Peer address of the connection.
    pub peer_ip: Option<IpAddr>,
    /// Fields the body scanner extracted, on the second pass after a
    /// [`Plan::NeedsBody`]. `None` on the first pass.
    pub body_fields: Option<&'a BodyFields>,
}

/// The routes for this host match on request body fields: scan the body for
/// `keys` (holding at most `max_bytes`), then plan again with
/// [`RequestFacts::body_fields`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyNeed {
    pub keys: &'static [&'static str],
    pub max_bytes: usize,
}

/// Top-level JSON keys an AI route can match on.
pub const AI_BODY_KEYS: &[&str] = &["model", "stream", "max_tokens"];
/// Bytes of a request body held while scanning for [`AI_BODY_KEYS`]; larger
/// bodies are refused with 413. Anthropic and OpenAI SDKs put `model` after
/// `messages`, so a 200k-token prompt puts it ~800 KB in.
pub const AI_BODY_SCAN_LIMIT: usize = 8 * 1024 * 1024;

/// Whether the request carries a body worth scanning.
fn has_request_body(headers: &(impl RequestHeaders + ?Sized)) -> bool {
    headers.contains("transfer-encoding")
        || header_str(headers, "content-length").is_some_and(|cl| cl.trim() != "0")
}

/// A response the data plane sends itself instead of proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    /// Whether the downstream connection may be reused afterwards.
    pub keepalive: bool,
}

impl Reply {
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"))],
            body: Bytes::new(),
            keepalive: true,
        }
    }

    /// A JSON body with its Content-Length set; `empty` pins the length to
    /// zero, so a body assigned afterwards would never reach the client.
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            headers: vec![
                (http::header::CONTENT_LENGTH, HeaderValue::from(body.len())),
                (http::header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
            ],
            body: Bytes::from(body),
            keepalive: true,
        }
    }

    pub fn text(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: vec![(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()))],
            body: Bytes::from_static(body.as_bytes()),
            keepalive: true,
        }
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }
}

/// Header mutations (add, set, remove) for one direction.
#[derive(Debug, Clone)]
pub struct HeaderMutations {
    pub add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub remove: Arc<Vec<HeaderName>>,
}

/// The header operations a stack's request/response object must offer so
/// the core can apply mutations to it. `http::HeaderMap` implements it; a
/// stack whose header type is not a plain map wraps it.
pub trait HeaderSink {
    fn get(&self, name: &HeaderName) -> Option<&[u8]>;
    /// Replace every value of `name` with `value`.
    fn insert(&mut self, name: HeaderName, value: HeaderValue);
    /// Add another value for `name`, keeping existing ones.
    fn append(&mut self, name: HeaderName, value: HeaderValue);
    fn remove(&mut self, name: &HeaderName);
}

impl HeaderSink for HeaderMap {
    fn get(&self, name: &HeaderName) -> Option<&[u8]> {
        HeaderMap::get(self, name).map(|v| v.as_bytes())
    }
    fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        HeaderMap::insert(self, name, value);
    }
    fn append(&mut self, name: HeaderName, value: HeaderValue) {
        HeaderMap::append(self, name, value);
    }
    fn remove(&mut self, name: &HeaderName) {
        HeaderMap::remove(self, name);
    }
}

impl HeaderMutations {
    /// Apply removes, then sets (overwrite), then adds (comma-append when the
    /// header exists, as the Gateway API defines `add`).
    pub fn apply<H: HeaderSink>(&self, headers: &mut H) {
        for name in self.remove.iter() {
            headers.remove(name);
        }
        for (name, value) in self.set.iter() {
            headers.insert(name.clone(), value.clone());
        }
        for (name, value) in self.add.iter() {
            let merged = match headers.get(name) {
                Some(existing) => appended_value(existing, value),
                None => value.clone(),
            };
            headers.insert(name.clone(), merged);
        }
    }
}

/// `existing,value` as one header value (Gateway API `add` semantics).
pub fn appended_value(existing: &[u8], value: &HeaderValue) -> HeaderValue {
    let mut merged = Vec::with_capacity(existing.len() + 1 + value.len());
    merged.extend_from_slice(existing);
    merged.push(b',');
    merged.extend_from_slice(value.as_bytes());
    HeaderValue::from_bytes(&merged).unwrap_or_else(|_| value.clone())
}

/// Everything the stack needs to proxy one request and account for it.
pub struct Forward {
    pub service_name: Arc<str>,
    pub port: u16,
    /// The endpoint pool for the chosen backend, if it has endpoints.
    pub pool: Option<Arc<Pool>>,
    /// BackendTLSPolicy for the chosen backend; overrides `upstream_tls`.
    pub backend_tls: Option<Arc<BackendTlsInfo>>,
    /// Client certificate this Gateway presents to TLS backends.
    pub client_identity: Option<Arc<ClientIdentity>>,
    pub upstream_tls: bool,
    pub upstream_sni: Arc<str>,
    pub upstream_verify: bool,
    pub protocol: BackendProtocol,
    pub connect_timeout: Option<Duration>,
    /// Read timeout after the route's `backendRequest` / `request` timeouts
    /// have been folded in.
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    /// Overall deadline for the request (HTTPRoute `timeouts.request`).
    pub request_timeout: Option<Duration>,
    /// A route timeout is configured, so upstream timeouts are 504 not 502.
    pub has_timeout: bool,
    pub max_retries: u32,
    pub retry_on: Arc<Vec<String>>,
    pub retry_codes: Arc<Vec<u16>>,
    /// Effective request body limit (route policy or the global default).
    pub max_request_body_bytes: u64,
    pub request_headers: HeaderMutations,
    pub response_headers: HeaderMutations,
    pub rewrite_path: Option<String>,
    pub rewrite_hostname: Option<Arc<str>>,
    /// CORS for a simple/actual request: the matched Origin, its config and
    /// whether the request carried credentials.
    pub cors: Option<(String, Arc<CorsConfig>, bool)>,
    pub circuit_breaker: Option<Arc<CircuitBreaker>>,
    /// Acquired connection-limit slot; the stack must release it when done.
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    /// Pre-resolved latency histogram for this route's labels.
    pub duration_histogram: prometheus::Histogram,
    /// The AI provider behind the route, when there is one: the adapter
    /// reads token usage from the response and records the request.
    pub ai: Option<crate::router::AiBackend>,
}

impl Forward {
    /// Label for the protocol dimension of the request metrics.
    pub fn protocol_label(&self) -> &'static str {
        protocol_label(self.protocol)
    }
}

pub fn protocol_label(protocol: BackendProtocol) -> &'static str {
    match protocol {
        BackendProtocol::Http => "http",
        BackendProtocol::Grpc => "grpc",
        BackendProtocol::H2c => "h2c",
        BackendProtocol::WebSocket => "ws",
    }
}

pub enum Plan {
    Respond(Reply),
    Forward(Box<Forward>),
    NeedsBody(BodyNeed),
}

/// Decide what to do with one request.
pub async fn plan_request<H: RequestHeaders + ?Sized>(
    snap: &ProxySnapshot,
    facts: RequestFacts<'_, H>,
    metrics: &ProxyMetrics,
) -> Plan {
    let (original_scheme, local_port) = listener_scheme_and_port(facts.local_port, facts.socket_is_tls);
    let host = facts.host;

    // HTTPRouteHTTPSListenerDetectMisdirectedRequests (GEP-1486): on HTTPS,
    // compare the listener that the TLS handshake selected (by SNI) with the
    // listener that the HTTP Host header claims. If they differ, 421 before
    // any routing.
    if facts.socket_is_tls {
        let port_buckets: &[ListenerBucket] =
            snap.listeners_by_port.get(&local_port).map(|v| v.as_slice()).unwrap_or(&[]);
        let sni = facts.sni.map(|s| s.trim_end_matches('.'));
        if detect_misdirected_request(sni, host, port_buckets) {
            log::debug!("421 Misdirected: sni={sni:?} host={host} port={local_port}");
            return Plan::Respond(Reply::empty(421));
        }
    }

    // GatewayHTTPListenerIsolation: resolve the listener claiming this request
    // first (most-specific listener hostname on the matching port), then match
    // routes only within that listener.
    let bucket = snap
        .listeners_by_port
        .get(&local_port)
        .and_then(|bs| select_listener_bucket(host, bs))
        .or_else(|| select_listener_bucket(host, &snap.any_port_listeners));
    log::debug!(
        "route lookup: host={} local_port={} chosen_listener={:?}",
        host,
        local_port,
        bucket.map(|b| b.listener_hostname.as_ref())
    );
    let host_routes = bucket.and_then(|b| {
        b.exact
            .get(host)
            .or_else(|| lookup_domain_wildcard_bucket(host, &b.domain_wildcards))
            .or(b.catch_all.as_ref())
    });
    if facts.body_fields.is_none()
        && host_routes.is_some_and(|hr| hr.needs_body)
        && has_request_body(facts.headers)
    {
        return Plan::NeedsBody(BodyNeed { keys: AI_BODY_KEYS, max_bytes: AI_BODY_SCAN_LIMIT });
    }
    let Some(pr) = host_routes
        .and_then(|hr| hr.match_request_with_body(facts.path, facts.method, facts.headers, facts.query, facts.body_fields))
    else {
        let mut reply = Reply::text(404, "no route");
        reply.keepalive = false;
        return Plan::Respond(reply);
    };
    log::debug!(
        "matched route: listener={} path={} backend={}:{}",
        pr.listener_name,
        pr.path,
        pr.service_name,
        pr.port
    );

    if let Some(redirect) = &pr.redirect {
        let location = redirect_location(pr, redirect, host, facts.path, original_scheme, local_port);
        return Plan::Respond(
            Reply::empty(redirect.status_code)
                .with_header(http::header::LOCATION, header_value(&location)),
        );
    }

    // CORS: check Origin against allow_origins.
    let mut cors = None;
    if let Some(cors_cfg) = &pr.cors
        && let Some(origin) = header_str(facts.headers, "origin")
    {
        let origin_matched = cors_origin_matches(&cors_cfg.allow_origins, origin);
        let is_preflight = facts.method == "OPTIONS" && facts.headers.contains("access-control-request-method");
        // Non-matching origin preflight: 403 with no CORS headers.
        if !origin_matched && is_preflight {
            return Plan::Respond(Reply::empty(403));
        }
        if origin_matched {
            let has_credentials = facts.headers.contains("cookie") || facts.headers.contains("authorization");
            if is_preflight {
                return Plan::Respond(preflight_reply(cors_cfg, origin, has_credentials, facts.headers));
            }
            cors = Some((origin.to_string(), Arc::clone(cors_cfg), has_credentials));
        }
    }

    // Client IP: from XFF when trusted proxy CIDRs are configured, else the peer.
    let client_ip: Option<IpAddr> = facts.peer_ip.map(|peer| {
        if pr.ip_trusted_proxy_cidrs.is_empty() {
            peer
        } else {
            let xff = header_str(facts.headers, "x-forwarded-for").unwrap_or("");
            extract_client_ip(xff, peer, &pr.ip_trusted_proxy_cidrs)
        }
    });

    if !pr.ip_allow_cidrs.is_empty() || !pr.ip_deny_cidrs.is_empty() {
        let denied = match client_ip {
            Some(ip) => {
                pr.ip_deny_cidrs.iter().any(|c| c.contains(&ip))
                    || (!pr.ip_allow_cidrs.is_empty() && !pr.ip_allow_cidrs.iter().any(|c| c.contains(&ip)))
            }
            None => !pr.ip_allow_cidrs.is_empty(),
        };
        if denied {
            return Plan::Respond(Reply::text(403, "Forbidden"));
        }
    }

    // Request body size limit (the global default when no policy).
    let max_request_body_bytes =
        if pr.max_request_body_bytes > 0 { pr.max_request_body_bytes } else { DEFAULT_MAX_REQUEST_BODY_BYTES };
    if let Some(len) = header_str(facts.headers, "content-length").and_then(|v| v.parse::<u64>().ok())
        && len > max_request_body_bytes
    {
        return Plan::Respond(Reply::text(413, "Request Entity Too Large"));
    }

    // Auth, before rate limiting so unauthenticated requests spend no tokens.
    if let Some(auth) = &pr.auth_config {
        match auth {
            AuthConfig::BasicAuth { credentials, realm } => {
                let authorization = facts.headers.get("authorization").and_then(|v| HeaderValue::from_bytes(v).ok());
                if let Err(status) = validate_basic_auth(authorization.as_ref(), credentials).await {
                    // Strip characters that would break out of the quoted realm.
                    let safe_realm: String =
                        realm.chars().filter(|c| *c != '"' && *c != '\r' && *c != '\n').collect();
                    return Plan::Respond(Reply::empty(status).with_header(
                        http::header::WWW_AUTHENTICATE,
                        header_value(&format!("Basic realm=\"{safe_realm}\"")),
                    ));
                }
            }
            AuthConfig::ApiKey { valid_keys, header_name } => {
                let key = facts.headers.get(header_name.as_str()).and_then(|v| HeaderValue::from_bytes(v).ok());
                if let Err(status) = validate_api_key(key.as_ref(), valid_keys) {
                    return Plan::Respond(Reply::empty(status));
                }
            }
        }
    }

    // Weighted backend selection; per-backend request headers override the
    // rule's when present.
    let (service_name, port, request_headers) =
        match select_weighted_backend(&pr.weighted_backends, pr.total_weight) {
            Some(selected) => {
                let own_headers = !selected.request_headers_add.is_empty()
                    || !selected.request_headers_set.is_empty()
                    || !selected.request_headers_remove.is_empty();
                let mutations = if own_headers {
                    HeaderMutations {
                        add: Arc::clone(&selected.request_headers_add),
                        set: Arc::clone(&selected.request_headers_set),
                        remove: Arc::clone(&selected.request_headers_remove),
                    }
                } else {
                    route_request_headers(pr)
                };
                (Arc::clone(&selected.service_name), selected.port, mutations)
            }
            None => (Arc::clone(&pr.service_name), pr.port, route_request_headers(pr)),
        };

    // A route with no valid backends (e.g. a cross-namespace ref without a
    // ReferenceGrant) compiles to an empty service name: 500.
    if service_name.is_empty() {
        return Plan::Respond(Reply::empty(500));
    }

    let key = (Arc::clone(&service_name), port);
    let pool = snap.lbs.get(&key).cloned();
    let backend_tls = snap.backend_tls.get(&key).cloned();
    let client_identity = snap.backend_client_cert.clone();

    let duration_histogram = metrics
        .request_duration
        .with_label_values(&[service_name.as_ref(), protocol_label(pr.protocol)]);

    // Timeouts: `backendRequest` tightens the read timeout; `request` is the
    // overall deadline and also bounds the read timeout when it is tighter.
    let mut read_timeout = pr.read_timeout;
    let mut has_timeout = false;
    if let Some(t) = pr.backend_request_timeout {
        read_timeout = Some(t);
        has_timeout = true;
    }
    if let Some(t) = pr.request_timeout {
        has_timeout = true;
        match read_timeout {
            Some(existing) if existing <= t => {}
            _ => read_timeout = Some(t),
        }
    }

    // Fire-and-forget mirrors: a faithful copy of the request target.
    for (mirror_svc, mirror_port, mirror_percent) in &pr.mirror_backends {
        if *mirror_percent > 0 && *mirror_percent < 100 {
            let roll: f64 = rand::random::<f64>() * 100.0;
            if roll >= *mirror_percent as f64 {
                continue;
            }
        }
        let mut mirror_headers: Vec<(String, String)> = Vec::new();
        facts.headers.for_each(&mut |name, value| {
            if name.starts_with("content-") || name.starts_with("x-") || name == "accept" || name == "user-agent" {
                mirror_headers.push((name.to_string(), std::str::from_utf8(value).unwrap_or("").to_string()));
            }
        });
        spawn_mirror_request(
            mirror_svc,
            *mirror_port,
            facts.method,
            facts.path_and_query,
            host,
            &mirror_headers,
            &snap.lbs,
        );
    }

    if let Some(limiter) = &pr.rate_limiter {
        let allowed = match limiter {
            RateLimiterMode::Shared(bucket) => bucket.try_acquire(),
            RateLimiterMode::PerIp(per_ip) => client_ip.is_some_and(|ip| per_ip.try_acquire(ip)),
        };
        if !allowed {
            metrics.rate_limit_rejected_total.with_label_values(&[pr.service_name.as_ref()]).inc();
            return Plan::Respond(Reply::text(429, "rate limit exceeded"));
        }
    }

    let circuit_breaker = match &pr.circuit_breaker {
        Some(cb) if !cb.allow_request() => return Plan::Respond(Reply::text(503, "circuit is open")),
        other => other.clone(),
    };
    let connection_limiter = match &pr.connection_limiter {
        Some(cl) if !cl.try_acquire() => return Plan::Respond(Reply::text(503, "connection limit reached")),
        other => other.clone(),
    };

    Plan::Forward(Box::new(Forward {
        service_name,
        port,
        pool,
        backend_tls,
        client_identity,
        upstream_tls: pr.upstream_tls,
        upstream_sni: Arc::clone(&pr.upstream_sni),
        upstream_verify: pr.upstream_verify,
        protocol: pr.protocol,
        connect_timeout: pr.connect_timeout,
        read_timeout,
        write_timeout: pr.write_timeout,
        request_timeout: pr.request_timeout,
        has_timeout,
        max_retries: pr.max_retries,
        retry_on: Arc::clone(&pr.retry_on),
        retry_codes: Arc::clone(&pr.retry_codes),
        max_request_body_bytes,
        request_headers,
        response_headers: HeaderMutations {
            add: Arc::clone(&pr.response_headers_add),
            set: Arc::clone(&pr.response_headers_set),
            remove: Arc::clone(&pr.response_headers_remove),
        },
        rewrite_path: pr.rewrite_path(facts.path),
        rewrite_hostname: pr.rewrite_hostname().cloned(),
        cors,
        circuit_breaker,
        connection_limiter,
        duration_histogram,
        ai: pr.ai.clone(),
    }))
}

fn route_request_headers(pr: &PathRoute) -> HeaderMutations {
    HeaderMutations {
        add: Arc::clone(&pr.request_headers_add),
        set: Arc::clone(&pr.request_headers_set),
        remove: Arc::clone(&pr.request_headers_remove),
    }
}

fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// `Location` for an HTTPRoute RequestRedirect filter.
fn redirect_location(
    pr: &PathRoute,
    redirect: &crate::router::RedirectConfig,
    host: &str,
    path: &str,
    original_scheme: &str,
    original_port: u16,
) -> String {
    let mut location = String::new();
    let effective_scheme = redirect.scheme.as_deref().unwrap_or(original_scheme);
    location.push_str(effective_scheme);
    location.push_str("://");
    location.push_str(redirect.hostname.as_deref().unwrap_or(host));

    // Port: explicit wins; a scheme change defaults to the new scheme's port
    // (omitted); a kept scheme keeps the listener port.
    let effective_port = if let Some(p) = redirect.port {
        Some(p)
    } else if redirect.scheme.is_some() {
        None
    } else {
        Some(original_port)
    };
    if let Some(port) = effective_port {
        let is_default_port =
            (effective_scheme == "http" && port == 80) || (effective_scheme == "https" && port == 443);
        if !is_default_port {
            location.push(':');
            location.push_str(&port.to_string());
        }
    }

    match &redirect.path {
        Some(redir_path) => match redirect.path_type.as_str() {
            "ReplaceFullPath" => location.push_str(redir_path),
            "ReplacePrefixMatch" => {
                let prefix = pr.path.as_ref();
                if let Some(suffix) = path.strip_prefix(prefix) {
                    location.push_str(redir_path);
                    if !redir_path.ends_with('/') && !suffix.starts_with('/') && !suffix.is_empty() {
                        location.push('/');
                    }
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
        },
        None => location.push_str(path),
    }
    location
}

/// A CORS preflight answer: 200 with the negotiated CORS headers.
fn preflight_reply(
    cors: &CorsConfig,
    origin: &str,
    has_credentials: bool,
    request: &(impl RequestHeaders + ?Sized),
) -> Reply {
    let mut reply = Reply::empty(200);
    let acao = cors_allow_origin_value(cors, origin, has_credentials);
    reply.headers.push((HeaderName::from_static("access-control-allow-origin"), header_value(&acao)));
    if acao != "*" {
        reply.headers.push((http::header::VARY, HeaderValue::from_static("Origin")));
    }
    let requested_method = header_str(request, "access-control-request-method").unwrap_or("");
    let methods = cors_methods_value(&cors.allow_methods, &cors.allow_methods_joined, requested_method);
    if !methods.is_empty() {
        reply.headers.push((HeaderName::from_static("access-control-allow-methods"), header_value(methods)));
    }
    let requested_headers = header_str(request, "access-control-request-headers").unwrap_or("");
    let headers = cors_headers_value(&cors.allow_headers, &cors.allow_headers_joined, requested_headers);
    if !headers.is_empty() {
        reply.headers.push((HeaderName::from_static("access-control-allow-headers"), header_value(headers)));
    }
    if !cors.expose_headers.is_empty() {
        reply.headers.push((
            HeaderName::from_static("access-control-expose-headers"),
            header_value(&cors.expose_headers_joined),
        ));
    }
    if cors.max_age > 0 {
        reply.headers.push((HeaderName::from_static("access-control-max-age"), header_value(&cors.max_age_str)));
    }
    if cors.allow_credentials && acao != "*" {
        reply.headers.push((
            HeaderName::from_static("access-control-allow-credentials"),
            HeaderValue::from_static("true"),
        ));
    }
    reply
}

/// CORS headers on a proxied (non-preflight) response.
pub fn apply_cors_response_headers<H: HeaderSink>(
    headers: &mut H,
    origin: &str,
    cors: &CorsConfig,
    has_credentials: bool,
) {
    let acao = cors_allow_origin_value(cors, origin, has_credentials);
    headers.insert(HeaderName::from_static("access-control-allow-origin"), header_value(&acao));
    if acao != "*" {
        headers.append(http::header::VARY, HeaderValue::from_static("Origin"));
    }
    if cors.allow_credentials && acao != "*" {
        headers.insert(
            HeaderName::from_static("access-control-allow-credentials"),
            HeaderValue::from_static("true"),
        );
    }
    if !cors.expose_headers.is_empty() {
        headers.insert(
            HeaderName::from_static("access-control-expose-headers"),
            header_value(&cors.expose_headers_joined),
        );
    }
}

/// True when a connect failure should be retried: attempts remain and the
/// route's `retry_on` is empty (connect failures only) or names
/// `connect-failure` / `gateway-error`.
pub fn should_retry_connect(retry_on: &[String], retries_left: u32) -> bool {
    retries_left > 0 && (retry_on.is_empty() || retry_on.iter().any(|c| c == "connect-failure" || c == "gateway-error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{HeaderMatchEntry, HeaderMatchType, HostRoutes};
    use crate::types::PathMatchType;
    use hashbrown::HashMap;

    fn messages_route(service: &str, model: Option<&str>) -> PathRoute {
        let mut route = crate::router::test_support::path_route("/v1/messages", PathMatchType::Exact);
        route.service_name = Arc::from(service);
        if let Some(model) = model {
            route.header_matches = vec![HeaderMatchEntry {
                name: HeaderName::from_static("portus-body-model"),
                value: model.to_string(),
                match_type: HeaderMatchType::Exact,
            }];
        }
        route
    }

    fn snapshot_with(routes: Vec<PathRoute>) -> ProxySnapshot {
        let needs_body = crate::router::needs_body_fields(
            &routes.iter().flat_map(|r| r.header_matches.iter().cloned()).collect::<Vec<_>>(),
        );
        let mut exact_map = HashMap::new();
        exact_map.insert(Arc::from("/v1/messages"), routes);
        let host_routes = HostRoutes { exact_map, rules: Vec::new(), catch_all: None, needs_body };
        let bucket = ListenerBucket {
            listener_hostname: Arc::from(""),
            exact: HashMap::from([("llm.example.com".to_string(), host_routes)]),
            domain_wildcards: HashMap::new(),
            catch_all: None,
        };
        let mut snap = ProxySnapshot::default();
        snap.listeners_by_port.insert(80, vec![bucket]);
        snap
    }

    fn metrics() -> &'static ProxyMetrics {
        crate::metrics::shared_metrics()
    }

    fn facts<'a>(headers: &'a HeaderMap, body_fields: Option<&'a BodyFields>) -> RequestFacts<'a, HeaderMap> {
        RequestFacts {
            host: "llm.example.com",
            path: "/v1/messages",
            path_and_query: "/v1/messages",
            query: None,
            method: "POST",
            headers,
            local_port: 80,
            socket_is_tls: false,
            sni: None,
            peer_ip: None,
            body_fields,
        }
    }

    #[tokio::test]
    async fn a_body_route_asks_for_the_body_once_then_routes_on_its_fields() {
        let snap = snapshot_with(vec![messages_route("opus", Some("claude-opus-5")), messages_route("fallback", None)]);
        let metrics = metrics();
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "512".parse().unwrap());

        let first = plan_request(&snap, facts(&headers, None), metrics).await;
        assert_eq!(
            match first {
                Plan::NeedsBody(need) => Some(need),
                _ => None,
            },
            Some(BodyNeed { keys: AI_BODY_KEYS, max_bytes: AI_BODY_SCAN_LIMIT })
        );

        let fields: BodyFields = vec![("model", "claude-opus-5".to_string())];
        match plan_request(&snap, facts(&headers, Some(&fields)), metrics).await {
            Plan::Forward(f) => assert_eq!(f.service_name.as_ref(), "opus"),
            _ => panic!("expected a forward"),
        }

        let other: BodyFields = vec![("model", "gpt-5".to_string())];
        match plan_request(&snap, facts(&headers, Some(&other)), metrics).await {
            Plan::Forward(f) => assert_eq!(f.service_name.as_ref(), "fallback"),
            _ => panic!("expected the fallback route"),
        }
    }

    #[tokio::test]
    async fn requests_without_a_body_skip_the_scan_and_the_body_routes() {
        let snap = snapshot_with(vec![messages_route("opus", Some("claude-opus-5")), messages_route("fallback", None)]);
        let metrics = metrics();
        let headers = HeaderMap::new();
        match plan_request(&snap, facts(&headers, None), metrics).await {
            Plan::Forward(f) => assert_eq!(f.service_name.as_ref(), "fallback"),
            _ => panic!("expected the fallback route"),
        }
        // Hosts without body routes never ask, body or not.
        let plain = snapshot_with(vec![messages_route("only", None)]);
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        match plan_request(&plain, facts(&headers, None), metrics).await {
            Plan::Forward(f) => assert_eq!(f.service_name.as_ref(), "only"),
            _ => panic!("expected a forward"),
        }
    }

    #[test]
    fn header_add_appends_with_a_comma_and_set_overwrites() {
        let m = HeaderMutations {
            add: Arc::new(vec![(HeaderName::from_static("x-a"), HeaderValue::from_static("2"))]),
            set: Arc::new(vec![(HeaderName::from_static("x-s"), HeaderValue::from_static("new"))]),
            remove: Arc::new(vec![HeaderName::from_static("x-r")]),
        };
        let mut h = HeaderMap::new();
        h.insert("x-a", HeaderValue::from_static("1"));
        h.insert("x-s", HeaderValue::from_static("old"));
        h.insert("x-r", HeaderValue::from_static("gone"));
        m.apply(&mut h);
        assert_eq!(h.get("x-a").unwrap(), "1,2");
        assert_eq!(h.get("x-s").unwrap(), "new");
        assert!(h.get("x-r").is_none());
        let mut fresh = HeaderMap::new();
        m.apply(&mut fresh);
        assert_eq!(fresh.get("x-a").unwrap(), "2", "add creates when missing");
    }

    #[test]
    fn retry_rules() {
        assert!(should_retry_connect(&[], 1), "empty retry_on retries connect failures");
        assert!(should_retry_connect(&["gateway-error".into()], 1));
        assert!(!should_retry_connect(&["5xx".into()], 1));
        assert!(!should_retry_connect(&[], 0));
    }

    #[test]
    fn replies_carry_content_length() {
        let r = Reply::text(404, "no route");
        assert_eq!(r.headers[0].0, http::header::CONTENT_LENGTH);
        assert_eq!(r.headers[0].1, "8");
        assert_eq!(Reply::empty(421).headers[0].1, "0");
    }
}
