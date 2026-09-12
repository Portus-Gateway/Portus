use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use log::{info, warn};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use hashbrown::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::circuit_breaker::{CircuitBreaker, ConnectionLimiter};
use crate::types::*;
use crate::metrics::ProxyMetrics;
use crate::outlier::Outliers;
#[cfg(test)]
use crate::rate_limiter::AtomicTokenBucket;

// ---------------------------------------------------------------------------
// SNI mux port mapping
// ---------------------------------------------------------------------------

const HTTPS_DEFAULT_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// Access log
// ---------------------------------------------------------------------------

/// One line per request on the `portus_dataplane::access` log target. Off unless
/// `PORTUS_ACCESS_LOG` says otherwise: at 100k+ requests/s the formatting and the
/// container log pipeline cost measurable CPU on every worker thread.
static ACCESS_LOG: AtomicBool = AtomicBool::new(false);

pub fn set_access_log(enabled: bool) {
    ACCESS_LOG.store(enabled, Ordering::Relaxed);
}

#[inline]
pub fn access_log_enabled() -> bool {
    ACCESS_LOG.load(Ordering::Relaxed)
}

/// `PORTUS_ACCESS_LOG` value → flag (`true`, `1`, `yes`, `on`; anything else off).
pub fn access_log_from_env_value(value: Option<&str>) -> bool {
    value.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
}

/// HTTP/2 flow-control windows for upstream connections (gRPC and h2c
/// backends): the h2 crate's 64 KiB defaults throttle large responses.
pub const UPSTREAM_H2_STREAM_WINDOW: u32 = 1 << 20;
pub const UPSTREAM_H2_CONNECTION_WINDOW: u32 = 4 << 20;

/// Scheme and listener port for a request from the socket it arrived on.
/// HTTPS connections reach Pingora on the original `:443` socket (handed off by
/// the SNI mux), so the local port is always the listener port; the scheme
/// follows the TLS state of the socket, with `:443` treated as HTTPS even when
/// the digest carries no TLS info.
pub(crate) fn listener_scheme_and_port(local_port: u16, is_tls: bool) -> (&'static str, u16) {
    if is_tls || local_port == HTTPS_DEFAULT_PORT {
        ("https", local_port)
    } else {
        ("http", local_port)
    }
}

// ---------------------------------------------------------------------------
// SEC-4: Default request body size limit (10 MB) when no policy is configured.
// ---------------------------------------------------------------------------
const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// PERF-1: Static empty Arc singletons — avoids 9 heap allocations per request
// in new_ctx(). All Arc::clone() on these is a single atomic increment.
// ---------------------------------------------------------------------------
static EMPTY_HEADER_VEC: LazyLock<Arc<Vec<(HeaderName, HeaderValue)>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
static EMPTY_NAME_VEC: LazyLock<Arc<Vec<HeaderName>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
static EMPTY_STRING_VEC: LazyLock<Arc<Vec<String>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
static EMPTY_CODES: LazyLock<Arc<Vec<u16>>> = LazyLock::new(|| Arc::new(Vec::new()));
static EMPTY_SNI: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from(""));

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A weighted backend with optional per-backend request header mutations.
#[derive(Clone)]
pub(crate) struct WeightedBackendEntry {
    pub(crate) service_name: Arc<str>,
    pub(crate) port: u16,
    pub(crate) weight: u32,
    pub(crate) request_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) request_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) request_headers_remove: Arc<Vec<HeaderName>>,
}

/// Configuration for HTTP redirect responses (3xx).
pub(crate) struct RedirectConfig {
    pub(crate) scheme: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) path: Option<String>,
    pub(crate) path_type: String,   // ReplaceFullPath or ReplacePrefixMatch
    pub(crate) status_code: u16,    // 301, 302, etc.
}

/// Configuration for URL rewriting before proxying.
#[derive(Clone)]
pub(crate) struct UrlRewriteConfig {
    pub(crate) hostname: Option<Arc<str>>,
    pub(crate) path: Option<String>,
    pub(crate) path_type: String,
}

/// CORS configuration for handling preflight and simple requests.
#[derive(Clone, Debug)]
pub(crate) struct CorsConfig {
    pub(crate) allow_origins: Vec<String>,
    pub(crate) allow_methods: Vec<String>,
    pub(crate) allow_headers: Vec<String>,
    pub(crate) expose_headers: Vec<String>,
    pub(crate) allow_credentials: bool,
    pub(crate) max_age: u32,
    // PERF-13: Pre-formatted max_age string to avoid per-request u32::to_string()
    pub(crate) max_age_str: Arc<str>,
    // Pre-joined strings for hot-path use (avoids per-request allocations)
    pub(crate) allow_methods_joined: Arc<str>,
    pub(crate) allow_headers_joined: Arc<str>,
    pub(crate) expose_headers_joined: Arc<str>,
}

/// Header match type for multi-dimensional request matching.
#[derive(Clone)]
pub(crate) enum HeaderMatchType {
    Exact,
    RegularExpression(regex::Regex),
}

impl PartialEq for HeaderMatchType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact, Self::Exact) => true,
            (Self::RegularExpression(a), Self::RegularExpression(b)) => {
                a.as_str() == b.as_str()
            }
            _ => false,
        }
    }
}

impl std::fmt::Debug for HeaderMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => write!(f, "Exact"),
            Self::RegularExpression(re) => write!(f, "RegularExpression({})", re.as_str()),
        }
    }
}

/// A single header match requirement.
#[derive(Clone, Debug)]
pub(crate) struct HeaderMatchEntry {
    pub(crate) name: HeaderName,
    pub(crate) value: String,
    pub(crate) match_type: HeaderMatchType,
}

/// Query parameter match type, mirroring HeaderMatchType.
/// RegularExpression holds a pre-compiled regex (built once at config time).
#[derive(Clone)]
pub(crate) enum QueryParamMatchType {
    Exact,
    RegularExpression(regex::Regex),
}

impl PartialEq for QueryParamMatchType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact, Self::Exact) => true,
            (Self::RegularExpression(a), Self::RegularExpression(b)) => {
                a.as_str() == b.as_str()
            }
            _ => false,
        }
    }
}

impl std::fmt::Debug for QueryParamMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => write!(f, "Exact"),
            Self::RegularExpression(re) => write!(f, "RegularExpression({})", re.as_str()),
        }
    }
}

/// A single query parameter match requirement.
#[derive(Clone, Debug)]
pub(crate) struct QueryParamMatchEntry {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) match_type: QueryParamMatchType,
}

/// A single path rule pointing to a backend.
pub(crate) struct PathRoute {
    pub(crate) path: Arc<str>,
    pub(crate) match_type: PathMatchType,
    pub(crate) service_name: Arc<str>,
    pub(crate) port: u16,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) read_timeout: Option<Duration>,
    pub(crate) write_timeout: Option<Duration>,
    pub(crate) rate_limiter: Option<crate::rate_limiter::RateLimiterMode>,
    pub(crate) max_retries: u32,
    pub(crate) upstream_tls: bool,
    pub(crate) upstream_sni: Arc<str>,
    pub(crate) upstream_verify: bool,
    pub(crate) protocol: BackendProtocol,
    pub(crate) request_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) request_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) request_headers_remove: Arc<Vec<HeaderName>>,
    pub(crate) response_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) response_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(crate) response_headers_remove: Arc<Vec<HeaderName>>,
    // Gateway API Core: multi-dimensional matching
    pub(crate) header_matches: Vec<HeaderMatchEntry>,
    pub(crate) method_match: Option<http::Method>,
    pub(crate) query_param_matches: Vec<QueryParamMatchEntry>,
    // Gateway API Core: filters
    pub(crate) redirect: Option<RedirectConfig>,
    pub(crate) url_rewrite: Option<UrlRewriteConfig>,
    // Listener binding
    pub(crate) listener_name: Arc<str>,
    // Extended HTTPRoute: mirror, weighted backends, per-route timeouts
    /// Multiple mirror backends: (service_name, port, percent). percent=0 means mirror all.
    pub(crate) mirror_backends: Vec<(Arc<str>, u16, u32)>,
    pub(crate) weighted_backends: Vec<WeightedBackendEntry>,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) backend_request_timeout: Option<Duration>,
    // Phase 9: Auth config
    pub(crate) auth_config: Option<crate::types::AuthConfig>,
    // Phase 10: CORS config
    pub(crate) cors: Option<Arc<CorsConfig>>,
    // Phase 11: IP allowlist
    pub(crate) ip_allow_cidrs: Vec<ipnet::IpNet>,
    pub(crate) ip_deny_cidrs: Vec<ipnet::IpNet>,
    pub(crate) ip_trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    // Phase 11: Request body size limit (0 = no limit)
    pub(crate) max_request_body_bytes: u64,
    // Phase 11: Retry conditions
    pub(crate) retry_on: Arc<Vec<String>>,
    /// HTTPRoute rule `retry.codes`: upstream statuses retried while
    /// `max_retries` attempts remain.
    pub(crate) retry_codes: Arc<Vec<u16>>,
    // PERF-8: Embedded circuit breaker and connection limiter (avoids per-request map lookups)
    pub(crate) circuit_breaker: Option<Arc<CircuitBreaker>>,
    pub(crate) connection_limiter: Option<Arc<ConnectionLimiter>>,
    // PERF-10: Pre-computed total weight for weighted backend selection
    pub(crate) total_weight: u32,
}

impl PathRoute {
    /// Returns true if this route is a redirect (should return 3xx, not proxy).
    #[cfg(test)]
    pub(crate) fn has_redirect(&self) -> bool {
        self.redirect.is_some()
    }

    /// Applies URL rewrite to the given path, returning the rewritten path if applicable.
    pub(crate) fn rewrite_path(&self, original_path: &str) -> Option<String> {
        let rewrite = self.url_rewrite.as_ref()?;
        let new_path = rewrite.path.as_ref()?;
        match rewrite.path_type.as_str() {
            "ReplaceFullPath" => Some(new_path.clone()),
            "ReplacePrefixMatch" => {
                // Replace the matched prefix with the new path
                let prefix = self.path.as_ref();
                if let Some(suffix) = original_path.strip_prefix(prefix) {
                    let mut result = new_path.clone();
                    if !result.ends_with('/') && !suffix.starts_with('/') && !suffix.is_empty() {
                        result.push('/');
                    }
                    // Avoid double slash when replacement ends with '/' and suffix starts with '/'
                    if result.ends_with('/') && suffix.starts_with('/') {
                        result.push_str(&suffix[1..]);
                    } else {
                        result.push_str(suffix);
                    }
                    Some(result)
                } else {
                    Some(new_path.clone())
                }
            }
            _ => None,
        }
    }

    /// Returns the rewrite hostname if URL rewrite is configured with a hostname.
    pub(crate) fn rewrite_hostname(&self) -> Option<&Arc<str>> {
        self.url_rewrite.as_ref()?.hostname.as_ref()
    }
}

/// All path routes for a given host, ordered for matching.
pub(crate) struct HostRoutes {
    /// Exact path → routes for O(1) lookup. Multiple routes may share a path
    /// (differentiated by headers/method/query).
    pub(crate) exact_map: HashMap<Arc<str>, Vec<PathRoute>>,
    /// Prefix rules sorted longest-first for linear scan.
    pub(crate) rules: Vec<PathRoute>,
    /// Catch-all when no paths are specified.
    pub(crate) catch_all: Option<PathRoute>,
}

impl HostRoutes {
    /// Find an existing rate limiter for a path/type/rps combo (for reuse across rebuilds).
    pub(crate) fn find_rate_limiter(
        &self,
        path: &str,
        match_type: &PathMatchType,
        rps: u32,
        per_client: bool,
    ) -> Option<crate::rate_limiter::RateLimiterMode> {
        use crate::rate_limiter::RateLimiterMode;
        let check = |pr: &PathRoute| -> Option<RateLimiterMode> {
            if pr.path.as_ref() == path
                && pr.match_type == *match_type
                && pr.rate_limiter.as_ref().is_some_and(|rl| rl.rps() == rps && rl.is_per_ip() == per_client)
            {
                pr.rate_limiter.clone()
            } else {
                None
            }
        };

        if let Some(ref ca) = self.catch_all
            && let Some(rl) = check(ca) {
                return Some(rl);
            }
        // Check exact_map entries
        for routes in self.exact_map.values() {
            for rule in routes {
                if let Some(rl) = check(rule) {
                    return Some(rl);
                }
            }
        }
        for rule in &self.rules {
            if let Some(rl) = check(rule) {
                return Some(rl);
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn match_path(&self, request_path: &str) -> Option<&PathRoute> {
        // Backward-compatible convenience: match by path only (no header/method/query checks).
        self.match_request(request_path, &http::Method::GET, &http::HeaderMap::new(), None)
    }

    /// Multi-dimensional request matching: path + method + headers + query params.
    /// Returns the first route where ALL dimensions match.
    pub(crate) fn match_request(
        &self,
        request_path: &str,
        method: &http::Method,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> Option<&PathRoute> {
        // O(1) exact path lookup
        if let Some(exact_routes) = self.exact_map.get(request_path) {
            for rule in exact_routes {
                if self.extra_dimensions_match(rule, method, headers, query) {
                    return Some(rule);
                }
            }
        }

        // Prefix rules (sorted longest-first)
        for rule in &self.rules {
            if self.path_matches(rule, request_path)
                && self.extra_dimensions_match(rule, method, headers, query)
            {
                return Some(rule);
            }
        }
        // Check catch-all with extra dimensions too
        if let Some(ref ca) = self.catch_all
            && self.extra_dimensions_match(ca, method, headers, query) {
                return Some(ca);
            }
        None
    }

    /// Check if a route's path matches the request path.
    fn path_matches(&self, rule: &PathRoute, request_path: &str) -> bool {
        match rule.match_type {
            PathMatchType::Exact => request_path == rule.path.as_ref(),
            PathMatchType::Prefix => {
                let prefix = rule.path.as_ref();
                if request_path.starts_with(prefix) {
                    let plen = prefix.len();
                    request_path.len() == plen
                        || request_path.as_bytes()[plen] == b'/'
                        || prefix.ends_with('/')
                } else {
                    false
                }
            }
            PathMatchType::RegularExpression(ref re) => re.is_match(request_path),
        }
    }

    /// Check non-path dimensions: method, headers, query params (AND logic).
    fn extra_dimensions_match(
        &self,
        rule: &PathRoute,
        method: &http::Method,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> bool {
        // Method match: if rule specifies a method, it must match
        if let Some(ref required_method) = rule.method_match
            && method != required_method {
                return false;
            }

        // Header matches: ALL must match (AND logic per Gateway API spec)
        for hm in &rule.header_matches {
            let actual = headers.get(&hm.name);
            match actual {
                Some(v) => {
                    let val_str = v.to_str().unwrap_or("");
                    match hm.match_type {
                        HeaderMatchType::Exact => {
                            if val_str != hm.value {
                                return false;
                            }
                        }
                        HeaderMatchType::RegularExpression(ref re) => {
                            if !re.is_match(val_str) {
                                return false;
                            }
                        }
                    }
                }
                None => return false,
            }
        }

        // Query param matches: ALL must match (AND logic)
        if !rule.query_param_matches.is_empty() {
            let query_str = query.unwrap_or("");
            for qm in &rule.query_param_matches {
                let found = query_str.split('&').any(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let name = parts.next().unwrap_or("");
                    let value = parts.next().unwrap_or("");
                    if name != qm.name {
                        return false;
                    }
                    match &qm.match_type {
                        QueryParamMatchType::RegularExpression(re) => re.is_match(value),
                        QueryParamMatchType::Exact => value == qm.value,
                    }
                });
                if !found {
                    return false;
                }
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Weighted backend selection (deterministic round-robin by weight)
// ---------------------------------------------------------------------------

thread_local! {
    // Per-thread round-robin position for weighted backend selection. Each
    // Pingora worker walks its own counter, so the proportional distribution
    // holds per thread without a globally shared atomic that every worker
    // would bounce between cores on every request.
    static WEIGHT_COUNTER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Reset the current thread's weighted-backend counter (tests only).
#[cfg(test)]
pub(crate) fn reset_weight_counter() {
    WEIGHT_COUNTER.with(|c| c.set(0));
}

/// Select a backend from weighted list using deterministic round-robin.
/// Distributes proportionally: weights [3, 2, 1] over 6 calls = 3 to A, 2 to B, 1 to C.
/// Returns a reference to the selected WeightedBackendEntry.
pub(crate) fn select_weighted_backend(backends: &[WeightedBackendEntry], precomputed_total: u32) -> Option<&WeightedBackendEntry> {
    if backends.is_empty() {
        return None;
    }
    let total = if precomputed_total > 0 { precomputed_total } else {
        backends.iter().map(|b| b.weight).sum()
    };
    if total == 0 {
        return backends.first();
    }
    let idx = WEIGHT_COUNTER.with(|c| {
        let v = c.get();
        c.set(v.wrapping_add(1));
        v
    }) % total as u64;
    let mut cumulative = 0u64;
    for backend in backends {
        cumulative += backend.weight as u64;
        if idx < cumulative {
            return Some(backend);
        }
    }
    backends.last()
}

// ---------------------------------------------------------------------------
// Mirror request spawning (fire-and-forget, bounded concurrency)
// ---------------------------------------------------------------------------

/// Maximum concurrent mirror requests. Permits are acquired before sending;
/// if none available, the mirror is silently skipped (best-effort per spec).
static MIRROR_SEMAPHORE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(128)));

/// Spawn a fire-and-forget mirror request to the given backend.
/// Clones essential request info and sends a minimal HTTP/1.1 request.
/// If the semaphore has no permits, the mirror is silently skipped.
/// SEC-11: Extract the real client IP from X-Forwarded-For using the
/// rightmost-untrusted-hop algorithm. Walks XFF right-to-left; the first IP
/// NOT in `trusted_cidrs` is the real client. If peer is not trusted, peer IS
/// the client (XFF is completely ignored to prevent spoofing).
fn extract_client_ip(
    xff: &str,
    peer_ip: std::net::IpAddr,
    trusted_cidrs: &[ipnet::IpNet],
) -> std::net::IpAddr {
    if !trusted_cidrs.iter().any(|c| c.contains(&peer_ip)) {
        return peer_ip;
    }
    if xff.is_empty() {
        return peer_ip;
    }
    let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
    for ip_str in ips.iter().rev() {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            if !trusted_cidrs.iter().any(|c| c.contains(&ip)) {
                return ip;
            }
        } else {
            return peer_ip;
        }
    }
    // All XFF entries are trusted — use leftmost (original hop) or peer
    ips.first()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .unwrap_or(peer_ip)
}

pub(crate) fn spawn_mirror_request(
    mirror_service: &Arc<str>,
    mirror_port: u16,
    method: &http::Method,
    path: &str,
    host: &str,
    extra_headers: &[(String, String)],
    lbs: &HashMap<(Arc<str>, u16), Arc<LoadBalancer<RoundRobin>>>,
) {
    let sem = Arc::clone(&MIRROR_SEMAPHORE);
    let permit = match sem.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!("mirror semaphore full, skipping mirror to {}:{}", mirror_service, mirror_port);
            return;
        }
    };

    let lb_key = (mirror_service.clone(), mirror_port);
    let lb = match lbs.get(&lb_key) {
        Some(lb) => Arc::clone(lb),
        None => {
            warn!("no endpoints for mirror backend {}:{}", mirror_service, mirror_port);
            return;
        }
    };

    let backend = match lb.select(b"", 256) {
        Some(b) => b,
        None => {
            warn!("no ready endpoints for mirror backend {}:{}", mirror_service, mirror_port);
            return;
        }
    };

    let addr_str = format!("{}", backend.addr);
    let method = method.clone();
    // SEC-8: Strip CRLF from host/path/headers to prevent header injection in raw HTTP/1.1 request.
    let safe_path = path.replace(['\r', '\n'], "");
    let safe_host = host.replace(['\r', '\n'], "");
    let safe_headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|(k, v)| (k.replace(['\r', '\n'], ""), v.replace(['\r', '\n'], "")))
        .collect();

    tokio::spawn(async move {
        let _permit = permit; // held until task completes
        match tokio::net::TcpStream::connect(&addr_str).await {
            Ok(mut stream) => {
                use tokio::io::AsyncWriteExt;
                let mut request = format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\n",
                    method, safe_path, safe_host
                );
                for (k, v) in &safe_headers {
                    request.push_str(&format!("{}: {}\r\n", k, v));
                }
                request.push_str("Connection: close\r\n\r\n");
                let _ = stream.write_all(request.as_bytes()).await;
                // Ignore response (fire-and-forget)
            }
            Err(e) => {
                warn!("mirror request to {} failed: {}", addr_str, e);
            }
        }
    });
}

/// Per-request context for retry tracking and cached route info.
pub(crate) struct RouterCtx {
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
    cached_lb: Option<Arc<LoadBalancer<RoundRobin>>>,
    // The endpoint the last upstream attempt went to, for outlier ejection.
    upstream_addr: Option<pingora_core::protocols::l4::socket::SocketAddr>,
    // BackendTLSPolicy config for the selected backend, resolved in request_filter
    // from the same snapshot load as `cached_lb`.
    cached_backend_tls: Option<Arc<BackendTlsInfo>>,
    // Client certificate this Gateway presents to TLS backends
    // (Gateway spec.tls.backend.clientCertificateRef), same snapshot load.
    cached_client_cert: Option<Arc<pingora_core::utils::tls::CertKey>>,
}

// ---------------------------------------------------------------------------
// PERF-9: ProxySnapshot — bundles all per-request config maps into a single
// ArcSwap to reduce atomic operations (one load instead of 4-6 per request).
// ---------------------------------------------------------------------------

/// All per-request config maps bundled into a single atomic snapshot.
/// One `ArcSwap::load()` (2-3 atomics) replaces 4-6 separate loads (8-18 atomics).
/// BackendTLS configuration from BackendTLSPolicy, stored per (service, port).
/// CA certs are pre-parsed at config build time (not per-request).
#[derive(Clone)]
pub(crate) struct BackendTlsInfo {
    pub(crate) ca_certs: Arc<pingora_core::protocols::tls::CaType>,
    pub(crate) hostname: Arc<str>,
    /// SubjectAltNames from BackendTLSPolicy for additional cert validation.
    /// Empty = no additional SAN checks (only hostname verification).
    pub(crate) subject_alt_names: Arc<Vec<(String, String)>>, // (type, value)
}

impl std::fmt::Debug for BackendTlsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendTlsInfo")
            .field("hostname", &self.hostname)
            .field("ca_certs_count", &self.ca_certs.len())
            .finish()
    }
}

/// A single listener's route table — isolated from other listeners so a
/// request bound to this listener cannot see routes attached to other
/// listeners on the same port (GatewayHTTPListenerIsolation).
///
/// `listener_hostname` is the listener's hostname restriction used for
/// picking which bucket claims a given request host:
///   - "" → empty-hostname listener (catch-all; lowest priority)
///   - "*.example.com" → wildcard listener (middle priority, ranked by suffix length)
///   - "abc.foo.example.com" → exact listener (highest priority)
pub(crate) struct ListenerBucket {
    pub(crate) listener_hostname: Arc<str>,
    /// Exact route host → HostRoutes (e.g. "foo.example.com").
    pub(crate) exact: HashMap<String, HostRoutes>,
    /// Route-host wildcard suffix → HostRoutes (e.g. ".example.com" for "*.example.com").
    pub(crate) domain_wildcards: HashMap<String, HostRoutes>,
    /// Route host "*" catch-all within this listener.
    pub(crate) catch_all: Option<HostRoutes>,
}

pub(crate) struct ProxySnapshot {
    /// Listener buckets indexed by listener port. Each inner vector is pre-sorted
    /// by listener hostname specificity, most specific first, so the first bucket
    /// whose hostname matches the request host claims it.
    pub(crate) listeners_by_port: HashMap<u16, Vec<ListenerBucket>>,
    /// Buckets for routes compiled with listener_port=0 (no port scoping).
    /// Consulted when no port-specific bucket claims the request.
    pub(crate) any_port_listeners: Vec<ListenerBucket>,
    pub(crate) lbs: HashMap<(Arc<str>, u16), Arc<LoadBalancer<RoundRobin>>>,
    pub(crate) circuit_breakers: HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>,
    pub(crate) connection_limiters: HashMap<(Arc<str>, u16), Arc<ConnectionLimiter>>,
    /// SEC F-2: Collected per-IP rate limiters for background eviction.
    /// Populated at config-build time; the eviction task iterates these periodically.
    pub(crate) per_ip_limiters: Vec<Arc<crate::rate_limiter::PerIpRateLimiter>>,
    /// BackendTLSPolicy: per-backend TLS config for proxy-to-backend connections.
    /// `Arc` so `request_filter` can cache a handle in `RouterCtx` without cloning
    /// the CA bundle.
    pub(crate) backend_tls: HashMap<(Arc<str>, u16), Arc<BackendTlsInfo>>,
    /// Client certificate this data plane's Gateway presents to TLS backends
    /// (`spec.tls.backend.clientCertificateRef`).
    pub(crate) backend_client_cert: Option<Arc<pingora_core::utils::tls::CertKey>>,
    /// Fingerprint of the endpoint set + health-check config each `LoadBalancer`
    /// was built from. `apply_config` reuses the existing `LoadBalancer` (and its
    /// health state) when the signature is unchanged.
    pub(crate) lb_signatures: HashMap<(Arc<str>, u16), u64>,
}

impl Default for ProxySnapshot {
    fn default() -> Self {
        Self {
            listeners_by_port: HashMap::new(),
            any_port_listeners: Vec::new(),
            lbs: HashMap::new(),
            circuit_breakers: HashMap::new(),
            connection_limiters: HashMap::new(),
            per_ip_limiters: Vec::new(),
            backend_tls: HashMap::new(),
            backend_client_cert: None,
            lb_signatures: HashMap::new(),
        }
    }
}

/// Returns true when a listener's hostname pattern claims a request host.
/// Case-insensitive. `""` matches any host; `"*.suffix"` matches any host
/// with a non-empty label before `.suffix`; otherwise exact match.
pub(crate) fn listener_hostname_claims(listener_hostname: &str, host: &str) -> bool {
    if listener_hostname.is_empty() {
        return true;
    }
    if let Some(suffix) = listener_hostname.strip_prefix("*.") {
        let host_lc = host.to_ascii_lowercase();
        let suffix_lc = suffix.to_ascii_lowercase();
        let dot_suffix = format!(".{}", suffix_lc);
        return host_lc.ends_with(&dot_suffix) && host_lc.len() > dot_suffix.len();
    }
    host.eq_ignore_ascii_case(listener_hostname)
}

/// Return the listener hostname specificity rank used to sort buckets.
/// Higher = more specific and should be checked first.
pub(crate) fn listener_specificity(listener_hostname: &str) -> u32 {
    if listener_hostname.is_empty() {
        1
    } else if let Some(suffix) = listener_hostname.strip_prefix("*.") {
        1000 + suffix.len() as u32
    } else {
        10_000 + listener_hostname.len() as u32
    }
}

/// Look up a host in a plain domain-wildcard suffix map (no port suffixes).
/// Equivalent to `lookup_domain_wildcard` but used when the bucket already
/// scopes by port.
pub(crate) fn lookup_domain_wildcard_bucket<'a>(
    host: &str,
    map: &'a HashMap<String, HostRoutes>,
) -> Option<&'a HostRoutes> {
    let mut search = host;
    while let Some(dot) = search.find('.') {
        let suffix = &search[dot..]; // ".example.com"
        if let Some(routes) = map.get(suffix) {
            return Some(routes);
        }
        search = &search[dot + 1..];
    }
    None
}

/// Pick the first listener bucket whose hostname pattern claims the request host.
/// Buckets must be pre-sorted by specificity (most specific first).
pub(crate) fn select_listener_bucket<'a>(
    host: &str,
    buckets: &'a [ListenerBucket],
) -> Option<&'a ListenerBucket> {
    buckets
        .iter()
        .find(|b| listener_hostname_claims(&b.listener_hostname, host))
}

/// GEP-1486 (HTTPRouteHTTPSListenerDetectMisdirectedRequests): decide whether
/// an HTTPS request is "misdirected" — the TLS handshake chose one listener
/// (by SNI) but the HTTP Host header belongs to a different listener on the
/// same port.
///
/// Returns `true` when the most-specific listener that claims the SNI differs
/// from the most-specific listener that claims the Host. Buckets must be
/// pre-sorted by specificity (most specific first) — the same ordering used
/// by `select_listener_bucket`.
///
/// Returns `false` when:
///   - SNI is absent (plain HTTP or TLS handshake without SNI),
///   - SNI and Host resolve to the same listener bucket,
///   - SNI matches no listener at all (fallback cert path; no 421 emitted).
pub(crate) fn detect_misdirected_request(
    sni: Option<&str>,
    host: &str,
    buckets: &[ListenerBucket],
) -> bool {
    let Some(sni) = sni else {
        return false;
    };
    let sni_bucket = select_listener_bucket(sni, buckets);
    let host_bucket = select_listener_bucket(host, buckets);
    match (sni_bucket, host_bucket) {
        (Some(s), Some(h)) => s.listener_hostname != h.listener_hostname,
        // SNI is claimed by a listener, Host is claimed by none — treat as misdirected.
        (Some(_), None) => true,
        // SNI matches no listener → fallback cert path; defer to Host-based routing.
        (None, _) => false,
    }
}

/// Single atomic slot for the bundled per-request config snapshot.
pub(crate) type SnapshotSlot = Arc<ArcSwap<ProxySnapshot>>;

/// Per-(service, port) load balancer, swapped atomically.
/// Keyed by (service_name, port) so multi-port services route correctly.
/// Used by L4 proxy and health check threads (not part of ProxySnapshot path).
pub(crate) type ServiceLbMap = Arc<ArcSwap<HashMap<(Arc<str>, u16), Arc<LoadBalancer<RoundRobin>>>>>;

/// Look up a host in a domain-wildcard map by trying every dot-suffix.
///
/// For `a.b.bar.com`, tries `.b.bar.com`, then `.bar.com`, then `.com`.
/// This correctly handles multi-level subdomains matching `*.bar.com`.
/// Returns `None` for apex names (e.g. `bar.com` never matches `*.bar.com`
/// because the first dot yields `.com`, which is not a wildcard key).
#[cfg(test)]
pub(crate) fn lookup_domain_wildcard<'a>(
    host: &str,
    map: &'a HashMap<String, HostRoutes>,
) -> Option<&'a HostRoutes> {
    lookup_domain_wildcard_with_port(host, 0, map)
}

/// Port-aware domain wildcard lookup. When `port > 0`, tries port-qualified
/// keys first (e.g. ".bar.com:80") then falls back to plain suffix (".bar.com").
/// This handles routes compiled with non-zero listener_port.
#[cfg(test)]
pub(crate) fn lookup_domain_wildcard_with_port<'a>(
    host: &str,
    port: u16,
    map: &'a HashMap<String, HostRoutes>,
) -> Option<&'a HostRoutes> {
    // Stack buffer for port-suffixed keys, avoiding heap allocation per dot position.
    // Max DNS hostname is 253 chars + ":" + 5-digit port = 259 bytes. 270 is safe.
    debug_assert!(host.len() <= 253, "hostname exceeds DNS max length: {}", host.len());
    let mut buf = [0u8; 270];
    let mut search = host;
    while let Some(dot) = search.find('.') {
        let suffix = &search[dot..]; // ".bar.com", ".com", etc.
        // Try port-specific key first (e.g. ".bar.com:80")
        if port > 0 {
            let key_len = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut buf[..]);
                let _ = write!(cursor, "{}:{}", suffix, port);
                cursor.position() as usize
            };
            if let Ok(key) = std::str::from_utf8(&buf[..key_len])
                && let Some(routes) = map.get(key) {
                    return Some(routes);
                }
        }
        if let Some(routes) = map.get(suffix) {
            return Some(routes);
        }
        search = &search[dot + 1..];
    }
    None
}

// ---------------------------------------------------------------------------
// Timeout error → HTTP status code mapping
// ---------------------------------------------------------------------------

/// True when an upstream response with `status` should be retried: the route
/// lists the status and attempts remain. An empty list never retries on
/// status (only connect failures, see `fail_to_connect`).
pub(crate) fn should_retry_status(status: u16, retry_codes: &[u16], retries_left: u32) -> bool {
    retries_left > 0 && retry_codes.contains(&status)
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
// CORS helper functions
// ---------------------------------------------------------------------------

/// Checks if a request origin matches the configured CORS allow origins.
///
/// Supports three origin formats:
/// - `"*"` — matches any origin
/// - Exact string — e.g., `"https://example.com"`
/// - Wildcard prefix — e.g., `"https://*.example.com"` matches any subdomain
///   including multi-level (e.g., `"https://a.b.example.com"`).
///   NOTE: Wildcards match across dot boundaries. `"https://*.com"` would match
///   any `.com` domain. Operators should use specific enough patterns.
fn cors_origin_matches(allow_origins: &[String], origin: &str) -> bool {
    for allowed in allow_origins {
        if allowed == "*" {
            return true;
        }
        if allowed == origin {
            return true;
        }
        // Wildcard matching: e.g. "https://*.bar.com" matches "https://www.bar.com"
        // Find the * in the pattern and split into prefix + suffix
        if let Some(star_pos) = allowed.find('*') {
            let prefix = &allowed[..star_pos];    // e.g. "https://"
            let suffix = &allowed[star_pos + 1..]; // e.g. ".bar.com"
            if origin.starts_with(prefix) && origin[prefix.len()..].ends_with(suffix) {
                // Ensure the wildcard matched at least something
                let middle = &origin[prefix.len()..origin.len() - suffix.len()];
                if !middle.is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

/// Determine the Access-Control-Allow-Origin value.
/// When allowCredentials is true and wildcard origins are used, echo the specific origin
/// (per W3C spec: credentialed requests cannot use "*" as Allow-Origin).
/// When allowCredentials is false and "*" is in allow_origins, may return "*" or the origin.
fn cors_allow_origin_value<'a>(cors: &CorsConfig, origin: &'a str, has_credentials: bool) -> std::borrow::Cow<'a, str> {
    if cors.allow_credentials || has_credentials {
        // When credentials are present (Cookie, Authorization) or allowCredentials
        // is true, MUST echo the specific origin — never "*" (W3C CORS spec).
        std::borrow::Cow::Borrowed(origin)
    } else if cors.allow_origins.iter().any(|o| o == "*") {
        std::borrow::Cow::Borrowed("*")
    } else {
        std::borrow::Cow::Borrowed(origin)
    }
}

/// Build the Allow-Methods header value for preflight responses.
/// Uses the pre-joined string to avoid per-request allocation.
fn cors_methods_value<'a>(allow_methods: &[String], pre_joined: &'a str, requested_method: &'a str) -> &'a str {
    if allow_methods.is_empty() {
        return "";
    }
    if allow_methods.iter().any(|m| m == "*") {
        // Wildcard: echo the requested method
        return requested_method;
    }
    pre_joined
}

/// Build the Allow-Headers header value for preflight responses.
/// Uses the pre-joined string to avoid per-request allocation.
fn cors_headers_value<'a>(allow_headers: &[String], pre_joined: &'a str, requested_headers: &'a str) -> &'a str {
    if allow_headers.is_empty() {
        return "";
    }
    if allow_headers.iter().any(|h| h == "*") {
        // Wildcard: echo the requested headers
        return requested_headers;
    }
    pre_joined
}

// ---------------------------------------------------------------------------
// Router (Pingora ProxyHttp implementation)
// ---------------------------------------------------------------------------

pub(crate) struct Router {
    /// PERF-9: Single atomic snapshot for all per-request config maps.
    /// One ArcSwap::load() replaces 4+ separate loads per request.
    pub(crate) snapshot: SnapshotSlot,
    pub(crate) metrics: Arc<ProxyMetrics>,
    /// Passive outlier ejection state, shared by the HTTP and HTTPS services.
    pub(crate) outliers: Arc<Outliers>,
}

impl Router {
    fn note_ejection(&self, ctx: &RouterCtx, addr: &pingora_core::protocols::l4::socket::SocketAddr, out: Duration, why: &str) {
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
                    use crate::auth::{validate_basic_auth, validate_api_key};
                    use crate::types::AuthConfig;
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
                    use crate::rate_limiter::RateLimiterMode;
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

        let backend = lb.select(b"", 256).ok_or_else(|| {
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

        ctx.upstream_addr = Some(backend.addr.clone());
        let mut peer = HttpPeer::new(backend.addr, use_tls, sni);
        if use_tls {
            // Gateway spec.tls.backend.clientCertificateRef: present the
            // Gateway's client certificate to the backend (mTLS). Part of the
            // peer's reuse hash, so pooled connections never mix identities.
            peer.client_cert_key = ctx.cached_client_cert.clone();
            if let Some(btls) = backend_tls_info {
                // BackendTLSPolicy: verify cert against the policy's custom CA certs
                peer.options.verify_cert = true;
                peer.options.ca = Some(Arc::clone(&btls.ca_certs));
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

/// Parse CRD header mutation config into pre-validated HeaderName/HeaderValue pairs.
/// Invalid names/values are logged at warn level and skipped.
///
/// Legacy version: merges `add` and `set` into a single add list.
/// Use `parse_header_mutations_full` for Gateway API conformance.
#[cfg(test)]
pub(crate) fn parse_header_mutations(
    mutation: &Option<crate::types::HeaderMutation>,
) -> (Vec<(HeaderName, HeaderValue)>, Vec<HeaderName>) {
    let (add, _, remove) = parse_header_mutations_full(mutation);
    (add, remove)
}

/// Parse CRD header mutation config into separate add, set, and remove lists.
///
/// Gateway API distinguishes:
/// - `add`: append to existing header value with comma separator
/// - `set`: overwrite the header value completely
/// - `remove`: remove the header
#[cfg(test)]
type HeaderMutationParts = (
    Vec<(HeaderName, HeaderValue)>,
    Vec<(HeaderName, HeaderValue)>,
    Vec<HeaderName>,
);

#[cfg(test)]
pub(crate) fn parse_header_mutations_full(
    mutation: &Option<crate::types::HeaderMutation>,
) -> HeaderMutationParts {
    let Some(m) = mutation else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let mut add = Vec::new();
    for (name_str, value_str) in &m.add {
        match (
            HeaderName::from_bytes(name_str.as_bytes()),
            HeaderValue::from_str(value_str),
        ) {
            (Ok(name), Ok(value)) => add.push((name, value)),
            (Err(e), _) => warn!("invalid header name '{}': {}, skipping", name_str, e),
            (_, Err(e)) => warn!("invalid header value for '{}': {}, skipping", name_str, e),
        }
    }
    let mut set = Vec::new();
    for (name_str, value_str) in &m.set {
        match (
            HeaderName::from_bytes(name_str.as_bytes()),
            HeaderValue::from_str(value_str),
        ) {
            (Ok(name), Ok(value)) => set.push((name, value)),
            (Err(e), _) => warn!("invalid header name '{}': {}, skipping", name_str, e),
            (_, Err(e)) => warn!("invalid header value for '{}': {}, skipping", name_str, e),
        }
    }
    let mut remove = Vec::new();
    for name_str in &m.remove {
        match HeaderName::from_bytes(name_str.as_bytes()) {
            Ok(name) => remove.push(name),
            Err(e) => warn!(
                "invalid header name to remove '{}': {}, skipping",
                name_str, e
            ),
        }
    }
    (add, set, remove)
}

/// Build the route map from a working set of CRDs keyed by name.
/// Groups CRDs by host, sorts path rules, and produces HostRoutes per host.
///
/// `old_routes` is used to preserve existing rate limiter state across rebuilds:
/// if a route has the same host, path, and RPS config, its `AtomicTokenBucket`
/// is reused rather than recreated (which would reset the token count).
#[cfg(test)]
pub(crate) fn build_route_map(
    crd_map: &HashMap<String, ProxyRouteSpec>,
    old_routes: &HashMap<String, HostRoutes>,
) -> (HashMap<String, HostRoutes>, Option<HostRoutes>) {
    let mut by_host: HashMap<&str, Vec<&ProxyRouteSpec>> = HashMap::new();
    for spec in crd_map.values() {
        by_host.entry(spec.host.as_str()).or_default().push(spec);
    }

    let mut route_map = HashMap::new();

    for (host, specs) in by_host {
        let mut exact_rules: Vec<PathRoute> = Vec::new();
        let mut prefix_rules: Vec<PathRoute> = Vec::new();
        let mut catch_all: Option<PathRoute> = None;

        // Look up old host routes for rate limiter reuse.
        let old_host = old_routes.get(host);

        for spec in specs {
            let upstream_tls = spec.tls.as_ref().is_some_and(|t| t.enabled);
            let upstream_sni: Arc<str> = spec
                .tls
                .as_ref()
                .and_then(|t| t.sni.as_deref())
                .unwrap_or(&spec.service_name)
                .into();
            let upstream_verify = spec
                .tls
                .as_ref()
                .is_none_or(|t| t.verify_cert);

            let (req_add, req_set, req_remove) = parse_header_mutations_full(&spec.request_headers);
            let (resp_add, resp_set, resp_remove) = parse_header_mutations_full(&spec.response_headers);
            let req_add = Arc::new(req_add);
            let req_set = Arc::new(req_set);
            let req_remove = Arc::new(req_remove);
            let resp_add = Arc::new(resp_add);
            let resp_set = Arc::new(resp_set);
            let resp_remove = Arc::new(resp_remove);

            let make_route = |path: Arc<str>, match_type: PathMatchType| {
                // Try to reuse an existing rate limiter with the same RPS.
                let rate_limiter = spec.rate_limit_rps.map(|rps| {
                    if let Some(old_hr) = old_host {
                        let existing = old_hr.find_rate_limiter(path.as_ref(), &match_type, rps, false);
                        if let Some(rl) = existing {
                            return rl;
                        }
                    }
                    crate::rate_limiter::RateLimiterMode::Shared(Arc::new(AtomicTokenBucket::new(rps)))
                });

                PathRoute {
                    path,
                    match_type,
                    service_name: Arc::from(spec.service_name.as_str()),
                    port: spec.port,
                    connect_timeout: spec.connect_timeout_ms.map(Duration::from_millis),
                    read_timeout: spec.read_timeout_ms.map(Duration::from_millis),
                    write_timeout: spec.write_timeout_ms.map(Duration::from_millis),
                    rate_limiter,
                    max_retries: spec.retries.unwrap_or(0),
                    upstream_tls,
                    upstream_sni: Arc::clone(&upstream_sni),
                    upstream_verify,
                    protocol: spec.protocol,
                    request_headers_add: Arc::clone(&req_add),
                    request_headers_set: Arc::clone(&req_set),
                    request_headers_remove: Arc::clone(&req_remove),
                    response_headers_add: Arc::clone(&resp_add),
                    response_headers_set: Arc::clone(&resp_set),
                    response_headers_remove: Arc::clone(&resp_remove),
                    header_matches: Vec::new(),
                    method_match: None,
                    query_param_matches: Vec::new(),
                    redirect: None,
                    url_rewrite: None,
                    listener_name: Arc::from(""),
                    mirror_backends: Vec::new(),
                    weighted_backends: Vec::new(),
                    request_timeout: None,
                    backend_request_timeout: None,
                    auth_config: None,
                    cors: None,
                    ip_allow_cidrs: Vec::new(),
                    ip_deny_cidrs: Vec::new(),
                    ip_trusted_proxy_cidrs: Vec::new(),
                    max_request_body_bytes: 0,
                    retry_on: Arc::new(Vec::new()),
            retry_codes: Arc::new(Vec::new()),
                    circuit_breaker: None,
                    connection_limiter: None,
                    total_weight: 0,
                }
            };

            let has_paths = spec.paths.as_ref().is_some_and(|v| !v.is_empty());
            if !has_paths {
                if catch_all.is_some() {
                    warn!("multiple catch-all routes for host {}, last wins", host);
                }
                catch_all = Some(make_route(Arc::from("/"), PathMatchType::Prefix));
            } else if let Some(paths) = &spec.paths {
                for pr in paths {
                    let route = make_route(Arc::from(pr.path.as_str()), pr.r#type.clone());
                    match route.match_type {
                        PathMatchType::Exact => exact_rules.push(route),
                        PathMatchType::Prefix => prefix_rules.push(route),
                        PathMatchType::RegularExpression(_) => prefix_rules.push(route),
                    }
                }
            }
        }

        // Sort prefix rules: longest-first (then more headers first).
        // Per Gateway API spec, routes with more header matches are more
        // specific and should be checked before less-specific routes.
        prefix_rules.sort_by(|a, b| {
            b.path.len().cmp(&a.path.len())
                .then_with(|| b.header_matches.len().cmp(&a.header_matches.len()))
        });

        // Build exact path HashMap for O(1) lookup.
        // Sort each bucket by specificity (more headers first).
        let mut exact_map: HashMap<Arc<str>, Vec<PathRoute>> = HashMap::new();
        exact_rules.sort_by_key(|r| std::cmp::Reverse(r.header_matches.len()));
        for rule in exact_rules {
            exact_map.entry(Arc::clone(&rule.path)).or_default().push(rule);
        }

        route_map.insert(
            host.to_string(),
            HostRoutes {
                exact_map,
                rules: prefix_rules,
                catch_all,
            },
        );
    }

    // Extract wildcard routes into separate slot (per CONTEXT.md locked decision).
    let wildcard = route_map.remove("*");

    (route_map, wildcard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_log_flag_parses_like_the_chart_boolean() {
        for v in ["true", "True", "1", "yes", "on", " on "] {
            assert!(access_log_from_env_value(Some(v)), "{v}");
        }
        for v in ["false", "0", "off", "", "nonsense"] {
            assert!(!access_log_from_env_value(Some(v)), "{v}");
        }
        assert!(!access_log_from_env_value(None), "unset means off");
    }
    use crate::types::{BackendProtocol, PathMatchType, PathRule, ProxyRouteSpec};
    use hashbrown::HashMap;

    /// Helper: build a PathRoute with minimal required fields
    fn make_path_route(path: &str, match_type: PathMatchType) -> PathRoute {
        PathRoute {
            path: Arc::from(path),
            match_type,
            service_name: Arc::from("test-svc"),
            port: 8080,
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            rate_limiter: None,
            max_retries: 0,
            upstream_tls: false,
            upstream_sni: Arc::from("test-svc"),
            upstream_verify: true,
            protocol: BackendProtocol::Http,
            request_headers_add: Arc::new(Vec::new()),
            request_headers_set: Arc::new(Vec::new()),
            request_headers_remove: Arc::new(Vec::new()),
            response_headers_add: Arc::new(Vec::new()),
            response_headers_set: Arc::new(Vec::new()),
            response_headers_remove: Arc::new(Vec::new()),
            header_matches: Vec::new(),
            method_match: None,
            query_param_matches: Vec::new(),
            redirect: None,
            url_rewrite: None,
            listener_name: Arc::from(""),
            mirror_backends: Vec::new(),
            weighted_backends: Vec::new(),
            request_timeout: None,
            backend_request_timeout: None,
            auth_config: None,
            cors: None,
            ip_allow_cidrs: Vec::new(),
            ip_deny_cidrs: Vec::new(),
            ip_trusted_proxy_cidrs: Vec::new(),
            max_request_body_bytes: 0,
            retry_on: Arc::new(Vec::new()),
            retry_codes: Arc::new(Vec::new()),
            circuit_breaker: None,
            connection_limiter: None,
            total_weight: 0,
        }
    }

    fn make_host_routes(rules: Vec<PathRoute>, catch_all: Option<PathRoute>) -> HostRoutes {
        let mut exact_map: HashMap<Arc<str>, Vec<PathRoute>> = HashMap::new();
        let mut prefix_rules = Vec::new();
        for rule in rules {
            match rule.match_type {
                PathMatchType::Exact => {
                    exact_map.entry(Arc::clone(&rule.path)).or_default().push(rule);
                }
                _ => prefix_rules.push(rule),
            }
        }
        HostRoutes { exact_map, rules: prefix_rules, catch_all }
    }

    #[test]
    fn exact_match_takes_precedence_over_prefix() {
        let routes = make_host_routes(
            vec![
                make_path_route("/api", PathMatchType::Exact),
                make_path_route("/api", PathMatchType::Prefix),
            ],
            None,
        );
        let matched = routes.match_path("/api").unwrap();
        assert_eq!(matched.match_type, PathMatchType::Exact);
    }

    #[test]
    fn longest_prefix_wins() {
        // Sorted longest-first as build_route_map would do
        let routes = make_host_routes(
            vec![
                make_path_route("/api/v1", PathMatchType::Prefix),
                make_path_route("/api", PathMatchType::Prefix),
            ],
            None,
        );
        let matched = routes.match_path("/api/v1/users").unwrap();
        assert_eq!(matched.path.as_ref(), "/api/v1");
    }

    #[test]
    fn trailing_slash_prefix_matches() {
        let routes = make_host_routes(
            vec![make_path_route("/api/", PathMatchType::Prefix)],
            None,
        );
        assert!(routes.match_path("/api/foo").is_some());
    }

    #[test]
    fn empty_path_no_match_falls_to_catch_all() {
        let routes = make_host_routes(
            vec![make_path_route("/api", PathMatchType::Prefix)],
            Some(make_path_route("/", PathMatchType::Prefix)),
        );
        let matched = routes.match_path("/other").unwrap();
        assert_eq!(matched.path.as_ref(), "/");
    }

    #[test]
    fn no_match_and_no_catch_all_returns_none() {
        let routes = make_host_routes(
            vec![make_path_route("/api", PathMatchType::Exact)],
            None,
        );
        assert!(routes.match_path("/other").is_none());
    }

    #[test]
    fn prefix_boundary_no_partial_match() {
        let routes = make_host_routes(
            vec![make_path_route("/api", PathMatchType::Prefix)],
            None,
        );
        assert!(routes.match_path("/apiary").is_none());
    }

    fn make_spec(host: &str, service: &str, port: u16) -> ProxyRouteSpec {
        ProxyRouteSpec {
            host: host.to_string(),
            paths: None,
            service_name: service.to_string(),
            port,
            connect_timeout_ms: None,
            read_timeout_ms: None,
            write_timeout_ms: None,
            rate_limit_rps: None,
            retries: None,
            tls: None,
            protocol: BackendProtocol::Http,
            request_headers: None,
            response_headers: None,
            circuit_breaker: None,
            max_connections: None,
        }
    }

    #[test]
    fn build_route_map_groups_by_host() {
        let mut crd_map = HashMap::new();
        let mut spec = make_spec("api.example.com", "backend", 8080);
        spec.paths = Some(vec![PathRule {
            path: "/v1".to_string(),
            r#type: PathMatchType::Prefix,
        }]);
        crd_map.insert("route-1".to_string(), spec);
        let empty = HashMap::new();
        let (result, wildcard) = build_route_map(&crd_map, &empty);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("api.example.com"));
        assert!(wildcard.is_none());
    }

    // -----------------------------------------------------------------------
    // Rate limiter preservation tests
    // -----------------------------------------------------------------------

    fn shared_arc_ptr(rl: &crate::rate_limiter::RateLimiterMode) -> *const AtomicTokenBucket {
        match rl {
            crate::rate_limiter::RateLimiterMode::Shared(a) => Arc::as_ptr(a),
            _ => panic!("expected Shared rate limiter"),
        }
    }

    #[test]
    fn rate_limiter_preserved_across_rebuild_when_rps_unchanged() {
        let mut crd_map = HashMap::new();
        let mut spec = make_spec("api.example.com", "backend", 8080);
        spec.paths = Some(vec![PathRule {
            path: "/v1".to_string(),
            r#type: PathMatchType::Prefix,
        }]);
        spec.rate_limit_rps = Some(100);
        crd_map.insert("route-1".to_string(), spec);

        let empty = HashMap::new();
        let (first, _) = build_route_map(&crd_map, &empty);
        let first_rl = first["api.example.com"].rules[0].rate_limiter.as_ref().unwrap();
        let first_ptr = shared_arc_ptr(first_rl);

        // Second build: same CRDs, old_routes = first build.
        let (second, _) = build_route_map(&crd_map, &first);
        let second_rl = second["api.example.com"].rules[0].rate_limiter.as_ref().unwrap();
        let second_ptr = shared_arc_ptr(second_rl);

        assert_eq!(first_ptr, second_ptr, "rate limiter must be reused (same Arc)");
    }

    #[test]
    fn rate_limiter_replaced_when_rps_changes() {
        let mut crd_map = HashMap::new();
        let mut spec = make_spec("api.example.com", "backend", 8080);
        spec.paths = Some(vec![PathRule {
            path: "/v1".to_string(),
            r#type: PathMatchType::Prefix,
        }]);
        spec.rate_limit_rps = Some(100);
        crd_map.insert("route-1".to_string(), spec);

        let empty = HashMap::new();
        let (first, _) = build_route_map(&crd_map, &empty);
        let first_ptr = shared_arc_ptr(
            first["api.example.com"].rules[0].rate_limiter.as_ref().unwrap()
        );

        crd_map.get_mut("route-1").unwrap().rate_limit_rps = Some(200);
        let (second, _) = build_route_map(&crd_map, &first);
        let second_ptr = shared_arc_ptr(
            second["api.example.com"].rules[0].rate_limiter.as_ref().unwrap()
        );

        assert_ne!(first_ptr, second_ptr, "rate limiter must be replaced when RPS changes");
    }

    // -----------------------------------------------------------------------
    // Wildcard routing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_wildcard_routes_stored_separately() {
        let mut crd_map = HashMap::new();
        crd_map.insert("wildcard".to_string(), make_spec("*", "fallback-svc", 8080));
        crd_map.insert("explicit".to_string(), make_spec("api.example.com", "api-svc", 8080));

        let empty = HashMap::new();
        let (routes, wildcard) = build_route_map(&crd_map, &empty);

        // Wildcard should NOT be in the HashMap
        assert!(!routes.contains_key("*"), "wildcard must not be in explicit routes");
        assert!(routes.contains_key("api.example.com"));
        // Wildcard should be in the separate Option
        assert!(wildcard.is_some(), "wildcard must be returned separately");
    }

    #[test]
    fn test_wildcard_host_routes_to_fallback() {
        let mut crd_map = HashMap::new();
        crd_map.insert("wildcard".to_string(), make_spec("*", "fallback-svc", 8080));

        let empty = HashMap::new();
        let (routes, wildcard) = build_route_map(&crd_map, &empty);

        assert!(routes.is_empty(), "only wildcard host, no explicit routes");
        let wc = wildcard.unwrap();
        // Wildcard catch-all should match any path
        let matched = wc.match_path("/anything").unwrap();
        assert_eq!(matched.service_name.as_ref(), "fallback-svc");
    }

    #[test]
    fn test_explicit_host_takes_priority_over_wildcard() {
        let mut crd_map = HashMap::new();
        crd_map.insert("wildcard".to_string(), make_spec("*", "fallback-svc", 8080));
        crd_map.insert("explicit".to_string(), make_spec("api.example.com", "api-svc", 9090));

        let empty = HashMap::new();
        let (routes, wildcard) = build_route_map(&crd_map, &empty);

        // Explicit host is in the map
        let host_routes = routes.get("api.example.com").unwrap();
        let matched = host_routes.match_path("/").unwrap();
        assert_eq!(matched.service_name.as_ref(), "api-svc");
        assert_eq!(matched.port, 9090);

        // Wildcard is separate, not checked for explicit hosts
        assert!(wildcard.is_some());
        let wc = wildcard.unwrap();
        let wc_matched = wc.match_path("/").unwrap();
        assert_eq!(wc_matched.service_name.as_ref(), "fallback-svc");
    }

    // -----------------------------------------------------------------------
    // Header mutation parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_header_mutations_valid() {
        use crate::types::HeaderMutation;
        use std::collections::BTreeMap;

        let mut add = BTreeMap::new();
        add.insert("x-custom".to_string(), "value1".to_string());
        add.insert("x-another".to_string(), "value2".to_string());
        let mutation = Some(HeaderMutation {
            add,
            remove: vec!["x-remove-me".to_string()],
            ..Default::default()
        });

        let (adds, removes) = parse_header_mutations(&mutation);
        assert_eq!(adds.len(), 2);
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].as_str(), "x-remove-me");
    }

    #[test]
    fn test_parse_header_mutations_invalid_name_skipped() {
        use crate::types::HeaderMutation;
        use std::collections::BTreeMap;

        let mut add = BTreeMap::new();
        add.insert("valid-header".to_string(), "ok".to_string());
        add.insert("bad header name".to_string(), "value".to_string()); // spaces are invalid
        let mutation = Some(HeaderMutation {
            add,
            remove: vec![],
            ..Default::default()
        });

        let (adds, _removes) = parse_header_mutations(&mutation);
        assert_eq!(adds.len(), 1, "only valid header should be parsed");
        assert_eq!(adds[0].0.as_str(), "valid-header");
    }

    #[test]
    fn test_parse_header_mutations_none_returns_empty() {
        let (adds, removes) = parse_header_mutations(&None);
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }

    #[test]
    fn test_header_mutation_in_route_map() {
        use crate::types::HeaderMutation;
        use std::collections::BTreeMap;

        let mut crd_map = HashMap::new();
        let mut spec = make_spec("api.example.com", "backend", 8080);
        let mut add = BTreeMap::new();
        add.insert("x-injected".to_string(), "hello".to_string());
        spec.request_headers = Some(HeaderMutation {
            add,
            remove: vec!["x-strip".to_string()],
            ..Default::default()
        });
        crd_map.insert("route-1".to_string(), spec);

        let empty = HashMap::new();
        let (result, _) = build_route_map(&crd_map, &empty);
        let host_routes = result.get("api.example.com").unwrap();
        let route = host_routes.catch_all.as_ref().unwrap();

        assert_eq!(route.request_headers_add.len(), 1);
        assert_eq!(route.request_headers_add[0].0.as_str(), "x-injected");
        assert_eq!(route.request_headers_remove.len(), 1);
        assert_eq!(route.request_headers_remove[0].as_str(), "x-strip");
    }

    // -----------------------------------------------------------------------
    // Header mutation application tests (OPS-02 / OPS-03)
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_header_add_applied() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let adds = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: [("x-injected".into(), "hello".into())].into(),
            remove: vec![],
            ..Default::default()
        }));

        // Apply the same way upstream_request_filter does
        for (name, value) in &adds.0 {
            req.insert_header(name.clone(), value).unwrap();
        }

        assert_eq!(req.headers.get("x-injected").unwrap(), "hello");
    }

    #[test]
    fn test_request_header_remove_applied() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-secret", "remove-me").unwrap();
        assert!(req.headers.get("x-secret").is_some());

        let (_, removes) = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: Default::default(),
            remove: vec!["x-secret".into()],
            ..Default::default()
        }));

        for name in &removes {
            req.remove_header(name);
        }

        assert!(req.headers.get("x-secret").is_none());
    }

    #[test]
    fn test_request_header_remove_then_add_replaces() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "old").unwrap();

        let mutation = Some(crate::types::HeaderMutation {
            add: [("x-version".into(), "new".into())].into(),
            remove: vec!["x-version".into()],
            ..Default::default()
        });
        let (adds, removes) = parse_header_mutations(&mutation);

        // Remove first, then add (same order as upstream_request_filter)
        for name in &removes {
            req.remove_header(name);
        }
        for (name, value) in &adds {
            req.insert_header(name.clone(), value).unwrap();
        }

        assert_eq!(req.headers.get("x-version").unwrap(), "new");
    }

    #[test]
    fn test_response_header_add_applied() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();

        let (adds, _) = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: [("x-request-id".into(), "abc-123".into())].into(),
            remove: vec![],
            ..Default::default()
        }));

        for (name, value) in &adds {
            resp.insert_header(name.clone(), value).unwrap();
        }

        assert_eq!(resp.headers.get("x-request-id").unwrap(), "abc-123");
    }

    #[test]
    fn test_response_header_remove_applied() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("server", "internal-v2").unwrap();
        assert!(resp.headers.get("server").is_some());

        let (_, removes) = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: Default::default(),
            remove: vec!["server".into()],
            ..Default::default()
        }));

        for name in &removes {
            resp.remove_header(name);
        }

        assert!(resp.headers.get("server").is_none());
    }

    #[test]
    fn test_multiple_headers_add_and_remove() {
        let mut req = pingora_http::RequestHeader::build("POST", b"/api", None).unwrap();
        req.insert_header("x-old", "remove-me").unwrap();
        req.insert_header("x-legacy", "also-remove").unwrap();

        let mutation = Some(crate::types::HeaderMutation {
            add: [
                ("x-trace-id".into(), "trace-1".into()),
                ("x-env".into(), "prod".into()),
            ]
            .into(),
            remove: vec!["x-old".into(), "x-legacy".into()],
            ..Default::default()
        });
        let (adds, removes) = parse_header_mutations(&mutation);

        for name in &removes {
            req.remove_header(name);
        }
        for (name, value) in &adds {
            req.insert_header(name.clone(), value).unwrap();
        }

        assert!(req.headers.get("x-old").is_none());
        assert!(req.headers.get("x-legacy").is_none());
        assert_eq!(req.headers.get("x-trace-id").unwrap(), "trace-1");
        assert_eq!(req.headers.get("x-env").unwrap(), "prod");
    }

    // -----------------------------------------------------------------------
    // Multi-dimensional matching tests (Gateway API Core)
    // -----------------------------------------------------------------------

    fn make_path_route_with_method(path: &str, match_type: PathMatchType, method: http::Method) -> PathRoute {
        let mut route = make_path_route(path, match_type);
        route.method_match = Some(method);
        route
    }

    fn make_path_route_with_headers(
        path: &str,
        match_type: PathMatchType,
        header_matches: Vec<HeaderMatchEntry>,
    ) -> PathRoute {
        let mut route = make_path_route(path, match_type);
        route.header_matches = header_matches;
        route
    }

    fn make_path_route_with_query(
        path: &str,
        match_type: PathMatchType,
        query_matches: Vec<QueryParamMatchEntry>,
    ) -> PathRoute {
        let mut route = make_path_route(path, match_type);
        route.query_param_matches = query_matches;
        route
    }

    #[test]
    fn match_request_header_match_returns_route_when_header_present() {
        let route = make_path_route_with_headers(
            "/api",
            PathMatchType::Prefix,
            vec![HeaderMatchEntry {
                name: HeaderName::from_static("x-custom"),
                value: "expected-value".to_string(),
                match_type: HeaderMatchType::Exact,
            }],
        );
        let routes = make_host_routes(vec![route], None);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("expected-value"));

        let matched = routes.match_request("/api/test", &http::Method::GET, &headers, None);
        assert!(matched.is_some(), "should match when header is present with correct value");
    }

    #[test]
    fn match_request_header_match_rejects_when_header_missing() {
        let route = make_path_route_with_headers(
            "/api",
            PathMatchType::Prefix,
            vec![HeaderMatchEntry {
                name: HeaderName::from_static("x-custom"),
                value: "expected-value".to_string(),
                match_type: HeaderMatchType::Exact,
            }],
        );
        let routes = make_host_routes(vec![route], None);

        let headers = http::HeaderMap::new();
        let matched = routes.match_request("/api/test", &http::Method::GET, &headers, None);
        assert!(matched.is_none(), "should NOT match when required header is missing");
    }

    #[test]
    fn match_request_header_match_rejects_wrong_value() {
        let route = make_path_route_with_headers(
            "/api",
            PathMatchType::Prefix,
            vec![HeaderMatchEntry {
                name: HeaderName::from_static("x-custom"),
                value: "expected-value".to_string(),
                match_type: HeaderMatchType::Exact,
            }],
        );
        let routes = make_host_routes(vec![route], None);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("wrong-value"));

        let matched = routes.match_request("/api/test", &http::Method::GET, &headers, None);
        assert!(matched.is_none(), "should NOT match when header has wrong value");
    }

    #[test]
    fn match_request_method_match_returns_route_for_correct_method() {
        let route = make_path_route_with_method("/api", PathMatchType::Prefix, http::Method::GET);
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request("/api/test", &http::Method::GET, &http::HeaderMap::new(), None);
        assert!(matched.is_some(), "should match GET request");
    }

    #[test]
    fn match_request_method_match_rejects_wrong_method() {
        let route = make_path_route_with_method("/api", PathMatchType::Prefix, http::Method::GET);
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request("/api/test", &http::Method::POST, &http::HeaderMap::new(), None);
        assert!(matched.is_none(), "should NOT match POST when route requires GET");
    }

    #[test]
    fn match_request_query_param_match_returns_route_when_param_present() {
        let route = make_path_route_with_query(
            "/api",
            PathMatchType::Prefix,
            vec![QueryParamMatchEntry {
                name: "version".to_string(),
                value: "v2".to_string(),
                match_type: QueryParamMatchType::Exact,
            }],
        );
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request(
            "/api/test",
            &http::Method::GET,
            &http::HeaderMap::new(),
            Some("version=v2&other=foo"),
        );
        assert!(matched.is_some(), "should match when query param is present");
    }

    #[test]
    fn match_request_query_param_match_rejects_when_param_missing() {
        let route = make_path_route_with_query(
            "/api",
            PathMatchType::Prefix,
            vec![QueryParamMatchEntry {
                name: "version".to_string(),
                value: "v2".to_string(),
                match_type: QueryParamMatchType::Exact,
            }],
        );
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request(
            "/api/test",
            &http::Method::GET,
            &http::HeaderMap::new(),
            Some("other=foo"),
        );
        assert!(matched.is_none(), "should NOT match when required query param is missing");
    }

    #[test]
    fn match_request_no_extra_dimensions_behaves_like_match_path() {
        // Route with no header/method/query matches should match just like match_path
        let route = make_path_route("/api", PathMatchType::Prefix);
        let routes = make_host_routes(vec![route], None);

        let matched_old = routes.match_path("/api/test");
        let matched_new = routes.match_request("/api/test", &http::Method::POST, &http::HeaderMap::new(), None);

        assert!(matched_old.is_some());
        assert!(matched_new.is_some());
        assert_eq!(matched_old.unwrap().path.as_ref(), matched_new.unwrap().path.as_ref());
    }

    #[test]
    fn match_request_multiple_header_matches_all_must_pass() {
        let route = make_path_route_with_headers(
            "/api",
            PathMatchType::Prefix,
            vec![
                HeaderMatchEntry {
                    name: HeaderName::from_static("x-first"),
                    value: "a".to_string(),
                    match_type: HeaderMatchType::Exact,
                },
                HeaderMatchEntry {
                    name: HeaderName::from_static("x-second"),
                    value: "b".to_string(),
                    match_type: HeaderMatchType::Exact,
                },
            ],
        );
        let routes = make_host_routes(vec![route], None);

        // Only one header present -- should NOT match
        let mut headers = http::HeaderMap::new();
        headers.insert("x-first", HeaderValue::from_static("a"));
        let matched = routes.match_request("/api", &http::Method::GET, &headers, None);
        assert!(matched.is_none(), "should NOT match with only one of two required headers");

        // Both headers present -- should match
        headers.insert("x-second", HeaderValue::from_static("b"));
        let matched = routes.match_request("/api", &http::Method::GET, &headers, None);
        assert!(matched.is_some(), "should match with both required headers");
    }

    // -----------------------------------------------------------------------
    // Redirect and URL rewrite tests
    // -----------------------------------------------------------------------

    #[test]
    fn has_redirect_returns_true_when_set() {
        let mut route = make_path_route("/old", PathMatchType::Prefix);
        route.redirect = Some(RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("new.example.com".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 301,
        });
        assert!(route.has_redirect());
    }

    #[test]
    fn has_redirect_returns_false_when_not_set() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert!(!route.has_redirect());
    }

    #[test]
    fn rewrite_path_full_replace() {
        let mut route = make_path_route("/old", PathMatchType::Prefix);
        route.url_rewrite = Some(UrlRewriteConfig {
            hostname: None,
            path: Some("/new/path".to_string()),
            path_type: "ReplaceFullPath".to_string(),
        });
        assert_eq!(route.rewrite_path("/old/anything"), Some("/new/path".to_string()));
    }

    #[test]
    fn rewrite_path_prefix_replace() {
        let mut route = make_path_route("/old", PathMatchType::Prefix);
        route.url_rewrite = Some(UrlRewriteConfig {
            hostname: None,
            path: Some("/new".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        });
        assert_eq!(route.rewrite_path("/old/sub/path"), Some("/new/sub/path".to_string()));
    }

    #[test]
    fn rewrite_path_returns_none_when_not_set() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert!(route.rewrite_path("/api/test").is_none());
    }

    #[test]
    fn rewrite_hostname_returns_value_when_set() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.url_rewrite = Some(UrlRewriteConfig {
            hostname: Some(Arc::from("new-host.example.com")),
            path: None,
            path_type: String::new(),
        });
        assert_eq!(route.rewrite_hostname().map(|s| s.as_ref()), Some("new-host.example.com"));
    }

    #[test]
    fn rewrite_hostname_returns_none_when_not_set() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert!(route.rewrite_hostname().is_none());
    }

    // -----------------------------------------------------------------------
    // Extended HTTPRoute: Regex matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn regex_path_matches_valid_pattern() {
        let re = regex::Regex::new(r"^/api/v[0-9]+").unwrap();
        let route = make_path_route("", PathMatchType::RegularExpression(re));
        let routes = make_host_routes(vec![route], None);
        assert!(routes.match_path("/api/v1/users").is_some());
        assert!(routes.match_path("/api/v2").is_some());
        assert!(routes.match_path("/web/page").is_none());
    }

    #[test]
    fn regex_path_no_match() {
        let re = regex::Regex::new(r"^/api/v[0-9]+").unwrap();
        let route = make_path_route("", PathMatchType::RegularExpression(re));
        let routes = make_host_routes(vec![route], None);
        assert!(routes.match_path("/web/page").is_none());
        assert!(routes.match_path("/different").is_none());
    }

    #[test]
    fn regex_header_matches_valid_pattern() {
        let re = regex::Regex::new(r"^Bearer .+$").unwrap();
        let mut route = make_path_route("/", PathMatchType::Prefix);
        route.header_matches = vec![HeaderMatchEntry {
            name: http::header::AUTHORIZATION,
            value: String::new(), // value unused for regex
            match_type: HeaderMatchType::RegularExpression(re),
        }];
        let routes = make_host_routes(vec![route], None);

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, "Bearer mytoken123".parse().unwrap());
        assert!(routes.match_request("/", &http::Method::GET, &headers, None).is_some());

        let mut bad_headers = http::HeaderMap::new();
        bad_headers.insert(http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(routes.match_request("/", &http::Method::GET, &bad_headers, None).is_none());
    }

    #[test]
    fn regex_path_and_header_combined() {
        let path_re = regex::Regex::new(r"^/api/v[0-9]+").unwrap();
        let header_re = regex::Regex::new(r"^v[0-9]+\.[0-9]+$").unwrap();
        let mut route = make_path_route("", PathMatchType::RegularExpression(path_re));
        route.header_matches = vec![HeaderMatchEntry {
            name: HeaderName::from_static("x-api-version"),
            value: String::new(),
            match_type: HeaderMatchType::RegularExpression(header_re),
        }];
        let routes = make_host_routes(vec![route], None);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-version", "v1.0".parse().unwrap());
        // Both match
        assert!(routes.match_request("/api/v1/users", &http::Method::GET, &headers, None).is_some());

        // Path matches but header doesn't
        let mut bad_headers = http::HeaderMap::new();
        bad_headers.insert("x-api-version", "latest".parse().unwrap());
        assert!(routes.match_request("/api/v1/users", &http::Method::GET, &bad_headers, None).is_none());

        // Header matches but path doesn't
        assert!(routes.match_request("/web/page", &http::Method::GET, &headers, None).is_none());
    }

    // -----------------------------------------------------------------------
    // Extended HTTPRoute: Weighted backend selection tests
    // -----------------------------------------------------------------------

    fn make_weighted_backend(name: &str, port: u16, weight: u32) -> WeightedBackendEntry {
        WeightedBackendEntry {
            service_name: Arc::from(name),
            port,
            weight,
            request_headers_add: Arc::new(Vec::new()),
            request_headers_set: Arc::new(Vec::new()),
            request_headers_remove: Arc::new(Vec::new()),
        }
    }

    #[test]
    fn weighted_backend_distributes_proportionally() {
        // Reset the global counter for deterministic testing
        reset_weight_counter();

        let backends = vec![
            make_weighted_backend("svc-a", 80, 3),
            make_weighted_backend("svc-b", 80, 2),
            make_weighted_backend("svc-c", 80, 1),
        ];

        let mut counts: HashMap<&str, u32> = HashMap::new();
        for _ in 0..6 {
            let selected = select_weighted_backend(&backends, 0).unwrap();
            *counts.entry(selected.service_name.as_ref()).or_default() += 1;
        }

        assert_eq!(counts.get("svc-a"), Some(&3), "svc-a should get 3 of 6");
        assert_eq!(counts.get("svc-b"), Some(&2), "svc-b should get 2 of 6");
        assert_eq!(counts.get("svc-c"), Some(&1), "svc-c should get 1 of 6");
    }

    #[test]
    fn weighted_backend_single_backend() {
        reset_weight_counter();
        let backends = vec![
            make_weighted_backend("only-svc", 8080, 1),
        ];
        let selected = select_weighted_backend(&backends, 0).unwrap();
        assert_eq!(selected.service_name.as_ref(), "only-svc");
        assert_eq!(selected.port, 8080);
    }

    #[test]
    fn weighted_backend_equal_weights() {
        let backends = vec![
            make_weighted_backend("svc-a", 80, 1),
            make_weighted_backend("svc-b", 80, 1),
        ];
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for _ in 0..4 {
            let selected = select_weighted_backend(&backends, 0).unwrap();
            *counts.entry(selected.service_name.as_ref()).or_default() += 1;
        }
        assert_eq!(counts["svc-a"], counts["svc-b"], "equal weights should distribute evenly over full cycles");
    }

    #[test]
    fn weighted_backend_zero_weight_never_selected() {
        // Conformance: GRPCRouteWeight has v1(70), v2(30), v3(0).
        // v3 with weight=0 should NEVER receive traffic.
        let backends = vec![
            make_weighted_backend("svc-a", 80, 70),
            make_weighted_backend("svc-b", 80, 30),
            make_weighted_backend("svc-c", 80, 0),
        ];

        let mut counts: HashMap<&str, u32> = HashMap::new();
        // Run enough iterations to cover multiple full cycles
        for _ in 0..1000 {
            let selected = select_weighted_backend(&backends, 0).unwrap();
            *counts.entry(selected.service_name.as_ref()).or_default() += 1;
        }

        assert_eq!(
            counts.get("svc-c").copied().unwrap_or(0),
            0,
            "weight=0 backend should never be selected"
        );
        assert!(counts["svc-a"] > 0, "svc-a should receive traffic");
        assert!(counts["svc-b"] > 0, "svc-b should receive traffic");
        // Check approximate ratio: 70:30 over 1000 requests
        let ratio = counts["svc-a"] as f64 / counts["svc-b"] as f64;
        assert!(
            (1.5..3.5).contains(&ratio),
            "svc-a/svc-b ratio should be ~2.33 (70:30), got {:.2}",
            ratio
        );
    }

    // -----------------------------------------------------------------------
    // Extended HTTPRoute: PathRoute new fields tests
    // -----------------------------------------------------------------------

    #[test]
    fn path_route_new_fields_default_none() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert!(route.mirror_backends.is_empty());
        assert!(route.weighted_backends.is_empty());
        assert!(route.request_timeout.is_none());
        assert!(route.backend_request_timeout.is_none());
    }

    #[test]
    fn path_route_mirror_backend_set() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.mirror_backends = vec![(Arc::from("mirror-svc"), 8080, 0)];
        let (svc, port, percent) = &route.mirror_backends[0];
        assert_eq!(svc.as_ref(), "mirror-svc");
        assert_eq!(*port, 8080);
        assert_eq!(*percent, 0);
    }

    #[test]
    fn path_route_multiple_mirrors() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.mirror_backends = vec![
            (Arc::from("mirror-svc-1"), 8080, 0),
            (Arc::from("mirror-svc-2"), 9090, 50),
        ];
        assert_eq!(route.mirror_backends.len(), 2);
        assert_eq!(route.mirror_backends[0].0.as_ref(), "mirror-svc-1");
        assert_eq!(route.mirror_backends[1].0.as_ref(), "mirror-svc-2");
        assert_eq!(route.mirror_backends[1].2, 50);
    }

    #[test]
    fn path_route_percentage_mirror() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.mirror_backends = vec![(Arc::from("mirror-svc"), 8080, 20)];
        let (_, _, percent) = &route.mirror_backends[0];
        assert_eq!(*percent, 20);
    }

    #[test]
    fn path_route_timeouts_set() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.request_timeout = Some(Duration::from_secs(30));
        route.backend_request_timeout = Some(Duration::from_secs(10));
        assert_eq!(route.request_timeout, Some(Duration::from_secs(30)));
        assert_eq!(route.backend_request_timeout, Some(Duration::from_secs(10)));
    }

    // --- OR match semantics data plane tests ---

    #[test]
    fn test_header_only_route_rejects_without_headers() {
        // A prefix "/" route with header matches should NOT match a request
        // without those headers.
        let mut route = make_path_route("/", PathMatchType::Prefix);
        route.header_matches = vec![HeaderMatchEntry {
            name: http::header::HeaderName::from_static("color"),
            value: "blue".to_string(),
            match_type: HeaderMatchType::Exact,
        }];
        let routes = make_host_routes(vec![route], None);

        // Request without the header -> should NOT match
        let empty_headers = http::HeaderMap::new();
        assert!(
            routes.match_request("/", &http::Method::GET, &empty_headers, None).is_none(),
            "route with header requirement should not match request without that header"
        );

        // Request WITH the header -> should match
        let mut headers = http::HeaderMap::new();
        headers.insert("color", http::HeaderValue::from_static("blue"));
        assert!(
            routes.match_request("/", &http::Method::GET, &headers, None).is_some(),
            "route with header requirement should match request with matching header"
        );
    }

    #[test]
    fn test_or_routes_match_independently() {
        // Two prefix "/" routes under same host, each with different header
        // requirement — request with either header should match the right one.
        let mut route_blue = make_path_route("/", PathMatchType::Prefix);
        route_blue.service_name = Arc::from("blue-svc");
        route_blue.header_matches = vec![HeaderMatchEntry {
            name: http::header::HeaderName::from_static("color"),
            value: "blue".to_string(),
            match_type: HeaderMatchType::Exact,
        }];

        let mut route_green = make_path_route("/", PathMatchType::Prefix);
        route_green.service_name = Arc::from("green-svc");
        route_green.header_matches = vec![HeaderMatchEntry {
            name: http::header::HeaderName::from_static("color"),
            value: "green".to_string(),
            match_type: HeaderMatchType::Exact,
        }];

        let routes = make_host_routes(vec![route_blue, route_green], None);

        // Blue header -> blue-svc
        let mut blue_headers = http::HeaderMap::new();
        blue_headers.insert("color", http::HeaderValue::from_static("blue"));
        let matched = routes.match_request("/", &http::Method::GET, &blue_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "blue-svc");

        // Green header -> green-svc
        let mut green_headers = http::HeaderMap::new();
        green_headers.insert("color", http::HeaderValue::from_static("green"));
        let matched = routes.match_request("/", &http::Method::GET, &green_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "green-svc");

        // No header -> no match
        let empty_headers = http::HeaderMap::new();
        assert!(
            routes.match_request("/", &http::Method::GET, &empty_headers, None).is_none(),
            "no header should not match either route"
        );
    }

    // -----------------------------------------------------------------------
    // Domain wildcard matching tests (Issue 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_wildcard_single_level() {
        // foo.bar.com should match wildcard for ".bar.com"
        let mut map = HashMap::new();
        map.insert(
            ".bar.com".to_string(),
            make_host_routes(vec![make_path_route("/", PathMatchType::Prefix)], None),
        );
        let result = lookup_domain_wildcard("foo.bar.com", &map);
        assert!(result.is_some(), "foo.bar.com should match wildcard .bar.com");
    }

    #[test]
    fn test_domain_wildcard_multi_level() {
        // a.b.bar.com should match wildcard for ".bar.com" by iterating dot positions
        let mut map = HashMap::new();
        map.insert(
            ".bar.com".to_string(),
            make_host_routes(vec![make_path_route("/", PathMatchType::Prefix)], None),
        );
        let result = lookup_domain_wildcard("a.b.bar.com", &map);
        assert!(result.is_some(), "a.b.bar.com should match wildcard .bar.com");
    }

    #[test]
    fn test_domain_wildcard_apex_no_match() {
        // bar.com should NOT match wildcard for ".bar.com"
        // (apex domain is not a subdomain of the wildcard)
        let mut map = HashMap::new();
        map.insert(
            ".bar.com".to_string(),
            make_host_routes(vec![make_path_route("/", PathMatchType::Prefix)], None),
        );
        let result = lookup_domain_wildcard("bar.com", &map);
        assert!(result.is_none(), "bar.com (apex) should NOT match wildcard .bar.com");
    }

    #[test]
    fn test_exact_host_takes_precedence_over_wildcard() {
        // When both exact "foo.bar.com" and wildcard ".bar.com" exist,
        // exact lookup in the route map should find "foo.bar.com" first,
        // and the wildcard map should never be consulted.
        // We simulate this by having both maps populated and checking that
        // exact map lookup returns a different service than wildcard.
        let mut exact_map: HashMap<String, HostRoutes> = HashMap::new();
        let mut exact_route = make_path_route("/", PathMatchType::Prefix);
        exact_route.service_name = Arc::from("exact-svc");
        exact_map.insert(
            "foo.bar.com".to_string(),
            make_host_routes(vec![exact_route], None),
        );

        let mut wildcard_map: HashMap<String, HostRoutes> = HashMap::new();
        let mut wildcard_route = make_path_route("/", PathMatchType::Prefix);
        wildcard_route.service_name = Arc::from("wildcard-svc");
        wildcard_map.insert(
            ".bar.com".to_string(),
            make_host_routes(vec![wildcard_route], None),
        );

        // Exact lookup should find the exact entry
        let exact_result = exact_map.get("foo.bar.com");
        assert!(exact_result.is_some(), "exact map should have foo.bar.com");
        let matched = exact_result.unwrap().match_path("/").unwrap();
        assert_eq!(matched.service_name.as_ref(), "exact-svc");

        // If exact misses, wildcard should match a different host
        let wc_result = lookup_domain_wildcard("other.bar.com", &wildcard_map);
        assert!(wc_result.is_some());
        let wc_matched = wc_result.unwrap().match_path("/").unwrap();
        assert_eq!(wc_matched.service_name.as_ref(), "wildcard-svc");
    }

    #[test]
    fn test_domain_wildcard_most_specific_wins() {
        // When both ".bar.com" and ".sub.bar.com" are in the map,
        // "x.sub.bar.com" should match ".sub.bar.com" (found first since
        // lookup_domain_wildcard iterates from the leftmost dot).
        let mut map = HashMap::new();
        let mut general_route = make_path_route("/", PathMatchType::Prefix);
        general_route.service_name = Arc::from("general-svc");
        map.insert(
            ".bar.com".to_string(),
            make_host_routes(vec![general_route], None),
        );

        let mut specific_route = make_path_route("/", PathMatchType::Prefix);
        specific_route.service_name = Arc::from("specific-svc");
        map.insert(
            ".sub.bar.com".to_string(),
            make_host_routes(vec![specific_route], None),
        );

        let result = lookup_domain_wildcard("x.sub.bar.com", &map);
        assert!(result.is_some());
        let matched = result.unwrap().match_path("/").unwrap();
        assert_eq!(
            matched.service_name.as_ref(),
            "specific-svc",
            "should match more specific wildcard .sub.bar.com"
        );
    }

    // -----------------------------------------------------------------------
    // Host header port stripping test (Issue 2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_host_header_port_stripping() {
        // Verify the port-stripping logic: "host:port" -> "host"
        let raw_host = "very.specific.com:1234";
        let host = raw_host.split(':').next().unwrap_or(raw_host);
        assert_eq!(host, "very.specific.com");

        // No port case
        let raw_host2 = "very.specific.com";
        let host2 = raw_host2.split(':').next().unwrap_or(raw_host2);
        assert_eq!(host2, "very.specific.com");

        // IPv6-style (just verifying split behavior — real IPv6 handling is separate)
        let raw_host3 = "[::1]:8080";
        let host3 = raw_host3.split(':').next().unwrap_or(raw_host3);
        // Note: this gives "[" for IPv6, which is expected to be handled differently
        assert_eq!(host3, "[");
    }

    #[test]
    fn test_exact_path_not_affected_by_prefix_with_headers() {
        // An exact "/one" route + a prefix "/" route with headers.
        // Request to "/one" matches exact. Request to "/" without headers -> 404.
        let exact_route = make_path_route("/one", PathMatchType::Exact);

        let mut prefix_with_header = make_path_route("/", PathMatchType::Prefix);
        prefix_with_header.service_name = Arc::from("header-svc");
        prefix_with_header.header_matches = vec![HeaderMatchEntry {
            name: http::header::HeaderName::from_static("x-test"),
            value: "yes".to_string(),
            match_type: HeaderMatchType::Exact,
        }];

        // exact rules first, then prefix rules (as build_route_map would sort)
        let routes = make_host_routes(vec![exact_route, prefix_with_header], None);

        // Request to /one -> exact match (no headers needed)
        let empty_headers = http::HeaderMap::new();
        let matched = routes.match_request("/one", &http::Method::GET, &empty_headers, None).unwrap();
        assert_eq!(matched.path.as_ref(), "/one");

        // Request to / without headers -> no match (prefix "/" requires header)
        assert!(
            routes.match_request("/", &http::Method::GET, &empty_headers, None).is_none(),
            "prefix / with header requirement should not match without the header"
        );

        // Request to / with header -> matches
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("yes"));
        let matched = routes.match_request("/", &http::Method::GET, &headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "header-svc");
    }

    // -----------------------------------------------------------------------
    // Helper: build redirect Location header (mirrors request_filter logic)
    // -----------------------------------------------------------------------

    /// Reproduces the Location header construction from request_filter so we
    /// can unit-test it without a live Pingora session.
    /// `original_scheme` and `original_port` simulate the listener context.
    fn build_redirect_location(
        redirect: &RedirectConfig,
        route_path: &str,        // the PathRoute.path (matched prefix)
        request_path: &str,      // the original request path
        request_host: &str,      // the Host header from the request
    ) -> String {
        build_redirect_location_full(redirect, route_path, request_path, request_host, "http", 80)
    }

    fn build_redirect_location_full(
        redirect: &RedirectConfig,
        route_path: &str,
        request_path: &str,
        request_host: &str,
        original_scheme: &str,
        original_port: u16,
    ) -> String {
        let mut location = String::new();

        let effective_scheme = redirect.scheme.as_deref().unwrap_or(original_scheme);
        location.push_str(effective_scheme);
        location.push_str("://");

        if let Some(ref hostname) = redirect.hostname {
            location.push_str(hostname);
        } else {
            location.push_str(request_host);
        }

        // Port logic mirrors request_filter:
        // - Explicit redirect port → use it
        // - Scheme changing (explicit) → default to new scheme's standard port (omit)
        // - Scheme preserved → carry original listener port
        let effective_port = if let Some(p) = redirect.port {
            Some(p)
        } else if redirect.scheme.is_some() {
            None
        } else {
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
                    if let Some(suffix) = request_path.strip_prefix(route_path) {
                        location.push_str(redir_path);
                        if !redir_path.ends_with('/') && !suffix.starts_with('/') && !suffix.is_empty() {
                            location.push('/');
                        }
                        location.push_str(suffix);
                    } else {
                        location.push_str(redir_path);
                    }
                }
                _ => location.push_str(request_path),
            }
        } else {
            location.push_str(request_path);
        }

        location
    }

    /// Helper: build a PathRoute with a RedirectConfig
    fn make_redirect_route(
        path: &str,
        match_type: PathMatchType,
        redirect: RedirectConfig,
    ) -> PathRoute {
        let mut route = make_path_route(path, match_type);
        route.redirect = Some(redirect);
        route
    }

    /// Helper: build a PathRoute with a UrlRewriteConfig
    fn make_rewrite_route(
        path: &str,
        match_type: PathMatchType,
        rewrite: UrlRewriteConfig,
    ) -> PathRoute {
        let mut route = make_path_route(path, match_type);
        route.url_rewrite = Some(rewrite);
        route
    }

    // =======================================================================
    // Conformance: HTTPRouteRedirectHostAndStatus
    // Gateway API: redirect with hostname only -> 302, hostname + status -> 301
    // =======================================================================

    #[test]
    fn conformance_redirect_hostname_only_defaults_to_302() {
        // YAML: /hostname-redirect -> requestRedirect { hostname: example.org }
        // Go test expects: status 302, Location host = example.org
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/hostname-redirect", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 302);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/hostname-redirect",
            "/hostname-redirect",
            "original.example.com",
        );
        // Should contain example.org as host, preserve original path
        assert!(location.contains("example.org"), "Location should contain redirect host");
        assert!(location.ends_with("/hostname-redirect"), "Location should preserve path");
        assert_eq!(location, "http://example.org/hostname-redirect");
    }

    #[test]
    fn conformance_redirect_host_and_status_301() {
        // YAML: /host-and-status -> requestRedirect { hostname: example.org, statusCode: 301 }
        // Go test expects: status 301, Location host = example.org
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 301,
        };
        let route = make_redirect_route("/host-and-status", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/host-and-status",
            "/host-and-status",
            "original.example.com",
        );
        assert_eq!(location, "http://example.org/host-and-status");
    }

    // =======================================================================
    // Conformance: HTTPRouteRedirectPath
    // Gateway API: ReplacePrefixMatch preserves suffix, ReplaceFullPath replaces all
    // =======================================================================

    #[test]
    fn conformance_redirect_path_replace_prefix_preserves_suffix() {
        // YAML: /original-prefix -> ReplacePrefixMatch /replacement-prefix
        // Request: /original-prefix/lemon -> Location path = /replacement-prefix/lemon
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/replacement-prefix".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
            status_code: 302,
        };
        let route = make_redirect_route("/original-prefix", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/original-prefix",
            "/original-prefix/lemon",
            "gateway.example.com",
        );
        assert!(location.contains("/replacement-prefix/lemon"),
            "Expected /replacement-prefix/lemon in Location, got: {}", location);
    }

    #[test]
    fn conformance_redirect_path_replace_full() {
        // YAML: /full -> ReplaceFullPath /full-path-replacement
        // Request: /full/path/original -> Location path = /full-path-replacement
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/full-path-replacement".to_string()),
            path_type: "ReplaceFullPath".to_string(),
            status_code: 302,
        };
        let route = make_redirect_route("/full", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/full",
            "/full/path/original",
            "gateway.example.com",
        );
        assert!(location.ends_with("/full-path-replacement"),
            "Expected Location to end with /full-path-replacement, got: {}", location);
    }

    #[test]
    fn conformance_redirect_path_and_host() {
        // YAML: /path-and-host -> hostname: example.org, ReplacePrefixMatch /replacement-prefix
        // Go test expects: host = example.org, path = /replacement-prefix
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: Some("/replacement-prefix".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
            status_code: 302,
        };
        let route = make_redirect_route("/path-and-host", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/path-and-host",
            "/path-and-host",
            "gateway.example.com",
        );
        assert_eq!(location, "http://example.org/replacement-prefix");
    }

    #[test]
    fn conformance_redirect_path_and_status_301() {
        // YAML: /path-and-status -> ReplacePrefixMatch /replacement-prefix, statusCode: 301
        // Go test expects: status 301, path = /replacement-prefix
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/replacement-prefix".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
            status_code: 301,
        };
        let route = make_redirect_route("/path-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/path-and-status",
            "/path-and-status",
            "gateway.example.com",
        );
        assert!(location.ends_with("/replacement-prefix"),
            "Expected path /replacement-prefix, got: {}", location);
    }

    #[test]
    fn conformance_redirect_full_path_and_host() {
        // YAML: /full-path-and-host -> hostname: example.org, ReplaceFullPath /replacement-full
        // Go test expects: host = example.org, path = /replacement-full
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: Some("/replacement-full".to_string()),
            path_type: "ReplaceFullPath".to_string(),
            status_code: 302,
        };
        let route = make_redirect_route("/full-path-and-host", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/full-path-and-host",
            "/full-path-and-host",
            "gateway.example.com",
        );
        assert_eq!(location, "http://example.org/replacement-full");
    }

    #[test]
    fn conformance_redirect_full_path_and_status_301() {
        // YAML: /full-path-and-status -> ReplaceFullPath /replacement-full, statusCode: 301
        // Go test expects: status 301, path = /replacement-full
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/replacement-full".to_string()),
            path_type: "ReplaceFullPath".to_string(),
            status_code: 301,
        };
        let route = make_redirect_route("/full-path-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/full-path-and-status",
            "/full-path-and-status",
            "gateway.example.com",
        );
        assert!(location.ends_with("/replacement-full"),
            "Expected path /replacement-full, got: {}", location);
    }

    // =======================================================================
    // Conformance: HTTPRouteRedirectPort
    // Gateway API: port redirect appears in Location header
    // =======================================================================

    #[test]
    fn conformance_redirect_port_only() {
        // YAML: /port -> requestRedirect { port: 8083 }
        // Go test expects: status 302, Location port = 8083
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: Some(8083),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/port", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/port",
            "/port",
            "gateway.example.com",
        );
        assert_eq!(location, "http://gateway.example.com:8083/port");
    }

    #[test]
    fn conformance_redirect_port_and_host() {
        // YAML: /port-and-host -> hostname: example.org, port: 8083
        // Go test expects: status 302, host = example.org, port = 8083
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: Some(8083),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/port-and-host", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/port-and-host",
            "/port-and-host",
            "gateway.example.com",
        );
        assert_eq!(location, "http://example.org:8083/port-and-host");
    }

    #[test]
    fn conformance_redirect_port_and_status_301() {
        // YAML: /port-and-status -> port: 8083, statusCode: 301
        // Go test expects: status 301, port = 8083
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: Some(8083),
            path: None,
            path_type: String::new(),
            status_code: 301,
        };
        let route = make_redirect_route("/port-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/port-and-status",
            "/port-and-status",
            "gateway.example.com",
        );
        assert!(location.contains(":8083"), "Expected port 8083 in Location, got: {}", location);
    }

    #[test]
    fn conformance_redirect_port_and_host_and_status() {
        // YAML: /port-and-host-and-status -> hostname: example.org, port: 8083, statusCode: 302
        // Go test expects: status 302, host = example.org, port = 8083
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: Some(8083),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/port-and-host-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 302);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/port-and-host-and-status",
            "/port-and-host-and-status",
            "gateway.example.com",
        );
        assert_eq!(location, "http://example.org:8083/port-and-host-and-status");
    }

    // =======================================================================
    // Conformance: HTTPRouteRedirectScheme
    // Gateway API: scheme redirect (http -> https)
    // =======================================================================

    #[test]
    fn conformance_redirect_scheme_only() {
        // YAML: /scheme -> requestRedirect { scheme: https }
        // Go test expects: status 302, scheme = https
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: None,
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/scheme",
            "/scheme",
            "gateway.example.com",
        );
        assert!(location.starts_with("https://"),
            "Expected https scheme, got: {}", location);
        assert_eq!(location, "https://gateway.example.com/scheme");
    }

    #[test]
    fn conformance_redirect_scheme_and_host() {
        // YAML: /scheme-and-host -> scheme: https, hostname: example.org
        // Go test expects: status 302, scheme = https, host = example.org
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-and-host", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/scheme-and-host",
            "/scheme-and-host",
            "gateway.example.com",
        );
        assert_eq!(location, "https://example.org/scheme-and-host");
    }

    #[test]
    fn conformance_redirect_scheme_and_status_301() {
        // YAML: /scheme-and-status -> scheme: https, statusCode: 301
        // Go test expects: status 301, scheme = https
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: None,
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 301,
        };
        let route = make_redirect_route("/scheme-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/scheme-and-status",
            "/scheme-and-status",
            "gateway.example.com",
        );
        assert!(location.starts_with("https://"), "Expected https scheme, got: {}", location);
    }

    #[test]
    fn conformance_redirect_scheme_and_host_and_status() {
        // YAML: /scheme-and-host-and-status -> scheme: https, hostname: example.org, statusCode: 302
        // Go test expects: status 302, scheme = https, host = example.org
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-and-host-and-status", PathMatchType::Prefix, redirect);
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 302);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/scheme-and-host-and-status",
            "/scheme-and-host-and-status",
            "gateway.example.com",
        );
        assert_eq!(location, "https://example.org/scheme-and-host-and-status");
    }

    // =======================================================================
    // Conformance: HTTPRouteRewriteHost
    // Gateway API: URL rewrite hostname is passed to upstream
    // =======================================================================

    #[test]
    fn conformance_rewrite_host_one() {
        // YAML: /one -> urlRewrite { hostname: one.example.org }
        // Go test expects: upstream sees Host: one.example.org, path unchanged /one
        let rewrite = UrlRewriteConfig {
            hostname: Some(Arc::from("one.example.org")),
            path: None,
            path_type: String::new(),
        };
        let route = make_rewrite_route("/one", PathMatchType::Prefix, rewrite);

        assert!(!route.has_redirect(), "rewrite route should not be a redirect");
        assert_eq!(route.rewrite_hostname().map(|s| s.as_ref()), Some("one.example.org"));
        assert_eq!(route.rewrite_path("/one"), None, "no path rewrite configured");
    }

    #[test]
    fn conformance_rewrite_host_two() {
        // YAML: catch-all -> urlRewrite { hostname: example.org }
        // Go test expects: upstream sees Host: example.org, path unchanged /two
        let rewrite = UrlRewriteConfig {
            hostname: Some(Arc::from("example.org")),
            path: None,
            path_type: String::new(),
        };
        let route = make_rewrite_route("/", PathMatchType::Prefix, rewrite);

        assert_eq!(route.rewrite_hostname().map(|s| s.as_ref()), Some("example.org"));
        assert_eq!(route.rewrite_path("/two"), None);
    }

    #[test]
    fn conformance_rewrite_host_and_modify_headers() {
        // YAML: /rewrite-host-and-modify-headers -> urlRewrite { hostname: test.example.org }
        // Go test expects: upstream sees Host: test.example.org
        // (header modification is tested elsewhere; we verify hostname rewrite)
        let rewrite = UrlRewriteConfig {
            hostname: Some(Arc::from("test.example.org")),
            path: None,
            path_type: String::new(),
        };
        let route = make_rewrite_route("/rewrite-host-and-modify-headers", PathMatchType::Prefix, rewrite);
        assert_eq!(route.rewrite_hostname().map(|s| s.as_ref()), Some("test.example.org"));
    }

    // =======================================================================
    // Conformance: HTTPRouteRewritePath
    // Gateway API: URL rewrite path (prefix and full)
    // =======================================================================

    #[test]
    fn conformance_rewrite_path_prefix_one_two() {
        // YAML: /prefix/one -> ReplacePrefixMatch /one
        // Request: /prefix/one/two -> backend sees /one/two
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/one".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        };
        let route = make_rewrite_route("/prefix/one", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/prefix/one/two");
        assert_eq!(result, Some("/one/two".to_string()));
    }

    #[test]
    fn conformance_rewrite_path_strip_prefix_with_suffix() {
        // YAML: /strip-prefix -> ReplacePrefixMatch /
        // Request: /strip-prefix/three -> backend sees /three
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        };
        let route = make_rewrite_route("/strip-prefix", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/strip-prefix/three");
        assert_eq!(result, Some("/three".to_string()));
    }

    #[test]
    fn conformance_rewrite_path_strip_prefix_exact() {
        // YAML: /strip-prefix -> ReplacePrefixMatch /
        // Request: /strip-prefix -> backend sees /
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        };
        let route = make_rewrite_route("/strip-prefix", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/strip-prefix");
        assert_eq!(result, Some("/".to_string()));
    }

    #[test]
    fn conformance_rewrite_path_full_replace() {
        // YAML: /full/one -> ReplaceFullPath /one
        // Request: /full/one/two -> backend sees /one
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/one".to_string()),
            path_type: "ReplaceFullPath".to_string(),
        };
        let route = make_rewrite_route("/full/one", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/full/one/two");
        assert_eq!(result, Some("/one".to_string()));
    }

    #[test]
    fn conformance_rewrite_path_full_with_headers() {
        // YAML: /full/rewrite-path-and-modify-headers -> ReplaceFullPath /test
        // Request: /full/rewrite-path-and-modify-headers/test -> backend sees /test
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/test".to_string()),
            path_type: "ReplaceFullPath".to_string(),
        };
        let route = make_rewrite_route("/full/rewrite-path-and-modify-headers", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/full/rewrite-path-and-modify-headers/test");
        assert_eq!(result, Some("/test".to_string()));
    }

    #[test]
    fn conformance_rewrite_path_prefix_with_headers() {
        // YAML: /prefix/rewrite-path-and-modify-headers -> ReplacePrefixMatch /prefix
        // Request: /prefix/rewrite-path-and-modify-headers/one -> backend sees /prefix/one
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/prefix".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        };
        let route = make_rewrite_route("/prefix/rewrite-path-and-modify-headers", PathMatchType::Prefix, rewrite);

        let result = route.rewrite_path("/prefix/rewrite-path-and-modify-headers/one");
        assert_eq!(result, Some("/prefix/one".to_string()));
    }

    // =======================================================================
    // has_redirect() edge cases
    // =======================================================================

    #[test]
    fn has_redirect_returns_false_for_plain_route() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert!(!route.has_redirect());
    }

    #[test]
    fn has_redirect_returns_false_for_rewrite_route() {
        let rewrite = UrlRewriteConfig {
            hostname: Some(Arc::from("example.org")),
            path: None,
            path_type: String::new(),
        };
        let route = make_rewrite_route("/api", PathMatchType::Prefix, rewrite);
        assert!(!route.has_redirect());
    }

    #[test]
    fn has_redirect_returns_true_for_redirect_route() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/api", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
    }

    // =======================================================================
    // rewrite_path() edge cases
    // =======================================================================

    #[test]
    fn rewrite_path_returns_none_when_no_rewrite() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert_eq!(route.rewrite_path("/api/foo"), None);
    }

    #[test]
    fn rewrite_path_returns_none_when_no_path_in_rewrite() {
        let rewrite = UrlRewriteConfig {
            hostname: Some(Arc::from("example.org")),
            path: None,
            path_type: String::new(),
        };
        let route = make_rewrite_route("/api", PathMatchType::Prefix, rewrite);
        assert_eq!(route.rewrite_path("/api/foo"), None);
    }

    #[test]
    fn rewrite_path_unknown_type_returns_none() {
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/new".to_string()),
            path_type: "UnknownType".to_string(),
        };
        let route = make_rewrite_route("/api", PathMatchType::Prefix, rewrite);
        assert_eq!(route.rewrite_path("/api/foo"), None);
    }

    #[test]
    fn rewrite_path_prefix_no_match_falls_back() {
        // If original_path doesn't start with the route prefix, returns just the new_path
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/new".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
        };
        let route = make_rewrite_route("/api", PathMatchType::Prefix, rewrite);
        assert_eq!(route.rewrite_path("/other/foo"), Some("/new".to_string()));
    }

    // =======================================================================
    // rewrite_hostname() edge cases
    // =======================================================================

    #[test]
    fn rewrite_hostname_returns_none_when_no_rewrite() {
        let route = make_path_route("/api", PathMatchType::Prefix);
        assert_eq!(route.rewrite_hostname(), None);
    }

    #[test]
    fn rewrite_hostname_returns_none_when_no_hostname() {
        let rewrite = UrlRewriteConfig {
            hostname: None,
            path: Some("/new".to_string()),
            path_type: "ReplaceFullPath".to_string(),
        };
        let route = make_rewrite_route("/api", PathMatchType::Prefix, rewrite);
        assert_eq!(route.rewrite_hostname(), None);
    }

    // =======================================================================
    // Combined redirect scenarios (scheme + host + port + path)
    // =======================================================================

    #[test]
    fn redirect_all_fields_combined() {
        // Scheme + host + port + full path replacement
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("secure.example.org".to_string()),
            port: Some(8443),
            path: Some("/new-path".to_string()),
            path_type: "ReplaceFullPath".to_string(),
            status_code: 301,
        };
        let route = make_redirect_route("/old", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/old",
            "/old/anything",
            "original.example.com",
        );
        assert_eq!(location, "https://secure.example.org:8443/new-path");
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 301);
    }

    #[test]
    fn redirect_prefix_match_with_scheme_and_port() {
        // Scheme + port + prefix replacement
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: None,
            port: Some(443),
            path: Some("/v2".to_string()),
            path_type: "ReplacePrefixMatch".to_string(),
            status_code: 302,
        };
        let route = make_redirect_route("/v1", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/v1",
            "/v1/users/123",
            "api.example.com",
        );
        // Port 443 is default for https, so it should be omitted
        assert_eq!(location, "https://api.example.com/v2/users/123");
    }

    #[test]
    fn redirect_no_path_preserves_original_request_path() {
        // No path config -> original path is preserved
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/any", PathMatchType::Prefix, redirect);

        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/any",
            "/any/deep/path",
            "original.com",
        );
        assert_eq!(location, "https://example.org/any/deep/path");
    }

    // =======================================================================
    // Conformance: HTTPRouteRedirectPortAndScheme
    // Tests that port/scheme redirect interacts correctly with listener context.
    // =======================================================================

    #[test]
    fn conformance_redirect_port_and_scheme_listener_80_nil_nil() {
        // Listener port 80: scheme=nil, port=nil -> http://example.org/... (port 80 omitted)
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-nil",
            "/scheme-nil-and-port-nil",
            "gateway.example.com",
            "http",
            80,
        );
        assert_eq!(location, "http://example.org/scheme-nil-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_80_nil_8080() {
        // Listener port 80: scheme=nil, port=8080 -> http://example.org:8080/...
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: Some(8080),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-8080", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-8080",
            "/scheme-nil-and-port-8080",
            "gateway.example.com",
            "http",
            80,
        );
        assert_eq!(location, "http://example.org:8080/scheme-nil-and-port-8080");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_80_https_nil() {
        // Listener port 80: scheme=https, port=nil -> https://example.org/... (no port, scheme default)
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-https-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-https-and-port-nil",
            "/scheme-https-and-port-nil",
            "gateway.example.com",
            "http",
            80,
        );
        assert_eq!(location, "https://example.org/scheme-https-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_8080_nil_nil() {
        // Listener port 8080: scheme=nil, port=nil -> http://example.org:8080/... (non-default)
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-nil",
            "/scheme-nil-and-port-nil",
            "gateway.example.com",
            "http",
            8080,
        );
        assert_eq!(location, "http://example.org:8080/scheme-nil-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_8080_nil_80() {
        // Listener port 8080: scheme=nil, port=80 -> http://example.org/... (port 80 is default)
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: Some(80),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-80", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-80",
            "/scheme-nil-and-port-80",
            "gateway.example.com",
            "http",
            8080,
        );
        assert_eq!(location, "http://example.org/scheme-nil-and-port-80");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_8080_https_nil() {
        // Listener port 8080: scheme=https, port=nil -> https://example.org/... (scheme changes, default port)
        let redirect = RedirectConfig {
            scheme: Some("https".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-https-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-https-and-port-nil",
            "/scheme-https-and-port-nil",
            "gateway.example.com",
            "http",
            8080,
        );
        assert_eq!(location, "https://example.org/scheme-https-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_443_nil_nil() {
        // HTTPS listener port 443: scheme=nil, port=nil -> https://example.org/... (default omitted)
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-nil",
            "/scheme-nil-and-port-nil",
            "gateway.example.com",
            "https",
            443,
        );
        assert_eq!(location, "https://example.org/scheme-nil-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_443_nil_8443() {
        // HTTPS listener port 443: scheme=nil, port=8443 -> https://example.org:8443/...
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: Some(8443),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-8443", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-8443",
            "/scheme-nil-and-port-8443",
            "gateway.example.com",
            "https",
            443,
        );
        assert_eq!(location, "https://example.org:8443/scheme-nil-and-port-8443");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_443_http_nil() {
        // HTTPS listener port 443: scheme=http, port=nil -> http://example.org/... (scheme changes)
        let redirect = RedirectConfig {
            scheme: Some("http".to_string()),
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-http-and-port-nil", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-http-and-port-nil",
            "/scheme-http-and-port-nil",
            "gateway.example.com",
            "https",
            443,
        );
        assert_eq!(location, "http://example.org/scheme-http-and-port-nil");
    }

    #[test]
    fn conformance_redirect_port_and_scheme_listener_443_http_8080() {
        // HTTPS listener port 443: scheme=http, port=8080 -> http://example.org:8080/...
        let redirect = RedirectConfig {
            scheme: Some("http".to_string()),
            hostname: Some("example.org".to_string()),
            port: Some(8080),
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-http-and-port-8080", PathMatchType::Prefix, redirect);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-http-and-port-8080",
            "/scheme-http-and-port-8080",
            "gateway.example.com",
            "https",
            443,
        );
        assert_eq!(location, "http://example.org:8080/scheme-http-and-port-8080");
    }

    // =======================================================================
    // Listener scheme/port resolution
    //
    // HTTPS connections are handed to Pingora on the original :443 socket, so
    // the local port is the listener port. The scheme comes from the socket's
    // TLS state, with :443 defaulting to https.
    // =======================================================================

    #[test]
    fn https_listener_redirect_preserves_https_443() {
        // On the HTTPS listener (port 443), redirect with scheme=nil, port=nil
        // produces "https://example.org/..." with no explicit port.
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/scheme-nil-and-port-nil", PathMatchType::Prefix, redirect);
        let (effective_scheme, effective_port) = listener_scheme_and_port(443, true);
        let location = build_redirect_location_full(
            route.redirect.as_ref().unwrap(),
            "/scheme-nil-and-port-nil",
            "/scheme-nil-and-port-nil",
            "gateway.example.com",
            effective_scheme,
            effective_port,
        );
        assert_eq!(location, "https://example.org/scheme-nil-and-port-nil");
    }

    #[test]
    fn listener_scheme_and_port_follows_socket() {
        assert_eq!(listener_scheme_and_port(443, true), ("https", 443));
        // :443 is HTTPS even if the digest carries no TLS info.
        assert_eq!(listener_scheme_and_port(443, false), ("https", 443));
        assert_eq!(listener_scheme_and_port(80, false), ("http", 80));
        // A TLS socket on a non-default port keeps its real port.
        assert_eq!(listener_scheme_and_port(8443, true), ("https", 8443));
        // No hidden remapping: an arbitrary plaintext port is reported as-is.
        assert_eq!(listener_scheme_and_port(18443, false), ("http", 18443));
    }

    // =======================================================================
    // Redirect route matching via HostRoutes
    // =======================================================================

    #[test]
    fn host_routes_match_returns_redirect_route() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let route = make_redirect_route("/redirect-me", PathMatchType::Prefix, redirect);
        let normal = make_path_route("/api", PathMatchType::Prefix);
        let routes = make_host_routes(vec![route, normal], None);

        let matched = routes.match_path("/redirect-me/something").unwrap();
        assert!(matched.has_redirect());
        assert_eq!(matched.redirect.as_ref().unwrap().status_code, 302);
        assert_eq!(matched.redirect.as_ref().unwrap().hostname.as_deref(), Some("example.org"));
    }

    // -----------------------------------------------------------------------
    // Extended: 303/307/308 redirect status codes
    // -----------------------------------------------------------------------

    #[test]
    fn conformance_redirect_303_see_other() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 303,
        };
        let route = make_redirect_route("/see-other", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 303);
        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/see-other",
            "/see-other",
            "localhost",
        );
        assert_eq!(location, "http://localhost/see-other");
    }

    #[test]
    fn conformance_redirect_307_temporary() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 307,
        };
        let route = make_redirect_route("/temporary", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 307);
        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/temporary",
            "/temporary",
            "localhost",
        );
        assert_eq!(location, "http://localhost/temporary");
    }

    #[test]
    fn conformance_redirect_308_permanent() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: None,
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 308,
        };
        let route = make_redirect_route("/permanent", PathMatchType::Prefix, redirect);
        assert!(route.has_redirect());
        assert_eq!(route.redirect.as_ref().unwrap().status_code, 308);
        let location = build_redirect_location(
            route.redirect.as_ref().unwrap(),
            "/permanent",
            "/permanent",
            "localhost",
        );
        assert_eq!(location, "http://localhost/permanent");
    }

    #[test]
    fn host_routes_match_normal_route_not_redirect() {
        let redirect = RedirectConfig {
            scheme: None,
            hostname: Some("example.org".to_string()),
            port: None,
            path: None,
            path_type: String::new(),
            status_code: 302,
        };
        let redirect_route = make_redirect_route("/redirect-me", PathMatchType::Prefix, redirect);
        let normal = make_path_route("/api", PathMatchType::Prefix);
        let routes = make_host_routes(vec![redirect_route, normal], None);

        let matched = routes.match_path("/api/users").unwrap();
        assert!(!matched.has_redirect());
    }

    // -----------------------------------------------------------------------
    // Header Add (comma-append) vs Set (overwrite) tests — Gateway API conformance
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_header_add_appends_with_comma_when_existing() {
        // Gateway API: `add` should append to existing header value with comma
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-existing", "original").unwrap();

        let (adds, _) = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: [("x-existing".into(), "appended".into())].into(),
            ..Default::default()
        }));

        // Simulate what upstream_request_filter should do for ADD operations:
        // comma-append if header exists, insert if not
        for (name, value) in &adds {
            if let Some(existing) = req.headers.get(name) {
                let new_val = format!("{},{}", existing.to_str().unwrap_or(""), value.to_str().unwrap_or(""));
                req.insert_header(name.clone(), &new_val).unwrap();
            } else {
                req.insert_header(name.clone(), value).unwrap();
            }
        }

        assert_eq!(
            req.headers.get("x-existing").unwrap(),
            "original,appended",
            "add should comma-append to existing header"
        );
    }

    #[test]
    fn test_request_header_add_creates_when_missing() {
        // Gateway API: `add` should create header if it doesn't exist
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        let (adds, _) = parse_header_mutations(&Some(crate::types::HeaderMutation {
            add: [("x-new".into(), "value".into())].into(),
            ..Default::default()
        }));

        for (name, value) in &adds {
            if let Some(existing) = req.headers.get(name) {
                let new_val = format!("{},{}", existing.to_str().unwrap_or(""), value.to_str().unwrap_or(""));
                req.insert_header(name.clone(), &new_val).unwrap();
            } else {
                req.insert_header(name.clone(), value).unwrap();
            }
        }

        assert_eq!(req.headers.get("x-new").unwrap(), "value");
    }

    #[test]
    fn test_request_header_set_overwrites_existing() {
        // Gateway API: `set` should overwrite existing header value
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-existing", "original").unwrap();

        let mutation = Some(crate::types::HeaderMutation {
            set: [("x-existing".into(), "replaced".into())].into(),
            ..Default::default()
        });
        let (_, sets, _) = parse_header_mutations_full(&mutation);

        for (name, value) in &sets {
            req.insert_header(name.clone(), value).unwrap();
        }

        assert_eq!(
            req.headers.get("x-existing").unwrap(),
            "replaced",
            "set should overwrite existing header"
        );
    }

    #[test]
    fn test_header_add_and_set_distinguished() {
        // Both add and set on the same mutation should produce separate vecs
        let mutation = Some(crate::types::HeaderMutation {
            add: [("x-added".into(), "a".into())].into(),
            set: [("x-set".into(), "s".into())].into(),
            remove: vec!["x-remove".into()],
        });
        let (adds, sets, removes) = parse_header_mutations_full(&mutation);

        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].0.as_str(), "x-added");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].0.as_str(), "x-set");
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].as_str(), "x-remove");
    }

    // -----------------------------------------------------------------------
    // Query param + header combo specificity tests — Gateway API conformance
    // -----------------------------------------------------------------------

    #[test]
    fn test_query_param_specificity_more_params_wins() {
        // Two routes on same path "/": one with 1 query param, one with 2.
        // Request matching both should go to the more specific (2 params) route.
        let route_1qp = {
            let mut r = make_path_route("/", PathMatchType::Prefix);
            r.service_name = Arc::from("v2");
            r.query_param_matches = vec![QueryParamMatchEntry {
                name: "animal".to_string(),
                value: "dolphin".to_string(),
                match_type: QueryParamMatchType::Exact,
            }];
            r
        };
        let route_2qp = {
            let mut r = make_path_route("/", PathMatchType::Prefix);
            r.service_name = Arc::from("v3");
            r.query_param_matches = vec![
                QueryParamMatchEntry {
                    name: "animal".to_string(),
                    value: "dolphin".to_string(),
                    match_type: QueryParamMatchType::Exact,
                },
                QueryParamMatchEntry {
                    name: "color".to_string(),
                    value: "blue".to_string(),
                    match_type: QueryParamMatchType::Exact,
                },
            ];
            r
        };

        // Route order: 2qp before 1qp (more specific first)
        let routes = make_host_routes(vec![route_2qp, route_1qp], None);
        let matched = routes.match_request("/", &http::Method::GET, &http::HeaderMap::new(), Some("animal=dolphin&color=blue"));
        assert_eq!(matched.unwrap().service_name.as_ref(), "v3", "2-param route should match before 1-param route");
    }

    #[test]
    fn test_query_param_with_header_combo_match() {
        // Route requires both query param AND header match (AND logic)
        let mut route = make_path_route("/", PathMatchType::Prefix);
        route.service_name = Arc::from("v2");
        route.query_param_matches = vec![QueryParamMatchEntry {
            name: "animal".to_string(),
            value: "whale".to_string(),
            match_type: QueryParamMatchType::Exact,
        }];
        route.header_matches = vec![HeaderMatchEntry {
            name: HeaderName::from_static("version"),
            value: "one".to_string(),
            match_type: HeaderMatchType::Exact,
        }];

        let plain_route = {
            let mut r = make_path_route("/", PathMatchType::Prefix);
            r.service_name = Arc::from("v1");
            r.query_param_matches = vec![QueryParamMatchEntry {
                name: "animal".to_string(),
                value: "whale".to_string(),
                match_type: QueryParamMatchType::Exact,
            }];
            r
        };

        // Route with header+query should be first (more specific)
        let routes = make_host_routes(vec![route, plain_route], None);

        let mut headers = http::HeaderMap::new();
        headers.insert("version", HeaderValue::from_static("one"));
        let matched = routes.match_request("/", &http::Method::GET, &headers, Some("animal=whale"));
        assert_eq!(matched.unwrap().service_name.as_ref(), "v2", "header+query combo should match");

        // Without header, should fall through to plain route
        let matched2 = routes.match_request("/", &http::Method::GET, &http::HeaderMap::new(), Some("animal=whale"));
        assert_eq!(matched2.unwrap().service_name.as_ref(), "v1", "without header, should match plain query route");
    }

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

    // -----------------------------------------------------------------------
    // Per-route timeout enforcement tests
    // -----------------------------------------------------------------------

    #[test]
    fn request_timeout_sets_read_timeout_when_no_backend_timeout() {
        // When request_timeout is set but backend_request_timeout is not,
        // read_timeout should be set to request_timeout so Pingora enforces it.
        let mut route = make_path_route("/request-timeout", PathMatchType::Prefix);
        route.request_timeout = Some(Duration::from_millis(500));
        route.backend_request_timeout = None;

        // Simulate what request_filter does:
        let mut read_timeout: Option<Duration> = None;
        let mut has_timeout = false;

        if let Some(t) = route.backend_request_timeout {
            read_timeout = Some(t);
            has_timeout = true;
        }
        if let Some(t) = route.request_timeout {
            has_timeout = true;
            match read_timeout {
                Some(existing) if existing <= t => {}
                _ => { read_timeout = Some(t); }
            }
        }

        assert_eq!(read_timeout, Some(Duration::from_millis(500)),
            "request_timeout should become read_timeout when no backend_request_timeout");
        assert!(has_timeout, "has_timeout should be true");
    }

    #[test]
    fn backend_timeout_wins_when_smaller_than_request_timeout() {
        // When both are set and backend_request_timeout < request_timeout,
        // read_timeout should be backend_request_timeout.
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.request_timeout = Some(Duration::from_secs(10));
        route.backend_request_timeout = Some(Duration::from_millis(500));

        let mut read_timeout: Option<Duration> = None;
        let mut has_timeout = false;

        if let Some(t) = route.backend_request_timeout {
            read_timeout = Some(t);
            has_timeout = true;
        }
        if let Some(t) = route.request_timeout {
            has_timeout = true;
            match read_timeout {
                Some(existing) if existing <= t => {}
                _ => { read_timeout = Some(t); }
            }
        }

        assert_eq!(read_timeout, Some(Duration::from_millis(500)),
            "backend_request_timeout should be used when smaller");
        assert!(has_timeout);
    }

    #[test]
    fn request_timeout_wins_when_smaller_than_backend_timeout() {
        // When both are set and request_timeout < backend_request_timeout,
        // read_timeout should be request_timeout.
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.request_timeout = Some(Duration::from_millis(200));
        route.backend_request_timeout = Some(Duration::from_millis(500));

        let mut read_timeout: Option<Duration> = None;
        let mut has_timeout = false;

        if let Some(t) = route.backend_request_timeout {
            read_timeout = Some(t);
            has_timeout = true;
        }
        if let Some(t) = route.request_timeout {
            has_timeout = true;
            match read_timeout {
                Some(existing) if existing <= t => {}
                _ => { read_timeout = Some(t); }
            }
        }

        assert_eq!(read_timeout, Some(Duration::from_millis(200)),
            "request_timeout should be used when smaller than backend_request_timeout");
        assert!(has_timeout);
    }

    #[test]
    fn zero_timeout_means_disabled() {
        // Gateway API: "0s" means timeout is disabled (infinite).
        // Our controller sends 0 for disabled timeouts, and the dataplane
        // only sets Some(..) for values > 0.
        let route = make_path_route("/disable", PathMatchType::Prefix);
        assert!(route.request_timeout.is_none());
        assert!(route.backend_request_timeout.is_none());
        // No timeout means no read_timeout override, no has_timeout flag
    }

    // -----------------------------------------------------------------------
    // CORS helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn cors_origin_exact_match() {
        let origins = vec!["https://www.foo.com".to_string()];
        assert!(cors_origin_matches(&origins, "https://www.foo.com"));
        assert!(!cors_origin_matches(&origins, "https://www.bar.com"));
    }

    #[test]
    fn cors_origin_wildcard_all() {
        let origins = vec!["*".to_string()];
        assert!(cors_origin_matches(&origins, "https://anything.com"));
        assert!(cors_origin_matches(&origins, "https://foo.bar.com:12345"));
    }

    #[test]
    fn cors_origin_wildcard_suffix() {
        let origins = vec!["https://*.bar.com".to_string()];
        assert!(cors_origin_matches(&origins, "https://www.bar.com"));
        assert!(cors_origin_matches(&origins, "https://xpto.www.bar.com"));
        assert!(!cors_origin_matches(&origins, "https://bar.com"));
        assert!(!cors_origin_matches(&origins, "https://foobar.com"));
    }

    #[test]
    fn cors_origin_non_matching_rejected() {
        let origins = vec![
            "https://www.foo.com".to_string(),
            "https://*.bar.com".to_string(),
        ];
        assert!(!cors_origin_matches(&origins, "https://foobar.com"));
    }

    #[test]
    fn cors_allow_origin_value_credentialed_echoes_origin() {
        let cors = CorsConfig {
            allow_origins: vec!["*".to_string()],
            allow_methods: vec![],
            allow_headers: vec![],
            expose_headers: vec![],
            allow_credentials: true,
            max_age: 0,
            max_age_str: Arc::from("0"),
            allow_methods_joined: Arc::from(""),
            allow_headers_joined: Arc::from(""),
            expose_headers_joined: Arc::from(""),
        };
        assert_eq!(cors_allow_origin_value(&cors, "https://foo.com", false), "https://foo.com");
    }

    #[test]
    fn cors_allow_origin_value_non_credentialed_wildcard() {
        let cors = CorsConfig {
            allow_origins: vec!["*".to_string()],
            allow_methods: vec![],
            allow_headers: vec![],
            expose_headers: vec![],
            allow_credentials: false,
            max_age: 0,
            max_age_str: Arc::from("0"),
            allow_methods_joined: Arc::from(""),
            allow_headers_joined: Arc::from(""),
            expose_headers_joined: Arc::from(""),
        };
        assert_eq!(cors_allow_origin_value(&cors, "https://foo.com", false), "*");
        // But with credentials, must echo origin
        assert_eq!(cors_allow_origin_value(&cors, "https://foo.com", true), "https://foo.com");
    }

    #[test]
    fn cors_methods_wildcard_echoes_requested() {
        let methods = vec!["*".to_string()];
        assert_eq!(cors_methods_value(&methods, "*", "POST"), "POST");
    }

    #[test]
    fn cors_methods_specific_list() {
        let methods = vec!["GET".to_string(), "OPTIONS".to_string()];
        assert_eq!(cors_methods_value(&methods, "GET, OPTIONS", "GET"), "GET, OPTIONS");
    }

    #[test]
    fn cors_headers_wildcard_echoes_requested() {
        let headers = vec!["*".to_string()];
        assert_eq!(cors_headers_value(&headers, "*", "x-header-1, x-header-2"), "x-header-1, x-header-2");
    }

    #[test]
    fn cors_headers_specific_list() {
        let headers = vec!["x-header-1".to_string(), "x-header-2".to_string()];
        assert_eq!(cors_headers_value(&headers, "x-header-1, x-header-2", "x-header-1"), "x-header-1, x-header-2");
    }

    // --- CORS bug fix tests ---

    #[test]
    fn cors_allow_origin_with_cookie_echoes_origin_not_wildcard() {
        // Conformance: HTTPRouteCORS credentials test
        // When request has Cookie header and allowCredentials is false but
        // allow_origins contains "*", MUST echo specific origin (not "*").
        // W3C spec: credentialed requests cannot receive "*" as Allow-Origin.
        let cors = CorsConfig {
            allow_origins: vec!["*".to_string()],
            allow_methods: vec!["*".to_string()],
            allow_headers: vec!["*".to_string()],
            expose_headers: vec![],
            allow_credentials: false,
            max_age: 0,
            max_age_str: Arc::from("0"),
            allow_methods_joined: Arc::from("*"),
            allow_headers_joined: Arc::from("*"),
            expose_headers_joined: Arc::from(""),
        };
        // Without credentials: wildcard is OK
        assert_eq!(cors_allow_origin_value(&cors, "https://other.foo.com", false), "*");
        // With credentials (Cookie present): must echo origin
        assert_eq!(cors_allow_origin_value(&cors, "https://other.foo.com", true), "https://other.foo.com");
    }

    #[test]
    fn cors_non_matching_origin_rejected() {
        // Conformance: HTTPRouteCORS non-matching origin preflight
        // When origin doesn't match allow_origins, cors_origin_matches returns false.
        // The router intercepts the preflight and returns bare 200 (no CORS headers).
        let origins = vec!["https://www.foo.com".to_string(), "https://*.bar.com".to_string()];
        assert!(!cors_origin_matches(&origins, "https://foobar.com"));
        assert!(!cors_origin_matches(&origins, "https://evil.com"));
        assert!(!cors_origin_matches(&origins, "https://bar.com")); // apex doesn't match wildcard
    }

    #[test]
    fn cors_allow_origin_with_allow_credentials_true_and_cookie() {
        // When allowCredentials=true AND has credentials, echo origin
        let cors = CorsConfig {
            allow_origins: vec!["https://www.foo.com".to_string()],
            allow_methods: vec![],
            allow_headers: vec![],
            expose_headers: vec![],
            allow_credentials: true,
            max_age: 0,
            max_age_str: Arc::from("0"),
            allow_methods_joined: Arc::from(""),
            allow_headers_joined: Arc::from(""),
            expose_headers_joined: Arc::from(""),
        };
        assert_eq!(cors_allow_origin_value(&cors, "https://www.foo.com", true), "https://www.foo.com");
        assert_eq!(cors_allow_origin_value(&cors, "https://www.foo.com", false), "https://www.foo.com");
    }

    // -----------------------------------------------------------------------
    // Port-specific route lookup tests
    // -----------------------------------------------------------------------

    fn make_named_path_route(path: &str, service_name: &str) -> PathRoute {
        let mut route = make_path_route(path, PathMatchType::Prefix);
        route.service_name = Arc::from(service_name);
        route
    }

    #[test]
    fn test_port_specific_route_lookup() {
        // Build a route map with port-keyed entries and verify different ports
        // return different routes.
        let mut map: HashMap<String, HostRoutes> = HashMap::new();

        map.insert(
            "foo.com:80".to_string(),
            make_host_routes(vec![make_named_path_route("/", "v1")], None),
        );

        map.insert(
            "foo.com:8080".to_string(),
            make_host_routes(vec![make_named_path_route("/", "v2")], None),
        );

        // Lookup "foo.com:80" → v1
        let r80 = map.get("foo.com:80").unwrap().match_path("/").unwrap();
        assert_eq!(r80.service_name.as_ref(), "v1");

        // Lookup "foo.com:8080" → v2
        let r8080 = map.get("foo.com:8080").unwrap().match_path("/").unwrap();
        assert_eq!(r8080.service_name.as_ref(), "v2");

        // They're different routes
        assert_ne!(r80.service_name.as_ref(), r8080.service_name.as_ref());
    }

    #[test]
    fn test_port_specific_fallback_to_plain_host() {
        // When no port-specific entry exists, the router should fall back to plain host.
        // This mirrors request_filter logic: try "host:port" then "host".
        let mut map: HashMap<String, HostRoutes> = HashMap::new();

        map.insert(
            "foo.com".to_string(),
            make_host_routes(vec![make_named_path_route("/", "default-backend")], None),
        );

        // No "foo.com:9999" entry exists → try plain "foo.com"
        let port_key = "foo.com:9999";
        let host = "foo.com";
        let resolved = map.get(port_key).or_else(|| map.get(host));
        assert!(resolved.is_some(), "should fall back to plain host");

        let matched = resolved.unwrap().match_path("/").unwrap();
        assert_eq!(matched.service_name.as_ref(), "default-backend");
    }

    #[test]
    fn test_domain_wildcard_with_port_lookup() {
        // Domain wildcard map has port-qualified keys (from listener_port > 0).
        // lookup_domain_wildcard_with_port should find ".bar.com:80" when port=80.
        let mut map: HashMap<String, HostRoutes> = HashMap::new();
        map.insert(
            ".bar.com:80".to_string(),
            make_host_routes(vec![make_named_path_route("/", "wildcard-v3")], None),
        );

        // baz.bar.com on port 80 → should match .bar.com:80
        let result = lookup_domain_wildcard_with_port("baz.bar.com", 80, &map);
        assert!(result.is_some(), "baz.bar.com:80 should match .bar.com:80");
        assert_eq!(result.unwrap().match_path("/").unwrap().service_name.as_ref(), "wildcard-v3");

        // multi.level.bar.com on port 80 → should also match
        let result = lookup_domain_wildcard_with_port("multi.level.bar.com", 80, &map);
        assert!(result.is_some(), "multi.level.bar.com:80 should match .bar.com:80");

        // baz.bar.com on port 8080 → should NOT match (wrong port)
        let result = lookup_domain_wildcard_with_port("baz.bar.com", 8080, &map);
        assert!(result.is_none(), "baz.bar.com:8080 should not match .bar.com:80");

        // baz.bar.com on port 0 → should NOT match (no plain .bar.com key)
        let result = lookup_domain_wildcard_with_port("baz.bar.com", 0, &map);
        assert!(result.is_none(), "baz.bar.com:0 should not match port-qualified key");
    }

    #[test]
    fn test_domain_wildcard_with_port_falls_back_to_plain() {
        // When both port-qualified and plain wildcard keys exist, port-specific wins.
        // When only plain exists, plain matches regardless of port.
        let mut map: HashMap<String, HostRoutes> = HashMap::new();
        map.insert(
            ".foo.com".to_string(),
            make_host_routes(vec![make_named_path_route("/", "plain-wildcard")], None),
        );
        map.insert(
            ".bar.com:80".to_string(),
            make_host_routes(vec![make_named_path_route("/", "port-wildcard")], None),
        );

        // sub.foo.com on any port → plain .foo.com
        let result = lookup_domain_wildcard_with_port("sub.foo.com", 80, &map);
        assert!(result.is_some());
        assert_eq!(result.unwrap().match_path("/").unwrap().service_name.as_ref(), "plain-wildcard");

        // sub.bar.com on port 80 → port-specific .bar.com:80
        let result = lookup_domain_wildcard_with_port("sub.bar.com", 80, &map);
        assert!(result.is_some());
        assert_eq!(result.unwrap().match_path("/").unwrap().service_name.as_ref(), "port-wildcard");
    }

    // -----------------------------------------------------------------------
    // Phase 11: Policy field storage tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_path_route_stores_ip_allowlist_cidrs() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.ip_allow_cidrs = vec![
            "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
            "192.168.0.0/16".parse::<ipnet::IpNet>().unwrap(),
        ];
        route.ip_deny_cidrs = vec![
            "10.0.0.5/32".parse::<ipnet::IpNet>().unwrap(),
        ];

        assert_eq!(route.ip_allow_cidrs.len(), 2);
        assert_eq!(route.ip_deny_cidrs.len(), 1);
        assert_eq!(
            route.ip_allow_cidrs[0],
            "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()
        );
        assert_eq!(
            route.ip_allow_cidrs[1],
            "192.168.0.0/16".parse::<ipnet::IpNet>().unwrap()
        );
        assert_eq!(
            route.ip_deny_cidrs[0],
            "10.0.0.5/32".parse::<ipnet::IpNet>().unwrap()
        );
    }

    #[test]
    fn test_path_route_stores_body_size_limit() {
        let mut route = make_path_route("/upload", PathMatchType::Prefix);
        route.max_request_body_bytes = 5_242_880; // 5MB

        assert_eq!(route.max_request_body_bytes, 5_242_880);
    }

    #[test]
    fn test_path_route_stores_retry_on() {
        let mut route = make_path_route("/api", PathMatchType::Prefix);
        route.retry_on = Arc::new(vec!["5xx".to_string(), "connect-failure".to_string(), "gateway-error".to_string()]);

        assert_eq!(route.retry_on.len(), 3);
        assert_eq!(route.retry_on[0], "5xx");
        assert_eq!(route.retry_on[1], "connect-failure");
        assert_eq!(route.retry_on[2], "gateway-error");
    }

    #[test]
    fn test_should_retry_status_follows_codes_and_remaining_attempts() {
        // httproute-retry: 500 retried while attempts remain; 503 not in the
        // list is passed through; exhausted attempts pass the error through.
        let codes = [500u16];
        assert!(should_retry_status(500, &codes, 3));
        assert!(should_retry_status(500, &codes, 1));
        assert!(!should_retry_status(500, &codes, 0), "attempts exhausted: the 500 is the answer");
        assert!(!should_retry_status(503, &codes, 3), "503 is not configured");
        assert!(!should_retry_status(200, &[500, 502, 503, 504], 2));
        assert!(should_retry_status(504, &[500, 502, 503, 504], 2));
        assert!(!should_retry_status(500, &[], 5), "no codes: status responses are never retried");
    }

    #[test]
    fn test_path_route_policy_fields_default_empty() {
        let route = make_path_route("/default", PathMatchType::Prefix);

        assert!(route.ip_allow_cidrs.is_empty());
        assert!(route.ip_deny_cidrs.is_empty());
        assert_eq!(route.max_request_body_bytes, 0);
        assert!(route.retry_on.is_empty());
        assert!(route.retry_codes.is_empty());
    }

    #[test]
    fn test_ip_cidrs_in_host_routes_match() {
        // Verify that a PathRoute with IP CIDRs is matchable through HostRoutes
        let mut route = make_path_route("/secure", PathMatchType::Prefix);
        route.ip_allow_cidrs = vec!["172.16.0.0/12".parse::<ipnet::IpNet>().unwrap()];
        route.ip_deny_cidrs = vec!["172.16.5.0/24".parse::<ipnet::IpNet>().unwrap()];

        let host_routes = make_host_routes(vec![route], None);
        let matched = host_routes.match_path("/secure/data").unwrap();
        assert_eq!(matched.ip_allow_cidrs.len(), 1);
        assert_eq!(matched.ip_deny_cidrs.len(), 1);
    }

    // --- SEC-11: extract_client_ip tests ---

    #[test]
    fn test_extract_client_ip_no_trusted_proxies() {
        let peer: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let result = extract_client_ip("5.6.7.8, 9.10.11.12", peer, &[]);
        assert_eq!(result, peer, "empty trusted list should return peer IP");
    }

    #[test]
    fn test_extract_client_ip_peer_not_trusted() {
        let peer: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("5.6.7.8", peer, &trusted);
        assert_eq!(result, peer, "untrusted peer should ignore XFF");
    }

    #[test]
    fn test_extract_client_ip_single_proxy() {
        let peer: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("203.0.113.50", peer, &trusted);
        assert_eq!(result, "203.0.113.50".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_multi_hop() {
        let peer: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("203.0.113.50, 10.0.0.1", peer, &trusted);
        assert_eq!(result, "203.0.113.50".parse::<std::net::IpAddr>().unwrap(),
            "should return first untrusted IP from right");
    }

    #[test]
    fn test_extract_client_ip_spoofed_xff() {
        // Attacker prepends "1.1.1.1" but real client is 203.0.113.50
        let peer: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("1.1.1.1, 203.0.113.50, 10.0.0.1", peer, &trusted);
        assert_eq!(result, "203.0.113.50".parse::<std::net::IpAddr>().unwrap(),
            "spoofed entry should be ignored — rightmost untrusted hop wins");
    }

    #[test]
    fn test_extract_client_ip_all_trusted() {
        let peer: std::net::IpAddr = "10.0.0.3".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("10.0.0.1, 10.0.0.2", peer, &trusted);
        assert_eq!(result, "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
            "all trusted — return leftmost");
    }

    #[test]
    fn test_extract_client_ip_empty_xff() {
        let peer: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("", peer, &trusted);
        assert_eq!(result, peer, "empty XFF should return peer");
    }

    #[test]
    fn test_extract_client_ip_unparseable_entry() {
        // "garbage" is after a trusted IP — walking right-to-left hits the trusted
        // IP first, then encounters garbage and bails to peer.
        let peer: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("garbage, 10.0.0.2", peer, &trusted);
        assert_eq!(result, peer, "unparseable XFF entry should return peer as fallback");
    }

    #[test]
    fn test_extract_client_ip_ipv6() {
        let peer: std::net::IpAddr = "::1".parse().unwrap();
        let trusted = vec!["::1/128".parse::<ipnet::IpNet>().unwrap()];
        let result = extract_client_ip("2001:db8::1", peer, &trusted);
        assert_eq!(result, "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
    }

    // --------------------------------------------------------------------
    // HTTPRouteHTTPSListenerDetectMisdirectedRequests (GEP-1486) — 421
    // detection pure-function matrix. Mirrors the upstream conformance
    // Gateway `same-namespace-with-https-listener` on port 443 with four
    // HTTPS listeners: catch-all "https", exact "second-example.org",
    // wildcard "*.wildcard.org", exact "fourth-example.wildcard.org".
    // --------------------------------------------------------------------

    fn mk_misdirected_bucket(hostname: &str) -> ListenerBucket {
        ListenerBucket {
            listener_hostname: Arc::from(hostname),
            exact: HashMap::new(),
            domain_wildcards: HashMap::new(),
            catch_all: None,
        }
    }

    /// Build the four-listener bucket list in the same specificity-sorted
    /// order that config_receiver produces (exact > wildcard > catch-all).
    fn misdirected_gateway_buckets() -> Vec<ListenerBucket> {
        let mut buckets = vec![
            mk_misdirected_bucket("second-example.org"),
            mk_misdirected_bucket("fourth-example.wildcard.org"),
            mk_misdirected_bucket("*.wildcard.org"),
            mk_misdirected_bucket(""),
        ];
        // Mirror config_receiver: sort by specificity descending.
        buckets.sort_by_key(|b| std::cmp::Reverse(listener_specificity(&b.listener_hostname)));
        buckets
    }

    /// Full 14-case matrix from upstream conformance tests/
    /// httproute-https-listener-detect-misdirected-requests.go.
    #[test]
    fn detect_misdirected_request_matrix() {
        let buckets = misdirected_gateway_buckets();
        let cases: &[(&str, &str, bool, &str)] = &[
            // SNI=example.org → catch-all listener.
            ("example.org", "example.org", false, "same catch-all listener"),
            ("example.org", "second-example.org", true, "Host claimed by second-example.org listener"),
            ("example.org", "unknown-example.org", false, "Host also catch-all → 404 by route miss, not 421"),

            // SNI=second-example.org → exact listener.
            ("second-example.org", "second-example.org", false, "same exact listener"),
            ("second-example.org", "example.org", true, "Host claimed by catch-all → different listener"),
            ("second-example.org", "unknown-example.org", true, "Host catch-all ≠ SNI exact"),

            // SNI=third-example.wildcard.org → wildcard listener.
            ("third-example.wildcard.org", "third-example.wildcard.org", false, "same wildcard listener"),
            ("third-example.wildcard.org", "fith-example.wildcard.org", false, "both claimed by *.wildcard.org"),
            ("third-example.wildcard.org", "fourth-example.wildcard.org", true, "Host claimed by more-specific exact listener"),
            ("third-example.wildcard.org", "second-example.org", true, "Host claimed by different exact listener"),
            ("third-example.wildcard.org", "unknown-example.org", true, "Host catch-all ≠ SNI wildcard"),

            // SNI=fourth-example.wildcard.org → exact listener.
            ("fourth-example.wildcard.org", "fourth-example.wildcard.org", false, "same exact listener"),
            ("fourth-example.wildcard.org", "fith-example.wildcard.org", true, "Host claimed by wildcard listener, SNI claimed by exact"),

            // SNI=unknown-example.org → catch-all listener (SNI matches nothing more specific).
            ("unknown-example.org", "example.org", false, "both catch-all"),
            ("unknown-example.org", "unknown-example.org", false, "both catch-all"),
        ];

        for (sni, host, expect_421, reason) in cases {
            let got = detect_misdirected_request(Some(sni), host, &buckets);
            assert_eq!(
                got, *expect_421,
                "SNI={sni:?} Host={host:?} expected 421={expect_421} ({reason})",
            );
        }
    }

    #[test]
    fn detect_misdirected_request_no_sni_never_misdirects() {
        let buckets = misdirected_gateway_buckets();
        // Plain HTTP or TLS without SNI → never misdirect.
        assert!(!detect_misdirected_request(None, "second-example.org", &buckets));
        assert!(!detect_misdirected_request(None, "example.org", &buckets));
        assert!(!detect_misdirected_request(None, "anything.foo", &buckets));
    }

    #[test]
    fn detect_misdirected_request_no_catch_all_sni_unclaimed() {
        // Gateway without a catch-all listener: SNI that matches no bucket
        // should not emit 421 (fallback cert path, defer to Host routing).
        let buckets = vec![mk_misdirected_bucket("api.example.com")];
        assert!(!detect_misdirected_request(Some("other.example.com"), "other.example.com", &buckets));
    }

    #[test]
    fn detect_misdirected_request_sni_claimed_host_unclaimed() {
        // No catch-all, Host falls outside every listener's scope while SNI is claimed.
        // Treat as 421 so requests for unclaimed Hosts don't bleed into a listener
        // they don't belong to.
        let buckets = vec![mk_misdirected_bucket("api.example.com")];
        assert!(detect_misdirected_request(Some("api.example.com"), "other.example.com", &buckets));
    }
}
