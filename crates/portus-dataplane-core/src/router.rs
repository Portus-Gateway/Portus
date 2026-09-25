use http::{HeaderName, HeaderValue};
use log::warn;
use hashbrown::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::circuit_breaker::{CircuitBreaker, ConnectionLimiter};
use crate::types::*;
use crate::pool::Pool;
use crate::stack::StackCache;
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

/// Scheme and listener port for a request from the socket it arrived on.
/// HTTPS connections reach the stack on the original `:443` socket (handed off by
/// the SNI mux), so the local port is always the listener port; the scheme
/// follows the TLS state of the socket, with `:443` treated as HTTPS even when
/// the digest carries no TLS info.
pub fn listener_scheme_and_port(local_port: u16, is_tls: bool) -> (&'static str, u16) {
    if is_tls || local_port == HTTPS_DEFAULT_PORT {
        ("https", local_port)
    } else {
        ("http", local_port)
    }
}

// ---------------------------------------------------------------------------
// SEC-4: Default request body size limit (10 MB) when no policy is configured.
// ---------------------------------------------------------------------------
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// PERF-1: Static empty Arc singletons — avoids 9 heap allocations per request
// in new_ctx(). All Arc::clone() on these is a single atomic increment.
// ---------------------------------------------------------------------------
pub static EMPTY_HEADER_VEC: LazyLock<Arc<Vec<(HeaderName, HeaderValue)>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
pub static EMPTY_NAME_VEC: LazyLock<Arc<Vec<HeaderName>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
pub static EMPTY_STRING_VEC: LazyLock<Arc<Vec<String>>> =
    LazyLock::new(|| Arc::new(Vec::new()));
pub static EMPTY_CODES: LazyLock<Arc<Vec<u16>>> = LazyLock::new(|| Arc::new(Vec::new()));
pub static EMPTY_SNI: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from(""));

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A weighted backend with optional per-backend request header mutations.
#[derive(Clone)]
pub struct WeightedBackendEntry {
    pub service_name: Arc<str>,
    pub port: u16,
    pub weight: u32,
    pub request_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub request_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub request_headers_remove: Arc<Vec<HeaderName>>,
}

/// Configuration for HTTP redirect responses (3xx).
pub struct RedirectConfig {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub path_type: String,   // ReplaceFullPath or ReplacePrefixMatch
    pub status_code: u16,    // 301, 302, etc.
}

/// Configuration for URL rewriting before proxying.
#[derive(Clone)]
pub struct UrlRewriteConfig {
    pub hostname: Option<Arc<str>>,
    pub path: Option<String>,
    pub path_type: String,
}

/// CORS configuration for handling preflight and simple requests.
#[derive(Clone, Debug)]
pub struct CorsConfig {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: u32,
    // PERF-13: Pre-formatted max_age string to avoid per-request u32::to_string()
    pub max_age_str: Arc<str>,
    // Pre-joined strings for hot-path use (avoids per-request allocations)
    pub allow_methods_joined: Arc<str>,
    pub allow_headers_joined: Arc<str>,
    pub expose_headers_joined: Arc<str>,
}

/// Header match type for multi-dimensional request matching.
#[derive(Clone)]
pub enum HeaderMatchType {
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
pub struct HeaderMatchEntry {
    pub name: HeaderName,
    pub value: String,
    pub match_type: HeaderMatchType,
}

/// Query parameter match type, mirroring HeaderMatchType.
/// RegularExpression holds a pre-compiled regex (built once at config time).
#[derive(Clone)]
pub enum QueryParamMatchType {
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
pub struct QueryParamMatchEntry {
    pub name: String,
    pub value: String,
    pub match_type: QueryParamMatchType,
}

/// A single path rule pointing to a backend.
pub struct PathRoute {
    pub path: Arc<str>,
    pub match_type: PathMatchType,
    pub service_name: Arc<str>,
    pub port: u16,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub rate_limiter: Option<crate::rate_limiter::RateLimiterMode>,
    pub max_retries: u32,
    pub upstream_tls: bool,
    pub upstream_sni: Arc<str>,
    pub upstream_verify: bool,
    pub protocol: BackendProtocol,
    pub request_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub request_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub request_headers_remove: Arc<Vec<HeaderName>>,
    pub response_headers_add: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub response_headers_set: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub response_headers_remove: Arc<Vec<HeaderName>>,
    // Gateway API Core: multi-dimensional matching
    pub header_matches: Vec<HeaderMatchEntry>,
    pub method_match: Option<http::Method>,
    pub query_param_matches: Vec<QueryParamMatchEntry>,
    // Gateway API Core: filters
    pub redirect: Option<RedirectConfig>,
    pub url_rewrite: Option<UrlRewriteConfig>,
    // Listener binding
    pub listener_name: Arc<str>,
    // Extended HTTPRoute: mirror, weighted backends, per-route timeouts
    /// Multiple mirror backends: (service_name, port, percent). percent=0 means mirror all.
    pub mirror_backends: Vec<(Arc<str>, u16, u32)>,
    pub weighted_backends: Vec<WeightedBackendEntry>,
    pub request_timeout: Option<Duration>,
    pub backend_request_timeout: Option<Duration>,
    // Phase 9: Auth config
    pub auth_config: Option<crate::types::AuthConfig>,
    // Phase 10: CORS config
    pub cors: Option<Arc<CorsConfig>>,
    // Phase 11: IP allowlist
    pub ip_allow_cidrs: Vec<ipnet::IpNet>,
    pub ip_deny_cidrs: Vec<ipnet::IpNet>,
    pub ip_trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    // Phase 11: Request body size limit (0 = no limit)
    pub max_request_body_bytes: u64,
    // Phase 11: Retry conditions
    pub retry_on: Arc<Vec<String>>,
    /// HTTPRoute rule `retry.codes`: upstream statuses retried while
    /// `max_retries` attempts remain.
    pub retry_codes: Arc<Vec<u16>>,
    // PERF-8: Embedded circuit breaker and connection limiter (avoids per-request map lookups)
    pub circuit_breaker: Option<Arc<CircuitBreaker>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    // PERF-10: Pre-computed total weight for weighted backend selection
    pub total_weight: u32,
    /// Set when the backend is an AIProvider: usage is read from responses.
    pub ai: Option<AiBackend>,
}

/// The AI provider behind a route, for usage accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiBackend {
    pub dialect: crate::ai::usage::Dialect,
    pub provider: Arc<str>,
    /// Requests must present a valid Portus API key.
    pub key_required: bool,
    /// Token budget from an AIUsagePolicy, enforced with ledger grants.
    pub budget: Option<crate::ai::budget::BudgetPolicy>,
    /// MCP: pin a session (`Mcp-Session-Id`) to the endpoint that created it.
    pub session_affinity: bool,
    /// OAuth bearer tokens accepted in place of a Portus API key.
    pub jwt: Option<crate::ai::jwt::JwtPolicy>,
    /// A trusted caller may name the user it acts for.
    pub on_behalf_of: Option<crate::ai::keys::OnBehalfOf>,
    /// MCP: the federation (`ProxySnapshot::federations` key) this route
    /// fans out to instead of forwarding to one server.
    pub federation: Option<Arc<str>>,
}

impl PathRoute {
    /// Returns true if this route is a redirect (should return 3xx, not proxy).
    #[cfg(test)]
    pub fn has_redirect(&self) -> bool {
        self.redirect.is_some()
    }

    /// Applies URL rewrite to the given path, returning the rewritten path if applicable.
    pub fn rewrite_path(&self, original_path: &str) -> Option<String> {
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
    pub fn rewrite_hostname(&self) -> Option<&Arc<str>> {
        self.url_rewrite.as_ref()?.hostname.as_ref()
    }
}

/// All path routes for a given host, ordered for matching.
pub struct HostRoutes {
    /// Exact path → routes for O(1) lookup. Multiple routes may share a path
    /// (differentiated by headers/method/query).
    pub exact_map: HashMap<Arc<str>, Vec<PathRoute>>,
    /// Prefix rules sorted longest-first for linear scan.
    pub rules: Vec<PathRoute>,
    /// Catch-all when no paths are specified.
    pub catch_all: Option<PathRoute>,
    /// At least one route matches on a request body field
    /// ([`BODY_FIELD_HEADER_PREFIX`]), so a request with a body must be
    /// scanned before it can be matched.
    pub needs_body: bool,
    /// The OAuth policy a route on this host accepts tokens under, served
    /// at `/.well-known/oauth-protected-resource` so MCP clients find the
    /// login.
    pub oauth: Option<crate::ai::jwt::JwtPolicy>,
}

/// The OAuth policy to advertise for a set of routes: the first route with
/// one.
pub fn oauth_of<'a>(routes: impl Iterator<Item = &'a PathRoute>) -> Option<crate::ai::jwt::JwtPolicy> {
    routes.filter_map(|r| r.ai.as_ref()).filter_map(|ai| ai.jwt.as_ref()).next().cloned()
}

/// Header-match names with this prefix are matched against fields the body
/// scanner extracted (`portus-body-model` ↔ the top-level `model` key), never
/// against request headers, so a client cannot forge them.
pub const BODY_FIELD_HEADER_PREFIX: &str = "portus-body-";

/// Body fields the scanner extracts, as (key, value) with the key as it
/// appears in the JSON (`model`, `stream`). Booleans and numbers are their
/// JSON text.
pub type BodyFields = Vec<(&'static str, String)>;

/// Whether any of `matches` needs the body scanned.
pub fn needs_body_fields(matches: &[HeaderMatchEntry]) -> bool {
    matches.iter().any(|hm| hm.name.as_str().starts_with(BODY_FIELD_HEADER_PREFIX))
}

/// Whether a route needs the request body scanned: it matches on a body
/// field, or it forwards to an AI provider at all. An AI route reads the
/// body for the key's allow lists (model, tool), the budget estimate
/// (`max_tokens`), the JSON-RPC id refusals echo and the usage row; a
/// path-only MCP rule that skipped the scan let every tool through and
/// recorded none of them.
pub fn route_needs_body(route: &PathRoute) -> bool {
    route.ai.is_some() || needs_body_fields(&route.header_matches)
}

fn body_field<'a>(body: Option<&'a BodyFields>, header_name: &str) -> Option<&'a str> {
    let key = header_name.strip_prefix(BODY_FIELD_HEADER_PREFIX)?;
    body?.iter().find(|(k, _)| *k == key).map(|(_, v)| v.as_str())
}

/// Read access to a request's headers, whatever type the network stack uses
/// for them. `http::HeaderMap` implements it; a stack with its own header
/// type wraps it in a newtype.
pub trait RequestHeaders {
    /// First value of `name` (case-insensitive), as bytes.
    fn get(&self, name: &str) -> Option<&[u8]>;
    fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    /// Every (name, value) pair, in order.
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8]));
}

impl RequestHeaders for http::HeaderMap {
    fn get(&self, name: &str) -> Option<&[u8]> {
        http::HeaderMap::get(self, name).map(|v| v.as_bytes())
    }
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) {
        for (name, value) in self.iter() {
            f(name.as_str(), value.as_bytes());
        }
    }
}

/// First value of `name` as UTF-8, if present and valid.
pub fn header_str<'h>(headers: &'h (impl RequestHeaders + ?Sized), name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|v| std::str::from_utf8(v).ok())
}

impl HostRoutes {
    /// Find an existing rate limiter for a path/type/rps combo (for reuse across rebuilds).
    pub fn find_rate_limiter(
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
    pub fn match_path(&self, request_path: &str) -> Option<&PathRoute> {
        // Backward-compatible convenience: match by path only (no header/method/query checks).
        self.match_request(request_path, "GET", &http::HeaderMap::new(), None)
    }

    /// Multi-dimensional request matching: path + method + headers + query params.
    /// Returns the first route where ALL dimensions match. Routes that match
    /// on body fields never match here; see [`Self::match_request_with_body`].
    pub fn match_request(
        &self,
        request_path: &str,
        method: &str,
        headers: &(impl RequestHeaders + ?Sized),
        query: Option<&str>,
    ) -> Option<&PathRoute> {
        self.match_request_with_body(request_path, method, headers, query, None)
    }

    /// [`Self::match_request`] with the fields the body scanner extracted;
    /// `None` when the request has no body or it was not scanned.
    pub fn match_request_with_body(
        &self,
        request_path: &str,
        method: &str,
        headers: &(impl RequestHeaders + ?Sized),
        query: Option<&str>,
        body: Option<&BodyFields>,
    ) -> Option<&PathRoute> {
        // O(1) exact path lookup
        if let Some(exact_routes) = self.exact_map.get(request_path) {
            for rule in exact_routes {
                if self.extra_dimensions_match(rule, method, headers, query, body) {
                    return Some(rule);
                }
            }
        }

        // Prefix rules (sorted longest-first)
        for rule in &self.rules {
            if self.path_matches(rule, request_path)
                && self.extra_dimensions_match(rule, method, headers, query, body)
            {
                return Some(rule);
            }
        }
        // Check catch-all with extra dimensions too
        if let Some(ref ca) = self.catch_all
            && self.extra_dimensions_match(ca, method, headers, query, body) {
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
        method: &str,
        headers: &(impl RequestHeaders + ?Sized),
        query: Option<&str>,
        body: Option<&BodyFields>,
    ) -> bool {
        // Method match: if rule specifies a method, it must match
        if let Some(ref required_method) = rule.method_match
            && method != required_method.as_str() {
                return false;
            }

        // Header matches: ALL must match (AND logic per Gateway API spec).
        // Body-field matches read the scanner's fields, never the headers.
        for hm in &rule.header_matches {
            let actual = if hm.name.as_str().starts_with(BODY_FIELD_HEADER_PREFIX) {
                body_field(body, hm.name.as_str()).map(str::as_bytes)
            } else {
                headers.get(hm.name.as_str())
            };
            match actual {
                Some(v) => {
                    let val_str = std::str::from_utf8(v).unwrap_or("");
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
    // worker walks its own counter, so the proportional distribution
    // holds per thread without a globally shared atomic that every worker
    // would bounce between cores on every request.
    static WEIGHT_COUNTER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Reset the current thread's weighted-backend counter (tests only).
#[cfg(test)]
pub fn reset_weight_counter() {
    WEIGHT_COUNTER.with(|c| c.set(0));
}

/// Select a backend from weighted list using deterministic round-robin.
/// Distributes proportionally: weights [3, 2, 1] over 6 calls = 3 to A, 2 to B, 1 to C.
/// Returns a reference to the selected WeightedBackendEntry.
pub fn select_weighted_backend(backends: &[WeightedBackendEntry], precomputed_total: u32) -> Option<&WeightedBackendEntry> {
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
pub fn extract_client_ip(
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

pub fn spawn_mirror_request(
    mirror_service: &Arc<str>,
    mirror_port: u16,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(String, String)],
    lbs: &HashMap<(Arc<str>, u16), Arc<Pool>>,
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

    let Some(backend) = lb.select() else {
        warn!("no ready endpoints for mirror backend {}:{}", mirror_service, mirror_port);
        return;
    };

    let addr_str = backend.to_string();
    let method = method.to_string();
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

// ---------------------------------------------------------------------------
// PERF-9: ProxySnapshot — bundles all per-request config maps into a single
// ArcSwap to reduce atomic operations (one load instead of 4-6 per request).
// ---------------------------------------------------------------------------

/// All per-request config maps bundled into a single atomic snapshot.
/// One `ArcSwap::load()` (2-3 atomics) replaces 4-6 separate loads (8-18 atomics).
/// BackendTLS configuration from BackendTLSPolicy, stored per (service, port).
/// CA certs are parsed to DER at config build time (not per-request); the
/// network stack keeps its own view in `stack`.
pub struct BackendTlsInfo {
    pub ca_certs_der: Arc<Vec<Vec<u8>>>,
    pub hostname: Arc<str>,
    /// SubjectAltNames from BackendTLSPolicy for additional cert validation.
    /// Empty = no additional SAN checks (only hostname verification).
    pub subject_alt_names: Arc<Vec<(String, String)>>, // (type, value)
    pub stack: StackCache,
}

/// The client certificate this data plane presents to TLS backends
/// (Gateway `spec.tls.backend.clientCertificateRef`): DER chain and DER key.
/// The network stack keeps its own view in `stack`.
pub struct ClientIdentity {
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub stack: StackCache,
}

impl ClientIdentity {
    pub fn new(cert_chain_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Self {
        Self { cert_chain_der, key_der, stack: StackCache::default() }
    }
}

impl Drop for ClientIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_der.zeroize();
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity").field("certs", &self.cert_chain_der.len()).finish_non_exhaustive()
    }
}

impl std::fmt::Debug for BackendTlsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendTlsInfo")
            .field("hostname", &self.hostname)
            .field("ca_certs_count", &self.ca_certs_der.len())
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
pub struct ListenerBucket {
    pub listener_hostname: Arc<str>,
    /// Exact route host → HostRoutes (e.g. "foo.example.com").
    pub exact: HashMap<String, HostRoutes>,
    /// Route-host wildcard suffix → HostRoutes (e.g. ".example.com" for "*.example.com").
    pub domain_wildcards: HashMap<String, HostRoutes>,
    /// Route host "*" catch-all within this listener.
    pub catch_all: Option<HostRoutes>,
}

pub struct ProxySnapshot {
    /// Listener buckets indexed by listener port. Each inner vector is pre-sorted
    /// by listener hostname specificity, most specific first, so the first bucket
    /// whose hostname matches the request host claims it.
    pub listeners_by_port: HashMap<u16, Vec<ListenerBucket>>,
    /// Buckets for routes compiled with listener_port=0 (no port scoping).
    /// Consulted when no port-specific bucket claims the request.
    pub any_port_listeners: Vec<ListenerBucket>,
    pub lbs: HashMap<(Arc<str>, u16), Arc<Pool>>,
    pub circuit_breakers: HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>,
    pub connection_limiters: HashMap<(Arc<str>, u16), Arc<ConnectionLimiter>>,
    /// SEC F-2: Collected per-IP rate limiters for background eviction.
    /// Populated at config-build time; the eviction task iterates these periodically.
    pub per_ip_limiters: Vec<Arc<crate::rate_limiter::PerIpRateLimiter>>,
    /// BackendTLSPolicy: per-backend TLS config for proxy-to-backend connections.
    /// `Arc` so `request_filter` can cache a handle in `RouterCtx` without cloning
    /// the CA bundle.
    pub backend_tls: HashMap<(Arc<str>, u16), Arc<BackendTlsInfo>>,
    /// Client certificate this data plane's Gateway presents to TLS backends
    /// (`spec.tls.backend.clientCertificateRef`).
    pub backend_client_cert: Option<Arc<ClientIdentity>>,
    /// Fingerprint of the endpoint set + health-check config each `LoadBalancer`
    /// was built from. `apply_config` reuses the existing `LoadBalancer` (and its
    /// health state) when the signature is unchanged.
    pub lb_signatures: HashMap<(Arc<str>, u16), u64>,
    /// MCP federations by namespace/name; routes point at them by
    /// `AiBackend::federation`.
    pub federations: HashMap<Arc<str>, Arc<crate::ai::federation::Federation>>,
    /// Every budget policy in the config (with fallback overflow counters),
    /// declared to the ledger so `/v1/limits` lists them before first use.
    pub budget_policies: Vec<crate::ai::budget::BudgetPolicy>,
}

impl Default for ProxySnapshot {
    fn default() -> Self {
        Self {
            listeners_by_port: HashMap::new(),
            any_port_listeners: Vec::new(),
            lbs: HashMap::new(),
            federations: HashMap::new(),
            budget_policies: Vec::new(),
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
pub fn listener_hostname_claims(listener_hostname: &str, host: &str) -> bool {
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
pub fn listener_specificity(listener_hostname: &str) -> u32 {
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
pub fn lookup_domain_wildcard_bucket<'a>(
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
pub fn select_listener_bucket<'a>(
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
pub fn detect_misdirected_request(
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
pub type SnapshotSlot = Arc<ArcSwap<ProxySnapshot>>;

/// Per-(service, port) load balancer, swapped atomically.
/// Keyed by (service_name, port) so multi-port services route correctly.
/// Used by L4 proxy and health check threads (not part of ProxySnapshot path).
pub type ServiceLbMap = Arc<ArcSwap<HashMap<(Arc<str>, u16), Arc<Pool>>>>;

/// Look up a host in a domain-wildcard map by trying every dot-suffix.
///
/// For `a.b.bar.com`, tries `.b.bar.com`, then `.bar.com`, then `.com`.
/// This correctly handles multi-level subdomains matching `*.bar.com`.
/// Returns `None` for apex names (e.g. `bar.com` never matches `*.bar.com`
/// because the first dot yields `.com`, which is not a wildcard key).
#[cfg(test)]
pub fn lookup_domain_wildcard<'a>(
    host: &str,
    map: &'a HashMap<String, HostRoutes>,
) -> Option<&'a HostRoutes> {
    lookup_domain_wildcard_with_port(host, 0, map)
}

/// Port-aware domain wildcard lookup. When `port > 0`, tries port-qualified
/// keys first (e.g. ".bar.com:80") then falls back to plain suffix (".bar.com").
/// This handles routes compiled with non-zero listener_port.
#[cfg(test)]
pub fn lookup_domain_wildcard_with_port<'a>(
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
pub fn should_retry_status(status: u16, retry_codes: &[u16], retries_left: u32) -> bool {
    retries_left > 0 && retry_codes.contains(&status)
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
pub fn cors_origin_matches(allow_origins: &[String], origin: &str) -> bool {
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
pub fn cors_allow_origin_value<'a>(cors: &CorsConfig, origin: &'a str, has_credentials: bool) -> std::borrow::Cow<'a, str> {
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
pub fn cors_methods_value<'a>(allow_methods: &[String], pre_joined: &'a str, requested_method: &'a str) -> &'a str {
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
pub fn cors_headers_value<'a>(allow_headers: &[String], pre_joined: &'a str, requested_headers: &'a str) -> &'a str {
    if allow_headers.is_empty() {
        return "";
    }
    if allow_headers.iter().any(|h| h == "*") {
        // Wildcard: echo the requested headers
        return requested_headers;
    }
    pre_joined
}

/// Parse CRD header mutation config into pre-validated HeaderName/HeaderValue pairs.
/// Invalid names/values are logged at warn level and skipped.
///
/// Legacy version: merges `add` and `set` into a single add list.
/// Use `parse_header_mutations_full` for Gateway API conformance.
#[cfg(test)]
pub fn parse_header_mutations(
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
pub fn parse_header_mutations_full(
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
pub fn build_route_map(
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
                    ai: None,
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
                needs_body: false,
                oauth: None,
            },
        );
    }

    // Extract wildcard routes into separate slot (per CONTEXT.md locked decision).
    let wildcard = route_map.remove("*");

    (route_map, wildcard)
}

/// Route constructors for tests in this crate.
#[cfg(test)]
pub mod test_support {
    use super::*;

    pub fn path_route(path: &str, match_type: PathMatchType) -> PathRoute {
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
            ai: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for a stack's request/response header object in tests that
    /// apply parsed header mutations the way an adapter does.
    #[derive(Default)]
    struct TestHeaders {
        headers: http::HeaderMap,
    }

    impl TestHeaders {
        fn insert_header<N, V>(&mut self, name: N, value: V) -> Result<(), String>
        where
            N: TryInto<HeaderName>,
            V: TryInto<HeaderValue>,
        {
            let name = name.try_into().map_err(|_| "invalid header name".to_string())?;
            let value = value.try_into().map_err(|_| "invalid header value".to_string())?;
            self.headers.insert(name, value);
            Ok(())
        }

        fn remove_header(&mut self, name: &HeaderName) -> Option<HeaderValue> {
            self.headers.remove(name)
        }
    }

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
        super::test_support::path_route(path, match_type)
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
        let needs_body = exact_map.values().flatten().chain(prefix_rules.iter()).chain(catch_all.iter()).any(route_needs_body);
        let oauth = oauth_of(exact_map.values().flatten().chain(prefix_rules.iter()).chain(catch_all.iter()));
        HostRoutes { exact_map, rules: prefix_rules, catch_all, needs_body, oauth }
    }

    #[test]
    fn body_field_matches_read_the_scanned_fields_not_the_headers() {
        let mut opus = make_path_route("/v1/messages", PathMatchType::Exact);
        opus.service_name = Arc::from("opus-provider");
        opus.header_matches = vec![HeaderMatchEntry {
            name: HeaderName::from_static("portus-body-model"),
            value: "claude-opus-5".to_string(),
            match_type: HeaderMatchType::Exact,
        }];
        let mut haiku = make_path_route("/v1/messages", PathMatchType::Exact);
        haiku.service_name = Arc::from("haiku-provider");
        haiku.header_matches = vec![HeaderMatchEntry {
            name: HeaderName::from_static("portus-body-model"),
            value: "^claude-haiku-.*".to_string(),
            match_type: HeaderMatchType::RegularExpression(regex::Regex::new("^claude-haiku-.*").unwrap()),
        }];
        let mut any = make_path_route("/v1/messages", PathMatchType::Exact);
        any.service_name = Arc::from("default-provider");
        let routes = make_host_routes(vec![opus, haiku, any], None);
        assert!(routes.needs_body);

        let mut forged = http::HeaderMap::new();
        forged.insert("portus-body-model", "claude-opus-5".parse().unwrap());
        let svc = |body: Option<&BodyFields>| {
            routes.match_request_with_body("/v1/messages", "POST", &forged, None, body).map(|r| r.service_name.to_string())
        };
        assert_eq!(svc(None), Some("default-provider".into()), "a forged header never matches a body route");
        assert_eq!(svc(Some(&vec![("model", "claude-opus-5".to_string())])), Some("opus-provider".into()));
        assert_eq!(svc(Some(&vec![("model", "claude-haiku-4-5".to_string())])), Some("haiku-provider".into()));
        assert_eq!(svc(Some(&vec![("model", "gpt-5".to_string())])), Some("default-provider".into()));
        assert_eq!(svc(Some(&vec![])), Some("default-provider".into()), "a body without the key skips body routes");
        assert!(!make_host_routes(vec![make_path_route("/", PathMatchType::Prefix)], None).needs_body);
    }

    #[test]
    fn a_path_only_ai_route_still_reads_the_body() {
        // The tool allow list, the budget estimate and the usage row all come
        // from the body; a path-only MCP rule must not skip the scan.
        let mut mcp = make_path_route("/", PathMatchType::Prefix);
        mcp.ai = Some(AiBackend {
            dialect: crate::ai::usage::Dialect::Mcp,
            provider: Arc::from("tools"),
            key_required: true,
            budget: None,
            session_affinity: true,
            jwt: None,
            on_behalf_of: None,
            federation: None,
        });
        assert!(route_needs_body(&mcp));
        assert!(make_host_routes(vec![mcp], None).needs_body);
        assert!(!route_needs_body(&make_path_route("/", PathMatchType::Prefix)), "an ordinary route does not pay for a scan");
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
        let mut req = TestHeaders::default();
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
        let mut req = TestHeaders::default();
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
        let mut req = TestHeaders::default();
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
        let mut resp = TestHeaders::default();

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
        let mut resp = TestHeaders::default();
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
        let mut req = TestHeaders::default();
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

        let matched = routes.match_request("/api/test", "GET", &headers, None);
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
        let matched = routes.match_request("/api/test", "GET", &headers, None);
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

        let matched = routes.match_request("/api/test", "GET", &headers, None);
        assert!(matched.is_none(), "should NOT match when header has wrong value");
    }

    #[test]
    fn match_request_method_match_returns_route_for_correct_method() {
        let route = make_path_route_with_method("/api", PathMatchType::Prefix, http::Method::GET);
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request("/api/test", "GET", &http::HeaderMap::new(), None);
        assert!(matched.is_some(), "should match GET request");
    }

    #[test]
    fn match_request_method_match_rejects_wrong_method() {
        let route = make_path_route_with_method("/api", PathMatchType::Prefix, http::Method::GET);
        let routes = make_host_routes(vec![route], None);

        let matched = routes.match_request("/api/test", "POST", &http::HeaderMap::new(), None);
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
            "GET",
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
            "GET",
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
        let matched_new = routes.match_request("/api/test", "POST", &http::HeaderMap::new(), None);

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
        let matched = routes.match_request("/api", "GET", &headers, None);
        assert!(matched.is_none(), "should NOT match with only one of two required headers");

        // Both headers present -- should match
        headers.insert("x-second", HeaderValue::from_static("b"));
        let matched = routes.match_request("/api", "GET", &headers, None);
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
        assert!(routes.match_request("/", "GET", &headers, None).is_some());

        let mut bad_headers = http::HeaderMap::new();
        bad_headers.insert(http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(routes.match_request("/", "GET", &bad_headers, None).is_none());
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
        assert!(routes.match_request("/api/v1/users", "GET", &headers, None).is_some());

        // Path matches but header doesn't
        let mut bad_headers = http::HeaderMap::new();
        bad_headers.insert("x-api-version", "latest".parse().unwrap());
        assert!(routes.match_request("/api/v1/users", "GET", &bad_headers, None).is_none());

        // Header matches but path doesn't
        assert!(routes.match_request("/web/page", "GET", &headers, None).is_none());
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
            routes.match_request("/", "GET", &empty_headers, None).is_none(),
            "route with header requirement should not match request without that header"
        );

        // Request WITH the header -> should match
        let mut headers = http::HeaderMap::new();
        headers.insert("color", http::HeaderValue::from_static("blue"));
        assert!(
            routes.match_request("/", "GET", &headers, None).is_some(),
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
        let matched = routes.match_request("/", "GET", &blue_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "blue-svc");

        // Green header -> green-svc
        let mut green_headers = http::HeaderMap::new();
        green_headers.insert("color", http::HeaderValue::from_static("green"));
        let matched = routes.match_request("/", "GET", &green_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "green-svc");

        // No header -> no match
        let empty_headers = http::HeaderMap::new();
        assert!(
            routes.match_request("/", "GET", &empty_headers, None).is_none(),
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
        let matched = routes.match_request("/one", "GET", &empty_headers, None).unwrap();
        assert_eq!(matched.path.as_ref(), "/one");

        // Request to / without headers -> no match (prefix "/" requires header)
        assert!(
            routes.match_request("/", "GET", &empty_headers, None).is_none(),
            "prefix / with header requirement should not match without the header"
        );

        // Request to / with header -> matches
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("yes"));
        let matched = routes.match_request("/", "GET", &headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "header-svc");
    }

    // -----------------------------------------------------------------------
    // Helper: build redirect Location header (mirrors request_filter logic)
    // -----------------------------------------------------------------------

    /// Reproduces the Location header construction from request_filter so we
    /// can unit-test it without a live proxy session.
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
    // HTTPS connections are handed to the stack on the original :443 socket, so
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
        let mut req = TestHeaders::default();
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
        let mut req = TestHeaders::default();

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
        let mut req = TestHeaders::default();
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
        let matched = routes.match_request("/", "GET", &http::HeaderMap::new(), Some("animal=dolphin&color=blue"));
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
        let matched = routes.match_request("/", "GET", &headers, Some("animal=whale"));
        assert_eq!(matched.unwrap().service_name.as_ref(), "v2", "header+query combo should match");

        // Without header, should fall through to plain route
        let matched2 = routes.match_request("/", "GET", &http::HeaderMap::new(), Some("animal=whale"));
        assert_eq!(matched2.unwrap().service_name.as_ref(), "v1", "without header, should match plain query route");
    }

    // -----------------------------------------------------------------------
    // Per-route timeout enforcement tests
    // -----------------------------------------------------------------------

    #[test]
    fn request_timeout_sets_read_timeout_when_no_backend_timeout() {
        // When request_timeout is set but backend_request_timeout is not,
        // read_timeout should be set to request_timeout so the stack enforces it.
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
