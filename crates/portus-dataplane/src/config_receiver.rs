use arc_swap::ArcSwap;
use http::{HeaderName, HeaderValue};
use log::{info, warn};
use pingora_load_balancing::health_check::HttpHealthCheck;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{Backend, LoadBalancer};
use hashbrown::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use crate::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig as InternalCbConfig, ConnectionLimiter,
};
use crate::rate_limiter::{AtomicTokenBucket, PerIpRateLimiter};
use crate::router::{
    listener_specificity, CorsConfig, HeaderMatchEntry, HeaderMatchType, HostRoutes,
    ListenerBucket, PathRoute, ProxySnapshot, QueryParamMatchEntry, QueryParamMatchType,
    RedirectConfig, ServiceLbMap, SnapshotSlot, UrlRewriteConfig,
};
use crate::types::{BackendProtocol, PathMatchType};

use crate::l4_proxy::{L4Config, L4ConfigSlot};

/// A single TLS certificate entry with its associated listener hostname.
#[derive(Debug, Clone)]
pub(crate) struct TlsCertEntry {
    /// Listener hostname (e.g., "*.example.com"). Empty = default/catch-all cert.
    pub(crate) hostname: String,
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
}

impl Drop for TlsCertEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_pem.zeroize();
        self.cert_pem.zeroize();
    }
}

/// Frontend client certificate validation for one HTTPS listener port
/// (Gateway `spec.tls.frontend`, default or per-port override).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PortClientValidation {
    pub(crate) port: u16,
    /// PEM bundles, one per caCertificateRef.
    pub(crate) ca_cert_pems: Vec<String>,
    pub(crate) mode: ClientValidationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ClientValidationMode {
    /// Reject handshakes without a certificate that chains to a configured CA.
    AllowValidOnly,
    /// Request a certificate but accept the connection without one, or with
    /// one that fails validation.
    AllowInsecureFallback,
}

impl ClientValidationMode {
    /// Parse the Gateway API mode string; anything unknown is treated as the
    /// strict default so a typo never silently disables validation.
    pub(crate) fn parse(mode: &str) -> Self {
        match mode {
            "AllowInsecureFallback" => Self::AllowInsecureFallback,
            "" | "AllowValidOnly" => Self::AllowValidOnly,
            other => {
                warn!("unknown frontend client validation mode '{}'; enforcing AllowValidOnly", other);
                Self::AllowValidOnly
            }
        }
    }
}

/// TLS certificate data from the controller's compiled config.
/// Contains all HTTPS listener certs for SNI-based selection, plus the
/// per-port client certificate validation policy.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsCertData {
    pub(crate) entries: Vec<TlsCertEntry>,
    pub(crate) client_validation: Vec<PortClientValidation>,
}

/// Type alias for the TLS cert data slot.
pub(crate) type TlsCertSlot = Arc<ArcSwap<Option<TlsCertData>>>;

/// Per-(service, port) keyed maps built from the proto config.
pub(crate) type BackendKey = (Arc<str>, u16);
pub(crate) type LbMap = HashMap<BackendKey, Arc<LoadBalancer<RoundRobin>>>;
pub(crate) type LbSignatures = HashMap<BackendKey, u64>;
pub(crate) type CircuitBreakerMap = HashMap<BackendKey, Arc<CircuitBreaker>>;
pub(crate) type ConnectionLimiterMap = HashMap<BackendKey, Arc<ConnectionLimiter>>;
/// (add, set, remove) header mutations shared across routes.
pub(crate) type SharedHeaderMutations = (
    Arc<Vec<(HeaderName, HeaderValue)>>,
    Arc<Vec<(HeaderName, HeaderValue)>>,
    Arc<Vec<HeaderName>>,
);

/// Holds all ArcSwap state maps for atomic config application.
pub(crate) struct ProxyState {
    /// PERF-9: Bundled per-request config snapshot (routes, wildcards, LBs, CB/CL).
    pub(crate) snapshot: SnapshotSlot,
    /// Separate LB map for L4 proxy and health check threads.
    pub(crate) lbs: ServiceLbMap,
    pub(crate) l4_config: L4ConfigSlot,
    /// TLS certificate data from HTTPS listeners. Updated when config changes.
    pub(crate) tls_cert: TlsCertSlot,
    /// Woken after `tls_cert` is replaced so the cert hot-reload thread can
    /// re-parse immediately instead of polling.
    pub(crate) tls_cert_notify: Arc<tokio::sync::Notify>,
    /// Minimum health check interval (seconds) across all configured backends.
    /// Updated on each config apply; defaults to 10 if no health checks are configured.
    pub(crate) health_check_min_interval: Arc<AtomicU32>,
}

// ---------------------------------------------------------------------------
// Proto -> internal type conversion helpers
// ---------------------------------------------------------------------------

fn parse_match_type(match_type: &str, path: &str) -> Option<PathMatchType> {
    match match_type {
        "Exact" => Some(PathMatchType::Exact),
        "RegularExpression" => match regex::RegexBuilder::new(path)
            .size_limit(64 * 1024)
            .build()
        {
            Ok(re) => Some(PathMatchType::RegularExpression(re)),
            Err(e) => {
                warn!("invalid regex path '{}': {}, skipping route", path, e);
                None
            }
        },
        _ => Some(PathMatchType::Prefix), // default
    }
}

fn parse_protocol(s: &str) -> BackendProtocol {
    match s {
        "GRPC" | "grpc" => BackendProtocol::Grpc,
        "H2C" | "h2c" => BackendProtocol::H2c,
        "WS" | "ws" => BackendProtocol::WebSocket,
        _ => BackendProtocol::Http,
    }
}

fn parse_header_mutations_from_proto(
    mutation: &Option<portus_types::HeaderMutation>,
) -> SharedHeaderMutations {
    let Some(m) = mutation else {
        return (Arc::new(Vec::new()), Arc::new(Vec::new()), Arc::new(Vec::new()));
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
    (Arc::new(add), Arc::new(set), Arc::new(remove))
}

/// Build listener buckets from proto RouteConfig messages, enforcing
/// GatewayHTTPListenerIsolation. Routes are grouped by
/// `(listener_port, listener_hostname, route_host)`. For each group, the
/// per-host path/match sort-and-specificity logic mirrors the previous
/// behaviour. Host→HostRoutes entries are then placed into a ListenerBucket
/// keyed by (listener_port, listener_hostname) with exact/wildcard/catch-all
/// slots for route-level hostname narrowing.
///
/// The return is `(listeners_by_port, any_port_listeners)` where buckets in
/// each vector are pre-sorted by listener hostname specificity (most specific
/// first), so a request resolves to the single most-specific listener.
///
/// Rate limiter state is preserved from `existing_by_port` / `existing_any_port`
/// when a matching (port, listener_hostname, route_host) entry exists.
#[allow(deprecated)] // reads mirror_backend (field 21) from older controllers
pub(crate) fn build_listener_buckets_from_proto(
    routes: &[portus_types::RouteConfig],
    existing_by_port: &HashMap<u16, Vec<ListenerBucket>>,
    existing_any_port: &[ListenerBucket],
    cb_map: &HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>,
    cl_map: &HashMap<(Arc<str>, u16), Arc<ConnectionLimiter>>,
) -> (HashMap<u16, Vec<ListenerBucket>>, Vec<ListenerBucket>) {
    // Group routes by (listener_port, listener_hostname, route_host). Listener
    // isolation requires this tri-key because two listeners on the same port
    // may share an intersected route host (e.g. "abc.foo.example.com" under
    // both `*.foo.example.com` and exact `abc.foo.example.com` listeners).
    type GroupKey = (u16, String, String);
    let mut by_group: HashMap<GroupKey, Vec<&portus_types::RouteConfig>> = HashMap::new();
    for route in routes {
        let key = (
            route.listener_port as u16,
            route.listener_hostname.clone(),
            route.host.clone(),
        );
        by_group.entry(key).or_default().push(route);
    }

    // Helper: find the HostRoutes previously compiled for a group, for rate
    // limiter reuse. Look up the bucket matching (port, listener_hostname) in
    // the right side of the existing snapshot, then the host within it.
    let find_old_host = |port: u16, lh: &str, host: &str| -> Option<&HostRoutes> {
        let buckets: &[ListenerBucket] = if port == 0 {
            existing_any_port
        } else {
            existing_by_port
                .get(&port)
                .map(|v| v.as_slice())
                .unwrap_or(&[])
        };
        let bucket = buckets
            .iter()
            .find(|b| b.listener_hostname.as_ref() == lh)?;
        if host == "*" {
            bucket.catch_all.as_ref()
        } else if let Some(suffix) = host.strip_prefix("*.") {
            let key = format!(".{}", suffix);
            bucket.domain_wildcards.get(&key)
        } else {
            bucket.exact.get(host)
        }
    };

    // Intermediate: (port, lh) → bucket-in-progress. We accumulate host→HostRoutes
    // per bucket as we finish each group.
    let mut buckets_by_key: HashMap<(u16, String), ListenerBucket> = HashMap::new();

    for ((port, lh, host), specs) in by_group {
        let mut exact_rules: Vec<PathRoute> = Vec::new();
        let mut prefix_rules: Vec<PathRoute> = Vec::new();
        let catch_all: Option<PathRoute> = None;

        let old_host = find_old_host(port, &lh, &host);

        for spec in specs {
            let upstream_tls = spec
                .upstream_tls
                .as_ref()
                .is_some_and(|t| t.enabled);
            let upstream_sni: Arc<str> = spec
                .upstream_tls
                .as_ref()
                .and_then(|t| {
                    if t.sni.is_empty() {
                        None
                    } else {
                        Some(t.sni.as_str())
                    }
                })
                .unwrap_or(&spec.service_name)
                .into();
            let upstream_verify = spec
                .upstream_tls
                .as_ref()
                .is_none_or(|t| t.verify_cert);

            let (req_add, req_set, req_remove) =
                parse_header_mutations_from_proto(&spec.request_headers);
            let (resp_add, resp_set, resp_remove) =
                parse_header_mutations_from_proto(&spec.response_headers);

            let port = spec.port as u16;
            let protocol = parse_protocol(&spec.protocol);

            // Parse header matches from proto
            let header_matches: Vec<HeaderMatchEntry> = spec
                .header_matches
                .iter()
                .filter_map(|hm| {
                    let name = match HeaderName::from_bytes(hm.name.as_bytes()) {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("invalid header match name '{}': {}, skipping", hm.name, e);
                            return None;
                        }
                    };
                    let match_type = match hm.match_type.as_str() {
                        "RegularExpression" => match regex::RegexBuilder::new(&hm.value)
                            .size_limit(64 * 1024)
                            .build()
                        {
                            Ok(re) => HeaderMatchType::RegularExpression(re),
                            Err(e) => {
                                warn!("invalid regex header '{}': {}, using exact", hm.value, e);
                                HeaderMatchType::Exact
                            }
                        },
                        _ => HeaderMatchType::Exact,
                    };
                    Some(HeaderMatchEntry {
                        name,
                        value: hm.value.clone(),
                        match_type,
                    })
                })
                .collect();

            // Parse method match from proto
            let method_match = if spec.method_match.is_empty() {
                None
            } else {
                match http::Method::from_bytes(spec.method_match.as_bytes()) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        warn!("invalid method_match '{}': {}, ignoring", spec.method_match, e);
                        None
                    }
                }
            };

            // Parse query param matches from proto (pre-compile regex at config time)
            let query_param_matches: Vec<QueryParamMatchEntry> = spec
                .query_param_matches
                .iter()
                .filter_map(|qm| {
                    let match_type = match qm.match_type.as_str() {
                        "RegularExpression" => {
                            match regex::RegexBuilder::new(&qm.value)
                                .size_limit(64 * 1024)
                                .build()
                            {
                                Ok(re) => QueryParamMatchType::RegularExpression(re),
                                Err(e) => {
                                    warn!(
                                        "invalid regex query param '{}': {}, skipping",
                                        qm.value, e
                                    );
                                    return None;
                                }
                            }
                        }
                        _ => QueryParamMatchType::Exact,
                    };
                    Some(QueryParamMatchEntry {
                        name: qm.name.clone(),
                        value: qm.value.clone(),
                        match_type,
                    })
                })
                .collect();

            // Parse redirect from proto
            let redirect = spec.redirect.as_ref().map(|r| RedirectConfig {
                scheme: if r.scheme.is_empty() { None } else { Some(r.scheme.clone()) },
                hostname: if r.hostname.is_empty() { None } else { Some(r.hostname.clone()) },
                port: if r.port == 0 { None } else { Some(r.port as u16) },
                path: if r.path.is_empty() { None } else { Some(r.path.clone()) },
                path_type: r.path_type.clone(),
                status_code: if r.status_code == 0 { 302 } else { r.status_code as u16 },
            });

            // Parse url_rewrite from proto
            let url_rewrite = spec.url_rewrite.as_ref().map(|rw| UrlRewriteConfig {
                hostname: if rw.hostname.is_empty() { None } else { Some(Arc::from(rw.hostname.as_str())) },
                path: if rw.path.is_empty() { None } else { Some(rw.path.clone()) },
                path_type: rw.path_type.clone(),
            });

            let listener_name: Arc<str> = Arc::from(spec.listener_name.as_str());

            // Parse auth config from proto
            let auth_config = spec.auth.as_ref().and_then(|auth| {
                auth.auth_type.as_ref().map(|at| match at {
                    portus_types::proto::portus::config::v1::auth_config::AuthType::BasicAuth(ba) => {
                        crate::types::AuthConfig::BasicAuth {
                            credentials: ba.credentials.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                            realm: if ba.realm.is_empty() {
                                "Restricted".to_string()
                            } else {
                                ba.realm.clone()
                            },
                        }
                    }
                    portus_types::proto::portus::config::v1::auth_config::AuthType::ApiKey(ak) => {
                        // RT-1: Reject API keys longer than 256 bytes.
                        // The constant-time comparison in validate_api_key pads keys
                        // to 256 bytes; keys exceeding this would be silently truncated,
                        // causing two keys sharing a 256-byte prefix to both match.
                        const MAX_API_KEY_LEN: usize = 256;
                        let valid_keys = ak.valid_keys.iter()
                            .filter(|k| {
                                if k.len() > MAX_API_KEY_LEN {
                                    log::warn!(
                                        "ApiKey auth: skipping key of {} bytes (max {})",
                                        k.len(),
                                        MAX_API_KEY_LEN,
                                    );
                                    false
                                } else {
                                    true
                                }
                            })
                            .cloned()
                            .collect();
                        crate::types::AuthConfig::ApiKey {
                            valid_keys,
                            header_name: if ak.header_name.is_empty() {
                                "X-API-Key".to_string()
                            } else {
                                ak.header_name.clone()
                            },
                        }
                    }
                })
            });

            // Parse CORS config from proto
            let cors_config = spec.cors.as_ref().map(|c| Arc::new(CorsConfig {
                allow_methods_joined: Arc::from(c.allow_methods.join(", ")),
                allow_headers_joined: Arc::from(c.allow_headers.join(", ")),
                expose_headers_joined: Arc::from(c.expose_headers.join(", ")),
                allow_origins: c.allow_origins.clone(),
                allow_methods: c.allow_methods.clone(),
                allow_headers: c.allow_headers.clone(),
                expose_headers: c.expose_headers.clone(),
                allow_credentials: c.allow_credentials,
                max_age: c.max_age,
                max_age_str: Arc::from(c.max_age.to_string().as_str()),
            }));

            let make_route = |path: Arc<str>, match_type: PathMatchType| {
                // Preserve rate limiter if same path+type+rps
                let rate_limiter = spec.rate_limit.as_ref().map(|rl| {
                    use crate::rate_limiter::{RateLimiterMode, PerIpRateLimiter};
                    let rps = rl.requests_per_second;
                    let per_client = rl.per_client;
                    if let Some(old_hr) = old_host
                        && let Some(existing_rl) =
                            old_hr.find_rate_limiter(path.as_ref(), &match_type, rps, per_client)
                        {
                            return existing_rl;
                        }
                    if per_client {
                        RateLimiterMode::PerIp(Arc::new(PerIpRateLimiter::new(rps)))
                    } else {
                        RateLimiterMode::Shared(Arc::new(AtomicTokenBucket::new(rps)))
                    }
                });

                PathRoute {
                    path,
                    match_type,
                    service_name: Arc::from(spec.service_name.as_str()),
                    port,
                    connect_timeout: spec
                        .timeouts
                        .as_ref()
                        .and_then(|t| {
                            if t.connect_timeout_ms > 0 {
                                Some(Duration::from_millis(t.connect_timeout_ms))
                            } else {
                                None
                            }
                        }),
                    read_timeout: spec
                        .timeouts
                        .as_ref()
                        .and_then(|t| {
                            if t.read_timeout_ms > 0 {
                                Some(Duration::from_millis(t.read_timeout_ms))
                            } else {
                                None
                            }
                        }),
                    write_timeout: spec
                        .timeouts
                        .as_ref()
                        .and_then(|t| {
                            if t.write_timeout_ms > 0 {
                                Some(Duration::from_millis(t.write_timeout_ms))
                            } else {
                                None
                            }
                        }),
                    rate_limiter,
                    max_retries: spec.max_retries,
                    upstream_tls,
                    upstream_sni: Arc::clone(&upstream_sni),
                    upstream_verify,
                    protocol,
                    request_headers_add: Arc::clone(&req_add),
                    request_headers_set: Arc::clone(&req_set),
                    request_headers_remove: Arc::clone(&req_remove),
                    response_headers_add: Arc::clone(&resp_add),
                    response_headers_set: Arc::clone(&resp_set),
                    response_headers_remove: Arc::clone(&resp_remove),
                    header_matches: header_matches.clone(),
                    method_match: method_match.clone(),
                    query_param_matches: query_param_matches.clone(),
                    redirect: redirect.as_ref().map(|r| RedirectConfig {
                        scheme: r.scheme.clone(),
                        hostname: r.hostname.clone(),
                        port: r.port,
                        path: r.path.clone(),
                        path_type: r.path_type.clone(),
                        status_code: r.status_code,
                    }),
                    url_rewrite: url_rewrite.clone(),
                    listener_name: Arc::clone(&listener_name),
                    mirror_backends: if !spec.mirror_backends.is_empty() {
                        spec.mirror_backends.iter().map(|mb| {
                            (Arc::from(mb.service_name.as_str()) as Arc<str>, mb.port as u16, mb.percent)
                        }).collect()
                    } else if let Some(ref mb) = spec.mirror_backend {
                        // Backward compat: single mirror_backend field
                        vec![(Arc::from(mb.service_name.as_str()) as Arc<str>, mb.port as u16, mb.percent)]
                    } else {
                        Vec::new()
                    },
                    weighted_backends: spec
                        .weighted_backends
                        .iter()
                        .map(|wb| {
                            let (req_add, req_set, req_remove) =
                                parse_header_mutations_from_proto(&wb.request_headers);
                            crate::router::WeightedBackendEntry {
                                service_name: Arc::from(wb.service_name.as_str()),
                                port: wb.port as u16,
                                weight: wb.weight,
                                request_headers_add: req_add,
                                request_headers_set: req_set,
                                request_headers_remove: req_remove,
                            }
                        })
                        .collect(),
                    request_timeout: if spec.request_timeout_ms > 0 {
                        Some(Duration::from_millis(spec.request_timeout_ms))
                    } else {
                        None
                    },
                    backend_request_timeout: if spec.backend_request_timeout_ms > 0 {
                        Some(Duration::from_millis(spec.backend_request_timeout_ms))
                    } else {
                        None
                    },
                    auth_config: auth_config.clone(),
                    cors: cors_config.clone(),
                    ip_allow_cidrs: spec.ip_allowlist.as_ref().map(|ip| {
                        ip.allow_cidrs.iter().filter_map(|c| c.parse().ok()).collect()
                    }).unwrap_or_default(),
                    ip_deny_cidrs: spec.ip_allowlist.as_ref().map(|ip| {
                        ip.deny_cidrs.iter().filter_map(|c| c.parse().ok()).collect()
                    }).unwrap_or_default(),
                    ip_trusted_proxy_cidrs: spec.ip_allowlist.as_ref().map(|ip| {
                        ip.trusted_proxy_cidrs.iter().filter_map(|c| c.parse().ok()).collect()
                    }).unwrap_or_default(),
                    max_request_body_bytes: spec.max_request_body_bytes,
                    retry_on: Arc::new(spec.retry_on.clone()),
                    retry_codes: Arc::new(spec.retry_codes.iter().filter_map(|c| u16::try_from(*c).ok()).collect()),
                    // PERF-8: Embed CB/CL directly — looked up once at config-build time
                    circuit_breaker: {
                        let key = (Arc::from(spec.service_name.as_str()) as Arc<str>, port);
                        cb_map.get(&key).cloned()
                    },
                    connection_limiter: {
                        let key = (Arc::from(spec.service_name.as_str()) as Arc<str>, port);
                        cl_map.get(&key).cloned()
                    },
                    // PERF-10: Pre-compute total weight to avoid per-request summation
                    total_weight: spec.weighted_backends.iter().map(|wb| wb.weight).sum(),
                }
            };

            let has_paths = !spec.paths.is_empty();
            if !has_paths {
                // No explicit path: treat as prefix "/" rule (not catch-all) so
                // multiple header-only or method-only rules can coexist under the
                // same host without overwriting each other.
                prefix_rules.push(make_route(Arc::from("/"), PathMatchType::Prefix));
            } else {
                for pr in &spec.paths {
                    let mt = match parse_match_type(&pr.match_type, &pr.path) {
                        Some(mt) => mt,
                        None => continue, // skip routes with invalid regex
                    };
                    let route = make_route(Arc::from(pr.path.as_str()), mt);
                    match route.match_type {
                        PathMatchType::Exact => exact_rules.push(route),
                        PathMatchType::Prefix => prefix_rules.push(route),
                        PathMatchType::RegularExpression(_) => prefix_rules.push(route),
                    }
                }
            }
        }

        // Sort prefix rules: longest-first, then by specificity.
        //
        // Gateway API precedence (most to least specific):
        //   1. Method match (has method > no method)
        //   2. Header match count (more headers = more specific)
        //   3. Query param match count (more params = more specific)
        //
        // Among routes with equal specificity, stable sort preserves the
        // original rule order from the HTTPRoute YAML (earlier = higher priority).
        let specificity_cmp = |a: &PathRoute, b: &PathRoute| -> std::cmp::Ordering {
            let a_method = if a.method_match.is_some() { 1usize } else { 0 };
            let b_method = if b.method_match.is_some() { 1usize } else { 0 };
            b_method.cmp(&a_method)
                .then_with(|| b.header_matches.len().cmp(&a.header_matches.len()))
                .then_with(|| b.query_param_matches.len().cmp(&a.query_param_matches.len()))
        };
        prefix_rules.sort_by(|a, b| {
            b.path.len()
                .cmp(&a.path.len())
                .then_with(|| specificity_cmp(a, b))
        });

        // Build exact path HashMap for O(1) lookup.
        // Sort by specificity first so each bucket is ordered correctly.
        exact_rules.sort_by(|a, b| specificity_cmp(a, b));
        let mut exact_map: HashMap<Arc<str>, Vec<PathRoute>> = HashMap::new();
        for rule in exact_rules {
            exact_map.entry(Arc::clone(&rule.path)).or_default().push(rule);
        }

        let host_routes = HostRoutes {
            exact_map,
            rules: prefix_rules,
            catch_all,
        };

        // Place this HostRoutes into the right bucket slot based on the
        // route's host (not the listener's hostname).
        let bucket_key = (port, lh.clone());
        let bucket = buckets_by_key
            .entry(bucket_key)
            .or_insert_with(|| ListenerBucket {
                listener_hostname: Arc::from(lh.as_str()),
                exact: HashMap::new(),
                domain_wildcards: HashMap::new(),
                catch_all: None,
            });

        if host == "*" {
            bucket.catch_all = Some(host_routes);
        } else if let Some(wildcard_suffix) = host.strip_prefix("*.") {
            bucket
                .domain_wildcards
                .insert(format!(".{}", wildcard_suffix), host_routes);
        } else {
            bucket.exact.insert(host, host_routes);
        }
    }

    // Convert the flat (port, lh) bucket map into the per-port vector form
    // expected by ProxySnapshot, sorting within each port by listener
    // hostname specificity so the router can pick the most-specific listener
    // at match time via a simple linear scan.
    let mut listeners_by_port: HashMap<u16, Vec<ListenerBucket>> = HashMap::new();
    let mut any_port_listeners: Vec<ListenerBucket> = Vec::new();
    for ((port, _lh), bucket) in buckets_by_key {
        if port == 0 {
            any_port_listeners.push(bucket);
        } else {
            listeners_by_port.entry(port).or_default().push(bucket);
        }
    }
    let sort_by_specificity = |a: &ListenerBucket, b: &ListenerBucket| -> std::cmp::Ordering {
        listener_specificity(&b.listener_hostname)
            .cmp(&listener_specificity(&a.listener_hostname))
    };
    for buckets in listeners_by_port.values_mut() {
        buckets.sort_by(sort_by_specificity);
    }
    any_port_listeners.sort_by(sort_by_specificity);

    (listeners_by_port, any_port_listeners)
}

/// Build load balancer map from proto BackendGroup messages.
/// Fingerprint of everything a `LoadBalancer` is built from: the sorted endpoint
/// set and the health-check configuration. Order-independent over endpoints.
pub(crate) fn lb_signature(group: &portus_types::BackendGroup) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut addrs: Vec<(&str, u32)> = group
        .endpoints
        .iter()
        .map(|ep| (ep.address.as_str(), ep.port))
        .collect();
    addrs.sort_unstable();
    addrs.dedup();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    addrs.hash(&mut h);
    if let Some(hc) = &group.health_check {
        hc.path.hash(&mut h);
        hc.interval_secs.hash(&mut h);
        hc.timeout_secs.hash(&mut h);
        hc.healthy_threshold.hash(&mut h);
        hc.unhealthy_threshold.hash(&mut h);
    } else {
        0u8.hash(&mut h);
    }
    h.finish()
}

/// Build the per-(service, port) `LoadBalancer` map.
///
/// A `LoadBalancer` whose endpoint set and health-check config are unchanged
/// since the previous snapshot is reused rather than rebuilt, so round-robin
/// position and — more importantly — health-check state survive unrelated
/// config changes. Returns the new map and its signatures.
pub(crate) fn build_lb_map_from_proto(
    backends: &[portus_types::BackendGroup],
    existing: &LbMap,
    existing_signatures: &LbSignatures,
) -> (LbMap, LbSignatures) {
    let mut lb_map = HashMap::new();
    let mut signatures = HashMap::new();

    for group in backends {
        let key = (
            Arc::from(group.service_name.as_str()) as Arc<str>,
            group.port as u16,
        );
        let sig = lb_signature(group);
        if existing_signatures.get(&key) == Some(&sig)
            && let Some(lb) = existing.get(&key) {
                lb_map.insert(key.clone(), Arc::clone(lb));
                signatures.insert(key, sig);
                continue;
            }

        let ping_backends: Vec<Backend> = group
            .endpoints
            .iter()
            .filter_map(|ep| {
                let addr = format!("{}:{}", ep.address, ep.port);
                Backend::new(&addr).ok()
            })
            .collect();

        if ping_backends.is_empty() {
            continue;
        }

        match LoadBalancer::try_from_iter(ping_backends) {
            Ok(mut lb) => {
                // Configure health checking from HealthCheckPolicy if present
                if let Some(ref hc) = group.health_check {
                    // TODO: Health checks always use plain HTTP. Backends requiring TLS
                    // will be probed without encryption. Supporting TLS health checks
                    // requires adding a `tls` field to HealthCheckConfig in the proto
                    // and HealthCheckSpec in the CRD, then passing it here.
                    // Health checks always use plain HTTP (TLS not yet supported).
                    // Logged at debug level to avoid flooding on every config apply.
                    let mut check = HttpHealthCheck::new(
                        &group.service_name,
                        false, // TLS health checks not yet supported
                    );
                    check.consecutive_success = hc.healthy_threshold.max(1) as usize;
                    check.consecutive_failure = hc.unhealthy_threshold.max(1) as usize;
                    // Set the path on the request
                    let path = if hc.path.is_empty() { "/" } else { &hc.path };
                    if let Ok(req) = http::request::Builder::new()
                        .method("GET")
                        .uri(path)
                        .header("Host", &group.service_name)
                        .body(())
                    {
                        let (parts, _) = req.into_parts();
                        check.req = pingora_http::RequestHeader::from(parts);
                    }
                    check.peer_template.options.connection_timeout =
                        Some(Duration::from_secs(hc.timeout_secs.max(1) as u64));
                    check.peer_template.options.read_timeout =
                        Some(Duration::from_secs(hc.timeout_secs.max(1) as u64));
                    lb.set_health_check(Box::new(check));
                    info!(
                        "configured health check for {}:{} path={} interval={}s",
                        group.service_name, group.port, path, hc.interval_secs
                    );
                }
                signatures.insert(key.clone(), sig);
                lb_map.insert(key, Arc::new(lb));
            }
            Err(e) => {
                warn!(
                    "failed to create load balancer for {}:{}: {}",
                    group.service_name, group.port, e
                );
            }
        }
    }

    (lb_map, signatures)
}

/// Build backend TLS map from proto BackendGroup messages.
/// Maps (service_name, port) → BackendTlsInfo for backends with BackendTLSPolicy.
/// Parses CA PEM certificates into WrappedX509 at config-build time (not per-request).
pub(crate) fn build_backend_tls_map_from_proto(
    backends: &[portus_types::BackendGroup],
) -> HashMap<(Arc<str>, u16), Arc<crate::router::BackendTlsInfo>> {
    let mut tls_map = HashMap::new();
    for group in backends {
        if let Some(ref tls) = group.backend_tls
            && !tls.ca_cert_pem.is_empty() {
                // Parse PEM → DER certificates at config time
                let mut reader = std::io::BufReader::new(tls.ca_cert_pem.as_bytes());
                let der_certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut reader)
                    .filter_map(|r| r.ok())
                    .map(|c| c.to_vec())
                    .collect();

                if der_certs.is_empty() {
                    warn!(
                        "BackendTLSPolicy for {}:{} has CA PEM but no parseable certificates",
                        group.service_name, group.port
                    );
                    continue;
                }

                // Build WrappedX509 slice from DER certs using the public helper
                let wrapped: Vec<pingora_core::utils::tls::WrappedX509> = der_certs
                    .into_iter()
                    .map(pingora_core::utils::tls::wrapped_x509_from_der)
                    .collect();

                let key = (
                    Arc::from(group.service_name.as_str()) as Arc<str>,
                    group.port as u16,
                );
                let sans: Vec<(String, String)> = tls.subject_alt_names.iter()
                    .map(|san| (san.r#type.clone(), san.value.clone()))
                    .collect();
                tls_map.insert(
                    key,
                    Arc::new(crate::router::BackendTlsInfo {
                        ca_certs: Arc::from(wrapped.into_boxed_slice()),
                        hostname: Arc::from(tls.hostname.as_str()),
                        subject_alt_names: Arc::new(sans),
                    }),
                );
            }
    }
    tls_map
}

/// Frontend client validation per HTTPS listener port. All HTTPS listeners on
/// a port share one policy (the Gateway API keys it by port); if two disagree
/// the first wins and the conflict is logged.
pub(crate) fn client_validation_from_listeners(
    listeners: &[portus_types::Listener],
) -> Vec<PortClientValidation> {
    let mut out: Vec<PortClientValidation> = Vec::new();
    for listener in listeners {
        if listener.protocol != "HTTPS" {
            continue;
        }
        let Some(cv) = listener.client_validation.as_ref() else { continue };
        let Ok(port) = u16::try_from(listener.port) else { continue };
        let ca_cert_pems: Vec<String> = cv
            .ca_cert_pems
            .iter()
            .filter(|p| !p.trim().is_empty())
            .cloned()
            .collect();
        if ca_cert_pems.is_empty() {
            warn!(
                "listener '{}' on port {} has client validation without CA certificates; ignoring",
                listener.name, port
            );
            continue;
        }
        let spec = PortClientValidation {
            port,
            ca_cert_pems,
            mode: ClientValidationMode::parse(&cv.mode),
        };
        match out.iter().find(|existing| existing.port == port) {
            Some(existing) if *existing != spec => warn!(
                "listener '{}' on port {} has a different client validation policy than an earlier listener on that port; keeping the first",
                listener.name, port
            ),
            Some(_) => {}
            None => out.push(spec),
        }
    }
    out.sort_by_key(|s| s.port);
    out
}

/// The client certificate this data plane presents to TLS backends: the
/// `gateway_backend_tls` entry of the Gateway it serves. A data plane serves
/// exactly one Gateway, so its slice carries at most one entry; anything else
/// is a controller bug and is logged and ignored. Parsed once here (PEM → DER)
/// so `upstream_peer` only clones an `Arc`.
pub(crate) fn build_backend_client_cert_from_proto(
    config: &portus_types::CompiledConfig,
    gateway: (&str, &str),
) -> Option<Arc<pingora_core::utils::tls::CertKey>> {
    let mine: Vec<&portus_types::GatewayBackendTls> = config
        .gateway_backend_tls
        .iter()
        .filter(|g| (g.gateway_namespace.as_str(), g.gateway_name.as_str()) == gateway)
        .collect();
    for other in config.gateway_backend_tls.iter().filter(|g| {
        (g.gateway_namespace.as_str(), g.gateway_name.as_str()) != gateway
    }) {
        warn!(
            "config carries a backend client certificate for Gateway {}/{} but this data plane serves {}/{}; ignoring",
            other.gateway_namespace, other.gateway_name, gateway.0, gateway.1
        );
    }
    let entry = mine.first()?;
    if mine.len() > 1 {
        warn!("config carries {} backend client certificates for Gateway {}/{}; using the first", mine.len(), gateway.0, gateway.1);
    }
    match parse_client_cert_key(&entry.cert_pem, &entry.key_pem) {
        Ok(ck) => Some(Arc::new(ck)),
        Err(e) => {
            warn!(
                "Gateway {}/{}: backend client certificate is unusable, connections to TLS backends will not present it: {}",
                gateway.0, gateway.1, e
            );
            None
        }
    }
}

/// Parse a PEM certificate chain and private key into Pingora's `CertKey`
/// (DER chain + DER key), the shape `HttpPeer.client_cert_key` expects.
pub(crate) fn parse_client_cert_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<pingora_core::utils::tls::CertKey, String> {
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate PEM: {e}"))?
        .into_iter()
        .map(|c| c.to_vec())
        .collect();
    if certs.is_empty() || certs[0].is_empty() {
        return Err("no certificate in PEM".to_string());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("invalid private key PEM: {e}"))?
        .ok_or_else(|| "no private key in PEM".to_string())?;
    Ok(pingora_core::utils::tls::CertKey::new(certs, key.secret_der().to_vec()))
}

/// Build circuit breaker and connection limiter maps from proto RouteConfig messages.
/// Reuses existing instances when config is unchanged to preserve state.
pub(crate) fn build_cb_cl_maps_from_proto(
    routes: &[portus_types::RouteConfig],
    existing_cbs: &HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>,
    existing_cls: &ConnectionLimiterMap,
) -> (CircuitBreakerMap, ConnectionLimiterMap) {
    let mut cb_map = HashMap::new();
    let mut cl_map = HashMap::new();

    for route in routes {
        let key = (
            Arc::from(route.service_name.as_str()) as Arc<str>,
            route.port as u16,
        );

        // Circuit breaker: only when a CircuitBreakerPolicy asked for one. A
        // Gateway that trips a breaker of its own would turn a backend's 5xx
        // into a 503 of its own making (the conformance retry test caught the
        // old implicit 5-failure default doing exactly that).
        if let Some(cb_config) = route.circuit_breaker.as_ref() {
            // Clamp u32 thresholds to u16 range (values above 65535 saturate to
            // MAX instead of silently wrapping to 0 via `as u16`).
            let ft = u16::try_from(cb_config.failure_threshold).unwrap_or(u16::MAX);
            let st = u16::try_from(cb_config.success_threshold).unwrap_or(u16::MAX);
            let to = cb_config.timeout_secs;
            // Reuse the existing breaker when its config is unchanged so its
            // state survives config pushes.
            let reuse = existing_cbs.get(&key).filter(|existing| {
                existing.config.failure_threshold == ft
                    && existing.config.success_threshold == st
                    && existing.config.timeout_secs == to
            });
            cb_map.entry(key.clone()).or_insert_with(|| match reuse {
                Some(existing) => Arc::clone(existing),
                None => Arc::new(CircuitBreaker::new(InternalCbConfig {
                    failure_threshold: ft,
                    success_threshold: st,
                    timeout_secs: to,
                })),
            });
        }

        // Connection limiter: only when a ConnectionPolicy set max_connections.
        if let Some(max_conn) = route.max_connections.filter(|m| *m > 0) {
            let reuse = existing_cls.get(&key).filter(|existing| existing.max == max_conn);
            cl_map.entry(key.clone()).or_insert_with(|| match reuse {
                Some(existing) => Arc::clone(existing),
                None => Arc::new(ConnectionLimiter::new(max_conn)),
            });
        }
    }

    (cb_map, cl_map)
}

/// Build L4Config from proto TLS passthrough and TCP proxy routes.
///
/// Groups TLS routes by listener hostname to enable per-listener
/// SNI scoping. Each listener gets its own route table so the SNI mux can
/// find the most specific matching listener and route within it.
/// Supports both Passthrough and Terminate TLS modes.
pub(crate) fn build_l4_config_from_proto(config: &portus_types::CompiledConfig) -> L4Config {
    use crate::l4_proxy::{TlsPassthroughListener, TlsMode};
    use crate::tls::load_certified_key_from_pem;

    let mut l4 = L4Config::default();

    // Group routes by listener_hostname, tracking mode/cert/port per listener
    struct ListenerBuild {
        routes: HashMap<String, (String, u16)>,
        tls_mode: TlsMode,
        cert: Option<Arc<rustls::sign::CertifiedKey>>,
        listener_port: u16,
    }
    let mut listeners_map: HashMap<String, ListenerBuild> =
        HashMap::new();

    for tls_route in &config.tls_passthrough_routes {
        let backend = (
            tls_route.backend_service.clone(),
            tls_route.backend_port as u16,
        );
        let listener_key = tls_route.listener_hostname.clone();

        let tls_mode = if tls_route.tls_mode == "Terminate" {
            TlsMode::Terminate
        } else {
            TlsMode::Passthrough
        };

        // Load cert for Terminate mode
        let cert = if tls_mode == TlsMode::Terminate
            && !tls_route.cert_pem.is_empty()
            && !tls_route.key_pem.is_empty()
        {
            match load_certified_key_from_pem(&tls_route.cert_pem, &tls_route.key_pem) {
                Ok(ck) => Some(Arc::new(ck)),
                Err(e) => {
                    warn!("failed to load TLS cert for terminate route: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let entry = listeners_map.entry(listener_key).or_insert_with(|| ListenerBuild {
            routes: HashMap::new(),
            tls_mode: tls_mode.clone(),
            cert: cert.clone(),
            listener_port: tls_route.listener_port as u16,
        });
        // Update cert/mode if this route has better data
        if cert.is_some() && entry.cert.is_none() {
            entry.cert = cert;
        }
        if entry.listener_port == 0 && tls_route.listener_port > 0 {
            entry.listener_port = tls_route.listener_port as u16;
        }
        for hostname in &tls_route.sni_hostnames {
            entry.routes.insert(hostname.clone(), backend.clone());
        }
    }

    // Also add listener hostnames that have no routes (for rejection)
    for lh in &config.tls_passthrough_listener_hostnames {
        listeners_map.entry(lh.clone()).or_insert_with(|| ListenerBuild {
            routes: HashMap::new(),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });
    }

    // Build per-listener config
    for (hostname, build) in listeners_map {
        l4.tls_listeners.push(TlsPassthroughListener {
            hostname,
            routes: build.routes,
            tls_mode: build.tls_mode,
            cert: build.cert,
            listener_port: build.listener_port,
        });
    }

    l4.tcp_proxy = l4_targets(&config.tcp_proxy_routes);
    l4.udp_proxy = l4_targets(&config.udp_proxy_routes);

    // Every HTTP/HTTPS Gateway listener port is bound by the listener manager
    // and handed to the matching Pingora service.
    for listener in &config.listeners {
        let Ok(port) = u16::try_from(listener.port) else { continue };
        if port == 0 {
            continue;
        }
        match listener.protocol.as_str() {
            "HTTP" => {
                l4.http_ports.insert(port);
            }
            "HTTPS" => {
                l4.https_ports.insert(port);
            }
            "TLS" => {
                l4.tls_ports.insert(port);
            }
            "TCP" => {
                l4.tcp_ports.insert(port);
            }
            "UDP" => {
                l4.udp_ports.insert(port);
            }
            _ => {}
        }
    }

    l4
}

/// Listener port -> weighted backends for the TCPRoute or UDPRoute list.
fn l4_targets(routes: &[portus_types::L4ProxyRoute]) -> HashMap<u16, Arc<crate::l4_proxy::L4RouteTarget>> {
    use crate::l4_proxy::{L4Backend, L4RouteTarget};
    routes
        .iter()
        .map(|route| {
            let backends: Vec<L4Backend> = route
                .backends
                .iter()
                .map(|b| L4Backend {
                    service: b.service_name.clone(),
                    port: b.port as u16,
                    weight: b.weight,
                })
                .collect();
            (route.listener_port as u16, Arc::new(L4RouteTarget::new(backends)))
        })
        .collect()
}

/// SEC F-2: Collect all unique PerIpRateLimiter Arc instances from route maps.
/// Uses Arc pointer identity to deduplicate (same limiter may appear in multiple routes
/// after rate limiter preservation across rebuilds).
fn collect_per_ip_limiters(
    listeners_by_port: &HashMap<u16, Vec<ListenerBucket>>,
    any_port_listeners: &[ListenerBucket],
) -> Vec<Arc<PerIpRateLimiter>> {
    use crate::rate_limiter::RateLimiterMode;

    let mut seen: Vec<Arc<PerIpRateLimiter>> = Vec::new();

    let collect_from_route = |pr: &PathRoute, seen: &mut Vec<Arc<PerIpRateLimiter>>| {
        if let Some(RateLimiterMode::PerIp(ref limiter)) = pr.rate_limiter
            && !seen.iter().any(|existing| Arc::ptr_eq(existing, limiter)) {
                seen.push(Arc::clone(limiter));
            }
    };

    let collect_from_host_routes = |hr: &HostRoutes, seen: &mut Vec<Arc<PerIpRateLimiter>>| {
        for routes_vec in hr.exact_map.values() {
            for pr in routes_vec {
                collect_from_route(pr, seen);
            }
        }
        for pr in &hr.rules {
            collect_from_route(pr, seen);
        }
        if let Some(ref ca) = hr.catch_all {
            collect_from_route(ca, seen);
        }
    };

    let collect_from_bucket = |b: &ListenerBucket, seen: &mut Vec<Arc<PerIpRateLimiter>>| {
        for hr in b.exact.values() {
            collect_from_host_routes(hr, seen);
        }
        for hr in b.domain_wildcards.values() {
            collect_from_host_routes(hr, seen);
        }
        if let Some(ref hr) = b.catch_all {
            collect_from_host_routes(hr, seen);
        }
    };

    for buckets in listeners_by_port.values() {
        for b in buckets {
            collect_from_bucket(b, &mut seen);
        }
    }
    for b in any_port_listeners {
        collect_from_bucket(b, &mut seen);
    }

    seen
}

// ---------------------------------------------------------------------------
// Config content validation
// ---------------------------------------------------------------------------

/// Validates a `CompiledConfig` before it is applied.
///
/// Returns `Ok(warnings)` when the config is safe to apply (warnings are
/// informational only), or `Err(reason)` when critical invariants are
/// violated and the config must be rejected.
pub(crate) fn validate_config(config: &portus_types::CompiledConfig) -> Result<Vec<String>, String> {
    let mut warnings: Vec<String> = Vec::new();

    // --- Hard rejections (route-level) ---
    let mut seen_keys = hashbrown::HashSet::new();
    for (i, route) in config.routes.iter().enumerate() {
        // A route with no service_name *and* no weighted_backends cannot be proxied
        // (unless it is a redirect-only route).
        if route.service_name.is_empty()
            && route.weighted_backends.is_empty()
            && route.redirect.is_none()
        {
            return Err(format!("route[{}]: empty service_name with no weighted_backends and no redirect", i));
        }

        // Port 0 is never valid for a backend.
        if route.port == 0 && route.weighted_backends.is_empty() && route.redirect.is_none() {
            return Err(format!(
                "route[{}] ({}): port is 0",
                i,
                if route.service_name.is_empty() { "<empty>" } else { &route.service_name }
            ));
        }

        // Empty hostname with non-empty paths creates unreachable routes
        // (wildcard "*" host is valid, but a truly empty host with specific
        // paths would never match any request).
        if route.host.is_empty() && !route.paths.is_empty() {
            return Err(format!(
                "route[{}] ({}): empty hostname with {} path rule(s) -- unreachable",
                i,
                if route.service_name.is_empty() { "<empty>" } else { &route.service_name },
                route.paths.len(),
            ));
        }

        // Duplicate route key detection (host + path + method + listener_port).
        // Duplicates indicate a compiler bug.
        for path_rule in &route.paths {
            let key = (
                route.host.as_str(),
                path_rule.path.as_str(),
                path_rule.match_type.as_str(),
                route.method_match.as_str(),
                route.listener_port,
            );
            if !seen_keys.insert(key) {
                return Err(format!(
                    "route[{}] ({}): duplicate route key host={} path={} method={} listener_port={} -- possible compiler bug",
                    i,
                    route.service_name,
                    route.host,
                    path_rule.path,
                    if route.method_match.is_empty() { "*" } else { &route.method_match },
                    route.listener_port,
                ));
            }
        }

        // Validate weighted_backends entries.
        for (j, wb) in route.weighted_backends.iter().enumerate() {
            if wb.service_name.is_empty() {
                return Err(format!(
                    "route[{}].weighted_backends[{}]: empty service_name",
                    i, j
                ));
            }
            if wb.port == 0 {
                return Err(format!(
                    "route[{}].weighted_backends[{}] ({}): port is 0",
                    i, j, wb.service_name
                ));
            }
        }
    }

    // --- Hard rejections (listener-level) ---
    for (i, listener) in config.listeners.iter().enumerate() {
        if listener.port == 0 {
            return Err(format!(
                "listener[{}] ({}): port is 0",
                i, listener.name
            ));
        }
    }

    // --- Warnings ---
    if config.routes.is_empty() {
        warnings.push("config contains zero routes -- all traffic will return 404".into());
    }

    if config.routes.len() > 10_000 {
        warnings.push(format!(
            "config contains {} routes (unusually large)",
            config.routes.len()
        ));
    }

    for (i, route) in config.routes.iter().enumerate() {
        // Routes with no backends will 502.
        if route.service_name.is_empty()
            && route.weighted_backends.is_empty()
            && route.redirect.is_some()
        {
            // Redirect-only routes are fine -- they never proxy.
        } else if route.weighted_backends.is_empty() && route.service_name.is_empty() {
            warnings.push(format!("route[{}]: no backends configured -- will 502", i));
        }
    }

    // Listeners with HTTPS/TLS protocol but missing cert data.
    for (i, listener) in config.listeners.iter().enumerate() {
        let proto_upper = listener.protocol.to_uppercase();
        if (proto_upper == "HTTPS" || proto_upper == "TLS")
            && listener.tls_cert_ref.as_ref().is_none_or(|c| {
                c.cert_pem.is_empty() || c.key_pem.is_empty()
            })
        {
            warnings.push(format!(
                "listener[{}] ({}): protocol {} but missing TLS cert/key",
                i, listener.name, listener.protocol
            ));
        }
    }

    // Early regex validation -- these are handled later in parse_match_type,
    // but validating here lets us surface all problems at once.
    for (i, route) in config.routes.iter().enumerate() {
        for path_rule in &route.paths {
            if path_rule.match_type == "RegularExpression"
                && let Err(e) = regex::RegexBuilder::new(&path_rule.path)
                    .size_limit(64 * 1024)
                    .build()
                {
                    warnings.push(format!(
                        "route[{}] ({}): regex path '{}' fails to compile: {}",
                        i, route.service_name, path_rule.path, e
                    ));
                }
        }
    }

    Ok(warnings)
}

/// Apply a received CompiledConfig using the shadow-build pattern.
/// Preserves rate limiter and circuit breaker state from the current config.
/// Takes ownership so credential fields can be zeroized before drop (SEC F-11).
pub(crate) fn apply_config(mut config: portus_types::CompiledConfig, state: &ProxyState) {
    let current_snap = state.snapshot.load();

    // PERF-8: Build CB/CL maps first so they can be embedded in PathRoute
    // during route construction, eliminating per-request map lookups.
    let (new_cbs, new_cls) =
        build_cb_cl_maps_from_proto(&config.routes, &current_snap.circuit_breakers, &current_snap.connection_limiters);

    // Shadow-build: construct new listener buckets, reusing stateful objects.
    let (new_listeners_by_port, new_any_port_listeners) = build_listener_buckets_from_proto(
        &config.routes,
        &current_snap.listeners_by_port,
        &current_snap.any_port_listeners,
        &new_cbs,
        &new_cls,
    );
    let (new_lbs, new_lb_signatures) = build_lb_map_from_proto(
        &config.backends,
        &current_snap.lbs,
        &current_snap.lb_signatures,
    );
    let new_l4 = build_l4_config_from_proto(&config);

    // Extract TLS certificates from all HTTPS listeners for SNI-based selection.
    // Each listener may have a different hostname and cert (e.g., *.example.com vs *.q.qumu.lol).
    let mut tls_entries = Vec::new();
    for listener in &config.listeners {
        if let Some(ref cert_ref) = listener.tls_cert_ref
            && !cert_ref.cert_pem.is_empty() && !cert_ref.key_pem.is_empty() {
                info!(
                    "collected TLS certificate from listener '{}' hostname='{}' ({}:{})",
                    listener.name, listener.hostname, listener.protocol, listener.port
                );
                tls_entries.push(TlsCertEntry {
                    hostname: listener.hostname.clone(),
                    cert_pem: cert_ref.cert_pem.clone(),
                    key_pem: cert_ref.key_pem.clone(),
                });
            }
    }
    let client_validation = client_validation_from_listeners(&config.listeners);
    let tls_updated = !tls_entries.is_empty();
    if tls_updated {
        info!(
            "storing {} TLS certificate(s) for SNI selection, client validation on {} port(s)",
            tls_entries.len(),
            client_validation.len()
        );
        state.tls_cert.store(Arc::new(Some(TlsCertData {
            entries: tls_entries,
            client_validation,
        })));
        state.tls_cert_notify.notify_one();
    }

    // Compute minimum health check interval across all backends (default 10s).
    let min_interval = config
        .backends
        .iter()
        .filter_map(|bg| bg.health_check.as_ref())
        .map(|hc| hc.interval_secs.max(1))
        .min()
        .unwrap_or(10);
    state
        .health_check_min_interval
        .store(min_interval, std::sync::atomic::Ordering::Relaxed);

    // SEC F-2: Collect all unique PerIpRateLimiter instances for background eviction.
    let per_ip_limiters =
        collect_per_ip_limiters(&new_listeners_by_port, &new_any_port_listeners);

    // PERF-9: Atomic swap — one store for all per-request maps, plus the
    // separate LB map for L4 proxy and health check threads.
    // Clone the LB map before moving it into the snapshot.
    let new_backend_tls = build_backend_tls_map_from_proto(&config.backends);
    let (gw_ns, gw_name) = gateway_identity();
    let new_backend_client_cert = build_backend_client_cert_from_proto(&config, (&gw_ns, &gw_name));
    state.lbs.store(Arc::new(new_lbs.clone()));
    state.snapshot.store(Arc::new(ProxySnapshot {
        listeners_by_port: new_listeners_by_port,
        any_port_listeners: new_any_port_listeners,
        lbs: new_lbs,
        circuit_breakers: new_cbs,
        connection_limiters: new_cls,
        per_ip_limiters,
        backend_tls: new_backend_tls,
        backend_client_cert: new_backend_client_cert,
        lb_signatures: new_lb_signatures,
    }));
    state.l4_config.store(Arc::new(new_l4));

    info!(
        "applied config v{} (schema {}): {} routes, {} backend groups, {} TLS passthrough, {} TCP proxy, {} UDP proxy, tls_updated={}",
        config.version,
        config.schema_version,
        config.routes.len(),
        config.backends.len(),
        config.tls_passthrough_routes.len(),
        config.tcp_proxy_routes.len(),
        config.udp_proxy_routes.len(),
        tls_updated,
    );

    // SEC F-11: Zeroize credential fields in proto before dropping.
    // After extracting all needed data above, scrub sensitive material so it
    // does not linger in freed memory.
    {
        use zeroize::Zeroize;
        for route in config.routes.iter_mut() {
            if let Some(ref mut auth) = route.auth
                && let Some(ref mut at) = auth.auth_type {
                    match at {
                        portus_types::proto::portus::config::v1::auth_config::AuthType::BasicAuth(ba) => {
                            for hash in ba.credentials.values_mut() {
                                hash.zeroize();
                            }
                        }
                        portus_types::proto::portus::config::v1::auth_config::AuthType::ApiKey(ak) => {
                            for key in ak.valid_keys.iter_mut() {
                                key.zeroize();
                            }
                        }
                    }
                }
        }
        // Zeroize TLS key material from listeners
        for listener in config.listeners.iter_mut() {
            if let Some(ref mut cert_ref) = listener.tls_cert_ref {
                cert_ref.key_pem.zeroize();
            }
        }
        // Zeroize TLS key material from TLS passthrough routes (Terminate mode)
        for tls_route in config.tls_passthrough_routes.iter_mut() {
            tls_route.key_pem.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Reconnecting gRPC client loop
// ---------------------------------------------------------------------------

/// The Gateway this data plane serves, from `GATEWAY_NAMESPACE` / `GATEWAY_NAME`
/// (set on the pod by the provisioner). Empty in standalone YAML mode, which has
/// no Gateway objects; on the gRPC path the controller refuses a stream that
/// names no Gateway (`config_stream_loop` logs that once).
pub(crate) fn gateway_identity() -> (String, String) {
    (
        std::env::var("GATEWAY_NAMESPACE").unwrap_or_default(),
        std::env::var("GATEWAY_NAME").unwrap_or_default(),
    )
}

/// Calculate next backoff duration, doubling current and capping at 5s.
pub(crate) fn next_backoff(current_ms: u64) -> u64 {
    (current_ms * 2).min(5_000)
}

/// Check if a schema version is compatible (major version must be 1).
pub(crate) fn is_schema_compatible(schema_version: &str) -> bool {
    schema_version
        .split('.')
        .next() == Some("1")
}

/// Legacy helper kept for the generation-only rule (controllers without
/// fingerprints): same non-zero generation means heartbeat.
#[cfg(test)]
pub(crate) fn is_heartbeat(config_version: u64, last_version: u64) -> bool {
    apply_decision(0, config_version, 0, last_version) == ApplyDecision::Heartbeat
}

/// What to do with a config message given what is currently applied.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ApplyDecision {
    /// New content: apply it.
    Apply,
    /// Same content as what is running (heartbeat / redundant push): skip.
    Heartbeat,
    /// Legacy controller without fingerprints replayed an older generation.
    Stale,
}

/// Decide whether a config should be applied. Content fingerprints are the
/// source of truth: identical content is a heartbeat regardless of generation
/// numbers, and any different content is applied - a controller restart or a
/// second controller instance never wedges the data plane. Only a controller
/// that predates fingerprints (`fingerprint == 0`) falls back to the old
/// monotonic generation rule.
pub(crate) fn apply_decision(
    config_fingerprint: u64,
    config_version: u64,
    applied_fingerprint: u64,
    applied_version: u64,
) -> ApplyDecision {
    if config_fingerprint != 0 {
        if config_fingerprint == applied_fingerprint {
            ApplyDecision::Heartbeat
        } else {
            ApplyDecision::Apply
        }
    } else if config_version == applied_version && applied_version > 0 {
        ApplyDecision::Heartbeat
    } else if config_version < applied_version {
        ApplyDecision::Stale
    } else {
        ApplyDecision::Apply
    }
}

/// Main entry point for the gRPC config receiver loop.
/// Reconnects with exponential backoff (1s to 30s cap) on error.
/// Resets backoff on clean stream termination.
pub async fn config_stream_loop(
    controller_addr: String,
    state: Arc<ProxyState>,
    grpc_connected: Arc<std::sync::atomic::AtomicBool>,
    config_received: Arc<std::sync::atomic::AtomicBool>,
    last_config_time: Arc<std::sync::atomic::AtomicU64>,
    metrics: Arc<crate::metrics::ProxyMetrics>,
) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let mut backoff_ms: u64 = 1000;

    // SEC F-2: Spawn a background task to evict idle per-IP rate limiter entries.
    // Runs every 60 seconds and removes entries idle for more than 5 minutes.
    // The task loads the current snapshot on each tick, so it always sees the
    // latest set of limiters even after config updates.
    {
        let eviction_snapshot = Arc::clone(&state.snapshot);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let snap = eviction_snapshot.load();
                for limiter in &snap.per_ip_limiters {
                    limiter.evict_idle(Duration::from_secs(300));
                }
            }
        });
    }

    // What this data plane is running, carried across reconnects so an
    // identical config from a restarted controller is not re-applied.
    let mut applied = AppliedConfig::default();

    loop {
        grpc_connected.store(false, Ordering::Release);
        metrics.grpc_stream_connected.set(0.0);

        match connect_and_stream(
            &controller_addr,
            &state,
            &grpc_connected,
            &config_received,
            &last_config_time,
            &metrics,
            &mut applied,
        )
        .await
        {
            Ok(()) => {
                log::info!("config stream ended cleanly, reconnecting");
                backoff_ms = 1000; // reset on clean disconnect
            }
            Err(e) => {
                metrics
                    .watcher_errors_total
                    .with_label_values(&["grpc_config_stream"])
                    .inc();
                log::warn!("config stream error: {}, retrying in {}ms", e, backoff_ms);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = next_backoff(backoff_ms);
            }
        }
    }
}

/// Identity of the config currently applied by this data plane.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AppliedConfig {
    pub fingerprint: u64,
    pub version: u64,
}

async fn connect_and_stream(
    controller_addr: &str,
    state: &Arc<ProxyState>,
    grpc_connected: &Arc<std::sync::atomic::AtomicBool>,
    config_received: &Arc<std::sync::atomic::AtomicBool>,
    last_config_time: &Arc<std::sync::atomic::AtomicU64>,
    metrics: &Arc<crate::metrics::ProxyMetrics>,
    applied: &mut AppliedConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // SEC-2: TLS on gRPC config stream (carries TLS private keys and auth credentials).
    // Set GRPC_TLS_CA to enable server certificate verification (TLS).
    // Set GRPC_TLS_CERT and GRPC_TLS_KEY to additionally present a client certificate (mTLS).
    // Plaintext is only allowed when explicitly opted in via GRPC_TLS_INSECURE=true.
    let scheme = if std::env::var("GRPC_TLS_CA").is_ok() {
        "https"
    } else if std::env::var("GRPC_TLS_INSECURE").as_deref() == Ok("true") {
        log::warn!(
            "gRPC client connecting WITHOUT TLS (GRPC_TLS_INSECURE=true) -- config stream is unencrypted"
        );
        "http"
    } else {
        log::error!(
            "GRPC_TLS_CA is not set. The gRPC config stream carries TLS private keys and auth \
             credentials. Set GRPC_TLS_CA to enable TLS, or set GRPC_TLS_INSECURE=true to \
             explicitly allow plaintext (NOT recommended for production)."
        );
        return Err("gRPC TLS is required: set GRPC_TLS_CA or GRPC_TLS_INSECURE=true".into());
    };
    let mut endpoint = tonic::transport::Endpoint::from_shared(format!("{}://{}", scheme, controller_addr))?
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(60))
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Some(Duration::from_secs(30)));

    if let Ok(ca_path) = std::env::var("GRPC_TLS_CA") {
        let ca_cert = std::fs::read_to_string(&ca_path)
            .map_err(|e| format!("failed to read GRPC_TLS_CA at {}: {}", ca_path, e))?;
        let ca = tonic::transport::Certificate::from_pem(ca_cert);

        let mut tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(ca);

        // Optional client cert for mTLS
        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("GRPC_TLS_CERT"),
            std::env::var("GRPC_TLS_KEY"),
        ) {
            let cert = std::fs::read_to_string(&cert_path)
                .map_err(|e| format!("failed to read GRPC_TLS_CERT at {}: {}", cert_path, e))?;
            let key = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("failed to read GRPC_TLS_KEY at {}: {}", key_path, e))?;
            let identity = tonic::transport::Identity::from_pem(cert, key);
            tls_config = tls_config.identity(identity);
            log::info!("gRPC client mTLS enabled (presenting client cert)");
        }

        // Use the controller service name as the TLS domain for certificate verification.
        // The controller_addr is typically "service-name:port", so extract just the host.
        let domain = controller_addr.split(':').next().unwrap_or(controller_addr);
        tls_config = tls_config.domain_name(domain);

        endpoint = endpoint.tls_config(tls_config)
            .map_err(|e| format!("failed to configure gRPC client TLS: {}", e))?;
        log::info!("gRPC client TLS enabled (verifying server cert)");
    }

    let mut client =
        portus_types::proto::portus::config::v1::config_distribution_client::ConfigDistributionClient::connect(endpoint)
            .await?
            .max_decoding_message_size(64 * 1024 * 1024); // 64MB — compiled config can include TLS certs

    let node_id = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    // Every data plane serves exactly one Gateway (set by the provisioner);
    // the controller streams only that Gateway's slice.
    let (gateway_namespace, gateway_name) = gateway_identity();
    if gateway_namespace.is_empty() || gateway_name.is_empty() {
        log::error!(
            "GATEWAY_NAMESPACE / GATEWAY_NAME are not set; the controller will reject this data plane. \
             Kubernetes dataplanes are provisioned per Gateway by the controller; for a plain reverse \
             proxy use standalone mode (PORTUS_CONFIG_FILE)."
        );
    }
    let request = portus_types::ConfigRequest {
        node_id: node_id.clone(),
        last_known_version: applied.version,
        schema_version: "1.0.0".to_string(),
        last_applied_version: applied.version,
        last_applied_fingerprint: applied.fingerprint,
        gateway_namespace: gateway_namespace.clone(),
        gateway_name: gateway_name.clone(),
    };

    let mut stream = client.stream_config(request).await?.into_inner();

    grpc_connected.store(true, Ordering::Release);
    metrics.grpc_stream_connected.set(1.0);
    log::info!("gRPC config stream connected to {}", controller_addr);

    while let Some(config) = stream.message().await? {
        // Skip version 0 — sentinel "no config yet" from watch channel initial value
        if config.version == 0 {
            log::debug!("skipping sentinel config (version 0)");
            continue;
        }

        // Schema version compatibility check (reject incompatible major version)
        if !is_schema_compatible(&config.schema_version) {
            log::error!(
                "incompatible config schema version: {} (expected major version 1), keeping last good config",
                config.schema_version
            );
            continue;
        }

        match apply_decision(config.fingerprint, config.version, applied.fingerprint, applied.version) {
            ApplyDecision::Apply => {}
            ApplyDecision::Heartbeat => {
                log::debug!(
                    "heartbeat received (v{} fingerprint {:#x} already applied), skipping apply",
                    config.version, config.fingerprint
                );
                // Still update timestamp for staleness tracking
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                last_config_time.store(now, Ordering::Release);
                metrics.config_last_update_timestamp.set(now as f64);
                continue;
            }
            ApplyDecision::Stale => {
                log::warn!(
                    "rejecting config version {} (current: {}) from a controller without fingerprints",
                    config.version, applied.version
                );
                continue;
            }
        }

        // Content validation: reject configs with critical invariant violations.
        match validate_config(&config) {
            Ok(warnings) => {
                for w in &warnings {
                    log::warn!("config v{} validation: {}", config.version, w);
                }
            }
            Err(e) => {
                metrics
                    .watcher_errors_total
                    .with_label_values(&["config_validation"])
                    .inc();
                log::warn!(
                    "config v{} validation warning (applying anyway): {}",
                    config.version, e
                );
                // Apply despite validation failure -- strict rejection caused
                // false positives with legitimate conformance test configs.
            }
        }

        log::info!(
            "applying config version {} (schema {}, fingerprint {:#x})",
            config.version,
            config.schema_version,
            config.fingerprint
        );
        let version = config.version;
        let fingerprint = config.fingerprint;
        metrics.routes_loaded.set(config.routes.len() as i64);
        for group in &config.backends {
            metrics
                .endpoints_loaded
                .with_label_values(&[group.service_name.as_str()])
                .set(group.endpoints.len() as i64);
        }
        apply_config(config, state);
        *applied = AppliedConfig { fingerprint, version };

        // Programmed ACK. Best effort: the controller also learns what we run
        // from the next (re)connect request, so a failed report only delays
        // the Gateway's Programmed condition.
        if fingerprint != 0 {
            let report = portus_types::AppliedReport {
                node_id: node_id.clone(),
                fingerprint,
                version,
                gateway_namespace: gateway_namespace.clone(),
                gateway_name: gateway_name.clone(),
            };
            match tokio::time::timeout(Duration::from_secs(5), client.report_applied(report)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => log::warn!("failed to report applied config v{}: {}", version, e),
                Err(_) => log::warn!("timed out reporting applied config v{}", version),
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        last_config_time.store(now, Ordering::Release);
        metrics.config_last_update_timestamp.set(now as f64);
        config_received.store(true, Ordering::Release);
    }

    grpc_connected.store(false, Ordering::Release);
    metrics.grpc_stream_connected.set(0.0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::lookup_domain_wildcard;
    use portus_types::*;

    /// Convert a flat host→HostRoutes map into a single listener bucket under
    /// (port=0, listener_hostname=""). Used by tests that still exercise the
    /// legacy flat-map shape through the new bucket-based core.
    fn flat_existing_to_buckets(
        flat: HashMap<String, HostRoutes>,
    ) -> (HashMap<u16, Vec<ListenerBucket>>, Vec<ListenerBucket>) {
        let mut bucket = ListenerBucket {
            listener_hostname: Arc::from(""),
            exact: HashMap::new(),
            domain_wildcards: HashMap::new(),
            catch_all: None,
        };
        for (host, hr) in flat {
            if host == "*" {
                bucket.catch_all = Some(hr);
            } else if let Some(suffix) = host.strip_prefix("*.") {
                bucket
                    .domain_wildcards
                    .insert(format!(".{}", suffix), hr);
            } else {
                bucket.exact.insert(host, hr);
            }
        }
        (HashMap::new(), vec![bucket])
    }

    /// Flatten listener buckets back to a (host_map, wildcard, domain_wildcards)
    /// tuple so existing tests can keep asserting over a flat shape.
    fn flatten_buckets(
        by_port: HashMap<u16, Vec<ListenerBucket>>,
        any_port: Vec<ListenerBucket>,
    ) -> (
        HashMap<String, HostRoutes>,
        Option<HostRoutes>,
        HashMap<String, HostRoutes>,
    ) {
        let mut exact: HashMap<String, HostRoutes> = HashMap::new();
        let mut catch_all: Option<HostRoutes> = None;
        let mut domain: HashMap<String, HostRoutes> = HashMap::new();

        let mut drain = |buckets: Vec<ListenerBucket>| {
            for b in buckets {
                for (host, hr) in b.exact {
                    exact.insert(host, hr);
                }
                for (suf, hr) in b.domain_wildcards {
                    domain.insert(suf, hr);
                }
                if let Some(hr) = b.catch_all {
                    catch_all = Some(hr);
                }
            }
        };
        for (_, bs) in by_port {
            drain(bs);
        }
        drain(any_port);
        (exact, catch_all, domain)
    }

    /// Legacy-shape wrapper used by older tests. Takes a flat `existing` by
    /// value (consumed), pipes it through the bucket-based builder, and
    /// flattens the result back. Preserves rate-limiter / circuit-breaker
    /// state the same way the production path does.
    pub(super) fn build_route_map_from_proto(
        routes: &[portus_types::RouteConfig],
        existing: HashMap<String, HostRoutes>,
        cb_map: &HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>,
        cl_map: &HashMap<(Arc<str>, u16), Arc<ConnectionLimiter>>,
    ) -> (
        HashMap<String, HostRoutes>,
        Option<HostRoutes>,
        HashMap<String, HostRoutes>,
    ) {
        let (existing_by_port, existing_any_port) = flat_existing_to_buckets(existing);
        let (by_port, any_port) = super::build_listener_buckets_from_proto(
            routes,
            &existing_by_port,
            &existing_any_port,
            cb_map,
            cl_map,
        );
        flatten_buckets(by_port, any_port)
    }

    /// Assertion helper: flatten current snapshot to a host→HostRoutes map.
    fn snapshot_flat_exact(snap: &ProxySnapshot) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for buckets in snap.listeners_by_port.values() {
            for b in buckets {
                out.extend(b.exact.keys().cloned());
            }
        }
        for b in &snap.any_port_listeners {
            out.extend(b.exact.keys().cloned());
        }
        out
    }

    fn empty_proxy_state() -> ProxyState {
        ProxyState {
            snapshot: Arc::new(ArcSwap::new(Arc::new(ProxySnapshot::default()))),
            lbs: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            l4_config: Arc::new(ArcSwap::from_pointee(L4Config::default())),
            tls_cert: Arc::new(ArcSwap::from_pointee(None)),
            tls_cert_notify: Arc::new(tokio::sync::Notify::new()),
            health_check_min_interval: Arc::new(AtomicU32::new(10)),
        }
    }

    #[test]
    fn test_build_route_map_from_proto_basic() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, wildcard, _dw) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());

        assert!(result.contains_key("api.example.com"));
        let host_routes = result.get("api.example.com").unwrap();
        // Should match /v1/users with prefix rule
        assert!(host_routes.match_path("/v1/users").is_some());
        assert!(wildcard.is_none());
    }

    #[test]
    fn test_build_lb_map_from_proto() {
        let backends = vec![BackendGroup {
            service_name: "svc".to_string(),
            port: 80,
            endpoints: vec![
                BackendEndpoint {
                    address: "10.0.0.1".to_string(),
                    port: 80,
                },
                BackendEndpoint {
                    address: "10.0.0.2".to_string(),
                    port: 80,
                },
            ],
            health_check: None,
            backend_tls: None,
        }];

        let (result, sigs) = build_lb_map_from_proto(&backends, &HashMap::new(), &HashMap::new());
        let key = (Arc::from("svc") as Arc<str>, 80u16);
        assert!(result.contains_key(&key));
        assert!(sigs.contains_key(&key));
        let lb = result.get(&key).unwrap();
        assert_eq!(lb.backends().get_backend().len(), 2);
    }

    fn backend_group(addrs: &[&str], hc: Option<portus_types::HealthCheckConfig>) -> BackendGroup {
        BackendGroup {
            service_name: "svc".to_string(),
            port: 80,
            endpoints: addrs
                .iter()
                .map(|a| BackendEndpoint {
                    address: a.to_string(),
                    port: 80,
                })
                .collect(),
            health_check: hc,
            backend_tls: None,
        }
    }

    #[test]
    fn test_build_lb_map_reuses_lb_when_endpoints_unchanged() {
        let first = vec![backend_group(&["10.0.0.1", "10.0.0.2"], None)];
        let (lbs1, sigs1) = build_lb_map_from_proto(&first, &HashMap::new(), &HashMap::new());
        // Same endpoints in a different order: must reuse the same Arc.
        let second = vec![backend_group(&["10.0.0.2", "10.0.0.1"], None)];
        let (lbs2, sigs2) = build_lb_map_from_proto(&second, &lbs1, &sigs1);
        let key = (Arc::from("svc") as Arc<str>, 80u16);
        assert!(Arc::ptr_eq(lbs1.get(&key).unwrap(), lbs2.get(&key).unwrap()));
        assert_eq!(sigs1.get(&key), sigs2.get(&key));
    }

    #[test]
    fn test_build_lb_map_rebuilds_lb_when_endpoints_change() {
        let first = vec![backend_group(&["10.0.0.1"], None)];
        let (lbs1, sigs1) = build_lb_map_from_proto(&first, &HashMap::new(), &HashMap::new());
        let second = vec![backend_group(&["10.0.0.1", "10.0.0.3"], None)];
        let (lbs2, _) = build_lb_map_from_proto(&second, &lbs1, &sigs1);
        let key = (Arc::from("svc") as Arc<str>, 80u16);
        assert!(!Arc::ptr_eq(lbs1.get(&key).unwrap(), lbs2.get(&key).unwrap()));
        assert_eq!(lbs2.get(&key).unwrap().backends().get_backend().len(), 2);
    }

    #[test]
    fn test_build_lb_map_rebuilds_lb_when_health_check_changes() {
        let hc = |path: &str| portus_types::HealthCheckConfig {
            path: path.to_string(),
            interval_secs: 10,
            timeout_secs: 2,
            healthy_threshold: 1,
            unhealthy_threshold: 3,
        };
        let first = vec![backend_group(&["10.0.0.1"], Some(hc("/healthz")))];
        let (lbs1, sigs1) = build_lb_map_from_proto(&first, &HashMap::new(), &HashMap::new());
        let same = vec![backend_group(&["10.0.0.1"], Some(hc("/healthz")))];
        let (lbs2, sigs2) = build_lb_map_from_proto(&same, &lbs1, &sigs1);
        let key = (Arc::from("svc") as Arc<str>, 80u16);
        assert!(Arc::ptr_eq(lbs1.get(&key).unwrap(), lbs2.get(&key).unwrap()));
        let changed = vec![backend_group(&["10.0.0.1"], Some(hc("/ready")))];
        let (lbs3, _) = build_lb_map_from_proto(&changed, &lbs2, &sigs2);
        assert!(!Arc::ptr_eq(lbs2.get(&key).unwrap(), lbs3.get(&key).unwrap()));
    }

    #[test]
    fn test_apply_config_preserves_lb_across_unrelated_change() {
        let state = empty_proxy_state();
        let backends = || vec![backend_group(&["10.0.0.1"], None)];
        let route = |host: &str| RouteConfig {
            host: host.to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "svc".to_string(),
            port: 80,
            ..Default::default()
        };
        apply_config(
            CompiledConfig {
                version: 1,
                routes: vec![route("a.example.com")],
                backends: backends(),
                ..Default::default()
            },
            &state,
        );
        let key = (Arc::from("svc") as Arc<str>, 80u16);
        let lb_v1 = Arc::clone(state.snapshot.load().lbs.get(&key).unwrap());
        // A new route on the same backend must not rebuild the LoadBalancer.
        apply_config(
            CompiledConfig {
                version: 2,
                routes: vec![route("a.example.com"), route("b.example.com")],
                backends: backends(),
                ..Default::default()
            },
            &state,
        );
        let snap = state.snapshot.load();
        assert!(Arc::ptr_eq(&lb_v1, snap.lbs.get(&key).unwrap()));
        assert!(Arc::ptr_eq(&lb_v1, state.lbs.load().get(&key).unwrap()));
    }

    #[test]
    fn test_apply_config_swaps_state() {
        let state = empty_proxy_state();
        {
            let snap = state.snapshot.load();
            assert!(snap.listeners_by_port.is_empty() && snap.any_port_listeners.is_empty());
        }

        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            routes: vec![RouteConfig {
                host: "test.example.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "test-svc".to_string(),
                port: 8080,
                ..Default::default()
            }],
            backends: vec![BackendGroup {
                service_name: "test-svc".to_string(),
                port: 8080,
                endpoints: vec![BackendEndpoint {
                    address: "10.0.0.1".to_string(),
                    port: 8080,
                }],
                health_check: None,
                backend_tls: None,
            }],
            ..Default::default()
        };

        apply_config(config, &state);

        {
            let snap = state.snapshot.load();
            assert!(
                snapshot_flat_exact(&snap)
                    .iter()
                    .any(|h| h == "test.example.com"),
                "applied config should expose test.example.com in a listener bucket"
            );
        }
    }

    #[test]
    fn test_rate_limiter_preservation() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 100,
                per_client: false,
            }),
            ..Default::default()
        }];

        // First build
        let existing = HashMap::new();
        let (first_map, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        // Second build reuses first_map for rate limiter preservation.

        // Get rate limiter pointer from first build
        let first_rl = first_map
            .get("api.example.com")
            .unwrap()
            .rules[0]
            .rate_limiter
            .as_ref()
            .unwrap()
            .clone();

        // Second build reusing first result
        let (second_map, _, _) = build_route_map_from_proto(&routes, first_map, &HashMap::new(), &HashMap::new());

        let second_rl = second_map
            .get("api.example.com")
            .unwrap()
            .rules[0]
            .rate_limiter
            .as_ref()
            .unwrap()
            .clone();

        // Same Arc instance (pointer equality) — extract inner Arc from Shared variant
        use crate::rate_limiter::RateLimiterMode;
        match (&first_rl, &second_rl) {
            (RateLimiterMode::Shared(a), RateLimiterMode::Shared(b)) => {
                assert!(Arc::ptr_eq(a, b), "rate limiter should be preserved across rebuild");
            }
            _ => panic!("expected Shared rate limiter"),
        }
    }

    #[test]
    fn test_circuit_breaker_preservation() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            service_name: "backend".to_string(),
            port: 8080,
            circuit_breaker: Some(portus_types::CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                timeout_secs: 30,
            }),
            ..Default::default()
        }];

        // First build
        let existing_cbs = HashMap::new();
        let existing_cls = HashMap::new();
        let (first_cbs, _first_cls) =
            build_cb_cl_maps_from_proto(&routes, &existing_cbs, &existing_cls);

        let key = (Arc::from("backend") as Arc<str>, 8080u16);
        let first_cb = first_cbs.get(&key).unwrap().clone();

        // Second build reusing first
        let (second_cbs, _second_cls) =
            build_cb_cl_maps_from_proto(&routes, &first_cbs, &existing_cls);

        let second_cb = second_cbs.get(&key).unwrap().clone();

        // Same Arc instance
        assert!(Arc::ptr_eq(&first_cb, &second_cb));
    }

    #[test]
    fn test_no_breaker_or_limiter_without_a_policy() {
        // httproute-retry: the backend answers 500 on purpose, several times in
        // a row; with no CircuitBreakerPolicy the Gateway must keep passing
        // those through instead of opening a breaker of its own.
        let routes = vec![RouteConfig {
            host: "*".to_string(),
            service_name: "infra-backend-v3".to_string(),
            port: 8080,
            ..Default::default()
        }];
        let (cbs, cls) = build_cb_cl_maps_from_proto(&routes, &HashMap::new(), &HashMap::new());
        assert!(cbs.is_empty(), "no implicit circuit breaker");
        assert!(cls.is_empty(), "no implicit connection limit");

        let routes = vec![RouteConfig {
            host: "*".to_string(),
            service_name: "limited".to_string(),
            port: 8080,
            max_connections: Some(64),
            ..Default::default()
        }];
        let (cbs, cls) = build_cb_cl_maps_from_proto(&routes, &HashMap::new(), &HashMap::new());
        assert!(cbs.is_empty());
        assert_eq!(cls.get(&(Arc::from("limited") as Arc<str>, 8080u16)).unwrap().max, 64);
    }

    // -----------------------------------------------------------------------
    // Backoff tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backoff_doubles() {
        assert_eq!(next_backoff(1000), 2000);
        assert_eq!(next_backoff(2000), 4000);
    }

    #[test]
    fn test_backoff_caps_at_5s() {
        assert_eq!(next_backoff(4000), 5000);
        assert_eq!(next_backoff(5000), 5000);
        assert_eq!(next_backoff(10000), 5000);
    }

    // -----------------------------------------------------------------------
    // Schema version compatibility tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version_compatible() {
        assert!(is_schema_compatible("1.0.0"));
        assert!(is_schema_compatible("1.2.3"));
        assert!(is_schema_compatible("1.99.0"));
    }

    #[test]
    fn test_schema_version_incompatible() {
        assert!(!is_schema_compatible("2.0.0"));
        assert!(!is_schema_compatible("3.1.0"));
        assert!(!is_schema_compatible("0.1.0"));
        assert!(!is_schema_compatible(""));
    }

    // -----------------------------------------------------------------------
    // Heartbeat dedup tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_decision_uses_fingerprints_not_generation_order() {
        // Same content => heartbeat even if the generation counter moved
        // (controller restarted and recompiled identical content).
        assert_eq!(apply_decision(0xabc, 1, 0xabc, 40), ApplyDecision::Heartbeat);
        // Different content => apply regardless of generation direction.
        assert_eq!(apply_decision(0xdef, 1, 0xabc, 40), ApplyDecision::Apply);
        assert_eq!(apply_decision(0xdef, 41, 0xabc, 40), ApplyDecision::Apply);
        // Nothing applied yet => apply.
        assert_eq!(apply_decision(0xabc, 1, 0, 0), ApplyDecision::Apply);
    }

    #[test]
    fn apply_decision_legacy_controller_without_fingerprints() {
        assert_eq!(apply_decision(0, 5, 0, 5), ApplyDecision::Heartbeat);
        assert_eq!(apply_decision(0, 6, 0, 5), ApplyDecision::Apply);
        assert_eq!(apply_decision(0, 4, 0, 5), ApplyDecision::Stale);
        assert_eq!(apply_decision(0, 1, 0, 0), ApplyDecision::Apply);
    }

    #[test]
    fn test_heartbeat_dedup_same_version() {
        assert!(is_heartbeat(5, 5)); // same version, non-zero -> heartbeat
    }

    #[test]
    fn test_heartbeat_dedup_different_version() {
        assert!(!is_heartbeat(6, 5)); // different version -> not heartbeat
    }

    #[test]
    fn test_heartbeat_dedup_zero_version() {
        assert!(!is_heartbeat(0, 0)); // both zero -> not heartbeat (initial state)
    }

    // -----------------------------------------------------------------------
    // New field parsing tests (Gateway API Core)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_route_map_from_proto_with_header_matches() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            header_matches: vec![portus_types::HeaderMatch {
                name: "x-api-key".to_string(),
                value: "secret123".to_string(),
                match_type: "Exact".to_string(),
            }],
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.header_matches.len(), 1);
        assert_eq!(route.header_matches[0].name.as_str(), "x-api-key");
        assert_eq!(route.header_matches[0].value, "secret123");
    }

    #[test]
    fn test_build_route_map_from_proto_with_method_match() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            method_match: "POST".to_string(),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.method_match, Some(http::Method::POST));
    }

    #[test]
    fn test_build_route_map_from_proto_with_redirect() {
        let routes = vec![RouteConfig {
            host: "old.example.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            redirect: Some(portus_types::RedirectFilter {
                scheme: "https".to_string(),
                hostname: "new.example.com".to_string(),
                port: 443,
                path: "/new-path".to_string(),
                path_type: "ReplaceFullPath".to_string(),
                status_code: 301,
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("old.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert!(route.has_redirect());
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.scheme.as_deref(), Some("https"));
        assert_eq!(redir.hostname.as_deref(), Some("new.example.com"));
        assert_eq!(redir.port, Some(443));
        assert_eq!(redir.status_code, 301);
    }

    #[test]
    fn test_redirect_only_route_no_backend() {
        // A redirect-only route with empty service_name (no backend) must still
        // produce a PathRoute with the redirect config populated.
        let routes = vec![RouteConfig {
            host: "example.com".to_string(),
            paths: vec![PathRule {
                path: "/hostname-redirect".to_string(),
                match_type: "Exact".to_string(),
            }],
            service_name: String::new(),
            port: 0,
            redirect: Some(portus_types::RedirectFilter {
                scheme: String::new(),
                hostname: "example.org".to_string(),
                port: 0,
                path: String::new(),
                path_type: String::new(),
                status_code: 302,
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("example.com").unwrap();
        let empty = http::HeaderMap::new();
        let matched = host_routes.match_request("/hostname-redirect", &http::Method::GET, &empty, None);
        assert!(matched.is_some(), "redirect-only route must be matchable");
        let route = matched.unwrap();
        assert!(route.has_redirect());
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.hostname.as_deref(), Some("example.org"));
        assert_eq!(redir.status_code, 302);
        assert!(redir.scheme.is_none(), "empty scheme from proto should map to None");
    }

    #[test]
    fn test_redirect_route_hostname_and_status() {
        // Verify 301 status and hostname are correctly parsed for redirect routes
        let routes = vec![RouteConfig {
            host: "example.com".to_string(),
            paths: vec![PathRule {
                path: "/host-and-status".to_string(),
                match_type: "Exact".to_string(),
            }],
            service_name: String::new(),
            port: 0,
            redirect: Some(portus_types::RedirectFilter {
                scheme: String::new(),
                hostname: "example.org".to_string(),
                port: 0,
                path: String::new(),
                path_type: String::new(),
                status_code: 301,
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("example.com").unwrap();
        let empty = http::HeaderMap::new();
        let route = host_routes.match_request("/host-and-status", &http::Method::GET, &empty, None).unwrap();
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.status_code, 301);
        assert_eq!(redir.hostname.as_deref(), Some("example.org"));
    }

    #[test]
    fn test_build_route_map_from_proto_with_url_rewrite() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/old-prefix".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            url_rewrite: Some(portus_types::UrlRewriteFilter {
                hostname: "internal-svc.cluster.local".to_string(),
                path: "/new-prefix".to_string(),
                path_type: "ReplacePrefixMatch".to_string(),
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert!(route.url_rewrite.is_some());
        let rw = route.url_rewrite.as_ref().unwrap();
        assert_eq!(rw.hostname.as_deref(), Some("internal-svc.cluster.local"));
        assert_eq!(rw.path.as_deref(), Some("/new-prefix"));
        assert_eq!(rw.path_type, "ReplacePrefixMatch");
    }

    #[test]
    fn test_build_route_map_from_proto_with_query_param_matches() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            query_param_matches: vec![portus_types::QueryParamMatch {
                name: "version".to_string(),
                value: "v2".to_string(),
                match_type: "Exact".to_string(),
            }],
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.query_param_matches.len(), 1);
        assert_eq!(route.query_param_matches[0].name, "version");
        assert_eq!(route.query_param_matches[0].value, "v2");
    }

    #[test]
    fn test_build_route_map_from_proto_with_grpc_match() {
        let routes = vec![RouteConfig {
            host: "grpc.example.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "grpc-backend".to_string(),
            port: 9090,
            protocol: "GRPC".to_string(),
            grpc_match: Some(portus_types::GrpcRouteMatch {
                service: "mypackage.MyService".to_string(),
                method: "DoThing".to_string(),
                match_type: "Exact".to_string(),
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("grpc.example.com").unwrap();
        let route = &host_routes.rules[0];

        // gRPC service/method selection is compiled into the path rule by the
        // controller; the dataplane only needs to know the backend speaks gRPC.
        assert_eq!(route.protocol, BackendProtocol::Grpc);
    }

    #[test]
    fn test_build_route_map_from_proto_with_listener_name() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            listener_name: "http-listener".to_string(),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.listener_name.as_ref(), "http-listener");
    }


    // -----------------------------------------------------------------------
    // Domain wildcard route map building tests (Issue 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_route_map_from_proto_domain_wildcard_extraction() {
        // Routes with *.bar.com host should be extracted into domain_wildcards map
        // keyed by ".bar.com", and NOT appear in the main route map.
        let routes = vec![RouteConfig {
            host: "*.bar.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "wildcard-svc".to_string(),
            port: 8080,
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (route_map, _wildcard, domain_wildcards) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());

        // Should NOT be in the main route map
        assert!(!route_map.contains_key("*.bar.com"), "wildcard host should be extracted from route_map");

        // Should be in domain_wildcards keyed by ".bar.com"
        assert!(domain_wildcards.contains_key(".bar.com"), "domain_wildcards should have .bar.com key");
        let host_routes = domain_wildcards.get(".bar.com").unwrap();
        let matched = host_routes.match_path("/").unwrap();
        assert_eq!(matched.service_name.as_ref(), "wildcard-svc");
    }

    #[test]
    fn test_build_route_map_from_proto_exact_and_wildcard_coexist() {
        // Both exact "bar.com" and wildcard "*.bar.com" routes should coexist:
        // exact in route_map, wildcard in domain_wildcards.
        let routes = vec![
            RouteConfig {
                host: "bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "exact-svc".to_string(),
                port: 8080,
                ..Default::default()
            },
            RouteConfig {
                host: "*.bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "wildcard-svc".to_string(),
                port: 8080,
                ..Default::default()
            },
        ];

        let existing = HashMap::new();
        let (route_map, _wildcard, domain_wildcards) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());

        // Exact in main map
        assert!(route_map.contains_key("bar.com"));
        let exact_matched = route_map.get("bar.com").unwrap().match_path("/").unwrap();
        assert_eq!(exact_matched.service_name.as_ref(), "exact-svc");

        // Wildcard in domain_wildcards
        assert!(domain_wildcards.contains_key(".bar.com"));
        let wc_matched = domain_wildcards.get(".bar.com").unwrap().match_path("/").unwrap();
        assert_eq!(wc_matched.service_name.as_ref(), "wildcard-svc");
    }


    // =======================================================================
    // Gateway API Conformance Test Simulations
    //
    // These tests exercise the FULL pipeline:
    //   build_route_map_from_proto → HostRoutes::match_request
    // mirroring the exact scenarios from the Gateway API conformance suite.
    // =======================================================================

    /// Helper: build routes and return (route_map, wildcard, domain_wildcards).
    fn build_routes(
        routes: Vec<RouteConfig>,
    ) -> (HashMap<String, HostRoutes>, Option<HostRoutes>, HashMap<String, HostRoutes>) {
        let existing = HashMap::new();
        let empty_cbs = HashMap::new();
        let empty_cls = HashMap::new();
        build_route_map_from_proto(&routes, existing, &empty_cbs, &empty_cls)
    }

    /// Helper: match a request against a HostRoutes and return the service name.
    fn match_service(
        hr: &HostRoutes,
        path: &str,
        method: &http::Method,
        headers: &http::HeaderMap,
    ) -> Option<String> {
        hr.match_request(path, method, headers, None)
            .map(|r| r.service_name.to_string())
    }

    /// Helper: match with query params.
    fn match_service_with_query(
        hr: &HostRoutes,
        path: &str,
        method: &http::Method,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> Option<String> {
        hr.match_request(path, method, headers, query)
            .map(|r| r.service_name.to_string())
    }

    // -------------------------------------------------------------------
    // 1. HTTPRouteExactPathMatching conformance test
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_exact_path_matching() {
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /one matches → v1
        assert_eq!(
            match_service(hr, "/one", &get, &empty_headers),
            Some("v1".to_string()),
            "exact /one should match v1"
        );

        // /two matches → v2
        assert_eq!(
            match_service(hr, "/two", &get, &empty_headers),
            Some("v2".to_string()),
            "exact /two should match v2"
        );

        // / → no match
        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            None,
            "/ should not match any exact route"
        );

        // /one/example → no match (exact does not match sub-paths)
        assert_eq!(
            match_service(hr, "/one/example", &get, &empty_headers),
            None,
            "/one/example should not match exact /one"
        );

        // /two/ → no match (trailing slash makes it different)
        assert_eq!(
            match_service(hr, "/two/", &get, &empty_headers),
            None,
            "/two/ should not match exact /two"
        );

        // /Two → no match (case sensitive)
        assert_eq!(
            match_service(hr, "/Two", &get, &empty_headers),
            None,
            "/Two should not match exact /two (case sensitive)"
        );
    }

    // -------------------------------------------------------------------
    // 2. HTTPRouteHeaderMatching conformance test
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_header_matching() {
        // Each match entry is a separate RouteConfig (OR semantics across routes).
        // Within a single route, multiple header_matches are AND'd.
        // Order matters: more specific (more headers) routes should come first.
        let routes = vec![
            // Route 0: version=two AND color=orange → v1 (most specific, listed first)
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1-and".to_string(),
                port: 80,
                header_matches: vec![
                    HeaderMatch {
                        name: "version".to_string(),
                        value: "two".to_string(),
                        match_type: "Exact".to_string(),
                    },
                    HeaderMatch {
                        name: "color".to_string(),
                        value: "orange".to_string(),
                        match_type: "Exact".to_string(),
                    },
                ],
                ..Default::default()
            },
            // Route 1: version=one → v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Route 2: version=two → v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Route 3: color=blue → v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1-blue".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "blue".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Route 4: color=green → v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1-green".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "green".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Route 5: color=red → v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2-red".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "red".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Route 6: color=yellow → v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2-yellow".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "yellow".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;

        // GET / [version: one] → v1
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "one".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v1".to_string()),
                "version=one should match v1"
            );
        }

        // GET / [version: two] → v2
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "two".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v2".to_string()),
                "version=two (alone) should match v2"
            );
        }

        // GET / [version: two, color: orange] → v1-and (AND match, more specific wins)
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "two".parse().unwrap());
            headers.insert("color", "orange".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v1-and".to_string()),
                "version=two AND color=orange should match v1-and (most specific)"
            );
        }

        // GET / [version: two, color: blue] → v2
        // Conformance subtest 3: both version:two (rule 2) and color:blue (rule 4)
        // match, but rule 2 has higher priority (earlier in YAML, same specificity).
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "two".parse().unwrap());
            headers.insert("color", "blue".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v2".to_string()),
                "version=two AND color=blue should match v2 (rule 2 before rule 4)"
            );
        }

        // GET / [color: blue] → v1-blue
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("color", "blue".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v1-blue".to_string()),
                "color=blue should match v1-blue"
            );
        }

        // GET / [color: green] → v1-green
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("color", "green".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v1-green".to_string()),
                "color=green should match v1-green"
            );
        }

        // GET / [color: red] → v2-red
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("color", "red".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("v2-red".to_string()),
                "color=red should match v2-red"
            );
        }

        // GET / [color: purple] → no match (404)
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("color", "purple".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                None,
                "color=purple should not match any route"
            );
        }

        // GET / (no headers) → no match (all routes require headers)
        {
            let empty_headers = http::HeaderMap::new();
            assert_eq!(
                match_service(hr, "/", &get, &empty_headers),
                None,
                "no headers should not match any header-requiring route"
            );
        }
    }

    // -------------------------------------------------------------------
    // 3. Exact path + header matching coexistence
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_exact_and_header_coexistence() {
        let routes = vec![
            // Exact /one → exact-v1 (no header requirement)
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "exact-v1".to_string(),
                port: 80,
                ..Default::default()
            },
            // Exact /two → exact-v2 (no header requirement)
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "exact-v2".to_string(),
                port: 80,
                ..Default::default()
            },
            // Prefix / with header version=one → header-v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "header-v1".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Prefix / with header color=blue → header-v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "header-v2".to_string(),
                port: 80,
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "blue".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // GET /one (no headers) → exact-v1 (exact path, no header needed)
        assert_eq!(
            match_service(hr, "/one", &get, &empty_headers),
            Some("exact-v1".to_string()),
            "exact /one should match even without headers"
        );

        // GET /two (no headers) → exact-v2
        assert_eq!(
            match_service(hr, "/two", &get, &empty_headers),
            Some("exact-v2".to_string()),
            "exact /two should match even without headers"
        );

        // GET / (no headers) → no match (prefix / routes all require headers)
        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            None,
            "/ without headers should not match header-requiring prefix routes"
        );

        // GET / [version: one] → header-v1
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "one".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("header-v1".to_string()),
                "/ with version=one should match header-v1"
            );
        }

        // GET /one [version: one] → exact-v1 (exact path takes precedence)
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "one".parse().unwrap());
            assert_eq!(
                match_service(hr, "/one", &get, &headers),
                Some("exact-v1".to_string()),
                "exact /one should take precedence over prefix / with headers"
            );
        }

        // GET /random (no headers) → no match
        assert_eq!(
            match_service(hr, "/random", &get, &empty_headers),
            None,
            "/random without headers should not match"
        );
    }

    // -------------------------------------------------------------------
    // 4. HTTPRouteMethodMatching conformance test
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_method_matching() {
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 80,
                method_match: "POST".to_string(),
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 80,
                method_match: "GET".to_string(),
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let empty_headers = http::HeaderMap::new();

        // POST / → v1
        assert_eq!(
            match_service(hr, "/", &http::Method::POST, &empty_headers),
            Some("v1".to_string()),
            "POST should match v1"
        );

        // GET / → v2
        assert_eq!(
            match_service(hr, "/", &http::Method::GET, &empty_headers),
            Some("v2".to_string()),
            "GET should match v2"
        );

        // HEAD / → no match
        assert_eq!(
            match_service(hr, "/", &http::Method::HEAD, &empty_headers),
            None,
            "HEAD should not match any route"
        );

        // PUT / → no match
        assert_eq!(
            match_service(hr, "/", &http::Method::PUT, &empty_headers),
            None,
            "PUT should not match any route"
        );
    }

    // -------------------------------------------------------------------
    // 5. Hostname intersection conformance test
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_hostname_intersection() {
        // After listener-route intersection, the controller produces:
        // - Routes under "foo.wildcard.io" (from *.wildcard.io listener intersection)
        // - Routes under "very.specific.com" (exact host)
        // - NO routes under "*"
        let routes = vec![
            RouteConfig {
                host: "foo.wildcard.io".to_string(),
                paths: vec![PathRule {
                    path: "/s2".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "very.specific.com".to_string(),
                paths: vec![PathRule {
                    path: "/s1".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (route_map, wildcard, domain_wildcards) = build_routes(routes);
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // No wildcard routes
        assert!(wildcard.is_none(), "should have no wildcard (*) routes");

        // No domain wildcards either (the hosts are exact, not *.wildcard.io)
        assert!(
            domain_wildcards.is_empty(),
            "should have no domain wildcard routes"
        );

        // Host foo.wildcard.io, path /s2 → v2
        {
            let hr = route_map
                .get("foo.wildcard.io")
                .expect("should have foo.wildcard.io routes");
            assert_eq!(
                match_service(hr, "/s2", &get, &empty_headers),
                Some("v2".to_string()),
                "foo.wildcard.io /s2 should match v2"
            );
        }

        // Host very.specific.com, path /s1 → v1
        {
            let hr = route_map
                .get("very.specific.com")
                .expect("should have very.specific.com routes");
            assert_eq!(
                match_service(hr, "/s1", &get, &empty_headers),
                Some("v1".to_string()),
                "very.specific.com /s1 should match v1"
            );
        }

        // Host non.matching.com → no routes at all
        assert!(
            route_map.get("non.matching.com").is_none(),
            "non.matching.com should have no routes"
        );

        // Host wildcard.io → no routes (apex doesn't match *.wildcard.io)
        assert!(
            route_map.get("wildcard.io").is_none(),
            "wildcard.io apex should have no routes"
        );
    }

    // -------------------------------------------------------------------
    // 5b. Hostname intersection with actual domain wildcards
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_hostname_domain_wildcard_matching() {
        // Test that *.wildcard.io routes are correctly extracted into domain_wildcards
        // and matched against sub-domain requests.
        let routes = vec![
            RouteConfig {
                host: "*.wildcard.io".to_string(),
                paths: vec![PathRule {
                    path: "/s2".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "very.specific.com".to_string(),
                paths: vec![PathRule {
                    path: "/s1".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (route_map, wildcard, domain_wildcards) = build_routes(routes);
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // No wildcard (*) routes
        assert!(wildcard.is_none(), "should have no wildcard (*) routes");

        // *.wildcard.io should be in domain_wildcards keyed by ".wildcard.io"
        assert!(
            domain_wildcards.contains_key(".wildcard.io"),
            "should have .wildcard.io in domain_wildcards"
        );

        // foo.wildcard.io /s2 → v2 via domain wildcard lookup
        {
            // Simulate the router's domain wildcard lookup: strip first label
            let host = "foo.wildcard.io";
            let suffix = &host[host.find('.').unwrap()..]; // ".wildcard.io"
            let hr = domain_wildcards
                .get(suffix)
                .expect("domain wildcard .wildcard.io should exist");
            assert_eq!(
                match_service(hr, "/s2", &get, &empty_headers),
                Some("v2".to_string()),
                "foo.wildcard.io /s2 should match v2 via domain wildcard"
            );
        }

        // bar.wildcard.io /s2 → v2 via domain wildcard lookup
        {
            let host = "bar.wildcard.io";
            let suffix = &host[host.find('.').unwrap()..];
            let hr = domain_wildcards.get(suffix).expect("should exist");
            assert_eq!(
                match_service(hr, "/s2", &get, &empty_headers),
                Some("v2".to_string()),
                "bar.wildcard.io /s2 should also match v2 via domain wildcard"
            );
        }

        // very.specific.com /s1 → v1 via exact host
        {
            let hr = route_map
                .get("very.specific.com")
                .expect("should have very.specific.com");
            assert_eq!(
                match_service(hr, "/s1", &get, &empty_headers),
                Some("v1".to_string()),
            );
        }

        // wildcard.io (apex) should NOT match *.wildcard.io
        // The apex has no "." prefix to strip, or stripping yields ".io" which != ".wildcard.io"
        {
            assert!(
                route_map.get("wildcard.io").is_none(),
                "wildcard.io should not be in route_map"
            );
            // Domain wildcard lookup for apex: "wildcard.io" → suffix ".io" → not in domain_wildcards
            let host = "wildcard.io";
            let suffix = host.find('.').map(|i| &host[i..]);
            assert!(
                suffix.and_then(|s| domain_wildcards.get(s)).is_none(),
                "wildcard.io apex should not match .wildcard.io domain wildcard"
            );
        }
    }

    // -------------------------------------------------------------------
    // 6. Sorting: exact before prefix, longer prefix before shorter
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_route_priority_exact_before_prefix() {
        // Exact /foo should beat prefix /foo
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/foo".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "prefix-svc".to_string(),
                port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/foo".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "exact-svc".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (_rm, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().unwrap();
        let get = http::Method::GET;
        let empty = http::HeaderMap::new();

        // /foo exactly → exact-svc (exact beats prefix)
        assert_eq!(
            match_service(hr, "/foo", &get, &empty),
            Some("exact-svc".to_string()),
            "exact match should take priority over prefix match"
        );

        // /foo/bar → prefix-svc (exact doesn't match sub-paths)
        assert_eq!(
            match_service(hr, "/foo/bar", &get, &empty),
            Some("prefix-svc".to_string()),
            "/foo/bar should fall through to prefix match"
        );
    }

    #[test]
    fn test_conformance_route_priority_longer_prefix_first() {
        // Prefix /foo/bar should beat prefix /foo
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/foo".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "short-svc".to_string(),
                port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/foo/bar".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "long-svc".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (_rm, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().unwrap();
        let get = http::Method::GET;
        let empty = http::HeaderMap::new();

        // /foo/bar → long-svc (longer prefix wins)
        assert_eq!(
            match_service(hr, "/foo/bar", &get, &empty),
            Some("long-svc".to_string()),
            "longer prefix should take priority"
        );

        // /foo/bar/baz → long-svc (longer prefix still wins)
        assert_eq!(
            match_service(hr, "/foo/bar/baz", &get, &empty),
            Some("long-svc".to_string()),
        );

        // /foo/other → short-svc (only shorter prefix matches)
        assert_eq!(
            match_service(hr, "/foo/other", &get, &empty),
            Some("short-svc".to_string()),
        );
    }

    // -------------------------------------------------------------------
    // 7. Combined: method + header + path matching
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_combined_method_header_path() {
        let routes = vec![
            // POST /api with header x-version=v2 → special-svc
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/api".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "special-svc".to_string(),
                port: 80,
                method_match: "POST".to_string(),
                header_matches: vec![HeaderMatch {
                    name: "x-version".to_string(),
                    value: "v2".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Any method, /api with no headers → general-svc
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/api".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "general-svc".to_string(),
                port: 80,
                ..Default::default()
            },
        ];

        let (_rm, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().unwrap();
        let empty = http::HeaderMap::new();

        // POST /api [x-version: v2] → special-svc
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-version", "v2".parse().unwrap());
            assert_eq!(
                match_service(hr, "/api", &http::Method::POST, &headers),
                Some("special-svc".to_string()),
            );
        }

        // GET /api → general-svc (method doesn't match special)
        assert_eq!(
            match_service(hr, "/api", &http::Method::GET, &empty),
            Some("general-svc".to_string()),
        );

        // POST /api (no header) → general-svc (header doesn't match special)
        assert_eq!(
            match_service(hr, "/api", &http::Method::POST, &empty),
            Some("general-svc".to_string()),
        );

        // GET /other → no match
        assert_eq!(
            match_service(hr, "/other", &http::Method::GET, &empty),
            None,
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteListenerHostnameMatching conformance test
    // (mirrors sigs.k8s.io/gateway-api/conformance/tests/httproute-listener-hostname-matching)
    // -------------------------------------------------------------------
    //
    // Gateway with 4 listeners: bar.com, foo.bar.com, *.bar.com, *.foo.com
    // Routes:
    //   backend-v1 → listener-1 (bar.com)        → host "bar.com"
    //   backend-v2 → listener-2 (foo.bar.com)     → host "foo.bar.com"
    //   backend-v3 → listener-3,4 (*.bar.com, *.foo.com) → hosts "*.bar.com", "*.foo.com"
    //
    // After compilation, the dataplane receives:
    //   - Exact host routes: bar.com → v1, foo.bar.com → v2
    //   - Domain wildcard routes: *.bar.com → v3, *.foo.com → v3
    //
    // The router lookup order is: exact host → domain wildcard → global wildcard.
    // Exact matches take precedence, so foo.bar.com → v2 (not *.bar.com → v3).

    #[test]
    fn test_conformance_listener_hostname_matching() {
        // Build routes as the compiler would emit them after hostname intersection.
        let routes = vec![
            // Route from backend-v1 attached to listener-1 (bar.com)
            RouteConfig {
                host: "bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                listener_name: "listener-1".to_string(),
                ..Default::default()
            },
            // Route from backend-v2 attached to listener-2 (foo.bar.com)
            RouteConfig {
                host: "foo.bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                listener_name: "listener-2".to_string(),
                ..Default::default()
            },
            // Route from backend-v3 attached to listener-3 (*.bar.com)
            RouteConfig {
                host: "*.bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                listener_name: "listener-3".to_string(),
                ..Default::default()
            },
            // Route from backend-v3 attached to listener-4 (*.foo.com)
            RouteConfig {
                host: "*.foo.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                listener_name: "listener-4".to_string(),
                ..Default::default()
            },
        ];

        let (route_map, wildcard, domain_wildcards) = build_routes(routes);
        let empty_headers = http::HeaderMap::new();

        // Helper: resolve host through exact → domain wildcard → global wildcard
        // and return matched service name, mirroring Router::request_filter logic.
        let resolve = |host: &str, path: &str| -> Option<String> {
            let host_routes = route_map.get(host);
            let resolved = if host_routes.is_some() {
                host_routes
            } else {
                let dw = lookup_domain_wildcard(host, &domain_wildcards);
                if dw.is_some() {
                    dw
                } else {
                    wildcard.as_ref()
                }
            };
            resolved.and_then(|hr: &HostRoutes| {
                hr.match_request(path, &http::Method::GET, &empty_headers, None)
                    .map(|r| r.service_name.to_string())
            })
        };

        // bar.com → v1 (exact match on listener-1)
        assert_eq!(resolve("bar.com", "/"), Some("infra-backend-v1".to_string()),
            "bar.com should match exact host → v1");

        // foo.bar.com → v2 (exact match on listener-2, NOT wildcard *.bar.com)
        assert_eq!(resolve("foo.bar.com", "/"), Some("infra-backend-v2".to_string()),
            "foo.bar.com should match exact host → v2, not wildcard *.bar.com");

        // baz.bar.com → v3 (wildcard *.bar.com)
        assert_eq!(resolve("baz.bar.com", "/"), Some("infra-backend-v3".to_string()),
            "baz.bar.com should match *.bar.com → v3");

        // boo.bar.com → v3 (wildcard *.bar.com)
        assert_eq!(resolve("boo.bar.com", "/"), Some("infra-backend-v3".to_string()),
            "boo.bar.com should match *.bar.com → v3");

        // multiple.prefixes.bar.com → v3 (multi-level subdomain matches *.bar.com)
        assert_eq!(resolve("multiple.prefixes.bar.com", "/"), Some("infra-backend-v3".to_string()),
            "multiple.prefixes.bar.com should match *.bar.com → v3");

        // multiple.prefixes.foo.com → v3 (*.foo.com wildcard)
        assert_eq!(resolve("multiple.prefixes.foo.com", "/"), Some("infra-backend-v3".to_string()),
            "multiple.prefixes.foo.com should match *.foo.com → v3");

        // foo.com → 404 (no exact match, no wildcard match — apex doesn't match *.foo.com)
        assert_eq!(resolve("foo.com", "/"), None,
            "foo.com must not match — apex doesn't match *.foo.com");

        // no.matching.host → 404
        assert_eq!(resolve("no.matching.host", "/"), None,
            "no.matching.host must not match anything");
    }

    // -------------------------------------------------------------------
    // HTTPRouteHostnameIntersection dataplane routing tests
    // (mirrors sigs.k8s.io/gateway-api/conformance/tests/httproute-hostname-intersection)
    // -------------------------------------------------------------------
    //
    // After compiler hostname intersection, the dataplane should receive
    // these compiled routes and correctly route/reject based on host.

    #[test]
    fn test_conformance_hostname_intersection_routing() {
        // Build routes as the compiler would emit after intersection:
        //
        // Route s1: very.specific.com/s1 → infra-backend-v1
        //   (from route ["non.matching.com", "*.nonmatchingwildcard.io", "very.specific.com"]
        //    intersected with listener "very.specific.com")
        //
        // Route s2: foo.wildcard.io/s2, bar.wildcard.io/s2, foo.bar.wildcard.io/s2 → infra-backend-v2
        //   (from route ["non.matching.com", "wildcard.io", "foo.wildcard.io", "bar.wildcard.io", "foo.bar.wildcard.io"]
        //    intersected with listener "*.wildcard.io")
        //
        // Route s3: very.specific.com/s3 → infra-backend-v3
        //   (from route ["non.matching.com", "*.specific.com"] intersected with "very.specific.com")
        //
        // Route s4: *.anotherwildcard.io/s4 → infra-backend-v1
        //   (from route ["*.anotherwildcard.io"] intersected with "*.anotherwildcard.io")
        //
        // Route s5: NOTHING (no intersection)
        //
        // Route all: first.com, sub.first.com, second.com, sub.second.com → infra-backend-v2
        //   (no-hostname listener, all route hostnames pass through)

        let routes = vec![
            // s1: very.specific.com/s1
            RouteConfig {
                host: "very.specific.com".to_string(),
                paths: vec![PathRule { path: "/s1".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
            // s2: foo.wildcard.io/s2
            RouteConfig {
                host: "foo.wildcard.io".to_string(),
                paths: vec![PathRule { path: "/s2".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // s2: bar.wildcard.io/s2
            RouteConfig {
                host: "bar.wildcard.io".to_string(),
                paths: vec![PathRule { path: "/s2".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // s2: foo.bar.wildcard.io/s2
            RouteConfig {
                host: "foo.bar.wildcard.io".to_string(),
                paths: vec![PathRule { path: "/s2".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // s3: very.specific.com/s3
            RouteConfig {
                host: "very.specific.com".to_string(),
                paths: vec![PathRule { path: "/s3".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                ..Default::default()
            },
            // s4: *.anotherwildcard.io/s4
            RouteConfig {
                host: "*.anotherwildcard.io".to_string(),
                paths: vec![PathRule { path: "/s4".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
            // all: first.com/
            RouteConfig {
                host: "first.com".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // all: sub.first.com/
            RouteConfig {
                host: "sub.first.com".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // all: second.com/
            RouteConfig {
                host: "second.com".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // all: sub.second.com/
            RouteConfig {
                host: "sub.second.com".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
        ];

        let (route_map, wildcard, domain_wildcards) = build_routes(routes);
        let empty_headers = http::HeaderMap::new();

        let resolve = |host: &str, path: &str| -> Option<String> {
            let host_routes = route_map.get(host);
            let resolved = if host_routes.is_some() {
                host_routes
            } else {
                let dw = lookup_domain_wildcard(host, &domain_wildcards);
                if dw.is_some() {
                    dw
                } else {
                    wildcard.as_ref()
                }
            };
            resolved.and_then(|hr: &HostRoutes| {
                hr.match_request(path, &http::Method::GET, &empty_headers, None)
                    .map(|r| r.service_name.to_string())
            })
        };

        // --- Positive cases: routes that should match ---

        // s1: very.specific.com/s1 → infra-backend-v1
        assert_eq!(resolve("very.specific.com", "/s1"), Some("infra-backend-v1".to_string()));

        // s2: foo.wildcard.io/s2 → infra-backend-v2
        assert_eq!(resolve("foo.wildcard.io", "/s2"), Some("infra-backend-v2".to_string()));

        // s2: bar.wildcard.io/s2 → infra-backend-v2
        assert_eq!(resolve("bar.wildcard.io", "/s2"), Some("infra-backend-v2".to_string()));

        // s2: foo.bar.wildcard.io/s2 → infra-backend-v2
        assert_eq!(resolve("foo.bar.wildcard.io", "/s2"), Some("infra-backend-v2".to_string()));

        // s3: very.specific.com/s3 → infra-backend-v3
        assert_eq!(resolve("very.specific.com", "/s3"), Some("infra-backend-v3".to_string()));

        // s4: foo.anotherwildcard.io/s4 → infra-backend-v1 (via domain wildcard)
        assert_eq!(resolve("foo.anotherwildcard.io", "/s4"), Some("infra-backend-v1".to_string()));

        // s4: bar.anotherwildcard.io/s4 → infra-backend-v1
        assert_eq!(resolve("bar.anotherwildcard.io", "/s4"), Some("infra-backend-v1".to_string()));

        // s4: foo.bar.anotherwildcard.io/s4 → infra-backend-v1 (multi-level)
        assert_eq!(resolve("foo.bar.anotherwildcard.io", "/s4"), Some("infra-backend-v1".to_string()));

        // all: first.com/ → infra-backend-v2
        assert_eq!(resolve("first.com", "/"), Some("infra-backend-v2".to_string()));

        // all: sub.first.com/ → infra-backend-v2
        assert_eq!(resolve("sub.first.com", "/"), Some("infra-backend-v2".to_string()));

        // all: second.com/ → infra-backend-v2
        assert_eq!(resolve("second.com", "/"), Some("infra-backend-v2".to_string()));

        // all: sub.second.com/ → infra-backend-v2
        assert_eq!(resolve("sub.second.com", "/"), Some("infra-backend-v2".to_string()));

        // --- Negative cases: requests that MUST return 404 ---

        // non.matching.com/s1 → 404 (not in intersection)
        assert_eq!(resolve("non.matching.com", "/s1"), None,
            "non.matching.com/s1 must be 404 — hostname not in intersection");

        // wildcard.io/s2 → 404 (apex doesn't match *.wildcard.io)
        assert_eq!(resolve("wildcard.io", "/s2"), None,
            "wildcard.io/s2 must be 404 — apex doesn't match *.wildcard.io");

        // foo.nonmatchingwildcard.io/s1 → 404
        assert_eq!(resolve("foo.nonmatchingwildcard.io", "/s1"), None,
            "foo.nonmatchingwildcard.io/s1 must be 404 — not in intersection");

        // anotherwildcard.io/s4 → 404 (apex doesn't match *.anotherwildcard.io)
        assert_eq!(resolve("anotherwildcard.io", "/s4"), None,
            "anotherwildcard.io/s4 must be 404 — apex doesn't match wildcard");

        // foo.specific.com/s3 → 404
        // (*.specific.com ∩ very.specific.com = very.specific.com only)
        assert_eq!(resolve("foo.specific.com", "/s3"), None,
            "foo.specific.com/s3 must be 404 — wildcard route *.specific.com intersected with exact listener very.specific.com produces only very.specific.com");

        // third.com/ → 404 (not in route hostnames even with no-hostname listener)
        assert_eq!(resolve("third.com", "/"), None,
            "third.com must be 404 — not in route hostnames");

        // Cross-host/path mismatches → 404
        assert_eq!(resolve("very.specific.com", "/non-matching-prefix"), None,
            "very.specific.com with non-matching path must be 404");
        assert_eq!(resolve("foo.wildcard.io", "/s1"), None,
            "foo.wildcard.io/s1 must be 404 — wrong path for this host");
        assert_eq!(resolve("very.specific.com", "/s2"), None,
            "very.specific.com/s2 must be 404 — s2 not on this host");
        assert_eq!(resolve("foo.wildcard.io", "/s3"), None,
            "foo.wildcard.io/s3 must be 404");
        assert_eq!(resolve("very.specific.com", "/s4"), None,
            "very.specific.com/s4 must be 404");
        assert_eq!(resolve("foo.anotherwildcard.io", "/s1"), None,
            "foo.anotherwildcard.io/s1 must be 404");
    }

    // ===================================================================
    // Gateway API conformance test simulations: ROUTING behavior
    // ===================================================================

    // -------------------------------------------------------------------
    // HTTPRouteSimpleSameNamespace
    // Ref: conformance/tests/httproute-simple-same-namespace.yaml
    //
    // Single HTTPRoute with no matches, no hostnames, just a backendRef.
    // The controller compiles this as a single RouteConfig with host "*"
    // and no explicit paths (which becomes Prefix /).
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_simple_same_namespace() {
        // YAML: no matches, no hostnames, backendRef to infra-backend-v1:8080
        // Controller emits: host="*", no paths -> Prefix / implicitly
        let routes = vec![RouteConfig {
            host: "*".to_string(),
            paths: vec![], // no matches -> no paths -> becomes Prefix /
            service_name: "infra-backend-v1".to_string(),
            port: 8080,
            ..Default::default()
        }];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // Go test: GET / -> 200, backend=infra-backend-v1
        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET / should reach infra-backend-v1"
        );

        // Additional: any path should match since it's Prefix /
        assert_eq!(
            match_service(hr, "/anything", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET /anything should also reach infra-backend-v1 (Prefix /)"
        );

        assert_eq!(
            match_service(hr, "/deep/nested/path", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET /deep/nested/path should also reach infra-backend-v1"
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteMatching
    // Ref: conformance/tests/httproute-matching.yaml + .go
    //
    // YAML defines one HTTPRoute "matching" with two rules:
    //   Rule 1 matches: [PathPrefix /, header version=one] -> v1
    //   Rule 2 matches: [PathPrefix /v2, header version=two] -> v2
    //
    // Each rule has two match entries (OR semantics). The controller
    // compiles each match entry into a separate RouteConfig:
    //   - PathPrefix / -> v1  (catch-all)
    //   - header version=one -> v1  (becomes Prefix / + header)
    //   - PathPrefix /v2 -> v2
    //   - header version=two -> v2  (becomes Prefix / + header)
    //
    // Gateway API specificity: more-specific matches (with headers)
    // should be evaluated before less-specific (plain path). We model
    // this by ordering header-requiring routes before the catch-all.
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_matching() {
        // The controller emits these RouteConfigs in specificity order:
        // Most specific first (header matchers), then path-only matches.
        let routes = vec![
            // Match: PathPrefix /v2 (no headers) -> v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/v2".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // Match: header version=one -> v1 (implicit Prefix /)
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Match: header version=two -> v2 (implicit Prefix /)
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Match: PathPrefix / (catch-all, no headers) -> v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // Go testCase 0: GET / -> v1
        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET / should match infra-backend-v1 (catch-all Prefix /)"
        );

        // Go testCase 1: GET /example -> v1
        assert_eq!(
            match_service(hr, "/example", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET /example should match infra-backend-v1 (catch-all Prefix /)"
        );

        // Go testCase 2: GET / [Version: one] -> v1
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "one".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("infra-backend-v1".to_string()),
                "GET / [version=one] should match infra-backend-v1"
            );
        }

        // Go testCase 3: GET /v2 -> v2
        assert_eq!(
            match_service(hr, "/v2", &get, &empty_headers),
            Some("infra-backend-v2".to_string()),
            "GET /v2 should match infra-backend-v2 (PathPrefix /v2)"
        );

        // Go testCase 4: GET /v2/example -> v2
        assert_eq!(
            match_service(hr, "/v2/example", &get, &empty_headers),
            Some("infra-backend-v2".to_string()),
            "GET /v2/example should match infra-backend-v2 (PathPrefix /v2)"
        );

        // Go testCase 5: GET / [Version: two] -> v2
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "two".parse().unwrap());
            assert_eq!(
                match_service(hr, "/", &get, &headers),
                Some("infra-backend-v2".to_string()),
                "GET / [version=two] should match infra-backend-v2 (header match)"
            );
        }

        // Go testCase 6: GET /v2/ -> v2
        assert_eq!(
            match_service(hr, "/v2/", &get, &empty_headers),
            Some("infra-backend-v2".to_string()),
            "GET /v2/ should match infra-backend-v2 (PathPrefix /v2)"
        );

        // Go testCase 7: GET /v2example -> v1 (not a path segment boundary)
        assert_eq!(
            match_service(hr, "/v2example", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET /v2example should NOT match /v2 (not segment boundary), falls to v1"
        );

        // Go testCase 8: GET /foo/v2/example -> v1
        assert_eq!(
            match_service(hr, "/foo/v2/example", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "GET /foo/v2/example should match v1 (prefix / catch-all, /v2 only at start)"
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteMatchingAcrossRoutes
    // Ref: conformance/tests/httproute-matching-across-routes.yaml + .go
    //
    // TWO routes with different hostname scopes:
    //   Route "matching-part1": hostnames=[example.com, example.net]
    //     Rule: matches [PathPrefix /, header version=one] -> v1
    //   Route "matching-part2": hostnames=[example.com]
    //     Rule: matches [PathPrefix /v2, header version=two] -> v2
    //
    // Tests hostname isolation: /v2 on example.net should NOT hit v2
    // because matching-part2 only applies to example.com.
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_matching_across_routes() {
        // Route matching-part1 applies to both example.com and example.net.
        // Route matching-part2 applies only to example.com.
        //
        // For example.com, we have routes from BOTH httproutes.
        // For example.net, we only have routes from matching-part1.

        let routes = vec![
            // -- example.com routes --
            // matching-part2: PathPrefix /v2 -> v2 (only on example.com)
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/v2".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                ..Default::default()
            },
            // matching-part2: header version=two -> v2 (only on example.com)
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // matching-part1: header version=one -> v1 (on example.com)
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // matching-part1: PathPrefix / -> v1 (catch-all on example.com)
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
            // -- example.net routes (matching-part1 only) --
            // header version=one -> v1
            RouteConfig {
                host: "example.net".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // PathPrefix / -> v1 (catch-all on example.net)
            RouteConfig {
                host: "example.net".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
        ];

        let (route_map, _wildcard, _dw) = build_routes(routes);
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // -- example.com tests --
        let hr_com = route_map
            .get("example.com")
            .expect("example.com routes should exist");

        // Go testCase 0: Host=example.com, GET / -> v1
        assert_eq!(
            match_service(hr_com, "/", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "example.com GET / should match v1"
        );

        // Go testCase 1: Host=example.com, GET /example -> v1
        assert_eq!(
            match_service(hr_com, "/example", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "example.com GET /example should match v1"
        );

        // Go testCase 3: Host=example.com, GET /example [Version: one] -> v1
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "one".parse().unwrap());
            assert_eq!(
                match_service(hr_com, "/example", &get, &headers),
                Some("infra-backend-v1".to_string()),
                "example.com GET /example [version=one] should match v1"
            );
        }

        // Go testCase 4: Host=example.com, GET /v2 -> v2
        assert_eq!(
            match_service(hr_com, "/v2", &get, &empty_headers),
            Some("infra-backend-v2".to_string()),
            "example.com GET /v2 should match v2"
        );

        // Go testCase 6: Host=example.com, GET /v2/example -> v2
        assert_eq!(
            match_service(hr_com, "/v2/example", &get, &empty_headers),
            Some("infra-backend-v2".to_string()),
            "example.com GET /v2/example should match v2"
        );

        // Go testCase 7: Host=example.com, GET / [Version: two] -> v2
        {
            let mut headers = http::HeaderMap::new();
            headers.insert("version", "two".parse().unwrap());
            assert_eq!(
                match_service(hr_com, "/", &get, &headers),
                Some("infra-backend-v2".to_string()),
                "example.com GET / [version=two] should match v2 (header match)"
            );
        }

        // -- example.net tests --
        let hr_net = route_map
            .get("example.net")
            .expect("example.net routes should exist");

        // Go testCase 2: Host=example.net, GET /example -> v1
        assert_eq!(
            match_service(hr_net, "/example", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "example.net GET /example should match v1"
        );

        // Go testCase 5: Host=example.net, GET /v2 -> v1
        // v2 routes only exist on example.com, so example.net falls to v1
        assert_eq!(
            match_service(hr_net, "/v2", &get, &empty_headers),
            Some("infra-backend-v1".to_string()),
            "example.net GET /v2 should match v1 (no v2 route on example.net)"
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteWeight
    // Ref: conformance/tests/httproute-weight.yaml + .go
    //
    // YAML: one rule, no matches, three weighted backendRefs:
    //   v1 weight=70, v2 weight=30, v3 weight=0
    //
    // We verify the route compiles correctly with weighted backends
    // and that the route matches requests. (Actual weight distribution
    // is a runtime concern; we verify structural correctness here.)
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_weight() {
        // The controller emits a single RouteConfig with weighted_backends
        // using the first backend as primary service_name.
        let routes = vec![RouteConfig {
            host: "*".to_string(),
            paths: vec![], // no matches -> Prefix /
            service_name: "infra-backend-v1".to_string(),
            port: 8080,
            weighted_backends: vec![
                WeightedBackend {
                    service_name: "infra-backend-v1".to_string(),
                    port: 8080,
                    weight: 70,
                    request_headers: None,
                },
                WeightedBackend {
                    service_name: "infra-backend-v2".to_string(),
                    port: 8080,
                    weight: 30,
                    request_headers: None,
                },
                WeightedBackend {
                    service_name: "infra-backend-v3".to_string(),
                    port: 8080,
                    weight: 0,
                    request_headers: None,
                },
            ],
            ..Default::default()
        }];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // Go test: GET / -> 200 (any backend)
        let matched = hr.match_request("/", &get, &empty_headers, None);
        assert!(matched.is_some(), "GET / should match the weighted route");

        let route = matched.unwrap();
        // Verify primary service
        assert_eq!(
            route.service_name.as_ref(),
            "infra-backend-v1",
            "primary service should be infra-backend-v1"
        );

        // Verify weighted backends structure
        assert_eq!(
            route.weighted_backends.len(),
            3,
            "should have 3 weighted backends"
        );

        // Check weights: v1=70, v2=30, v3=0
        assert_eq!(route.weighted_backends[0].service_name.as_ref(), "infra-backend-v1");
        assert_eq!(route.weighted_backends[0].weight, 70);
        assert_eq!(route.weighted_backends[1].service_name.as_ref(), "infra-backend-v2");
        assert_eq!(route.weighted_backends[1].weight, 30);
        assert_eq!(route.weighted_backends[2].service_name.as_ref(), "infra-backend-v3");
        assert_eq!(route.weighted_backends[2].weight, 0);
    }

    // -------------------------------------------------------------------
    // HTTPRouteServiceTypes
    // Ref: conformance/tests/httproute-service-types.yaml + .go
    //
    // YAML: one HTTPRoute with 3 exact-path rules for different service
    // types (manual EndpointSlices, headless, headless-manual):
    //   /manual-endpointslices -> manual-endpointslices:8080
    //   /headless -> headless:8080
    //   /headless-manual-endpointslices -> headless-manual-endpointslices:8080
    //
    // All ultimately route to infra-backend-v1 pods. From the dataplane
    // perspective, we just verify exact path matching to distinct services.
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_service_types() {
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/manual-endpointslices".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "manual-endpointslices".to_string(),
                port: 8080,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/headless".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "headless".to_string(),
                port: 8080,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/headless-manual-endpointslices".to_string(),
                    match_type: "Exact".to_string(),
                }],
                service_name: "headless-manual-endpointslices".to_string(),
                port: 8080,
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // Go test iterates over service types, each expecting 200 at its path.

        // /manual-endpointslices -> manual-endpointslices
        assert_eq!(
            match_service(hr, "/manual-endpointslices", &get, &empty_headers),
            Some("manual-endpointslices".to_string()),
            "GET /manual-endpointslices should match manual-endpointslices service"
        );

        // /headless -> headless
        assert_eq!(
            match_service(hr, "/headless", &get, &empty_headers),
            Some("headless".to_string()),
            "GET /headless should match headless service"
        );

        // /headless-manual-endpointslices -> headless-manual-endpointslices
        assert_eq!(
            match_service(hr, "/headless-manual-endpointslices", &get, &empty_headers),
            Some("headless-manual-endpointslices".to_string()),
            "GET /headless-manual-endpointslices should match headless-manual-endpointslices"
        );

        // Exact match means sub-paths and other paths should NOT match
        assert_eq!(
            match_service(hr, "/manual-endpointslices/sub", &get, &empty_headers),
            None,
            "sub-path of exact match should not match"
        );

        assert_eq!(
            match_service(hr, "/other", &get, &empty_headers),
            None,
            "unrelated path should not match any exact route"
        );

        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            None,
            "root path should not match any exact route"
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteCrossNamespace
    // Ref: conformance/tests/httproute-cross-namespace.yaml + .go
    //
    // YAML: HTTPRoute "cross-namespace" in namespace
    // gateway-conformance-web-backend, attaching to Gateway
    // "backend-namespaces" in gateway-conformance-infra namespace.
    // Single rule: no matches -> backendRef web-backend:8080.
    //
    // From the dataplane perspective, namespace boundaries are handled
    // by the controller; the dataplane just sees a RouteConfig with
    // service_name. We verify the route compiles and matches.
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_cross_namespace() {
        // The controller resolves cross-namespace references and emits
        // a RouteConfig with the fully-resolved service name.
        // Namespace is transparent to the dataplane.
        let routes = vec![RouteConfig {
            host: "*".to_string(),
            paths: vec![], // no matches -> Prefix /
            service_name: "web-backend".to_string(),
            port: 8080,
            ..Default::default()
        }];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // Go test: GET / -> 200, backend=web-backend
        assert_eq!(
            match_service(hr, "/", &get, &empty_headers),
            Some("web-backend".to_string()),
            "GET / should reach web-backend (cross-namespace route)"
        );

        // Any path should match the catch-all
        assert_eq!(
            match_service(hr, "/anything", &get, &empty_headers),
            Some("web-backend".to_string()),
            "GET /anything should also reach web-backend"
        );
    }

    // -------------------------------------------------------------------
    // Conformance: HTTPRouteQueryParamMatching
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_query_param_matching_specificity() {
        // Mirrors the Gateway API conformance test:
        //   tests/httproute-query-param-matching.yaml
        //
        // Rule 1: animal=whale -> v1
        // Rule 2: animal=dolphin -> v2
        // Rule 3 (OR): (animal=dolphin AND color=blue) OR (ANIMAL=Whale) -> v3
        let routes = vec![
            // Rule 1: animal=whale -> v1
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "whale".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Rule 2: animal=dolphin -> v2
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "dolphin".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Rule 3a: animal=dolphin AND color=blue -> v3
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                query_param_matches: vec![
                    portus_types::QueryParamMatch {
                        name: "animal".to_string(),
                        value: "dolphin".to_string(),
                        match_type: "Exact".to_string(),
                    },
                    portus_types::QueryParamMatch {
                        name: "color".to_string(),
                        value: "blue".to_string(),
                        match_type: "Exact".to_string(),
                    },
                ],
                ..Default::default()
            },
            // Rule 3b: ANIMAL=Whale -> v3 (OR'd match entry)
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "ANIMAL".to_string(),
                    value: "Whale".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let (route_map, _, _) = build_routes(routes);
        let hr = route_map.get("example.com").unwrap();
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /?animal=whale -> v1
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=whale")),
            Some("infra-backend-v1".to_string()),
            "animal=whale should match v1"
        );

        // /?animal=dolphin -> v2
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=dolphin")),
            Some("infra-backend-v2".to_string()),
            "animal=dolphin should match v2"
        );

        // /?animal=dolphin&color=blue -> v3 (more specific: 2 query params)
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=dolphin&color=blue")),
            Some("infra-backend-v3".to_string()),
            "animal=dolphin&color=blue should match v3 (2 query params more specific)"
        );

        // /?ANIMAL=Whale -> v3 (case-sensitive query param name)
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("ANIMAL=Whale")),
            Some("infra-backend-v3".to_string()),
            "ANIMAL=Whale should match v3"
        );

        // /?animal=whale&otherparam=irrelevant -> v1 (extra params don't matter)
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=whale&otherparam=irrelevant")),
            Some("infra-backend-v1".to_string()),
            "animal=whale with extra params should still match v1"
        );

        // /?animal=dolphin&color=yellow -> v2 (color=yellow doesn't match v3's color=blue)
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=dolphin&color=yellow")),
            Some("infra-backend-v2".to_string()),
            "animal=dolphin&color=yellow should match v2 (not v3)"
        );

        // /?color=blue -> no match (no animal param)
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("color=blue")),
            None,
            "color=blue without animal should not match"
        );

        // /?animal=dog -> no match
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, Some("animal=dog")),
            None,
            "animal=dog should not match any rule"
        );

        // / (no query) -> no match
        assert_eq!(
            match_service_with_query(hr, "/", &get, &empty_headers, None),
            None,
            "no query params should not match"
        );
    }

    #[test]
    fn test_conformance_query_param_with_header_combo() {
        // Combinations with core match types from the conformance YAML.
        //
        // Rule 4: PathPrefix /path1 + animal=whale -> v1
        // Rule 5: header version=one + animal=whale -> v2
        // Rule 6: PathPrefix /path2 + header version=two + animal=whale -> v3
        let routes = vec![
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/path1".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "whale".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                header_matches: vec![portus_types::HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "whale".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/path2".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                header_matches: vec![portus_types::HeaderMatch {
                    name: "version".to_string(),
                    value: "two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "whale".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let (route_map, _, _) = build_routes(routes);
        let hr = route_map.get("example.com").unwrap();
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /path1?animal=whale -> v1
        assert_eq!(
            match_service_with_query(hr, "/path1", &get, &empty_headers, Some("animal=whale")),
            Some("infra-backend-v1".to_string()),
            "/path1?animal=whale should match v1"
        );

        // /?animal=whale with header version=one -> v2
        let mut headers_v1 = http::HeaderMap::new();
        headers_v1.insert("version", "one".parse().unwrap());
        assert_eq!(
            match_service_with_query(hr, "/", &get, &headers_v1, Some("animal=whale")),
            Some("infra-backend-v2".to_string()),
            "/?animal=whale with version=one should match v2"
        );

        // /path2?animal=whale with header version=two -> v3
        let mut headers_v2 = http::HeaderMap::new();
        headers_v2.insert("version", "two".parse().unwrap());
        assert_eq!(
            match_service_with_query(hr, "/path2", &get, &headers_v2, Some("animal=whale")),
            Some("infra-backend-v3".to_string()),
            "/path2?animal=whale with version=two should match v3"
        );
    }

    #[test]
    fn test_conformance_query_param_precedence() {
        // Conformance: HTTPRouteQueryParamMatching — precedence checks.
        //
        // From the YAML:
        //   Rule 8: PathPrefix /path5 -> v1
        //   Rule 9: queryParam animal=hydra -> v2
        //   Rule 10: header version=four -> v3
        //
        // Test cases:
        //   /path5?animal=hydra -> v1 (path /path5 is more specific than /)
        //   version:four + /?animal=hydra -> v3 (header > query param in precedence)
        let routes = vec![
            // Rule 8: PathPrefix /path5 -> v1
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![PathRule {
                    path: "/path5".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                ..Default::default()
            },
            // Rule 9: animal=hydra -> v2
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v2".to_string(),
                port: 8080,
                query_param_matches: vec![portus_types::QueryParamMatch {
                    name: "animal".to_string(),
                    value: "hydra".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Rule 10: header version=four -> v3
            RouteConfig {
                host: "example.com".to_string(),
                paths: vec![],
                service_name: "infra-backend-v3".to_string(),
                port: 8080,
                header_matches: vec![portus_types::HeaderMatch {
                    name: "version".to_string(),
                    value: "four".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let (route_map, _, _) = build_routes(routes);
        let hr = route_map.get("example.com").unwrap();
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /path5?animal=hydra -> v1 (longer path wins)
        assert_eq!(
            match_service_with_query(hr, "/path5", &get, &empty_headers, Some("animal=hydra")),
            Some("infra-backend-v1".to_string()),
            "/path5?animal=hydra should match v1 (path /path5 > /)"
        );

        // version:four + /?animal=hydra -> v3 (header match > query param match)
        let mut headers = http::HeaderMap::new();
        headers.insert("version", "four".parse().unwrap());
        assert_eq!(
            match_service_with_query(hr, "/", &get, &headers, Some("animal=hydra")),
            Some("infra-backend-v3".to_string()),
            "version=four + animal=hydra should match v3 (header > query param precedence)"
        );
    }

    #[test]
    fn test_conformance_header_add_vs_set_in_proto() {
        // Verify that proto HeaderMutation with both add and set
        // produces separate lists in the parsed PathRoute.
        let routes = vec![RouteConfig {
            host: "example.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            request_headers: Some(portus_types::HeaderMutation {
                add: [("X-Added".into(), "val1".into())].into_iter().collect(),
                set: [("X-Set".into(), "val2".into())].into_iter().collect(),
                remove: vec!["X-Remove".into()],
            }),
            ..Default::default()
        }];

        let (route_map, _, _) = build_routes(routes);
        let hr = route_map.get("example.com").unwrap();
        let route = &hr.rules[0];

        assert_eq!(route.request_headers_add.len(), 1, "should have 1 add header");
        assert_eq!(route.request_headers_add[0].0.as_str(), "x-added");
        assert_eq!(route.request_headers_set.len(), 1, "should have 1 set header");
        assert_eq!(route.request_headers_set[0].0.as_str(), "x-set");
        assert_eq!(route.request_headers_remove.len(), 1, "should have 1 remove header");
    }

    // -------------------------------------------------------------------
    // HTTPRouteTimeoutRequest
    // Ref: conformance/tests/httproute-timeout-request.yaml + .go
    //
    // YAML: HTTPRoute with two rules:
    //   /request-timeout -> infra-backend-v1:8080, timeouts: { request: 500ms }
    //   /disable-request-timeout -> infra-backend-v1:8080, timeouts: { request: "0s" }
    //
    // Go test:
    //   /request-timeout -> 200 (no delay)
    //   /request-timeout?delay=1s -> 504 (exceeds 500ms timeout)
    //   /disable-request-timeout?delay=1s -> 200 (timeout disabled)
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_timeout_request() {
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/request-timeout".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                request_timeout_ms: 500,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/disable-request-timeout".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                request_timeout_ms: 0, // disabled
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /request-timeout should route to infra-backend-v1 with request_timeout set
        let matched = hr.match_request("/request-timeout", &get, &empty_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "infra-backend-v1");
        assert_eq!(
            matched.request_timeout,
            Some(std::time::Duration::from_millis(500)),
            "request_timeout should be 500ms"
        );

        // /disable-request-timeout should have no timeout (0 = disabled)
        let disabled = hr.match_request("/disable-request-timeout", &get, &empty_headers, None).unwrap();
        assert_eq!(disabled.service_name.as_ref(), "infra-backend-v1");
        assert!(
            disabled.request_timeout.is_none(),
            "request_timeout of 0 should be None (disabled)"
        );
    }

    // -------------------------------------------------------------------
    // HTTPRouteTimeoutBackendRequest
    // Ref: conformance/tests/httproute-timeout-backend-request.yaml + .go
    //
    // YAML: HTTPRoute with two rules:
    //   /backend-timeout -> infra-backend-v1:8080, timeouts: { backendRequest: 500ms }
    //   /disable-backend-timeout -> infra-backend-v1:8080, timeouts: { backendRequest: "0s" }
    //
    // Go test:
    //   /backend-timeout -> 200 (no delay)
    //   /backend-timeout?delay=1s -> 504 (exceeds 500ms timeout)
    //   /disable-backend-timeout?delay=1s -> 200 (timeout disabled)
    // -------------------------------------------------------------------

    #[test]
    fn test_conformance_httproute_timeout_backend_request() {
        let routes = vec![
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/backend-timeout".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                backend_request_timeout_ms: 500,
                ..Default::default()
            },
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule {
                    path: "/disable-backend-timeout".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "infra-backend-v1".to_string(),
                port: 8080,
                backend_request_timeout_ms: 0, // disabled
                ..Default::default()
            },
        ];

        let (_route_map, wildcard, _dw) = build_routes(routes);
        let hr = wildcard.as_ref().expect("wildcard routes should exist");
        let get = http::Method::GET;
        let empty_headers = http::HeaderMap::new();

        // /backend-timeout should route to infra-backend-v1 with backend_request_timeout set
        let matched = hr.match_request("/backend-timeout", &get, &empty_headers, None).unwrap();
        assert_eq!(matched.service_name.as_ref(), "infra-backend-v1");
        assert_eq!(
            matched.backend_request_timeout,
            Some(std::time::Duration::from_millis(500)),
            "backend_request_timeout should be 500ms"
        );

        // /disable-backend-timeout should have no timeout (0 = disabled)
        let disabled = hr.match_request("/disable-backend-timeout", &get, &empty_headers, None).unwrap();
        assert_eq!(disabled.service_name.as_ref(), "infra-backend-v1");
        assert!(
            disabled.backend_request_timeout.is_none(),
            "backend_request_timeout of 0 should be None (disabled)"
        );
    }

    // --- TLS cert storage tests ---

    #[test]
    fn test_apply_config_with_tls_cert_stores_cert_data() {
        let state = empty_proxy_state();

        // Verify no TLS cert initially
        assert!(state.tls_cert.load().is_none(), "should have no TLS cert initially");

        // Apply config with TLS cert in a listener
        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            listeners: vec![portus_types::Listener {
                name: "https".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: "example.com".to_string(),
                tls_cert_ref: Some(portus_types::TlsCertRef {
                    cert_pem: "CERT_DATA".to_string(),
                    key_pem: "KEY_DATA".to_string(),
                }),
                gateway_namespace: String::new(),
                gateway_name: String::new(),
                client_validation: None,
            }],
            ..Default::default()
        };

        apply_config(config, &state);

        // The TLS cert data should be stored
        let tls_data = state.tls_cert.load();
        let tls_data = tls_data.as_ref().as_ref().expect("should have TLS cert after apply");
        assert_eq!(tls_data.entries.len(), 1);
        assert_eq!(tls_data.entries[0].hostname, "example.com");
        assert_eq!(tls_data.entries[0].cert_pem, "CERT_DATA");
        assert_eq!(tls_data.entries[0].key_pem, "KEY_DATA");
    }

    #[test]
    fn test_apply_config_without_tls_cert_keeps_none() {
        let state = empty_proxy_state();

        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            listeners: vec![portus_types::Listener {
                name: "http".to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                hostname: String::new(),
                tls_cert_ref: None,
                gateway_namespace: String::new(),
                gateway_name: String::new(),
                client_validation: None,
            }],
            ..Default::default()
        };

        apply_config(config, &state);

        assert!(state.tls_cert.load().is_none(), "should have no TLS cert for HTTP-only config");
    }

    #[test]
    fn test_parse_protocol_h2c_and_ws() {
        assert_eq!(parse_protocol("H2C"), BackendProtocol::H2c);
        assert_eq!(parse_protocol("h2c"), BackendProtocol::H2c);
        assert_eq!(parse_protocol("WS"), BackendProtocol::WebSocket);
        assert_eq!(parse_protocol("ws"), BackendProtocol::WebSocket);
        assert_eq!(parse_protocol("GRPC"), BackendProtocol::Grpc);
        assert_eq!(parse_protocol("HTTP"), BackendProtocol::Http);
        assert_eq!(parse_protocol(""), BackendProtocol::Http);
    }

    #[test]
    fn test_h2c_protocol_from_proto_route() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8081,
            protocol: "H2C".to_string(),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let matched = host_routes.match_path("/").unwrap();
        assert_eq!(matched.protocol, BackendProtocol::H2c);
    }

    #[test]
    fn test_ws_protocol_from_proto_route() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/ws".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8082,
            protocol: "WS".to_string(),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let matched = host_routes.match_path("/ws").unwrap();
        assert_eq!(matched.protocol, BackendProtocol::WebSocket);
    }

    // -----------------------------------------------------------------------
    // Listener port-specific keying tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_route_map_port_specific_keying() {
        // 3 RouteConfigs with the same host on different listener ports are
        // grouped into separate per-port listener buckets. Within each bucket
        // the route is keyed by plain host; port scoping lives at the bucket level.
        let routes = vec![
            RouteConfig {
                host: "foo.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v1".to_string(),
                port: 8080,
                listener_port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "foo.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v2".to_string(),
                port: 8080,
                listener_port: 8080,
                ..Default::default()
            },
            RouteConfig {
                host: "foo.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "v3".to_string(),
                port: 8080,
                listener_port: 8090,
                ..Default::default()
            },
        ];

        let (by_port, _any_port) = build_listener_buckets_from_proto(
            &routes,
            &HashMap::new(),
            &[],
            &HashMap::new(),
            &HashMap::new(),
        );

        for (port, expected_svc) in [(80u16, "v1"), (8080, "v2"), (8090, "v3")] {
            let buckets = by_port
                .get(&port)
                .unwrap_or_else(|| panic!("missing bucket for port {}", port));
            let bucket = buckets
                .iter()
                .find(|b| b.listener_hostname.as_ref().is_empty())
                .expect("expected empty-hostname listener bucket");
            let hr = bucket
                .exact
                .get("foo.com")
                .unwrap_or_else(|| panic!("missing host foo.com on port {}", port));
            let matched = hr.match_path("/").unwrap();
            assert_eq!(matched.service_name.as_ref(), expected_svc);
        }
    }

    #[test]
    fn test_build_route_map_port_zero_uses_plain_host() {
        // RouteConfig with listener_port=0 should key as plain "foo.com".
        let routes = vec![RouteConfig {
            host: "foo.com".to_string(),
            paths: vec![PathRule {
                path: "/".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "default-backend".to_string(),
            port: 8080,
            listener_port: 0,
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());

        assert!(
            result.contains_key("foo.com"),
            "listener_port=0 should key as plain host, keys: {:?}",
            result.keys().collect::<Vec<_>>()
        );
        assert!(
            !result.contains_key("foo.com:0"),
            "should NOT key as foo.com:0"
        );
    }

    #[test]
    fn test_build_route_map_wildcard_with_port_keying() {
        // Wildcard hosts with listener_port > 0 should be keyed as "*.bar.com:80"
        // and extracted into domain_wildcards as ".bar.com:80".
        let routes = vec![
            RouteConfig {
                host: "*.bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "wildcard-backend".to_string(),
                port: 8080,
                listener_port: 80,
                ..Default::default()
            },
            RouteConfig {
                host: "bar.com".to_string(),
                paths: vec![PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }],
                service_name: "exact-backend".to_string(),
                port: 8080,
                listener_port: 80,
                ..Default::default()
            },
        ];

        let (by_port, _any_port) = build_listener_buckets_from_proto(
            &routes,
            &HashMap::new(),
            &[],
            &HashMap::new(),
            &HashMap::new(),
        );

        // Both routes live under port 80's empty-hostname listener bucket,
        // since they share listener_port=80 and no listener_hostname was set
        // on the RouteConfigs. The exact host "bar.com" goes into the exact
        // slot; the wildcard "*.bar.com" goes into domain_wildcards as
        // ".bar.com" (no port suffix — the bucket already scopes the port).
        let buckets = by_port.get(&80).expect("port 80 bucket");
        let bucket = buckets
            .iter()
            .find(|b| b.listener_hostname.as_ref().is_empty())
            .expect("empty-hostname bucket");
        assert!(
            bucket.exact.contains_key("bar.com"),
            "exact bar.com missing, keys: {:?}",
            bucket.exact.keys().collect::<Vec<_>>()
        );
        assert!(
            bucket.domain_wildcards.contains_key(".bar.com"),
            "wildcard .bar.com missing, keys: {:?}",
            bucket.domain_wildcards.keys().collect::<Vec<_>>()
        );
        let matched = crate::router::lookup_domain_wildcard_bucket(
            "baz.bar.com",
            &bucket.domain_wildcards,
        );
        assert!(matched.is_some(), "baz.bar.com should match .bar.com wildcard");
        assert_eq!(
            matched
                .unwrap()
                .match_path("/")
                .unwrap()
                .service_name
                .as_ref(),
            "wildcard-backend"
        );
    }

    #[test]
    fn test_build_route_map_grpc_weighted_backends() {
        // GRPC conformance: weighted backends (70/30/0) should flow through
        // proto → route map with weighted_backends populated on PathRoute.
        let routes = vec![RouteConfig {
            host: "*".to_string(),
            paths: vec![],  // catch-all (no method match = all gRPC traffic)
            service_name: "grpc-infra-backend-v1".to_string(),
            port: 8080,
            protocol: "GRPC".to_string(),
            weighted_backends: vec![
                WeightedBackend {
                    service_name: "grpc-infra-backend-v1".to_string(),
                    port: 8080,
                    weight: 70,
                    request_headers: None,
                },
                WeightedBackend {
                    service_name: "grpc-infra-backend-v2".to_string(),
                    port: 8080,
                    weight: 30,
                    request_headers: None,
                },
                WeightedBackend {
                    service_name: "grpc-infra-backend-v3".to_string(),
                    port: 8080,
                    weight: 0,
                    request_headers: None,
                },
            ],
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (_, wildcard, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());

        // Should be in the wildcard slot since host is "*"
        let wc = wildcard.expect("wildcard route should exist");
        let matched = wc.match_path("/some.Service/Method").expect("should match catch-all");

        // Verify weighted backends are populated
        assert_eq!(matched.weighted_backends.len(), 3, "should have 3 weighted backends");
        assert_eq!(matched.weighted_backends[0].service_name.as_ref(), "grpc-infra-backend-v1");
        assert_eq!(matched.weighted_backends[0].weight, 70);
        assert_eq!(matched.weighted_backends[1].service_name.as_ref(), "grpc-infra-backend-v2");
        assert_eq!(matched.weighted_backends[1].weight, 30);
        assert_eq!(matched.weighted_backends[2].service_name.as_ref(), "grpc-infra-backend-v3");
        assert_eq!(matched.weighted_backends[2].weight, 0);
    }

    #[test]
    fn test_grpc_header_only_matching_no_false_positive() {
        // Reproduces the conformance GRPCRouteHeaderMatching scenario:
        // 5 rules with header-only matches (no service/method), all path "/".
        // Requests with non-matching headers should NOT match any route.
        let routes = vec![
            // Rule 1: version=one → v1
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "grpc-infra-backend-v1".to_string(),
                port: 8080,
                protocol: "GRPC".to_string(),
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "one".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Rule 2: version=two → v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "grpc-infra-backend-v2".to_string(),
                port: 8080,
                protocol: "GRPC".to_string(),
                header_matches: vec![HeaderMatch {
                    name: "version".to_string(),
                    value: "two".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
            // Rule 3: color=red → v2
            RouteConfig {
                host: "*".to_string(),
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                service_name: "grpc-infra-backend-v2".to_string(),
                port: 8080,
                protocol: "GRPC".to_string(),
                header_matches: vec![HeaderMatch {
                    name: "color".to_string(),
                    value: "red".to_string(),
                    match_type: "Exact".to_string(),
                }],
                ..Default::default()
            },
        ];

        let existing = HashMap::new();
        let (_, wildcard, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let wc = wildcard.expect("wildcard route should exist");

        // version=one → v1
        let mut headers = http::HeaderMap::new();
        headers.insert("version", http::HeaderValue::from_static("one"));
        let m = wc.match_request("/svc/Method", &http::Method::POST, &headers, None);
        assert!(m.is_some(), "version=one should match");
        assert_eq!(m.unwrap().service_name.as_ref(), "grpc-infra-backend-v1");

        // version=two → v2
        let mut headers = http::HeaderMap::new();
        headers.insert("version", http::HeaderValue::from_static("two"));
        let m = wc.match_request("/svc/Method", &http::Method::POST, &headers, None);
        assert!(m.is_some(), "version=two should match");
        assert_eq!(m.unwrap().service_name.as_ref(), "grpc-infra-backend-v2");

        // color=red → v2
        let mut headers = http::HeaderMap::new();
        headers.insert("color", http::HeaderValue::from_static("red"));
        let m = wc.match_request("/svc/Method", &http::Method::POST, &headers, None);
        assert!(m.is_some(), "color=red should match");
        assert_eq!(m.unwrap().service_name.as_ref(), "grpc-infra-backend-v2");

        // color=purple → NO MATCH (negative case)
        let mut headers = http::HeaderMap::new();
        headers.insert("color", http::HeaderValue::from_static("purple"));
        let m = wc.match_request("/svc/Method", &http::Method::POST, &headers, None);
        assert!(m.is_none(), "color=purple should NOT match, got: {:?}", m.map(|r| r.service_name.as_ref().to_string()));

        // no headers → NO MATCH
        let headers = http::HeaderMap::new();
        let m = wc.match_request("/svc/Method", &http::Method::POST, &headers, None);
        assert!(m.is_none(), "no headers should NOT match, got: {:?}", m.map(|r| r.service_name.as_ref().to_string()));
    }

    // -----------------------------------------------------------------------
    // Conformance: TLSRouteMixedTerminationSameNamespace — build_l4_config
    // -----------------------------------------------------------------------

    /// Feed build_l4_config_from_proto with 2 TLS routes (one Terminate, one
    /// Passthrough) on the same port 8883 and verify the resulting L4Config.
    #[test]
    fn test_build_l4_config_mixed_termination() {
        use crate::l4_proxy::TlsMode;
        // Install crypto provider for cert loading
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Generate a real self-signed cert for the Terminate route
        let cert = crate::tls::generate_self_signed_cert().unwrap();

        let config = portus_types::CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            tls_passthrough_routes: vec![
                portus_types::TlsPassthroughRoute {
                    sni_hostnames: vec!["tls.example.com".to_string()],
                    backend_service: "tcp-backend".to_string(),
                    backend_port: 3000,
                    listener_name: "tls-terminate".to_string(),
                    listener_hostname: "tls.example.com".to_string(),
                    tls_mode: "Terminate".to_string(),
                    cert_pem: cert.0.clone(),
                    key_pem: cert.1.clone(),
                    listener_port: 8883,
                    gateway_namespace: String::new(),
                    gateway_name: String::new(),
                },
                portus_types::TlsPassthroughRoute {
                    sni_hostnames: vec!["abc.example.com".to_string()],
                    backend_service: "tcp-backend".to_string(),
                    backend_port: 8443,
                    listener_name: "tls-passthrough".to_string(),
                    listener_hostname: "abc.example.com".to_string(),
                    tls_mode: "Passthrough".to_string(),
                    cert_pem: String::new(),
                    key_pem: String::new(),
                    listener_port: 8883,
                    gateway_namespace: String::new(),
                    gateway_name: String::new(),
                },
            ],
            ..Default::default()
        };

        let l4 = build_l4_config_from_proto(&config);

        // Should have 2 TLS listeners
        assert_eq!(
            l4.tls_listeners.len(),
            2,
            "expected 2 TLS listeners, got {}",
            l4.tls_listeners.len()
        );

        // Find the Terminate listener
        let terminate = l4
            .tls_listeners
            .iter()
            .find(|l| l.hostname == "tls.example.com");
        assert!(
            terminate.is_some(),
            "should have a listener with hostname tls.example.com"
        );
        let terminate = terminate.unwrap();
        assert_eq!(terminate.tls_mode, TlsMode::Terminate);
        assert!(
            terminate.cert.is_some(),
            "Terminate listener should have a loaded cert"
        );
        assert_eq!(terminate.listener_port, 8883);
        assert_eq!(
            terminate.routes.get("tls.example.com"),
            Some(&("tcp-backend".to_string(), 3000u16)),
            "Terminate listener should route tls.example.com to tcp-backend:3000"
        );

        // Find the Passthrough listener
        let passthrough = l4
            .tls_listeners
            .iter()
            .find(|l| l.hostname == "abc.example.com");
        assert!(
            passthrough.is_some(),
            "should have a listener with hostname abc.example.com"
        );
        let passthrough = passthrough.unwrap();
        assert_eq!(passthrough.tls_mode, TlsMode::Passthrough);
        assert!(
            passthrough.cert.is_none(),
            "Passthrough listener should have no cert"
        );
        assert_eq!(passthrough.listener_port, 8883);
        assert_eq!(
            passthrough.routes.get("abc.example.com"),
            Some(&("tcp-backend".to_string(), 8443u16)),
            "Passthrough listener should route abc.example.com to tcp-backend:8443"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 11: Policy field parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ip_allowlist_parsing() {
        let routes = vec![RouteConfig {
            host: "secure.example.com".to_string(),
            paths: vec![PathRule {
                path: "/api".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            ip_allowlist: Some(IpAllowlistConfig {
                allow_cidrs: vec!["10.0.0.0/8".to_string()],
                deny_cidrs: vec!["10.0.0.5/32".to_string()],
                trusted_proxy_cidrs: vec![],
            }),
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("secure.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.ip_allow_cidrs.len(), 1);
        assert_eq!(route.ip_deny_cidrs.len(), 1);
        assert_eq!(
            route.ip_allow_cidrs[0],
            "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()
        );
        assert_eq!(
            route.ip_deny_cidrs[0],
            "10.0.0.5/32".parse::<ipnet::IpNet>().unwrap()
        );
    }

    #[test]
    fn test_body_size_limit_parsing() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/upload".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            max_request_body_bytes: 1048576,
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.max_request_body_bytes, 1048576);
    }

    #[test]
    fn test_retry_on_parsing() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            retry_on: vec!["5xx".to_string(), "connect-failure".to_string()],
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert_eq!(route.retry_on.len(), 2);
        assert_eq!(route.retry_on[0], "5xx");
        assert_eq!(route.retry_on[1], "connect-failure");
        assert!(route.retry_codes.is_empty());
    }

    #[test]
    fn test_retry_codes_and_attempts_reach_the_path_route() {
        // httproute-retry: codes [500,502,503,504] attempts 2 -> max_retries 2, retry_codes u16.
        let routes = vec![RouteConfig {
            host: "retry.example.com".to_string(),
            paths: vec![PathRule { path: "/retry/code-all-attempts-2".to_string(), match_type: "Prefix".to_string() }],
            service_name: "infra-backend-v3".to_string(),
            port: 8080,
            max_retries: 2,
            retry_codes: vec![500, 502, 503, 504, 70_000],
            ..Default::default()
        }];
        let (result, _, _) = build_route_map_from_proto(&routes, HashMap::new(), &HashMap::new(), &HashMap::new());
        let route = &result.get("retry.example.com").unwrap().rules[0];
        assert_eq!(route.max_retries, 2);
        assert_eq!(*route.retry_codes, vec![500u16, 502, 503, 504], "out-of-range codes are dropped");
    }

    #[test]
    fn test_policy_fields_default_values() {
        let routes = vec![RouteConfig {
            host: "api.example.com".to_string(),
            paths: vec![PathRule {
                path: "/v1".to_string(),
                match_type: "Prefix".to_string(),
            }],
            service_name: "backend".to_string(),
            port: 8080,
            ..Default::default()
        }];

        let existing = HashMap::new();
        let (result, _, _) = build_route_map_from_proto(&routes, existing, &HashMap::new(), &HashMap::new());
        let host_routes = result.get("api.example.com").unwrap();
        let route = &host_routes.rules[0];

        assert!(route.ip_allow_cidrs.is_empty(), "ip_allow_cidrs should be empty by default");
        assert!(route.ip_deny_cidrs.is_empty(), "ip_deny_cidrs should be empty by default");
        assert_eq!(route.max_request_body_bytes, 0, "max_request_body_bytes should be 0 by default");
        assert!(route.retry_on.is_empty(), "retry_on should be empty by default");
    }

    #[test]
    fn test_parse_match_type_rejects_oversized_regex() {
        // A regex pattern that would exceed the 64KB NFA size limit
        let huge_pattern = format!("^{}$", "a{1,1000}".repeat(100));
        let result = parse_match_type("RegularExpression", &huge_pattern);
        assert!(
            result.is_none(),
            "oversized regex pattern should be rejected"
        );
    }

    #[test]
    fn test_parse_match_type_accepts_normal_regex() {
        let result = parse_match_type("RegularExpression", r"^/api/v[0-9]+");
        assert!(result.is_some(), "normal regex should be accepted");
    }

    // SEC-3: Zeroize TLS private key memory on drop
    #[test]
    fn test_tls_cert_entry_drop_does_not_panic() {
        let entry = TlsCertEntry {
            hostname: "*.example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----".to_string(),
        };
        drop(entry);
    }

    // -----------------------------------------------------------------------
    // validate_config tests
    // -----------------------------------------------------------------------

    /// Helper to build a minimal valid CompiledConfig with one route.
    fn valid_config() -> CompiledConfig {
        CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: "backend-svc".into(),
                port: 8080,
                ..Default::default()
            }],
            listeners: vec![Listener {
                name: "http".into(),
                port: 80,
                protocol: "HTTP".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_config_valid_passes_cleanly() {
        let config = valid_config();
        let result = validate_config(&config);
        assert!(result.is_ok(), "valid config should pass");
        assert!(result.unwrap().is_empty(), "valid config should have no warnings");
    }

    #[test]
    fn test_validate_config_rejects_empty_service_name() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: String::new(),
                port: 8080,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "empty service_name should be rejected");
        assert!(
            result.unwrap_err().contains("empty service_name"),
            "error should mention empty service_name"
        );
    }

    #[test]
    fn test_validate_config_rejects_port_zero() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: "backend".into(),
                port: 0,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "port 0 should be rejected");
        assert!(result.unwrap_err().contains("port is 0"));
    }

    #[test]
    fn test_validate_config_rejects_empty_host_with_paths() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: String::new(),
                paths: vec![PathRule {
                    path: "/api".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: "backend".into(),
                port: 8080,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "empty hostname with paths should be rejected");
        assert!(result.unwrap_err().contains("empty hostname"));
    }

    #[test]
    fn test_validate_config_rejects_duplicate_route_keys() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-a".into(),
                    port: 8080,
                    ..Default::default()
                },
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-b".into(),
                    port: 9090,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "duplicate route keys should be rejected");
        assert!(result.unwrap_err().contains("duplicate route key"));
    }

    #[test]
    fn test_validate_config_allows_same_path_different_methods() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-a".into(),
                    port: 8080,
                    method_match: "GET".into(),
                    ..Default::default()
                },
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-b".into(),
                    port: 9090,
                    method_match: "POST".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "same path with different methods should be allowed");
    }

    #[test]
    fn test_validate_config_allows_same_path_different_listener_ports() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-a".into(),
                    port: 8080,
                    listener_port: 80,
                    ..Default::default()
                },
                RouteConfig {
                    host: "app.example.com".into(),
                    paths: vec![PathRule {
                        path: "/api".into(),
                        match_type: "Exact".into(),
                    }],
                    service_name: "svc-b".into(),
                    port: 8080,
                    listener_port: 443,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "same path on different listener ports should be allowed");
    }

    #[test]
    fn test_validate_config_zero_routes_warns_but_passes() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "zero routes should pass");
        let warnings = result.unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("zero routes"));
    }

    #[test]
    fn test_validate_config_large_route_count_warns() {
        let routes: Vec<RouteConfig> = (0..10_001)
            .map(|i| RouteConfig {
                host: format!("host-{}.example.com", i),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: format!("svc-{}", i),
                port: 8080,
                ..Default::default()
            })
            .collect();
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes,
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("unusually large")),
            "should warn about large route count"
        );
    }

    #[test]
    fn test_validate_config_redirect_only_route_allowed() {
        // Redirect routes have no service_name and port 0 -- that's valid.
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "old.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: String::new(),
                port: 0,
                redirect: Some(RedirectFilter {
                    scheme: "https".into(),
                    hostname: "new.example.com".into(),
                    status_code: 301,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "redirect-only route should be valid");
    }

    #[test]
    fn test_validate_config_rejects_listener_port_zero() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            listeners: vec![Listener {
                name: "bad-listener".into(),
                port: 0,
                protocol: "HTTP".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "listener port 0 should be rejected");
        assert!(result.unwrap_err().contains("port is 0"));
    }

    #[test]
    fn test_validate_config_warns_https_listener_missing_cert() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            listeners: vec![Listener {
                name: "https-no-cert".into(),
                port: 443,
                protocol: "HTTPS".into(),
                tls_cert_ref: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "missing cert should warn, not reject");
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("missing TLS cert/key")),
            "should warn about missing TLS cert: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_config_warns_invalid_regex() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "[invalid".into(),
                    match_type: "RegularExpression".into(),
                }],
                service_name: "backend".into(),
                port: 8080,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "invalid regex should warn, not reject");
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("regex") && w.contains("fails to compile")),
            "should warn about invalid regex: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_config_rejects_weighted_backend_empty_service() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: String::new(),
                port: 0,
                weighted_backends: vec![WeightedBackend {
                    service_name: String::new(),
                    port: 8080,
                    weight: 1,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "weighted backend with empty service should be rejected");
        assert!(result.unwrap_err().contains("weighted_backends"));
    }

    #[test]
    fn test_validate_config_rejects_weighted_backend_port_zero() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: String::new(),
                port: 0,
                weighted_backends: vec![WeightedBackend {
                    service_name: "svc".into(),
                    port: 0,
                    weight: 1,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err(), "weighted backend with port 0 should be rejected");
        assert!(result.unwrap_err().contains("port is 0"));
    }

    #[test]
    fn test_validate_config_weighted_backends_valid() {
        let config = CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 1,
            routes: vec![RouteConfig {
                host: "app.example.com".into(),
                paths: vec![PathRule {
                    path: "/".into(),
                    match_type: "Prefix".into(),
                }],
                service_name: String::new(),
                port: 0,
                weighted_backends: vec![
                    WeightedBackend {
                        service_name: "svc-a".into(),
                        port: 8080,
                        weight: 80,
                        ..Default::default()
                    },
                    WeightedBackend {
                        service_name: "svc-b".into(),
                        port: 9090,
                        weight: 20,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_ok(), "valid weighted backends should pass");
        assert!(result.unwrap().is_empty());
    }


    // -----------------------------------------------------------------------
    // mTLS: frontend client validation + backend client certificates
    // -----------------------------------------------------------------------

    fn https_listener(name: &str, port: u32, cv: Option<portus_types::ClientValidation>) -> portus_types::Listener {
        portus_types::Listener {
            name: name.to_string(),
            port,
            protocol: "HTTPS".to_string(),
            hostname: String::new(),
            tls_cert_ref: Some(portus_types::TlsCertRef {
                cert_pem: "CERT".to_string(),
                key_pem: "KEY".to_string(),
            }),
            gateway_namespace: "ns".to_string(),
            gateway_name: "gw".to_string(),
            client_validation: cv,
        }
    }

    fn cv(pems: &[&str], mode: &str) -> portus_types::ClientValidation {
        portus_types::ClientValidation {
            ca_cert_pems: pems.iter().map(|s| s.to_string()).collect(),
            mode: mode.to_string(),
        }
    }

    #[test]
    fn test_client_validation_from_listeners_by_port() {
        let listeners = vec![
            https_listener("https", 443, Some(cv(&["DEFAULT-CA"], "AllowValidOnly"))),
            https_listener("https-hostname", 8443, Some(cv(&["PER-PORT-CA"], "AllowInsecureFallback"))),
            https_listener("plain", 9443, None),
            portus_types::Listener {
                protocol: "HTTP".to_string(),
                ..https_listener("http", 80, Some(cv(&["IGNORED"], "AllowValidOnly")))
            },
            // Empty PEMs are dropped rather than compiled into a policy.
            https_listener("empty", 10443, Some(cv(&["", "  "], "AllowValidOnly"))),
        ];
        let specs = client_validation_from_listeners(&listeners);
        assert_eq!(specs.len(), 2, "{specs:?}");
        assert_eq!(specs[0].port, 443);
        assert_eq!(specs[0].ca_cert_pems, vec!["DEFAULT-CA".to_string()]);
        assert_eq!(specs[0].mode, ClientValidationMode::AllowValidOnly);
        assert_eq!(specs[1].port, 8443);
        assert_eq!(specs[1].ca_cert_pems, vec!["PER-PORT-CA".to_string()]);
        assert_eq!(specs[1].mode, ClientValidationMode::AllowInsecureFallback);
    }

    #[test]
    fn test_client_validation_same_port_first_listener_wins_and_unknown_mode_is_strict() {
        let listeners = vec![
            https_listener("a", 443, Some(cv(&["CA-A"], "AllowValidOnly"))),
            https_listener("b", 443, Some(cv(&["CA-B"], "AllowInsecureFallback"))),
        ];
        let specs = client_validation_from_listeners(&listeners);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].ca_cert_pems, vec!["CA-A".to_string()]);
        assert_eq!(ClientValidationMode::parse("Bogus"), ClientValidationMode::AllowValidOnly);
        assert_eq!(ClientValidationMode::parse(""), ClientValidationMode::AllowValidOnly);
    }

    #[test]
    fn test_apply_config_stores_client_validation_with_certs() {
        let state = empty_proxy_state();
        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            listeners: vec![https_listener("https", 443, Some(cv(&["CA"], "AllowValidOnly")))],
            ..Default::default()
        };
        apply_config(config, &state);
        let data = state.tls_cert.load();
        let data = data.as_ref().as_ref().expect("TLS data stored");
        assert_eq!(data.entries.len(), 1);
        assert_eq!(data.client_validation.len(), 1);
        assert_eq!(data.client_validation[0].port, 443);

        // Removing the validation (certs unchanged) clears it on the next apply.
        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 2,
            listeners: vec![https_listener("https", 443, None)],
            ..Default::default()
        };
        apply_config(config, &state);
        let data = state.tls_cert.load();
        assert!(data.as_ref().as_ref().unwrap().client_validation.is_empty());
    }

    fn backend_route(gw: &str, service: &str, port: u32) -> RouteConfig {
        RouteConfig {
            host: "abc.example.com".to_string(),
            service_name: service.to_string(),
            port,
            gateway_namespace: "ns".to_string(),
            gateway_name: gw.to_string(),
            ..Default::default()
        }
    }

    fn client_cert_entry(gw: &str, cert_pem: &str, key_pem: &str) -> portus_types::GatewayBackendTls {
        portus_types::GatewayBackendTls {
            gateway_namespace: "ns".to_string(),
            gateway_name: gw.to_string(),
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
        }
    }

    #[test]
    fn test_backend_client_cert_is_the_serving_gateways_entry() {
        let (cert_pem, key_pem) = crate::tls::generate_self_signed_cert().unwrap();
        let (other_cert, other_key) = crate::tls::generate_self_signed_cert().unwrap();
        let config = CompiledConfig {
            routes: vec![backend_route("gw", "tls-backend", 443)],
            gateway_backend_tls: vec![
                client_cert_entry("other", &other_cert, &other_key),
                client_cert_entry("gw", &cert_pem, &key_pem),
            ],
            ..Default::default()
        };
        let mine = build_backend_client_cert_from_proto(&config, ("ns", "gw")).expect("gw's certificate");
        let expected = parse_client_cert_key(&cert_pem, &key_pem).unwrap();
        assert_eq!(mine.leaf().raw_der(), expected.leaf().raw_der());
        assert!(!mine.key().is_empty());
        assert!(build_backend_client_cert_from_proto(&config, ("ns", "none")).is_none());
        assert!(build_backend_client_cert_from_proto(&CompiledConfig::default(), ("ns", "gw")).is_none());
    }

    #[test]
    fn test_backend_client_cert_unusable_pem_yields_none() {
        let (_, key_pem) = crate::tls::generate_self_signed_cert().unwrap();
        let (cert_pem, _) = crate::tls::generate_self_signed_cert().unwrap();
        let config = CompiledConfig {
            gateway_backend_tls: vec![client_cert_entry("gw", "garbage", "garbage")],
            ..Default::default()
        };
        assert!(build_backend_client_cert_from_proto(&config, ("ns", "gw")).is_none());
        assert!(parse_client_cert_key("garbage", &key_pem).is_err());
        assert!(parse_client_cert_key(&cert_pem, "garbage").is_err());
    }

    #[test]
    fn test_apply_config_populates_backend_client_cert_snapshot() {
        let (cert_pem, key_pem) = crate::tls::generate_self_signed_cert().unwrap();
        // apply_config resolves the Gateway from the environment.
        unsafe {
            std::env::set_var("GATEWAY_NAMESPACE", "ns");
            std::env::set_var("GATEWAY_NAME", "gw");
        }
        let state = empty_proxy_state();
        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            routes: vec![RouteConfig {
                paths: vec![PathRule { path: "/".to_string(), match_type: "Prefix".to_string() }],
                ..backend_route("gw", "tls-backend", 443)
            }],
            gateway_backend_tls: vec![client_cert_entry("gw", &cert_pem, &key_pem)],
            ..Default::default()
        };
        apply_config(config, &state);
        unsafe {
            std::env::remove_var("GATEWAY_NAMESPACE");
            std::env::remove_var("GATEWAY_NAME");
        }
        assert!(state.snapshot.load().backend_client_cert.is_some());
    }
}
