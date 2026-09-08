//! Standalone YAML configuration mode for the Portus dataplane.
//!
//! When the `PORTUS_CONFIG_FILE` environment variable is set, the dataplane reads
//! configuration from a YAML file instead of receiving it via gRPC from a
//! controller. This enables use as a standalone reverse proxy without Kubernetes.
//!
//! The YAML format maps directly to the proto `CompiledConfig` schema, with
//! ergonomic naming (snake_case, nested objects instead of flat proto fields).
//!
//! File watching with debounce enables hot-reload: edit the YAML and the proxy
//! picks up changes within ~500ms, with zero downtime.

use log::{info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::config_receiver::{apply_config, validate_config, ProxyState};

// ---------------------------------------------------------------------------
// YAML deserialization types
// ---------------------------------------------------------------------------

/// Top-level standalone configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct StandaloneConfig {
    #[serde(default)]
    pub listeners: Vec<YamlListener>,
}

/// A listener defines a port, protocol, optional TLS, and a set of routes.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlListener {
    pub port: u32,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub tls: Option<YamlListenerTls>,
    /// Optional hostname restriction for this listener.
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub routes: Vec<YamlRoute>,
}

fn default_protocol() -> String {
    "HTTP".to_string()
}

/// TLS configuration for an HTTPS listener.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlListenerTls {
    pub cert_file: String,
    pub key_file: String,
}

/// A route matches requests by host/path/headers and forwards to backends.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlRoute {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<YamlPathRule>,
    #[serde(default)]
    pub backends: Vec<YamlBackend>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Vec<YamlHeaderMatch>,
    #[serde(default)]
    pub query_params: Vec<YamlQueryParamMatch>,
    /// Backend protocol: HTTP (default), GRPC, H2C, WS.
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub redirect: Option<YamlRedirect>,
    #[serde(default)]
    pub rewrite: Option<YamlRewrite>,
    #[serde(default)]
    pub timeouts: Option<YamlTimeouts>,
    #[serde(default)]
    pub retries: Option<YamlRetries>,
    #[serde(default)]
    pub rate_limit: Option<YamlRateLimit>,
    #[serde(default)]
    pub circuit_breaker: Option<YamlCircuitBreaker>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    #[serde(default)]
    pub auth: Option<YamlAuth>,
    #[serde(default)]
    pub cors: Option<YamlCors>,
    #[serde(default)]
    pub ip_allowlist: Option<YamlIpAllowlist>,
    #[serde(default)]
    pub request_headers: Option<YamlHeaderMutation>,
    #[serde(default)]
    pub response_headers: Option<YamlHeaderMutation>,
    #[serde(default)]
    pub mirrors: Vec<YamlMirror>,
}

/// Path matching rule.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlPathRule {
    pub path: String,
    #[serde(default = "default_path_type", rename = "type")]
    pub match_type: String,
}

fn default_path_type() -> String {
    "Prefix".to_string()
}

/// A backend endpoint with optional weight.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct YamlBackend {
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Header match rule for request routing.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlHeaderMatch {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default = "default_match_type", rename = "type")]
    pub match_type: String,
}

fn default_match_type() -> String {
    "Exact".to_string()
}

/// Query parameter match rule.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlQueryParamMatch {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default = "default_match_type", rename = "type")]
    pub match_type: String,
}

/// Redirect configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlRedirect {
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_type: Option<String>,
    #[serde(default = "default_redirect_status")]
    pub status_code: u32,
}

fn default_redirect_status() -> u32 {
    302
}

/// URL rewrite configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlRewrite {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_type: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Timeout configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlTimeouts {
    #[serde(default)]
    pub request_ms: Option<u64>,
    #[serde(default)]
    pub backend_request_ms: Option<u64>,
    #[serde(default)]
    pub connect_ms: Option<u64>,
}

/// Retry configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlRetries {
    #[serde(default)]
    pub max: Option<u32>,
    /// Connection-time conditions: `connect-failure`, `gateway-error`.
    #[serde(default)]
    pub on: Vec<String>,
    /// Upstream response statuses to retry (the HTTPRoute `retry.codes`
    /// equivalent), e.g. `[500, 502, 503, 504]`.
    #[serde(default)]
    pub codes: Vec<u16>,
}

/// Rate limiting configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlRateLimit {
    #[serde(default)]
    pub requests_per_second: u32,
    #[serde(default)]
    pub per_client: bool,
}

/// Circuit breaker configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlCircuitBreaker {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_cb_timeout")]
    pub timeout_secs: u32,
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_success_threshold() -> u32 {
    1
}
fn default_cb_timeout() -> u32 {
    30
}

/// Authentication configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlAuth {
    #[serde(default)]
    pub basic: Option<YamlBasicAuth>,
    #[serde(default)]
    pub api_key: Option<YamlApiKeyAuth>,
}

/// HTTP Basic authentication.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlBasicAuth {
    #[serde(default = "default_realm")]
    pub realm: String,
    #[serde(default)]
    pub credentials: HashMap<String, String>,
}

fn default_realm() -> String {
    "Restricted".to_string()
}

/// API key authentication.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlApiKeyAuth {
    #[serde(default = "default_api_key_header")]
    pub header: String,
    #[serde(default)]
    pub keys: Vec<String>,
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

/// CORS configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlCors {
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub max_age: u32,
}

/// IP allowlist/denylist configuration.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlIpAllowlist {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// Header mutation (add/set/remove).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct YamlHeaderMutation {
    #[serde(default)]
    pub add: HashMap<String, String>,
    #[serde(default)]
    pub set: HashMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Request mirroring configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct YamlMirror {
    pub address: String,
    #[serde(default = "default_mirror_percent")]
    pub percent: u32,
}

fn default_mirror_percent() -> u32 {
    0 // 0 = mirror 100% of requests (proto convention)
}

// ---------------------------------------------------------------------------
// YAML -> CompiledConfig conversion
// ---------------------------------------------------------------------------

/// Generate a deterministic service name from a sorted set of backend addresses.
/// Same set of backends (regardless of order) always produces the same name.
fn synthetic_service_name(backends: &[YamlBackend]) -> String {
    let mut sorted: Vec<&YamlBackend> = backends.iter().collect();
    sorted.sort_by(|a, b| a.address.cmp(&b.address));
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for b in &sorted {
        b.address.hash(&mut hasher);
    }
    format!("standalone-{:08x}", hasher.finish() as u32)
}

/// Parse a "host:port" address string into (host, port).
/// Returns an error if the format is invalid.
fn parse_backend_address(addr: &str) -> Result<(String, u16), String> {
    // Handle IPv6 addresses like [::1]:8080
    if let Some(bracket_end) = addr.find("]:") {
        let host = &addr[..bracket_end + 1];
        let port_str = &addr[bracket_end + 2..];
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("invalid port in '{}': {}", addr, e))?;
        return Ok((host.to_string(), port));
    }

    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid backend address '{}': expected host:port",
            addr
        ));
    }
    let port: u16 = parts[0]
        .parse()
        .map_err(|e| format!("invalid port in '{}': {}", addr, e))?;
    Ok((parts[1].to_string(), port))
}

/// Convert a `StandaloneConfig` into a `portus_types::CompiledConfig`.
#[allow(deprecated)] // mirror_backend (field 21) must be explicitly None in the struct literal
pub(crate) fn to_compiled_config(config: &StandaloneConfig) -> Result<portus_types::CompiledConfig, String> {
    let mut proto = portus_types::CompiledConfig {
        schema_version: "1.0.0".to_string(),
        version: 1,
        ..Default::default()
    };

    // Track backend groups by service name to avoid duplicates.
    let mut backend_groups: HashMap<String, portus_types::BackendGroup> = HashMap::new();

    for listener in &config.listeners {
        // Build proto Listener
        let listener_name = format!("standalone-{}-{}", listener.protocol.to_lowercase(), listener.port);

        let tls_cert_ref = if let Some(ref tls) = listener.tls {
            let cert_pem = std::fs::read_to_string(&tls.cert_file)
                .map_err(|e| format!("failed to read TLS cert '{}': {}", tls.cert_file, e))?;
            let key_pem = std::fs::read_to_string(&tls.key_file)
                .map_err(|e| format!("failed to read TLS key '{}': {}", tls.key_file, e))?;
            Some(portus_types::TlsCertRef { cert_pem, key_pem })
        } else {
            None
        };

        proto.listeners.push(portus_types::Listener {
            name: listener_name.clone(),
            port: listener.port,
            protocol: listener.protocol.to_uppercase(),
            hostname: listener.hostname.clone().unwrap_or_default(),
            tls_cert_ref,
            // Standalone mode has no Gateway objects; the empty owner keeps the
            // listener in the shared (unscoped) view.
            gateway_namespace: String::new(),
            gateway_name: String::new(),
            client_validation: None,
        });

        // Build routes for this listener
        for route in &listener.routes {
            let hosts = if route.hosts.is_empty() {
                vec!["*".to_string()]
            } else {
                route.hosts.clone()
            };

            let paths = if route.paths.is_empty() {
                vec![portus_types::PathRule {
                    path: "/".to_string(),
                    match_type: "Prefix".to_string(),
                }]
            } else {
                route
                    .paths
                    .iter()
                    .map(|p| portus_types::PathRule {
                        path: p.path.clone(),
                        match_type: p.match_type.clone(),
                    })
                    .collect()
            };

            // Build service name and backend group from backends
            let service_name = if route.backends.is_empty() {
                // Redirect-only routes have no backends
                String::new()
            } else {
                let svc = synthetic_service_name(&route.backends);

                // Parse the first backend to determine the port for the backend group
                let first_addr = parse_backend_address(&route.backends[0].address)?;
                let svc_port = first_addr.1;

                if !backend_groups.contains_key(&svc) {
                    let endpoints: Vec<portus_types::BackendEndpoint> = route
                        .backends
                        .iter()
                        .map(|b| {
                            let (host, port) = parse_backend_address(&b.address)?;
                            Ok(portus_types::BackendEndpoint {
                                address: host,
                                port: port as u32,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?;

                    backend_groups.insert(
                        svc.clone(),
                        portus_types::BackendGroup {
                            service_name: svc.clone(),
                            port: svc_port as u32,
                            endpoints,
                            health_check: None,
                            backend_tls: None,
                        },
                    );
                }

                svc
            };

            // Determine the port for the RouteConfig (first backend's port, or 0 for redirects)
            let route_port = if route.backends.is_empty() {
                0
            } else {
                let (_, port) = parse_backend_address(&route.backends[0].address)?;
                port as u32
            };

            // Build header matches
            let header_matches: Vec<portus_types::HeaderMatch> = route
                .headers
                .iter()
                .map(|h| portus_types::HeaderMatch {
                    name: h.name.clone(),
                    value: h.value.clone(),
                    match_type: h.match_type.clone(),
                })
                .collect();

            // Build query param matches
            let query_param_matches: Vec<portus_types::QueryParamMatch> = route
                .query_params
                .iter()
                .map(|q| portus_types::QueryParamMatch {
                    name: q.name.clone(),
                    value: q.value.clone(),
                    match_type: q.match_type.clone(),
                })
                .collect();

            // Build redirect
            let redirect = route.redirect.as_ref().map(|r| portus_types::RedirectFilter {
                scheme: r.scheme.clone().unwrap_or_default(),
                hostname: r.hostname.clone().unwrap_or_default(),
                port: r.port.unwrap_or(0),
                path: r.path.clone().unwrap_or_default(),
                path_type: r.path_type.clone().unwrap_or_default(),
                status_code: r.status_code,
            });

            // Build URL rewrite
            let url_rewrite = route.rewrite.as_ref().map(|rw| portus_types::UrlRewriteFilter {
                hostname: rw.hostname.clone().unwrap_or_default(),
                path: rw.path.clone().unwrap_or_default(),
                path_type: rw.path_type.clone().unwrap_or_default(),
            });

            // Build timeouts
            let timeouts = route.timeouts.as_ref().map(|t| portus_types::TimeoutConfig {
                connect_timeout_ms: t.connect_ms.unwrap_or(0),
                read_timeout_ms: t.request_ms.unwrap_or(0),
                write_timeout_ms: 0,
            });

            // Build rate limit
            let rate_limit = route.rate_limit.as_ref().map(|rl| portus_types::RateLimitConfig {
                requests_per_second: rl.requests_per_second,
                per_client: rl.per_client,
            });

            // Build circuit breaker
            let circuit_breaker = route.circuit_breaker.as_ref().map(|cb| portus_types::CircuitBreakerConfig {
                failure_threshold: cb.failure_threshold,
                success_threshold: cb.success_threshold,
                timeout_secs: cb.timeout_secs,
            });

            // Build auth config
            let auth = build_auth_config(&route.auth);

            // Build CORS config
            let cors = route.cors.as_ref().map(|c| portus_types::CorsConfig {
                allow_origins: c.allow_origins.clone(),
                allow_methods: c.allow_methods.clone(),
                allow_headers: c.allow_headers.clone(),
                expose_headers: c.expose_headers.clone(),
                allow_credentials: c.allow_credentials,
                max_age: c.max_age,
            });

            // Build IP allowlist
            let ip_allowlist = route.ip_allowlist.as_ref().map(|ip| portus_types::IpAllowlistConfig {
                allow_cidrs: ip.allow.clone(),
                deny_cidrs: ip.deny.clone(),
                trusted_proxy_cidrs: ip.trusted_proxies.clone(),
            });

            // Build header mutations
            let request_headers = build_header_mutation(&route.request_headers);
            let response_headers = build_header_mutation(&route.response_headers);

            // Build mirror backends
            let mirror_backends: Vec<portus_types::MirrorBackend> = route
                .mirrors
                .iter()
                .filter_map(|m| {
                    let (host, port) = match parse_backend_address(&m.address) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("invalid mirror address '{}': {}, skipping", m.address, e);
                            return None;
                        }
                    };
                    let mirror_svc = format!("standalone-mirror-{}-{}", host, port);
                    // Register a backend group for the mirror
                    backend_groups.entry(mirror_svc.clone()).or_insert_with(|| {
                        portus_types::BackendGroup {
                            service_name: mirror_svc.clone(),
                            port: port as u32,
                            endpoints: vec![portus_types::BackendEndpoint {
                                address: host,
                                port: port as u32,
                            }],
                            health_check: None,
                            backend_tls: None,
                        }
                    });
                    Some(portus_types::MirrorBackend {
                        service_name: mirror_svc,
                        port: port as u32,
                        percent: m.percent,
                    })
                })
                .collect();

            // Emit one RouteConfig per host
            for host in &hosts {
                proto.routes.push(portus_types::RouteConfig {
                    host: host.clone(),
                    paths: paths.clone(),
                    service_name: service_name.clone(),
                    port: route_port,
                    timeouts,
                    max_retries: route.retries.as_ref().and_then(|r| r.max).unwrap_or(0),
                    protocol: route.protocol.clone().unwrap_or_default(),
                    request_headers: request_headers.clone(),
                    response_headers: response_headers.clone(),
                    rate_limit,
                    circuit_breaker,
                    max_connections: route.max_connections,
                    header_matches: header_matches.clone(),
                    method_match: route.method.clone().unwrap_or_default(),
                    query_param_matches: query_param_matches.clone(),
                    redirect: redirect.clone(),
                    url_rewrite: url_rewrite.clone(),
                    listener_name: listener_name.clone(),
                    listener_port: listener.port,
                    listener_hostname: listener
                        .hostname
                        .clone()
                        .unwrap_or_default(),
                    mirror_backends: mirror_backends.clone(),
                    request_timeout_ms: route
                        .timeouts
                        .as_ref()
                        .and_then(|t| t.request_ms)
                        .unwrap_or(0),
                    backend_request_timeout_ms: route
                        .timeouts
                        .as_ref()
                        .and_then(|t| t.backend_request_ms)
                        .unwrap_or(0),
                    auth: auth.clone(),
                    cors: cors.clone(),
                    ip_allowlist: ip_allowlist.clone(),
                    max_request_body_bytes: route.max_request_body_bytes.unwrap_or(0),
                    retry_on: route
                        .retries
                        .as_ref()
                        .map(|r| r.on.clone())
                        .unwrap_or_default(),
                    retry_codes: route
                        .retries
                        .as_ref()
                        .map(|r| r.codes.iter().map(|c| u32::from(*c)).collect())
                        .unwrap_or_default(),
                    // Fields not used in standalone mode
                    upstream_tls: None,
                    grpc_match: None,
                    mirror_backend: None,
                    weighted_backends: Vec::new(),
                                    gateway_namespace: String::new(),
                    gateway_name: String::new(),
                });
            }
        }
    }

    proto.backends = backend_groups.into_values().collect();

    Ok(proto)
}

fn build_auth_config(auth: &Option<YamlAuth>) -> Option<portus_types::AuthConfig> {
    let auth = auth.as_ref()?;

    if let Some(ref basic) = auth.basic {
        return Some(portus_types::AuthConfig {
            auth_type: Some(
                portus_types::proto::portus::config::v1::auth_config::AuthType::BasicAuth(
                    portus_types::BasicAuthConfig {
                        credentials: basic.credentials.clone(),
                        realm: basic.realm.clone(),
                    },
                ),
            ),
        });
    }

    if let Some(ref api_key) = auth.api_key {
        return Some(portus_types::AuthConfig {
            auth_type: Some(
                portus_types::proto::portus::config::v1::auth_config::AuthType::ApiKey(
                    portus_types::ApiKeyAuthConfig {
                        valid_keys: api_key.keys.clone(),
                        header_name: api_key.header.clone(),
                    },
                ),
            ),
        });
    }

    None
}

fn build_header_mutation(mutation: &Option<YamlHeaderMutation>) -> Option<portus_types::HeaderMutation> {
    let m = mutation.as_ref()?;
    if m.add.is_empty() && m.set.is_empty() && m.remove.is_empty() {
        return None;
    }
    Some(portus_types::HeaderMutation {
        add: m.add.clone(),
        set: m.set.clone(),
        remove: m.remove.clone(),
    })
}

// ---------------------------------------------------------------------------
// Public API: load, apply, and watch
// ---------------------------------------------------------------------------

/// Parse a YAML config file, convert to `CompiledConfig`, validate, and apply.
pub(crate) fn load_and_apply(path: &str, state: &ProxyState) -> Result<(), String> {
    let yaml_str = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file '{}': {}", path, e))?;

    let config: StandaloneConfig = serde_yaml_ng::from_str(&yaml_str)
        .map_err(|e| format!("failed to parse YAML config '{}': {}", path, e))?;

    let compiled = to_compiled_config(&config)?;

    let warnings = validate_config(&compiled)?;
    for w in &warnings {
        warn!("config validation warning: {}", w);
    }

    apply_config(compiled, state);

    info!(
        "standalone config applied from '{}': {} listeners, {} routes",
        path,
        config.listeners.len(),
        config.listeners.iter().map(|l| l.routes.len()).sum::<usize>(),
    );

    Ok(())
}

/// Watch a config file for changes and hot-reload on modification.
///
/// Uses the `notify` crate to watch the parent directory (handles atomic
/// renames). Debounces events by 500ms to avoid rapid reloads.
pub(crate) fn watch_config_file(path: &str, state: std::sync::Arc<ProxyState>) {
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (tx, rx) = mpsc::channel();

    let mut watcher = match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        match res {
            Ok(event) => {
                // Only reload on content-modifying events
                use notify::EventKind;
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        let _ = tx.send(());
                    }
                    _ => {}
                }
            }
            Err(e) => warn!("file watcher error: {}", e),
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            warn!("failed to create file watcher: {}, hot-reload disabled", e);
            return;
        }
    };

    // Watch the parent directory for atomic rename handling
    let watch_path = std::path::Path::new(path);
    let watch_dir = watch_path.parent().unwrap_or(std::path::Path::new("."));
    if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
        warn!(
            "failed to watch directory '{}': {}, hot-reload disabled",
            watch_dir.display(),
            e
        );
        return;
    }

    info!("watching config file '{}' for changes", path);

    let debounce = Duration::from_millis(500);
    let mut last_reload = Instant::now() - debounce;

    loop {
        match rx.recv() {
            Ok(()) => {
                // Debounce: skip if last reload was too recent
                if last_reload.elapsed() < debounce {
                    // Drain any pending events
                    while rx.try_recv().is_ok() {}
                    continue;
                }
                // Small delay to let atomic writes complete
                std::thread::sleep(Duration::from_millis(100));
                // Drain any accumulated events
                while rx.try_recv().is_ok() {}

                info!("config file change detected, reloading '{}'", path);
                match load_and_apply(path, &state) {
                    Ok(()) => {
                        last_reload = Instant::now();
                        info!("config hot-reload successful");
                    }
                    Err(e) => {
                        warn!("config hot-reload failed: {}, keeping previous config", e);
                    }
                }
            }
            Err(e) => {
                warn!("file watcher channel closed: {}, hot-reload disabled", e);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].port, 80);
        assert_eq!(config.listeners[0].protocol, "HTTP");
        assert_eq!(config.listeners[0].routes.len(), 1);
        assert_eq!(config.listeners[0].routes[0].backends.len(), 1);
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
listeners:
  - port: 80
    protocol: HTTP
    routes:
      - hosts: ["example.com", "www.example.com"]
        paths:
          - path: /api
            type: Prefix
          - path: /exact
            type: Exact
        backends:
          - address: "10.0.0.1:8080"
            weight: 3
          - address: "10.0.0.2:8080"
            weight: 1
        method: GET
        headers:
          - name: X-Version
            value: "2"
            type: Exact
        query_params:
          - name: debug
            value: "true"
        protocol: HTTP
        timeouts:
          request_ms: 30000
          backend_request_ms: 10000
          connect_ms: 5000
        retries:
          max: 3
          on: ["connect-failure", "5xx"]
        rate_limit:
          requests_per_second: 100
          per_client: true
        circuit_breaker:
          failure_threshold: 10
          success_threshold: 2
          timeout_secs: 60
        max_connections: 256
        max_request_body_bytes: 1048576
        auth:
          basic:
            realm: "Admin"
            credentials:
              admin: "$2b$10$somehash"
        cors:
          allow_origins: ["https://app.example.com"]
          allow_methods: [GET, POST]
          allow_headers: [Content-Type]
          expose_headers: [X-Request-Id]
          allow_credentials: true
          max_age: 3600
        ip_allowlist:
          allow: ["10.0.0.0/8"]
          deny: ["10.0.0.99/32"]
          trusted_proxies: ["172.16.0.0/12"]
        request_headers:
          add:
            X-Forwarded-By: portus
          set:
            X-Env: prod
          remove: [X-Debug]
        response_headers:
          add:
            X-Served-By: portus
        mirrors:
          - address: "10.0.0.5:9090"
            percent: 10
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.listeners.len(), 1);

        let route = &config.listeners[0].routes[0];
        assert_eq!(route.hosts.len(), 2);
        assert_eq!(route.paths.len(), 2);
        assert_eq!(route.backends.len(), 2);
        assert_eq!(route.backends[0].weight, 3);
        assert_eq!(route.method.as_deref(), Some("GET"));
        assert_eq!(route.headers.len(), 1);
        assert_eq!(route.query_params.len(), 1);

        let timeouts = route.timeouts.as_ref().unwrap();
        assert_eq!(timeouts.request_ms, Some(30000));
        assert_eq!(timeouts.backend_request_ms, Some(10000));
        assert_eq!(timeouts.connect_ms, Some(5000));

        let retries = route.retries.as_ref().unwrap();
        assert_eq!(retries.max, Some(3));
        assert_eq!(retries.on.len(), 2);

        let rl = route.rate_limit.as_ref().unwrap();
        assert_eq!(rl.requests_per_second, 100);
        assert!(rl.per_client);

        let cb = route.circuit_breaker.as_ref().unwrap();
        assert_eq!(cb.failure_threshold, 10);
        assert_eq!(cb.success_threshold, 2);
        assert_eq!(cb.timeout_secs, 60);

        assert_eq!(route.max_connections, Some(256));
        assert_eq!(route.max_request_body_bytes, Some(1048576));

        let auth = route.auth.as_ref().unwrap();
        let basic = auth.basic.as_ref().unwrap();
        assert_eq!(basic.realm, "Admin");
        assert_eq!(basic.credentials.len(), 1);

        let cors = route.cors.as_ref().unwrap();
        assert_eq!(cors.allow_origins.len(), 1);
        assert!(cors.allow_credentials);

        let ip = route.ip_allowlist.as_ref().unwrap();
        assert_eq!(ip.allow.len(), 1);
        assert_eq!(ip.deny.len(), 1);
        assert_eq!(ip.trusted_proxies.len(), 1);

        assert_eq!(route.mirrors.len(), 1);
        assert_eq!(route.mirrors[0].percent, 10);
    }

    #[test]
    fn test_defaults_applied() {
        let yaml = r#"
listeners:
  - port: 8080
    routes:
      - backends:
          - address: "127.0.0.1:3000"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let listener = &config.listeners[0];
        assert_eq!(listener.protocol, "HTTP");
        assert!(listener.tls.is_none());
        assert!(listener.hostname.is_none());

        let route = &listener.routes[0];
        assert!(route.hosts.is_empty()); // defaults to ["*"] during conversion
        assert!(route.paths.is_empty()); // defaults to ["/", Prefix] during conversion
        assert_eq!(route.backends[0].weight, 1);
        assert!(route.method.is_none());
        assert!(route.timeouts.is_none());
        assert!(route.rate_limit.is_none());
        assert!(route.circuit_breaker.is_none());
        assert!(route.auth.is_none());
        assert!(route.cors.is_none());
    }

    #[test]
    fn test_to_compiled_config_basic() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["example.com"]
        paths:
          - path: /api
            type: Prefix
        backends:
          - address: "10.0.0.1:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        assert_eq!(compiled.schema_version, "1.0.0");
        assert_eq!(compiled.version, 1);
        assert_eq!(compiled.listeners.len(), 1);
        assert_eq!(compiled.listeners[0].port, 80);
        assert_eq!(compiled.listeners[0].protocol, "HTTP");

        assert_eq!(compiled.routes.len(), 1);
        assert_eq!(compiled.routes[0].host, "example.com");
        assert_eq!(compiled.routes[0].paths.len(), 1);
        assert_eq!(compiled.routes[0].paths[0].path, "/api");
        assert_eq!(compiled.routes[0].paths[0].match_type, "Prefix");
        assert_eq!(compiled.routes[0].listener_port, 80);
        assert!(!compiled.routes[0].service_name.is_empty());

        assert_eq!(compiled.backends.len(), 1);
        assert_eq!(compiled.backends[0].endpoints.len(), 1);
        assert_eq!(compiled.backends[0].endpoints[0].address, "10.0.0.1");
        assert_eq!(compiled.backends[0].endpoints[0].port, 8080);
    }

    #[test]
    fn test_to_compiled_config_multiple_hosts() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["a.com", "b.com"]
        backends:
          - address: "10.0.0.1:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        // One RouteConfig per host
        assert_eq!(compiled.routes.len(), 2);
        let hosts: Vec<&str> = compiled.routes.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.contains(&"a.com"));
        assert!(hosts.contains(&"b.com"));
    }

    #[test]
    fn test_to_compiled_config_wildcard_host() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["*"]
        backends:
          - address: "10.0.0.1:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();
        assert_eq!(compiled.routes[0].host, "*");
    }

    #[test]
    fn test_to_compiled_config_default_host_and_path() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();
        assert_eq!(compiled.routes[0].host, "*");
        assert_eq!(compiled.routes[0].paths[0].path, "/");
        assert_eq!(compiled.routes[0].paths[0].match_type, "Prefix");
    }

    #[test]
    fn test_synthetic_service_name_deterministic() {
        let backends_a = vec![
            YamlBackend { address: "10.0.0.2:8080".to_string(), weight: 1 },
            YamlBackend { address: "10.0.0.1:8080".to_string(), weight: 1 },
        ];
        let backends_b = vec![
            YamlBackend { address: "10.0.0.1:8080".to_string(), weight: 1 },
            YamlBackend { address: "10.0.0.2:8080".to_string(), weight: 1 },
        ];
        // Same backends in different order should produce the same name
        assert_eq!(
            synthetic_service_name(&backends_a),
            synthetic_service_name(&backends_b)
        );
    }

    #[test]
    fn test_synthetic_service_name_different_backends() {
        let a = vec![YamlBackend { address: "10.0.0.1:8080".to_string(), weight: 1 }];
        let b = vec![YamlBackend { address: "10.0.0.2:8080".to_string(), weight: 1 }];
        assert_ne!(synthetic_service_name(&a), synthetic_service_name(&b));
    }

    #[test]
    fn test_parse_backend_address_ipv4() {
        let (host, port) = parse_backend_address("10.0.0.1:8080").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_backend_address_ipv6() {
        let (host, port) = parse_backend_address("[::1]:8080").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_backend_address_hostname() {
        let (host, port) = parse_backend_address("backend.local:3000").unwrap();
        assert_eq!(host, "backend.local");
        assert_eq!(port, 3000);
    }

    #[test]
    fn test_parse_backend_address_invalid() {
        assert!(parse_backend_address("no-port").is_err());
        assert!(parse_backend_address("host:notanumber").is_err());
    }

    #[test]
    fn test_to_compiled_config_redirect_only() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["example.com"]
        redirect:
          scheme: https
          status_code: 301
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        assert_eq!(compiled.routes.len(), 1);
        assert!(compiled.routes[0].service_name.is_empty());
        assert!(compiled.routes[0].redirect.is_some());
        let redir = compiled.routes[0].redirect.as_ref().unwrap();
        assert_eq!(redir.scheme, "https");
        assert_eq!(redir.status_code, 301);
    }

    #[test]
    fn test_to_compiled_config_with_rate_limit() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        rate_limit:
          requests_per_second: 50
          per_client: true
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let rl = compiled.routes[0].rate_limit.as_ref().unwrap();
        assert_eq!(rl.requests_per_second, 50);
        assert!(rl.per_client);
    }

    #[test]
    fn test_to_compiled_config_with_circuit_breaker() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        circuit_breaker:
          failure_threshold: 10
          success_threshold: 2
          timeout_secs: 60
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let cb = compiled.routes[0].circuit_breaker.as_ref().unwrap();
        assert_eq!(cb.failure_threshold, 10);
        assert_eq!(cb.success_threshold, 2);
        assert_eq!(cb.timeout_secs, 60);
    }

    #[test]
    fn test_to_compiled_config_with_auth() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        auth:
          basic:
            realm: "Protected"
            credentials:
              admin: "$2b$10$hash"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let auth = compiled.routes[0].auth.as_ref().unwrap();
        match &auth.auth_type {
            Some(portus_types::proto::portus::config::v1::auth_config::AuthType::BasicAuth(ba)) => {
                assert_eq!(ba.realm, "Protected");
                assert_eq!(ba.credentials.len(), 1);
                assert!(ba.credentials.contains_key("admin"));
            }
            _ => panic!("expected BasicAuth"),
        }
    }

    #[test]
    fn test_to_compiled_config_with_api_key_auth() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        auth:
          api_key:
            header: X-Custom-Key
            keys: ["key1", "key2"]
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let auth = compiled.routes[0].auth.as_ref().unwrap();
        match &auth.auth_type {
            Some(portus_types::proto::portus::config::v1::auth_config::AuthType::ApiKey(ak)) => {
                assert_eq!(ak.header_name, "X-Custom-Key");
                assert_eq!(ak.valid_keys.len(), 2);
            }
            _ => panic!("expected ApiKey auth"),
        }
    }

    #[test]
    fn test_to_compiled_config_with_cors() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        cors:
          allow_origins: ["https://app.example.com"]
          allow_methods: [GET, POST]
          allow_headers: [Content-Type]
          allow_credentials: true
          max_age: 3600
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let cors = compiled.routes[0].cors.as_ref().unwrap();
        assert_eq!(cors.allow_origins, vec!["https://app.example.com"]);
        assert_eq!(cors.allow_methods, vec!["GET", "POST"]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, 3600);
    }

    #[test]
    fn test_to_compiled_config_with_ip_allowlist() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        ip_allowlist:
          allow: ["10.0.0.0/8"]
          deny: ["10.0.0.99/32"]
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let ip = compiled.routes[0].ip_allowlist.as_ref().unwrap();
        assert_eq!(ip.allow_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(ip.deny_cidrs, vec!["10.0.0.99/32"]);
    }

    #[test]
    fn test_to_compiled_config_with_timeouts() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        timeouts:
          request_ms: 30000
          backend_request_ms: 10000
          connect_ms: 5000
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let route = &compiled.routes[0];
        assert_eq!(route.request_timeout_ms, 30000);
        assert_eq!(route.backend_request_timeout_ms, 10000);
        let t = route.timeouts.as_ref().unwrap();
        assert_eq!(t.connect_timeout_ms, 5000);
    }

    #[test]
    fn test_to_compiled_config_with_retries() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        retries:
          max: 3
          on: ["connect-failure", "5xx"]
          codes: [502, 503]
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        assert_eq!(compiled.routes[0].max_retries, 3);
        assert_eq!(compiled.routes[0].retry_on, vec!["connect-failure", "5xx"]);
        assert_eq!(compiled.routes[0].retry_codes, vec![502, 503]);
    }

    #[test]
    fn test_to_compiled_config_with_header_mutations() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        request_headers:
          add:
            X-Forwarded-By: portus
          remove: [X-Debug]
        response_headers:
          set:
            X-Served-By: portus
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let req = compiled.routes[0].request_headers.as_ref().unwrap();
        assert_eq!(req.add.get("X-Forwarded-By").unwrap(), "portus");
        assert_eq!(req.remove, vec!["X-Debug"]);

        let resp = compiled.routes[0].response_headers.as_ref().unwrap();
        assert_eq!(resp.set.get("X-Served-By").unwrap(), "portus");
    }

    #[test]
    fn test_to_compiled_config_with_mirrors() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        mirrors:
          - address: "10.0.0.5:9090"
            percent: 10
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        assert_eq!(compiled.routes[0].mirror_backends.len(), 1);
        assert_eq!(compiled.routes[0].mirror_backends[0].percent, 10);
        // Mirror backend should also be registered in backend groups
        assert!(compiled.backends.len() >= 2);
    }

    #[test]
    fn test_tls_cert_loading() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("portus-test-tls");
        std::fs::create_dir_all(&dir).unwrap();

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
            .unwrap();

        let yaml = format!(
            r#"
listeners:
  - port: 443
    protocol: HTTPS
    tls:
      cert_file: {}
      key_file: {}
    routes:
      - hosts: ["secure.example.com"]
        backends:
          - address: "10.0.0.1:8080"
"#,
            cert_path.display(),
            key_path.display()
        );

        let config: StandaloneConfig = serde_yaml_ng::from_str(&yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let listener = &compiled.listeners[0];
        assert_eq!(listener.protocol, "HTTPS");
        let cert_ref = listener.tls_cert_ref.as_ref().unwrap();
        assert!(cert_ref.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_ref.key_pem.contains("BEGIN PRIVATE KEY"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_invalid_yaml_returns_error() {
        let yaml = "this is not: [valid: yaml: {{}";
        let result: Result<StandaloneConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_backend_address_port_returns_error() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "no-port-here"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let result = to_compiled_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected host:port"));
    }

    #[test]
    fn test_empty_listeners() {
        let yaml = "listeners: []";
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();
        assert!(compiled.routes.is_empty());
        assert!(compiled.backends.is_empty());
        assert!(compiled.listeners.is_empty());
    }

    #[test]
    fn test_to_compiled_config_multiple_listeners() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["a.com"]
        backends:
          - address: "10.0.0.1:8080"
  - port: 8080
    routes:
      - hosts: ["b.com"]
        backends:
          - address: "10.0.0.2:9090"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        assert_eq!(compiled.listeners.len(), 2);
        assert_eq!(compiled.routes.len(), 2);
        // Routes should have different listener_port values
        let ports: Vec<u32> = compiled.routes.iter().map(|r| r.listener_port).collect();
        assert!(ports.contains(&80));
        assert!(ports.contains(&8080));
    }

    #[test]
    fn test_to_compiled_config_url_rewrite() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["example.com"]
        backends:
          - address: "10.0.0.1:8080"
        rewrite:
          path: /v2
          path_type: ReplaceFullPath
          hostname: internal.example.com
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let rw = compiled.routes[0].url_rewrite.as_ref().unwrap();
        assert_eq!(rw.path, "/v2");
        assert_eq!(rw.path_type, "ReplaceFullPath");
        assert_eq!(rw.hostname, "internal.example.com");
    }

    #[test]
    fn test_to_compiled_config_header_and_query_matches() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["example.com"]
        backends:
          - address: "10.0.0.1:8080"
        method: POST
        headers:
          - name: X-Version
            value: "2"
          - name: Accept
            value: "application/json"
            type: Exact
        query_params:
          - name: format
            value: json
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        let route = &compiled.routes[0];
        assert_eq!(route.method_match, "POST");
        assert_eq!(route.header_matches.len(), 2);
        assert_eq!(route.header_matches[0].name, "X-Version");
        assert_eq!(route.header_matches[0].value, "2");
        assert_eq!(route.query_param_matches.len(), 1);
        assert_eq!(route.query_param_matches[0].name, "format");
    }

    #[test]
    fn test_circuit_breaker_defaults() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - backends:
          - address: "10.0.0.1:8080"
        circuit_breaker:
          failure_threshold: 3
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let cb = config.listeners[0].routes[0].circuit_breaker.as_ref().unwrap();
        assert_eq!(cb.failure_threshold, 3);
        assert_eq!(cb.success_threshold, 1); // default
        assert_eq!(cb.timeout_secs, 30); // default
    }

    #[test]
    fn test_redirect_defaults() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["example.com"]
        redirect:
          scheme: https
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let redir = config.listeners[0].routes[0].redirect.as_ref().unwrap();
        assert_eq!(redir.status_code, 302); // default
        assert_eq!(redir.scheme, Some("https".to_string()));
        assert!(redir.hostname.is_none());
        assert!(redir.port.is_none());
    }

    #[test]
    fn test_shared_backends_produce_same_service_name() {
        let yaml = r#"
listeners:
  - port: 80
    routes:
      - hosts: ["a.com"]
        backends:
          - address: "10.0.0.1:8080"
          - address: "10.0.0.2:8080"
      - hosts: ["b.com"]
        backends:
          - address: "10.0.0.1:8080"
          - address: "10.0.0.2:8080"
"#;
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = to_compiled_config(&config).unwrap();

        // Both routes should share the same service name and backend group
        assert_eq!(compiled.routes[0].service_name, compiled.routes[1].service_name);
        assert_eq!(compiled.backends.len(), 1);
    }
}
