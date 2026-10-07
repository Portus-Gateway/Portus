//! Standalone YAML configuration mode for the Portus dataplane.
//!
//! When the `PORTUS_CONFIG_FILE` environment variable is set, the dataplane reads
//! configuration from a YAML file instead of receiving it via gRPC from a
//! controller. This enables use as a standalone reverse proxy without Kubernetes.
//!
//! The YAML format maps directly to the proto `CompiledConfig` schema, with
//! ergonomic naming (snake_case, nested objects instead of flat proto fields).
//!
//! Hot reload ([`reload`]): the YAML and every certificate file it names are
//! watched, backend hostnames are re-resolved periodically, and certificates
//! issued over ACME ([`acme`]) are swapped in without a restart.

pub mod acme;
pub mod reload;

pub use reload::start;

use log::warn;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// YAML deserialization types
// ---------------------------------------------------------------------------

/// Top-level standalone configuration.
#[derive(Debug, Deserialize)]
pub struct StandaloneConfig {
    #[serde(default)]
    pub listeners: Vec<YamlListener>,
    /// Seconds between re-resolutions of backend hostnames; 0 disables.
    #[serde(default = "default_dns_refresh_secs")]
    pub dns_refresh_secs: u64,
    /// ACME account and CA settings, shared by every `tls.acme` listener.
    #[serde(default)]
    pub acme: acme::AcmeSettings,
}

fn default_dns_refresh_secs() -> u64 {
    30
}

/// A listener defines a port, protocol, optional TLS, and a set of routes.
#[derive(Debug, Deserialize)]
pub struct YamlListener {
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

/// TLS configuration for an HTTPS listener: certificate files on disk, or
/// certificates obtained over ACME.
#[derive(Debug, Deserialize)]
pub struct YamlListenerTls {
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub acme: Option<acme::ListenerAcme>,
}

/// A route matches requests by host/path/headers and forwards to backends.
#[derive(Debug, Default, Deserialize)]
pub struct YamlRoute {
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
pub struct YamlPathRule {
    pub path: String,
    #[serde(default = "default_path_type", rename = "type")]
    pub match_type: String,
}

fn default_path_type() -> String {
    "Prefix".to_string()
}

/// A backend endpoint with optional weight.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct YamlBackend {
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Header match rule for request routing.
#[derive(Debug, Deserialize)]
pub struct YamlHeaderMatch {
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
pub struct YamlQueryParamMatch {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default = "default_match_type", rename = "type")]
    pub match_type: String,
}

/// Redirect configuration.
#[derive(Debug, Default, Deserialize)]
pub struct YamlRedirect {
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
pub struct YamlRewrite {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_type: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Timeout configuration.
#[derive(Debug, Default, Deserialize)]
pub struct YamlTimeouts {
    #[serde(default)]
    pub request_ms: Option<u64>,
    #[serde(default)]
    pub backend_request_ms: Option<u64>,
    #[serde(default)]
    pub connect_ms: Option<u64>,
}

/// Retry configuration.
#[derive(Debug, Default, Deserialize)]
pub struct YamlRetries {
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
pub struct YamlRateLimit {
    #[serde(default)]
    pub requests_per_second: u32,
    #[serde(default)]
    pub per_client: bool,
}

/// Circuit breaker configuration.
#[derive(Debug, Deserialize)]
pub struct YamlCircuitBreaker {
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
pub struct YamlAuth {
    #[serde(default)]
    pub basic: Option<YamlBasicAuth>,
    #[serde(default)]
    pub api_key: Option<YamlApiKeyAuth>,
}

/// HTTP Basic authentication.
#[derive(Debug, Default, Deserialize)]
pub struct YamlBasicAuth {
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
pub struct YamlApiKeyAuth {
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
pub struct YamlCors {
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
pub struct YamlIpAllowlist {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// Header mutation (add/set/remove).
#[derive(Debug, Default, Deserialize)]
pub struct YamlHeaderMutation {
    #[serde(default)]
    pub add: HashMap<String, String>,
    #[serde(default)]
    pub set: HashMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Request mirroring configuration.
#[derive(Debug, Deserialize)]
pub struct YamlMirror {
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

/// Addresses each backend hostname resolved to, from [`resolve_backend_hosts`].
/// IP-literal backends are not in the table.
pub type DnsTable = HashMap<String, Vec<IpAddr>>;

/// A hostname lookup: the system resolver in production, a fixed table in tests.
pub type Lookup = fn(&str) -> std::io::Result<Vec<IpAddr>>;

/// Resolve `host` with the system resolver (`/etc/hosts`, then DNS).
pub fn system_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    Ok((host, 0).to_socket_addrs()?.map(|sa| sa.ip()).collect())
}

/// The IP of an IP-literal backend host (`10.0.0.1`, `[::1]`), else `None`.
fn literal_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok()
}

/// Every backend and mirror hostname in the config that needs a DNS lookup.
fn backend_hostnames(config: &StandaloneConfig) -> BTreeSet<String> {
    config
        .listeners
        .iter()
        .flat_map(|l| &l.routes)
        .flat_map(|r| r.backends.iter().map(|b| &b.address).chain(r.mirrors.iter().map(|m| &m.address)))
        .filter_map(|addr| parse_backend_address(addr).ok())
        .map(|(host, _)| host)
        .filter(|host| literal_ip(host).is_none())
        .collect()
}

/// Resolve every backend hostname in `config`. A lookup that fails or comes
/// back empty keeps the addresses from `previous`, so a DNS blip never empties
/// a pool; a hostname that has never resolved gets no endpoints (502 until it
/// does) rather than failing the whole config.
pub fn resolve_backend_hosts(config: &StandaloneConfig, previous: &DnsTable, lookup: Lookup) -> DnsTable {
    backend_hostnames(config)
        .into_iter()
        .map(|host| {
            let ips = match lookup(&host) {
                Ok(mut ips) if !ips.is_empty() => {
                    ips.sort_unstable();
                    ips.dedup();
                    ips
                }
                result => {
                    let reason = result.err().map_or_else(|| "no addresses".to_string(), |e| e.to_string());
                    match previous.get(&host) {
                        Some(last) => {
                            warn!("backend host '{host}' did not resolve ({reason}); keeping its last {} address(es)", last.len());
                            last.clone()
                        }
                        None => {
                            warn!("backend host '{host}' did not resolve ({reason}); its routes return 502 until it does");
                            Vec::new()
                        }
                    }
                }
            };
            (host, ips)
        })
        .collect()
}

/// The endpoints one backend address stands for: itself when it is an IP
/// literal, else every address its hostname resolved to.
fn backend_endpoints(address: &str, dns: &DnsTable) -> Result<(u16, Vec<portus_types::BackendEndpoint>), String> {
    let (host, port) = parse_backend_address(address)?;
    let ips = match literal_ip(&host) {
        Some(ip) => vec![ip],
        None => dns.get(&host).cloned().unwrap_or_default(),
    };
    let endpoints = ips
        .into_iter()
        .map(|ip| portus_types::BackendEndpoint {
            // Bracketed so `"{address}:{port}"` parses as a SocketAddr.
            address: match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            },
            port: u32::from(port),
        })
        .collect();
    Ok((port, endpoints))
}

/// Register a backend group for `backends` (once per distinct set) and return
/// its service name and port.
fn backend_group(
    backends: &[YamlBackend],
    dns: &DnsTable,
    groups: &mut HashMap<String, portus_types::BackendGroup>,
) -> Result<(String, u32), String> {
    let service_name = synthetic_service_name(backends);
    let mut port = None;
    let mut endpoints = Vec::new();
    for backend in backends {
        let (p, eps) = backend_endpoints(&backend.address, dns)?;
        port.get_or_insert(u32::from(p));
        endpoints.extend(eps);
    }
    let port = port.unwrap_or_default();
    groups.entry(service_name.clone()).or_insert_with(|| portus_types::BackendGroup {
        service_name: service_name.clone(),
        port,
        endpoints,
        health_check: None,
        backend_tls: None,
    });
    Ok((service_name, port))
}

/// What the reloader needs besides the proto: the ACME work the config asks
/// for and the files whose changes should trigger a reload.
pub struct Compiled {
    pub config: portus_types::CompiledConfig,
    pub acme: Option<acme::AcmePlan>,
    /// Certificate and key files the config read, with [`content_hash`] of
    /// the bytes read (the YAML itself is the reloader's own business).
    pub read_files: Vec<(PathBuf, u64)>,
}

/// Hash of a file's contents, to tell a real change from an unrelated event.
pub fn content_hash(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn read_file(path: &str, what: &str, out: &mut Compiled) -> Result<String, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| format!("failed to read TLS {what} '{path}': {e}"))?;
    out.read_files.push((PathBuf::from(path), content_hash(contents.as_bytes())));
    Ok(contents)
}

/// One listener's TLS: the certificate for the listener itself plus, for an
/// ACME listener with several domains, one extra (route-less) listener per
/// further domain so each domain's certificate is selected by SNI.
fn listener_tls(
    listener: &YamlListener,
    config: &StandaloneConfig,
    listener_name: &str,
    out: &mut Compiled,
) -> Result<(Option<portus_types::TlsCertRef>, Vec<portus_types::Listener>), String> {
    let Some(tls) = &listener.tls else { return Ok((None, Vec::new())) };
    match (&tls.cert_file, &tls.key_file, &tls.acme) {
        (Some(cert_file), Some(key_file), None) => {
            let cert_pem = read_file(cert_file, "cert", out)?;
            let key_pem = read_file(key_file, "key", out)?;
            Ok((Some(portus_types::TlsCertRef { cert_pem, key_pem }), Vec::new()))
        }
        (None, None, Some(listener_acme)) => {
            let domains = acme::listener_domains(listener, listener_acme)?;
            let plan = out.acme.get_or_insert_with(|| acme::AcmePlan {
                settings: config.acme.clone(),
                domains: BTreeSet::new(),
            });
            plan.domains.extend(domains.iter().cloned());
            // The listener's own entry carries its hostname's certificate (or
            // the first domain's, as the default for a hostname-less listener).
            let hostname = listener.hostname.as_deref().unwrap_or_default();
            let main = domains.iter().find(|d| *d == hostname).unwrap_or(&domains[0]);
            let cert_ref = |domain: &str| {
                acme::current_cert(&config.acme, domain)
                    .map(|(cert_pem, key_pem)| portus_types::TlsCertRef { cert_pem, key_pem })
            };
            let extras = domains
                .iter()
                .filter(|d| *d != main)
                .map(|domain| {
                    Ok(portus_types::Listener {
                        name: format!("{listener_name}-acme-{domain}"),
                        port: listener.port,
                        protocol: listener.protocol.to_uppercase(),
                        hostname: domain.clone(),
                        tls_cert_ref: Some(cert_ref(domain)?),
                        ..Default::default()
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((Some(cert_ref(main)?), extras))
        }
        _ => Err(format!(
            "listener on port {}: tls needs either cert_file and key_file, or acme",
            listener.port
        )),
    }
}

/// Convert a `StandaloneConfig` into a `portus_types::CompiledConfig`, with
/// backend hostnames taken from `dns`.
#[allow(deprecated)] // mirror_backend (field 21) must be explicitly None in the struct literal
pub fn to_compiled_config(config: &StandaloneConfig, dns: &DnsTable) -> Result<Compiled, String> {
    let mut out = Compiled {
        config: portus_types::CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 1,
            ..Default::default()
        },
        acme: None,
        read_files: Vec::new(),
    };
    let mut proto = std::mem::take(&mut out.config);

    // Track backend groups by service name to avoid duplicates.
    let mut backend_groups: HashMap<String, portus_types::BackendGroup> = HashMap::new();

    for listener in &config.listeners {
        // Build proto Listener
        let listener_name = format!("standalone-{}-{}", listener.protocol.to_lowercase(), listener.port);

        let (tls_cert_ref, acme_listeners) = listener_tls(listener, config, &listener_name, &mut out)?;

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
        proto.listeners.extend(acme_listeners);

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

            // Equal weights share one pool (per-endpoint health and outlier
            // state); unequal weights get a pool per backend and a weighted
            // split across them. Redirect-only routes have no backends.
            let unequal_weights = route.backends.windows(2).any(|w| w[0].weight != w[1].weight);
            let (service_name, route_port, weighted_backends) = if route.backends.is_empty() {
                (String::new(), 0, Vec::new())
            } else if unequal_weights {
                let weighted = route
                    .backends
                    .iter()
                    .map(|b| {
                        let (service_name, port) = backend_group(std::slice::from_ref(b), dns, &mut backend_groups)?;
                        Ok(portus_types::WeightedBackend {
                            service_name,
                            port,
                            weight: b.weight,
                            request_headers: None,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                (weighted[0].service_name.clone(), weighted[0].port, weighted)
            } else {
                let (service_name, port) = backend_group(&route.backends, dns, &mut backend_groups)?;
                (service_name, port, Vec::new())
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
                    let (port, endpoints) = match backend_endpoints(&m.address, dns) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("invalid mirror address '{}': {}, skipping", m.address, e);
                            return None;
                        }
                    };
                    let host = parse_backend_address(&m.address).map(|(h, _)| h).unwrap_or_default();
                    let mirror_svc = format!("standalone-mirror-{host}-{port}");
                    // Register a backend group for the mirror
                    backend_groups.entry(mirror_svc.clone()).or_insert_with(|| {
                        portus_types::BackendGroup {
                            service_name: mirror_svc.clone(),
                            port: u32::from(port),
                            endpoints,
                            health_check: None,
                            backend_tls: None,
                        }
                    });
                    Some(portus_types::MirrorBackend {
                        service_name: mirror_svc,
                        port: u32::from(port),
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
                    ext_auth: None,
                    upstream_tls: None,
                    grpc_match: None,
                    mirror_backend: None,
                    weighted_backends: weighted_backends.clone(),
                                    gateway_namespace: String::new(),
                    gateway_name: String::new(),
                    ai_dialect: String::new(),
                    ai_provider: String::new(),
                    ai_key_required: false,
                    ai_budget: None,
                    ai_session_affinity: false,
                    ai_jwt: None,
                    ai_on_behalf_of: None,
                    ai_federation: String::new(),
                });
            }
        }
    }

    proto.backends = backend_groups.into_values().collect();
    proto.backends.sort_by(|a, b| a.service_name.cmp(&b.service_name));
    acme::check_challenge_reachable(config, out.acme.as_ref())?;
    out.config = proto;
    Ok(out)
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::compile;
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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();
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
        let compiled = compile(&config).unwrap();
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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let result = compile(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected host:port"));
    }

    #[test]
    fn test_empty_listeners() {
        let yaml = "listeners: []";
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = compile(&config).unwrap();
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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

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
        let compiled = compile(&config).unwrap();

        // Both routes should share the same service name and backend group
        assert_eq!(compiled.routes[0].service_name, compiled.routes[1].service_name);
        assert_eq!(compiled.backends.len(), 1);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::config_receiver::{ProxyState, TlsCertSlot};
    use crate::l4_proxy::L4Config;
    use arc_swap::ArcSwap;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    pub(crate) fn proxy_state() -> Arc<ProxyState> {
        let tls_cert: TlsCertSlot = Arc::new(ArcSwap::from_pointee(None));
        Arc::new(ProxyState {
            snapshot: Arc::new(ArcSwap::from_pointee(crate::router::ProxySnapshot::default())),
            lbs: Arc::new(ArcSwap::from_pointee(Default::default())),
            l4_config: Arc::new(ArcSwap::from_pointee(L4Config::default())),
            tls_cert,
            tls_cert_notify: Arc::new(tokio::sync::Notify::new()),
            health_check_min_interval: Arc::new(AtomicU32::new(10)),
        })
    }

    /// Compile with no DNS table (IP-literal backends only).
    pub(crate) fn compile(config: &super::StandaloneConfig) -> Result<portus_types::CompiledConfig, String> {
        super::to_compiled_config(config, &super::DnsTable::new()).map(|c| c.config)
    }
}

/// Regression tests for standalone bugs found in the 2026-10-01 survey: each
/// drives the YAML through `apply_config` and checks what the router sees.
#[cfg(test)]
mod pipeline_tests {
    use super::test_support::{compile, proxy_state};
    use super::*;
    use crate::config_receiver::{apply_config, ProxyState};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn has_host(state: &ProxyState, port: u16, host: &str) -> bool {
        state
            .snapshot
            .load()
            .listeners_by_port
            .get(&port)
            .is_some_and(|buckets| buckets.iter().any(|b| b.exact.contains_key(host)))
    }

    /// Poll `cond` for up to `within`; file watchers deliver asynchronously.
    fn eventually(within: Duration, cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        cond()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("portus-standalone-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn route_yaml(host: &str) -> String {
        format!(
            "listeners:\n  - port: 80\n    routes:\n      - hosts: [\"{host}\"]\n        backends:\n          - address: \"127.0.0.1:9\"\n"
        )
    }

    /// Bug: a backend named by DNS (`app:8080`, the docker-compose case) was
    /// passed through as the endpoint address, failed `SocketAddr` parsing in
    /// `build_lb_map_from_proto` and was dropped without a word: the route had
    /// no pool.
    #[test]
    fn dns_named_backend_gets_a_pool() {
        let state = proxy_state();
        let config: StandaloneConfig = serde_yaml_ng::from_str(
            "listeners:\n  - port: 80\n    routes:\n      - hosts: [\"app.example.com\"]\n        backends:\n          - address: \"localhost:8080\"\n",
        )
        .unwrap();
        let dns = resolve_backend_hosts(&config, &DnsTable::new(), system_lookup);
        let compiled = to_compiled_config(&config, &dns).unwrap().config;
        let service = compiled.routes[0].service_name.clone();
        apply_config(compiled, &state);

        let snap = state.snapshot.load();
        let pool = snap.lbs.get(&(Arc::from(service.as_str()), 8080)).expect("route has a pool");
        assert!(pool
            .endpoints()
            .iter()
            .all(|ep| ep.addr.ip().is_loopback() && ep.addr.port() == 8080));
        assert!(!pool.is_empty());
    }

    /// Bug: `weight` was parsed and ignored; every backend shared one
    /// round-robin pool, so `weight: 3` / `weight: 1` split traffic 50/50.
    #[test]
    fn backend_weights_reach_the_router() {
        let state = proxy_state();
        let config: StandaloneConfig = serde_yaml_ng::from_str(
            "listeners:\n  - port: 80\n    routes:\n      - hosts: [\"api.example.com\"]\n        backends:\n          - address: \"10.0.1.1:8080\"\n            weight: 3\n          - address: \"10.0.1.2:8080\"\n            weight: 1\n",
        )
        .unwrap();
        apply_config(compile(&config).unwrap(), &state);

        let snap = state.snapshot.load();
        let bucket = &snap.listeners_by_port[&80][0];
        let route = bucket.exact["api.example.com"].catch_all.as_ref().or_else(|| bucket.exact["api.example.com"].rules.first()).unwrap();
        let mut weights: Vec<u32> = route.weighted_backends.iter().map(|wb| wb.weight).collect();
        weights.sort_unstable();
        assert_eq!(weights, vec![1, 3]);
        // Each weighted backend has its own pool holding exactly its address.
        for wb in &route.weighted_backends {
            let pool = &snap.lbs[&(Arc::clone(&wb.service_name), wb.port)];
            assert_eq!(pool.endpoints().len(), 1);
        }
    }

    /// Equal weights keep one shared pool (health and outlier state per
    /// endpoint, no weighted split).
    #[test]
    fn equal_weights_keep_one_pool() {
        let config: StandaloneConfig = serde_yaml_ng::from_str(
            "listeners:\n  - port: 80\n    routes:\n      - backends:\n          - address: \"10.0.1.1:8080\"\n          - address: \"10.0.1.2:8080\"\n",
        )
        .unwrap();
        let compiled = compile(&config).unwrap();
        assert!(compiled.routes[0].weighted_backends.is_empty());
        assert_eq!(compiled.backends.len(), 1);
        assert_eq!(compiled.backends[0].endpoints.len(), 2);
    }

    /// Bug: an edit landing within 500 ms of the previous reload was drained
    /// and never applied, so the proxy kept serving the older file until the
    /// next unrelated edit.
    #[test]
    fn second_edit_right_after_a_reload_is_applied() {
        let dir = temp_dir("debounce");
        let path = dir.join("portus.yaml");
        std::fs::write(&path, route_yaml("v1.example.com")).unwrap();
        let state = proxy_state();
        reload::start_with_lookup(path.to_str().unwrap(), state.clone(), system_lookup).unwrap();
        std::thread::sleep(Duration::from_millis(300));

        std::fs::write(&path, route_yaml("v2.example.com")).unwrap();
        assert!(eventually(Duration::from_secs(5), || has_host(&state, 80, "v2.example.com")));
        std::fs::write(&path, route_yaml("v3.example.com")).unwrap();
        assert!(
            eventually(Duration::from_secs(5), || has_host(&state, 80, "v3.example.com")),
            "the edit made right after a reload was lost"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bug: only the YAML's directory was watched, so a certificate renewed
    /// in its own directory (certbot's `live/<domain>/`) was not served until
    /// the YAML itself changed.
    #[test]
    fn renewed_cert_in_another_directory_is_reloaded() {
        let dir = temp_dir("certwatch");
        let conf_dir = dir.join("conf");
        let cert_dir = dir.join("certs");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::create_dir_all(&cert_dir).unwrap();
        let (cert1, key1) = crate::tls::generate_self_signed_cert().unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &cert1).unwrap();
        std::fs::write(cert_dir.join("key.pem"), &key1).unwrap();
        let path = conf_dir.join("portus.yaml");
        std::fs::write(
            &path,
            format!(
                "listeners:\n  - port: 443\n    protocol: HTTPS\n    tls:\n      cert_file: {}\n      key_file: {}\n    routes:\n      - backends:\n          - address: \"127.0.0.1:9\"\n",
                cert_dir.join("cert.pem").display(),
                cert_dir.join("key.pem").display()
            ),
        )
        .unwrap();
        let state = proxy_state();
        reload::start_with_lookup(path.to_str().unwrap(), state.clone(), system_lookup).unwrap();
        std::thread::sleep(Duration::from_millis(300));

        let (cert2, key2) = crate::tls::generate_self_signed_cert().unwrap();
        std::fs::write(cert_dir.join("key.pem"), &key2).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &cert2).unwrap();
        let served = |pem: &str| {
            state.tls_cert.load().as_ref().as_ref().is_some_and(|d| d.entries.iter().any(|e| e.cert_pem == pem))
        };
        assert!(
            eventually(Duration::from_secs(5), || served(&cert2)),
            "renewed certificate was not picked up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Found by the Pebble e2e run: a log file written next to the YAML
    /// raised directory events, every reload logged, and the reloader
    /// reapplied the config every 200 ms forever. Unrelated files changing in
    /// the directory must not reapply an unchanged config.
    #[test]
    fn an_unchanged_config_is_not_reapplied() {
        let dir = temp_dir("noloop");
        let path = dir.join("portus.yaml");
        std::fs::write(&path, route_yaml("still.example.com")).unwrap();
        let state = proxy_state();
        reload::start_with_lookup(path.to_str().unwrap(), state.clone(), system_lookup).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let applied = state.snapshot.load_full();
        let log = dir.join("portus.log");
        for i in 0..15 {
            std::fs::write(&log, format!("line {i}\n")).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(500));
        assert!(Arc::ptr_eq(&applied, &state.snapshot.load_full()), "config was reapplied with no change");
        // ...and a real edit still lands.
        std::fs::write(&path, route_yaml("moved.example.com")).unwrap();
        assert!(eventually(Duration::from_secs(5), || has_host(&state, 80, "moved.example.com")));
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// The example shipped in the repo must keep compiling as the schema grows.
    #[test]
    fn the_shipped_example_compiles() {
        let yaml = include_str!("../../../../examples/standalone.yaml");
        let config: StandaloneConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let compiled = compile(&config).unwrap();
        crate::config_receiver::validate_config(&compiled).unwrap();
        assert!(compiled.routes.iter().any(|r| r.host == "api.example.com" && r.weighted_backends.len() == 2));
    }

}
