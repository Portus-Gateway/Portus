use hashbrown::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Authentication configuration for a route, compiled from policy CRDs.
#[derive(Clone)]
pub enum AuthConfig {
    BasicAuth {
        /// Map of username -> bcrypt hash
        credentials: HashMap<String, String>,
        realm: String,
    },
    ApiKey {
        /// Set of valid API keys (stored as HashSet for O(1) lookup)
        valid_keys: HashSet<String>,
        header_name: String,
    },
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthConfig::BasicAuth { credentials, realm } => {
                f.debug_struct("BasicAuth")
                    .field("credentials", &format_args!("[{} entries REDACTED]", credentials.len()))
                    .field("realm", realm)
                    .finish()
            }
            AuthConfig::ApiKey { valid_keys, header_name } => {
                f.debug_struct("ApiKey")
                    .field("valid_keys", &format_args!("[{} keys REDACTED]", valid_keys.len()))
                    .field("header_name", header_name)
                    .finish()
            }
        }
    }
}

impl Drop for AuthConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            AuthConfig::BasicAuth {
                credentials,
                realm: _,
            } => {
                for (_, hash) in credentials.iter_mut() {
                    hash.zeroize();
                }
                credentials.clear();
            }
            AuthConfig::ApiKey {
                valid_keys,
                header_name: _,
            } => {
                // HashSet does not allow mutable access to elements (would break
                // hashing invariants), so we drain and zeroize each key individually.
                let keys: Vec<String> = valid_keys.drain().collect();
                for mut key in keys {
                    key.zeroize();
                }
            }
        }
    }
}

/// Equivalent of crd::PathMatchType for the data plane (no kube dependency).
///
/// `RegularExpression` wraps a pre-compiled `regex::Regex` for linear-time
/// matching. The Regex is compiled once at config-build time, not per-request.
#[derive(Clone)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Default)]
pub enum PathMatchType {
    Exact,
    #[default]
    Prefix,
    RegularExpression(regex::Regex),
}

impl PartialEq for PathMatchType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact, Self::Exact) => true,
            (Self::Prefix, Self::Prefix) => true,
            (Self::RegularExpression(a), Self::RegularExpression(b)) => {
                a.as_str() == b.as_str()
            }
            _ => false,
        }
    }
}
impl Eq for PathMatchType {}

impl std::fmt::Debug for PathMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => write!(f, "Exact"),
            Self::Prefix => write!(f, "Prefix"),
            Self::RegularExpression(re) => write!(f, "RegularExpression({})", re.as_str()),
        }
    }
}

impl serde::Serialize for PathMatchType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Exact => serializer.serialize_str("Exact"),
            Self::Prefix => serializer.serialize_str("Prefix"),
            Self::RegularExpression(re) => serializer.serialize_str(&format!("RegularExpression({})", re.as_str())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for PathMatchType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Exact" => Ok(Self::Exact),
            "Prefix" => Ok(Self::Prefix),
            _ => Ok(Self::Prefix), // default
        }
    }
}


#[cfg(test)]
/// Equivalent of crd::PathRule for the data plane.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathRule {
    pub path: String,
    #[serde(default)]
    pub r#type: PathMatchType,
}

/// Backend protocol for upstream connections.
///
/// `HTTP` (default) uses HTTP/1.1. `GRPC` forces HTTP/2 with appropriate
/// stream concurrency and keepalive settings for gRPC backends.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(Default)]
pub enum BackendProtocol {
    #[default]
    Http,
    Grpc,
    /// HTTP/2 cleartext (h2c) — used when Service has appProtocol: kubernetes.io/h2c
    H2c,
    /// WebSocket — used when Service has appProtocol: kubernetes.io/ws
    WebSocket,
}


#[cfg(test)]
pub(crate) fn default_true() -> bool {
    true
}

#[cfg(test)]
/// Equivalent of crd::UpstreamTls for the data plane.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamTls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub verify_cert: bool,
    #[serde(default)]
    pub sni: Option<String>,
}

#[cfg(test)]
/// Equivalent of crd::HeaderMutation for the data plane.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMutation {
    #[serde(default)]
    pub add: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
/// Equivalent of crd::CircuitBreakerCrdConfig for the data plane.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerCrdConfig {
    /// Number of consecutive failures to trip the circuit. Default: 5.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Number of consecutive successes in HalfOpen to close. Default: 1.
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    /// Seconds in Open state before probing. Default: 30.
    #[serde(default = "default_cb_timeout")]
    pub timeout: u32,
}

#[cfg(test)]
fn default_failure_threshold() -> u32 {
    5
}
#[cfg(test)]
fn default_success_threshold() -> u32 {
    1
}
#[cfg(test)]
fn default_cb_timeout() -> u32 {
    30
}

#[cfg(test)]
/// Equivalent of crd::ProxyRouteSpec for the data plane (used in test code).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRouteSpec {
    pub host: String,
    #[serde(default)]
    pub paths: Option<Vec<PathRule>>,
    pub service_name: String,
    pub port: u16,
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,
    #[serde(default)]
    pub write_timeout_ms: Option<u64>,
    #[serde(default)]
    pub rate_limit_rps: Option<u32>,
    #[serde(default)]
    pub retries: Option<u32>,
    #[serde(default)]
    pub tls: Option<UpstreamTls>,
    /// Backend protocol. Defaults to HTTP (HTTP/1.1 upstream).
    /// Set to GRPC for gRPC backends (forces HTTP/2 with stream multiplexing).
    #[serde(default)]
    pub protocol: BackendProtocol,
    #[serde(default)]
    pub request_headers: Option<HeaderMutation>,
    #[serde(default)]
    pub response_headers: Option<HeaderMutation>,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerCrdConfig>,
    /// Maximum concurrent connections to this service. Default: 128.
    #[serde(default)]
    pub max_connections: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_crd_defaults() {
        let json = r#"{"failureThreshold": 10}"#;
        let config: CircuitBreakerCrdConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.success_threshold, 1); // default
        assert_eq!(config.timeout, 30); // default
    }

    #[test]
    fn test_proxy_route_spec_with_circuit_breaker() {
        let json = r#"{
            "host": "api.example.com",
            "serviceName": "backend",
            "port": 8080,
            "circuitBreaker": {"failureThreshold": 3, "timeout": 60},
            "maxConnections": 256
        }"#;
        let spec: ProxyRouteSpec = serde_json::from_str(json).unwrap();
        let cb = spec.circuit_breaker.unwrap();
        assert_eq!(cb.failure_threshold, 3);
        assert_eq!(cb.timeout, 60);
        assert_eq!(spec.max_connections, Some(256));
    }

    #[test]
    fn test_proxy_route_spec_without_circuit_breaker() {
        let json = r#"{"host": "api.example.com", "serviceName": "backend", "port": 8080}"#;
        let spec: ProxyRouteSpec = serde_json::from_str(json).unwrap();
        assert!(spec.circuit_breaker.is_none());
        assert!(spec.max_connections.is_none());
    }

    // SEC-3: Zeroize credential memory on drop
    #[test]
    fn test_auth_config_basic_auth_drop_does_not_panic() {
        let config = AuthConfig::BasicAuth {
            credentials: [("user".to_string(), "$2b$12$fakehashvalue".to_string())]
                .into_iter()
                .collect(),
            realm: "test".to_string(),
        };
        drop(config);
    }

    #[test]
    fn test_auth_config_api_key_drop_does_not_panic() {
        let config = AuthConfig::ApiKey {
            valid_keys: ["secret-key-1".to_string(), "secret-key-2".to_string()]
                .into_iter()
                .collect(),
            header_name: "X-Api-Key".to_string(),
        };
        drop(config);
    }
}
