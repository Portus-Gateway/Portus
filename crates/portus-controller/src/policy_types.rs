//! Policy CRD types for the portus gateway controller.
//!
//! Defines 5 policy attachment CRDs under the `portus-gateway.dev` API group,
//! following the Gateway API Policy Attachment pattern (GEP-713).

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::store::NamespacedName;

// ---- Shared types ----

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PolicyTargetRef {
    pub group: String,
    pub kind: String, // HTTPRoute, GRPCRoute, Gateway, Service
    pub name: String,
    #[serde(
        rename = "sectionName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub section_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PolicyStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SecretRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ---- RateLimitPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "RateLimitPolicy",
    plural = "ratelimitpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct RateLimitPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "rateLimit")]
    pub rate_limit: RateLimitSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitSpec {
    #[serde(rename = "requestsPerSecond")]
    pub requests_per_second: u32,
    #[serde(rename = "perClient", default)]
    pub per_client: bool,
}

// ---- CircuitBreakerPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "CircuitBreakerPolicy",
    plural = "circuitbreakerpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct CircuitBreakerPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "circuitBreaker")]
    pub circuit_breaker: CircuitBreakerSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CircuitBreakerSpec {
    #[serde(rename = "failureThreshold")]
    pub failure_threshold: u32,
    #[serde(rename = "successThreshold")]
    pub success_threshold: u32,
    #[serde(rename = "timeoutSecs")]
    pub timeout_secs: u32,
}

// ---- ConnectionPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "ConnectionPolicy",
    plural = "connectionpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct ConnectionPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "maxConnections")]
    pub max_connections: u32,
}

// ---- BasicAuthPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "BasicAuthPolicy",
    plural = "basicauthpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct BasicAuthPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "basicAuth")]
    pub basic_auth: BasicAuthSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BasicAuthSpec {
    #[serde(rename = "secretRef")]
    pub secret_ref: SecretRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

// ---- APIKeyAuthPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "APIKeyAuthPolicy",
    plural = "apikeyauthpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct APIKeyAuthPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "apiKey")]
    pub api_key: ApiKeySpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ApiKeySpec {
    #[serde(rename = "secretRef")]
    pub secret_ref: SecretRef,
    /// Header name to check for API key. Defaults to "X-API-Key".
    #[serde(
        rename = "headerName",
        default = "default_api_key_header",
        skip_serializing_if = "Option::is_none"
    )]
    pub header_name: Option<String>,
}

// ---- JWTAuthPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "JWTAuthPolicy",
    plural = "jwtauthpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct JWTAuthPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    pub jwt: JwtSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct JwtSpec {
    /// Issuers whose tokens are accepted; a token must verify against one.
    pub providers: Vec<JwtProviderSpec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct JwtProviderSpec {
    /// The `iss` claim tokens carry, an http(s) URL.
    pub issuer: String,
    /// Accepted `aud` values (any one); empty accepts any audience.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    /// Where the issuer publishes its keys; found by OpenID discovery when unset.
    #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Claims copied into request headers for the backend.
    #[serde(rename = "claimToHeaders", default, skip_serializing_if = "Vec::is_empty")]
    pub claim_to_headers: Vec<ClaimToHeader>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ClaimToHeader {
    pub claim: String,
    pub header: String,
}

// ---- ExtAuthPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "ExtAuthPolicy",
    plural = "extauthpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct ExtAuthPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "extAuth")]
    pub ext_auth: ExtAuthSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ExtAuthSpec {
    /// The authorization Service.
    #[serde(rename = "backendRef")]
    pub backend_ref: ServiceBackendRef,
    /// Path of the check request; `/` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// How long to wait for a decision; 1000 when unset.
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    /// Allow requests when the service cannot answer.
    #[serde(rename = "failOpen", default)]
    pub fail_open: bool,
    /// Client headers sent to the service; all when empty.
    #[serde(rename = "requestHeaders", default, skip_serializing_if = "Vec::is_empty")]
    pub request_headers: Vec<String>,
    /// Service response headers copied into the backend request on a 2xx.
    #[serde(rename = "responseHeaders", default, skip_serializing_if = "Vec::is_empty")]
    pub response_headers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ServiceBackendRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub port: u16,
}

fn default_api_key_header() -> Option<String> {
    Some("X-API-Key".to_string())
}

// ---- RetryPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "RetryPolicy",
    plural = "retrypolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct RetryPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    pub retry: RetrySpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RetrySpec {
    #[serde(rename = "maxRetries", default)]
    pub max_retries: u32,
    /// Conditions that trigger a retry: `connect-failure`, `gateway-error`.
    /// Both retry at upstream connection time only; responses already received
    /// from a backend are never retried.
    #[serde(rename = "retryOn", default)]
    pub retry_on: Vec<String>,
}

// ---- IPAllowlistPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "IPAllowlistPolicy",
    plural = "ipallowlistpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct IPAllowlistPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    /// CIDRs to allow (e.g., ["10.0.0.0/8", "192.168.1.0/24"]). If non-empty, only these are allowed.
    #[serde(rename = "allowCIDRs", default)]
    pub allow_cidrs: Vec<String>,
    /// CIDRs to deny (e.g., ["10.0.0.5/32"]). Deny takes precedence over allow.
    #[serde(rename = "denyCIDRs", default)]
    pub deny_cidrs: Vec<String>,
    /// CIDRs of trusted proxies/LBs for X-Forwarded-For client IP extraction.
    #[serde(rename = "trustedProxyCIDRs", default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

// ---- RequestBodySizeLimitPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "RequestBodySizeLimitPolicy",
    plural = "requestbodysizelimitpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct RequestBodySizeLimitPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    /// Maximum request body size in bytes. Requests exceeding this get 413.
    #[serde(rename = "maxBytes")]
    pub max_bytes: u64,
}

// ---- HealthCheckPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "HealthCheckPolicy",
    plural = "healthcheckpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct HealthCheckPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    #[serde(rename = "healthCheck")]
    pub health_check: HealthCheckSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HealthCheckSpec {
    /// HTTP path to probe (e.g., "/healthz")
    #[serde(default)]
    pub path: String,
    /// Interval between probes in seconds. Default: 10.
    #[serde(rename = "intervalSecs", default = "default_hc_interval")]
    pub interval_secs: u32,
    /// Probe timeout in seconds. Default: 5.
    #[serde(rename = "timeoutSecs", default = "default_hc_timeout")]
    pub timeout_secs: u32,
    /// Consecutive successes to mark healthy. Default: 1.
    #[serde(rename = "healthyThreshold", default = "default_hc_healthy")]
    pub healthy_threshold: u32,
    /// Consecutive failures to mark unhealthy. Default: 3.
    #[serde(rename = "unhealthyThreshold", default = "default_hc_unhealthy")]
    pub unhealthy_threshold: u32,
}

fn default_hc_interval() -> u32 { 10 }
fn default_hc_timeout() -> u32 { 5 }
fn default_hc_healthy() -> u32 { 1 }
fn default_hc_unhealthy() -> u32 { 3 }

// ---- CORSPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "CORSPolicy",
    plural = "corspolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct CORSPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    pub cors: CORSSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CORSSpec {
    #[serde(rename = "allowOrigins", default)]
    pub allow_origins: Vec<String>,
    #[serde(rename = "allowMethods", default)]
    pub allow_methods: Vec<String>,
    #[serde(rename = "allowHeaders", default)]
    pub allow_headers: Vec<String>,
    #[serde(rename = "exposeHeaders", default)]
    pub expose_headers: Vec<String>,
    #[serde(rename = "maxAge", default)]
    pub max_age: u32,
    #[serde(rename = "allowCredentials", default)]
    pub allow_credentials: bool,
}

// ---- TimeoutPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1beta1",
    kind = "TimeoutPolicy",
    plural = "timeoutpolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct TimeoutPolicySpec {
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    pub timeout: TimeoutSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TimeoutSpec {
    /// Request timeout in milliseconds. 0 means no timeout.
    #[serde(rename = "requestTimeoutMs", default)]
    pub request_timeout_ms: u64,
    /// Backend request timeout in milliseconds. 0 means no timeout.
    #[serde(rename = "backendRequestTimeoutMs", default)]
    pub backend_request_timeout_ms: u64,
    /// Connect timeout in milliseconds. Default: 5000.
    #[serde(rename = "connectTimeoutMs", default)]
    pub connect_timeout_ms: u64,
}

// ---- Conflict resolution ----

/// Determines if the existing policy wins over a new policy targeting the same resource.
/// Oldest creation_timestamp wins; ties broken by namespace/name alphabetically.
pub fn is_policy_winner(
    existing_timestamp: &Option<Time>,
    existing_key: &NamespacedName,
    new_timestamp: &Option<Time>,
    new_key: &NamespacedName,
) -> bool {
    match (existing_timestamp, new_timestamp) {
        (Some(e), Some(n)) => {
            if e.0 == n.0 {
                existing_key.to_string() <= new_key.to_string()
            } else {
                e.0 < n.0
            }
        }
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => existing_key.to_string() <= new_key.to_string(),
    }
}

#[cfg(test)]
mod crd_manifest_tests {
    use super::*;
    use crate::ai_types::{AIProvider, AIRoute, AIUsagePolicy};
    use kube::Resource;

    /// (kind, version) the controller watches, for every Portus CRD.
    fn watched() -> Vec<(String, String)> {
        macro_rules! of {
            ($($t:ty),*) => { vec![$((<$t as Resource>::kind(&()).to_string(), <$t as Resource>::version(&()).to_string())),*] };
        }
        of!(RateLimitPolicy, CircuitBreakerPolicy, ConnectionPolicy, BasicAuthPolicy, APIKeyAuthPolicy, JWTAuthPolicy,
            ExtAuthPolicy, RetryPolicy, IPAllowlistPolicy, RequestBodySizeLimitPolicy, HealthCheckPolicy, CORSPolicy,
            TimeoutPolicy, AIProvider, AIRoute, AIUsagePolicy)
    }

    /// The chart's CRD manifests with the `crds.install` guard stripped.
    fn manifests() -> Vec<(String, serde_json::Value)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/helm/templates/crds");
        let mut out: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .map(|path| {
                let text = std::fs::read_to_string(&path).unwrap();
                let body: String = text.lines().filter(|l| !l.trim_start().starts_with("{{")).collect::<Vec<_>>().join("\n");
                (path.file_name().unwrap().to_string_lossy().into_owned(), serde_yaml_ng::from_str(&body).unwrap())
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Every CRD stores the version the controller watches and still serves
    /// the deprecated v1alpha1 with the same schema, so objects written
    /// before the promotion keep working without a conversion webhook.
    #[test]
    fn chart_crds_store_the_watched_version_and_serve_v1alpha1_unchanged() {
        let watched = watched();
        let manifests = manifests();
        assert_eq!(manifests.len(), watched.len(), "one manifest per CRD type");
        for (file, crd) in &manifests {
            let kind = crd["spec"]["names"]["kind"].as_str().unwrap();
            let (_, version) = watched.iter().find(|(k, _)| k == kind).unwrap_or_else(|| panic!("{file}: no Rust type for {kind}"));
            assert_eq!(crd["metadata"]["annotations"]["helm.sh/resource-policy"], "keep", "{file}");
            let versions = crd["spec"]["versions"].as_array().unwrap();
            let storage: Vec<_> = versions.iter().filter(|v| v["storage"] == true).collect();
            assert_eq!(storage.len(), 1, "{file}");
            assert_eq!(storage[0]["name"], version.as_str(), "{file}: stores what the controller watches");
            assert_eq!(storage[0]["served"], true, "{file}");
            let alpha = versions.iter().find(|v| v["name"] == "v1alpha1").unwrap_or_else(|| panic!("{file}: v1alpha1 dropped"));
            assert_eq!(alpha["served"], true, "{file}");
            assert_eq!(alpha["deprecated"], true, "{file}");
            assert_eq!(alpha["schema"], storage[0]["schema"], "{file}: no conversion webhook, so the schemas must match");
            assert_eq!(alpha["subresources"], storage[0]["subresources"], "{file}");
        }
    }
}
