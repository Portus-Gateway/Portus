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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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

fn default_api_key_header() -> Option<String> {
    Some("X-API-Key".to_string())
}

// ---- RetryPolicy ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
    version = "v1alpha1",
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
