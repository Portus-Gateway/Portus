//! Hand-defined Gateway API CRD types for kube 3.x / k8s-openapi 0.27.
//!
//! The `gateway-api` crate 0.19 requires kube 2.x / k8s-openapi 0.26, which is
//! incompatible with our workspace. These types are defined manually using kube
//! derive macros to match the Gateway API v1 spec.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---- GatewayClass ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GatewayClass",
    plural = "gatewayclasses",
    status = "GatewayClassStatus",
    derive = "Default"
)]
pub struct GatewayClassSpec {
    /// The controller that manages Gateways of this class.
    #[serde(rename = "controllerName")]
    pub controller_name: String,

    /// Parameters for this GatewayClass (optional).
    #[serde(rename = "parametersRef", default, skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<ParametersReference>,

    /// Description of the GatewayClass (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayClassStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParametersReference {
    pub group: String,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ---- Gateway ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "Gateway",
    plural = "gateways",
    namespaced,
    status = "GatewayStatus",
    derive = "Default"
)]
pub struct GatewaySpec {
    /// The name of the GatewayClass used by this Gateway.
    #[serde(rename = "gatewayClassName")]
    pub gateway_class_name: String,

    /// Listeners associated with this Gateway.
    #[serde(default)]
    pub listeners: Vec<Listener>,

    /// Addresses requested for this Gateway (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<GatewayAddress>,

    /// AllowedListeners opts in ListenerSet attachment.
    /// When absent, ListenerSets attempting to attach are rejected with
    /// reason `NotAllowed`.
    #[serde(rename = "allowedListeners", default, skip_serializing_if = "Option::is_none")]
    pub allowed_listeners: Option<AllowedListeners>,

    /// Infrastructure settings (labels/annotations/parametersRef). Only
    /// `parametersRef` is interpreted, and only to reject unknown kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infrastructure: Option<GatewayInfrastructure>,

    /// Gateway-wide TLS settings: frontend client certificate validation
    /// (mTLS towards clients) and the backend client certificate (mTLS
    /// towards upstreams).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTLS>,
}

/// `Gateway.spec.tls`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayTLS {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<GatewayBackendTLS>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend: Option<FrontendTLSConfig>,
}

/// `Gateway.spec.tls.backend`: the client certificate presented to backends.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayBackendTLS {
    #[serde(rename = "clientCertificateRef", default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_ref: Option<SecretObjectReference>,
}

/// `Gateway.spec.tls.frontend`: a default client validation config for every
/// HTTPS listener, optionally overridden per port.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FrontendTLSConfig {
    #[serde(default)]
    pub default: FrontendTLSListenerConfig,
    #[serde(rename = "perPort", default, skip_serializing_if = "Vec::is_empty")]
    pub per_port: Vec<TLSPortConfig>,
}

/// One per-port override in `spec.tls.frontend.perPort`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TLSPortConfig {
    pub port: u16,
    #[serde(default)]
    pub tls: FrontendTLSListenerConfig,
}

/// The `TLSConfig` type of the Gateway API (`default` / `perPort[].tls`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FrontendTLSListenerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<FrontendTLSValidation>,
}

/// Client certificate validation: CA trust anchors plus the enforcement mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FrontendTLSValidation {
    #[serde(rename = "caCertificateRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub ca_certificate_refs: Vec<ObjectReference>,
    /// `AllowValidOnly` (default) or `AllowInsecureFallback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// Gateway API `ObjectReference` (group, kind, name, optional namespace).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ObjectReference {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayInfrastructure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "parametersRef", default, skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<LocalParametersReference>,
}

/// `infrastructure.parametersRef`: a same-namespace reference to an
/// implementation-specific configuration object.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct LocalParametersReference {
    pub group: String,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AllowedListeners {
    /// Which namespaces ListenerSets may attach from (Same, All, Selector).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<ListenerSetNamespaces>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ListenerSetNamespaces {
    /// From: Same, All, Selector (default Same per spec).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Listener {
    /// Unique name for this listener within the Gateway.
    pub name: String,

    /// Port that this listener listens on.
    pub port: u16,

    /// Protocol: HTTP, HTTPS, TLS, TCP, UDP.
    pub protocol: String,

    /// Hostname for this listener (optional, None = match all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// TLS configuration for HTTPS/TLS listeners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTLSConfig>,

    /// Routes allowed to bind to this listener.
    #[serde(rename = "allowedRoutes", default, skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<AllowedRoutes>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayTLSConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    #[serde(rename = "certificateRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_refs: Vec<SecretObjectReference>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SecretObjectReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllowedRoutes {
    /// Which namespaces can routes come from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<RouteNamespaces>,

    /// Which route kinds are allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<RouteGroupKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouteNamespaces {
    /// From: Same, All, or Selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Label selector when from=Selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouteGroupKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GatewayAddress {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Empty in `spec.addresses` means "assign one for me" (GatewayAddressEmpty).
    /// Must default: a required field here would make a Gateway with an
    /// empty-value address undeserialisable and break the whole watch.
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GatewayStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerStatus>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<GatewayAddress>,

    /// Count of ListenerSets successfully attached to this Gateway.
    /// Surfaced under `status.attachedListenerSets` per Gateway API v1.5 ListenerSet feature.
    #[serde(rename = "attachedListenerSets", default, skip_serializing_if = "Option::is_none")]
    pub attached_listener_sets: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListenerStatus {
    pub name: String,

    #[serde(rename = "attachedRoutes")]
    pub attached_routes: i32,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(rename = "supportedKinds", default, skip_serializing_if = "Vec::is_empty")]
    pub supported_kinds: Vec<RouteGroupKind>,
}

// ---- GRPCRoute ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GRPCRoute",
    plural = "grpcroutes",
    namespaced,
    status = "GRPCRouteStatus",
    derive = "Default"
)]
pub struct GRPCRouteSpec {
    /// Hostnames that this route matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// Parent references (Gateways this route attaches to).
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,

    /// Routing rules for gRPC traffic.
    #[serde(default)]
    pub rules: Vec<GRPCRouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<RouteParentStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCRouteRule {
    /// Matches for this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<GRPCRouteMatch>,

    /// Backend references for matched traffic.
    #[serde(rename = "backendRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub backend_refs: Vec<GRPCBackendRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCRouteMatch {
    /// gRPC method to match (service + method name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<GRPCMethodMatch>,

    /// Header (metadata) matches for this gRPC route match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<GRPCHeaderMatch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCHeaderMatch {
    /// Match type: Exact (default) or RegularExpression.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,

    /// Header name to match.
    pub name: String,

    /// Header value to match.
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCMethodMatch {
    /// Match type: Exact (default) or RegularExpression.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,

    /// gRPC service name to match (e.g. "mypackage.MyService").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// gRPC method name to match (e.g. "DoThing").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GRPCBackendRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

// ---- Shared route types ----

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ParentReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    pub name: String,

    #[serde(rename = "sectionName", default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,

    /// Port on the parent Gateway to bind to.  When set, only listeners
    /// matching this port are eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RouteParentStatus {
    #[serde(rename = "parentRef")]
    pub parent_ref: ParentReference,

    #[serde(rename = "controllerName")]
    pub controller_name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---- HTTPRoute ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    plural = "httproutes",
    namespaced,
    status = "HTTPRouteStatus",
    derive = "Default"
)]
pub struct HTTPRouteSpec {
    /// Parent references (Gateways this route attaches to).
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,

    /// Hostnames that this route matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// Routing rules for HTTP traffic.
    #[serde(default)]
    pub rules: Vec<HTTPRouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<RouteParentStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRouteRule {
    /// Matches for this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<HTTPRouteMatchCRD>,

    /// Filters for this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<HTTPRouteFilterCRD>,

    /// Backend references for matched traffic.
    #[serde(rename = "backendRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub backend_refs: Vec<HTTPBackendRef>,

    /// Timeouts for this rule (Phase 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<HTTPRouteTimeouts>,

    /// Retry configuration for this rule (Gateway API v1.6 `HTTPRouteRetry`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<HTTPRouteRetry>,
}

/// `HTTPRouteRule.retry`: retry a backend request whose response status is
/// one of `codes`, at most `attempts` more times.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRouteRetry {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,

    /// Gateway API duration between attempts. Accepted and stored; the
    /// dataplane retries immediately (`HTTPRouteRetryBackoff` is not claimed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRouteTimeouts {
    /// Request timeout (e.g., "10s").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,

    /// Backend request timeout (e.g., "5s").
    #[serde(rename = "backendRequest", default, skip_serializing_if = "Option::is_none")]
    pub backend_request: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRouteMatchCRD {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathMatchCRD>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HTTPHeaderMatchCRD>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    #[serde(rename = "queryParams", default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<HTTPQueryParamMatchCRD>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPPathMatchCRD {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPHeaderMatchCRD {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPQueryParamMatchCRD {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum HTTPRouteFilterCRD {
    RequestHeaderModifier {
        #[serde(rename = "requestHeaderModifier")]
        request_header_modifier: HTTPHeaderFilterCRD,
    },
    ResponseHeaderModifier {
        #[serde(rename = "responseHeaderModifier")]
        response_header_modifier: HTTPHeaderFilterCRD,
    },
    RequestRedirect {
        #[serde(rename = "requestRedirect")]
        request_redirect: HTTPRequestRedirectFilterCRD,
    },
    URLRewrite {
        #[serde(rename = "urlRewrite")]
        url_rewrite: HTTPURLRewriteFilterCRD,
    },
    RequestMirror {
        #[serde(rename = "requestMirror")]
        request_mirror: HTTPRequestMirrorFilterCRD,
    },
    CORS {
        cors: CORSFilterCRD,
    },
}

/// CORS filter configuration from Gateway API v1.5 extended feature.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CORSFilterCRD {
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub max_age: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRequestMirrorFilterCRD {
    #[serde(rename = "backendRef")]
    pub backend_ref: HTTPBackendRef,
    /// Percentage of requests to mirror (0-100). If not set, mirrors all requests.
    #[serde(default)]
    pub percent: Option<u32>,
    /// Fraction of requests to mirror (numerator/denominator). Takes precedence over percent.
    #[serde(default)]
    pub fraction: Option<HTTPMirrorFraction>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPMirrorFraction {
    pub numerator: u32,
    #[serde(default)]
    pub denominator: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPHeaderFilterCRD {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<HTTPHeaderCRD>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set: Vec<HTTPHeaderCRD>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPHeaderCRD {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPRequestRedirectFilterCRD {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifierCRD>,
    #[serde(rename = "statusCode", default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPPathModifierCRD {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub modifier_type: Option<String>,
    #[serde(rename = "replaceFullPath", default, skip_serializing_if = "Option::is_none")]
    pub replace_full_path: Option<String>,
    #[serde(rename = "replacePrefixMatch", default, skip_serializing_if = "Option::is_none")]
    pub replace_prefix_match: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPURLRewriteFilterCRD {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifierCRD>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct HTTPBackendRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,

    /// Per-backend filters (e.g., RequestHeaderModifier at the backendRef level).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<HTTPRouteFilterCRD>,
}

// ---- TLSRoute (v1, graduated in Gateway API v1.5) ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "TLSRoute",
    plural = "tlsroutes",
    namespaced,
    status = "TLSRouteStatus",
    derive = "Default"
)]
pub struct TLSRouteSpec {
    /// Parent references (Gateways this route attaches to).
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,

    /// Hostnames (SNI) that this route matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// Routing rules for TLS passthrough traffic.
    #[serde(default)]
    pub rules: Vec<TLSRouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TLSRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<RouteParentStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TLSRouteRule {
    #[serde(rename = "backendRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub backend_refs: Vec<TLSBackendRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TLSBackendRef {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

// ---- TCPRoute (v1; GA since Gateway API 1.6) ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "TCPRoute",
    plural = "tcproutes",
    namespaced,
    status = "TCPRouteStatus",
    derive = "Default"
)]
pub struct TCPRouteSpec {
    /// Parent references (Gateways this route attaches to).
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,

    /// Routing rules for TCP traffic.
    #[serde(default)]
    pub rules: Vec<L4RouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TCPRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<RouteParentStatus>,
}

// ---- UDPRoute (v1; GA since Gateway API 1.6). Same shape as TCPRoute. ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "UDPRoute",
    plural = "udproutes",
    namespaced,
    status = "UDPRouteStatus",
    derive = "Default"
)]
pub struct UDPRouteSpec {
    /// Parent references (Gateways this route attaches to).
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,

    /// Routing rules for UDP traffic.
    #[serde(default)]
    pub rules: Vec<L4RouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct UDPRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<RouteParentStatus>,
}

/// One rule of a TCPRoute or UDPRoute: backendRefs only, no matching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct L4RouteRule {
    #[serde(rename = "backendRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub backend_refs: Vec<L4BackendRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct L4BackendRef {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

// ---- BackendTLSPolicy (v1, graduated in Gateway API v1.5) ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "BackendTLSPolicy",
    plural = "backendtlspolicies",
    namespaced,
    status = "BackendTLSPolicyStatus",
    derive = "Default"
)]
pub struct BackendTLSPolicySpec {
    /// Target references (Services this policy applies to).
    #[serde(rename = "targetRefs")]
    pub target_refs: Vec<BackendTLSPolicyTargetRef>,

    /// TLS validation configuration.
    pub validation: BackendTLSPolicyValidation,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BackendTLSPolicyTargetRef {
    #[serde(default)]
    pub group: String,
    pub kind: String,
    pub name: String,
    #[serde(rename = "sectionName", default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BackendTLSPolicyValidation {
    /// References to CA certificate objects (ConfigMap or Secret).
    #[serde(rename = "caCertificateRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub ca_certificate_refs: Vec<LocalObjectReference>,

    /// Hostname for TLS server certificate verification.
    pub hostname: String,

    /// Subject alternative names for additional validation.
    #[serde(rename = "subjectAltNames", default, skip_serializing_if = "Vec::is_empty")]
    pub subject_alt_names: Vec<BackendTLSPolicySubjectAltName>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct LocalObjectReference {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BackendTLSPolicySubjectAltName {
    /// SAN type: "Hostname" or "URI".
    #[serde(rename = "type")]
    pub san_type: String,
    /// Hostname value (when type is "Hostname").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// URI value (when type is "URI").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BackendTLSPolicyStatus {
    /// Per-ancestor status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<PolicyAncestorStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PolicyAncestorStatus {
    #[serde(rename = "ancestorRef")]
    pub ancestor_ref: ParentReference,

    #[serde(rename = "controllerName")]
    pub controller_name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---- ReferenceGrant ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1beta1",
    kind = "ReferenceGrant",
    plural = "referencegrants",
    namespaced,
    derive = "Default"
)]
pub struct ReferenceGrantSpec {
    /// Resources that may reference the resources described in "to".
    #[serde(default)]
    pub from: Vec<ReferenceGrantFromCRD>,

    /// Resources that may be referenced by the resources described in "from".
    #[serde(default)]
    pub to: Vec<ReferenceGrantToCRD>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceGrantFromCRD {
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceGrantToCRD {
    pub group: String,
    pub kind: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

// ---- ListenerSet ----

/// A set of additional listeners attached to a parent Gateway.
/// Gateway API v1 (per gateway-api v1.5.1). Enables listener composition
/// across multiple CRs while sharing one Gateway address/port binding.
#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "ListenerSet",
    plural = "listenersets",
    namespaced,
    status = "ListenerSetStatus",
    derive = "Default"
)]
pub struct ListenerSetSpec {
    /// Parent Gateway this ListenerSet attaches to.
    #[serde(rename = "parentRef")]
    pub parent_ref: ParentGatewayReference,

    /// Listeners contributed by this set.
    #[serde(default)]
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ParentGatewayReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ListenerSetStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerStatus>,
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn gateway_address_without_value_deserialises() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "g", "namespace": "ns"},
            "spec": {
                "gatewayClassName": "portus-gateway",
                "addresses": [{"type": "IPAddress"}],
                "listeners": [{"name": "http", "port": 8080, "protocol": "HTTP"}]
            }
        }))
        .expect("an address with no value must not break deserialisation");
        assert_eq!(gw.spec.addresses.len(), 1);
        assert!(gw.spec.addresses[0].value.is_empty());
    }
}

