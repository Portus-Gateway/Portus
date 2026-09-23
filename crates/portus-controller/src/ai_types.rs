//! AI gateway CRDs under `portus-gateway.dev`: `AIProvider` (an LLM API the
//! gateway forwards to) and `AIRoute` (an HTTPRoute-shaped route that can
//! match on request body fields such as `model`).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::gateway_types::{HTTPHeaderMatchCRD, HTTPPathMatchCRD, ParentReference};
use crate::policy_types::{PolicyStatus, PolicyTargetRef};

// ---- AIProvider ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1alpha1",
    kind = "AIProvider",
    plural = "aiproviders",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct AIProviderSpec {
    /// API dialect the provider speaks: `anthropic`, `openai`,
    /// `openai-compatible` or `mcp` (Model Context Protocol over Streamable
    /// HTTP). Decides the default credential header and how usage is read
    /// from responses.
    pub kind: String,
    /// Base URL: scheme and host, optional port, no path
    /// (`https://api.anthropic.com`).
    pub url: String,
    /// Where the provider's API key comes from and how it is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<AICredentialSpec>,
    /// `header` pins requests carrying `Mcp-Session-Id` to the endpoint the
    /// session hashes to; `none` load-balances every request. Default
    /// `header` for `mcp`, `none` otherwise.
    #[serde(rename = "sessionAffinity", default, skip_serializing_if = "Option::is_none")]
    pub session_affinity: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AICredentialSpec {
    /// Secret in the provider's namespace holding the key.
    #[serde(rename = "secretRef")]
    pub secret_ref: AISecretKeyRef,
    /// Header the key is sent in. Defaults per kind: `x-api-key` for
    /// anthropic, `authorization` for openai and openai-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Text placed before the key in the header value. Defaults per kind:
    /// empty for anthropic, `Bearer ` for openai and openai-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AISecretKeyRef {
    pub name: String,
    /// Key within the Secret's data. Default `api-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

// ---- AIRoute ----

#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1alpha1",
    kind = "AIRoute",
    plural = "airoutes",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct AIRouteSpec {
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Requests must present a Portus API key issued by the ledger.
    #[serde(rename = "requireApiKey", default)]
    pub require_api_key: bool,
    /// Other credentials the route accepts in place of a Portus key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AIRouteAuth>,
    #[serde(default)]
    pub rules: Vec<AIRouteRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIRouteAuth {
    /// OAuth bearer tokens (JWTs) from one issuer, verified on the data
    /// plane against the issuer's JWKS, which the ledger fetches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<AIJwtSpec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIJwtSpec {
    /// The token's `iss`, an `https://` URL the ledger is configured with
    /// (`aiGateway.jwt.issuers`).
    pub issuer: String,
    /// Required `aud` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Claim naming the tenant; default `groups` (first entry of an array).
    #[serde(rename = "tenantClaim", default, skip_serializing_if = "Option::is_none")]
    pub tenant_claim: Option<String>,
    /// Claim listing the MCP tools the subject may call (array or
    /// space-separated string); default `scope`.
    #[serde(rename = "toolsClaim", default, skip_serializing_if = "Option::is_none")]
    pub tools_claim: Option<String>,
    /// Scopes MCP clients are told to request (protected-resource metadata
    /// `scopes_supported` and the 401 challenge); default
    /// `[openid, profile, email, groups]`. Dex behind an upstream connector
    /// may need `federated:id` as well.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIRouteRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<AIRouteMatch>,
    /// Providers in this rule's namespace; weights split traffic.
    #[serde(rename = "providerRefs", default)]
    pub provider_refs: Vec<AIProviderRef>,
}

/// One match: every set field must match (AND). A rule with several matches
/// matches when any of them does (OR), as in HTTPRoute.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIRouteMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathMatchCRD>,
    /// The request body's top-level `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<AIStringMatch>,
    /// The request body's top-level `stream` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// MCP: the JSON-RPC `method` (`tools/call`, `tools/list`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AIStringMatch>,
    /// MCP: the tool a `tools/call` names (`params.name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<AIStringMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HTTPHeaderMatchCRD>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIStringMatch {
    /// `Exact` (default), `Prefix` or `RegularExpression`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIProviderRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

// ---- AIUsagePolicy ----

/// A token budget attached to an AIRoute. The data plane enforces it with
/// grants from the ledger; overrun is bounded by one grant per pod.
#[derive(CustomResource, Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "portus-gateway.dev",
    version = "v1alpha1",
    kind = "AIUsagePolicy",
    plural = "aiusagepolicies",
    namespaced,
    status = "PolicyStatus",
    derive = "Default"
)]
pub struct AIUsagePolicySpec {
    /// The AIRoute this budget applies to (kind `AIRoute`, same namespace).
    #[serde(rename = "targetRef")]
    pub target_ref: PolicyTargetRef,
    pub budget: AIBudgetSpec,
    /// `Open` (default) lets requests through while no allowance is held and
    /// the ledger cannot be reached; `Closed` refuses them.
    #[serde(rename = "onLedgerUnavailable", default, skip_serializing_if = "Option::is_none")]
    pub on_ledger_unavailable: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AIBudgetSpec {
    /// Tokens (input + output + cache read + cache creation) per window.
    /// Exactly one of `tokens` and `calls` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// Requests that reached the server per window (MCP routes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<u64>,
    /// `Hourly`, `Daily` or `Monthly`, fixed windows in UTC.
    pub window: String,
    /// Whose counter: `Key` (default), `Tenant` or `Route`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per: Option<String>,
}
