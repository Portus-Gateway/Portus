//! AI gateway CRDs under `portus-gateway.dev`: `AIProvider` (an LLM API the
//! gateway forwards to) and `AIRoute` (an HTTPRoute-shaped route that can
//! match on request body fields such as `model`).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::gateway_types::{HTTPHeaderMatchCRD, HTTPPathMatchCRD, ParentReference};
use crate::policy_types::PolicyStatus;

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
    /// API dialect the provider speaks: `anthropic`, `openai` or
    /// `openai-compatible`. Decides the default credential header and, later,
    /// how usage is read from responses.
    pub kind: String,
    /// Base URL: scheme and host, optional port, no path
    /// (`https://api.anthropic.com`).
    pub url: String,
    /// Where the provider's API key comes from and how it is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<AICredentialSpec>,
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
    #[serde(default)]
    pub rules: Vec<AIRouteRule>,
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
