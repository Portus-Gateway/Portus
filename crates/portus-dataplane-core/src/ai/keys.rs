//! Portus API keys on the request path: one SHA-256 and one hash-map lookup
//! against the snapshot the ledger pushed. No call-out, no allocation for a
//! valid key. Keys are compared by hash, so the data plane never holds a
//! plaintext key and a stolen snapshot yields nothing usable.

use std::sync::Arc;

use hashbrown::HashMap;
use sha2::{Digest, Sha256};

use crate::ai::usage::Dialect;
use crate::plan::Reply;
use crate::router::RequestHeaders;
use portus_types::proto::portus::ledger::v1::KeySnapshot;

pub type KeyHash = [u8; 32];

/// What the data plane knows about one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: u64,
    pub tenant: Arc<str>,
    pub name: Arc<str>,
    /// Empty: any model.
    pub allowed_models: Arc<[String]>,
    /// MCP: tools a `tools/call` may name, exact or `prefix.*`. Empty: any.
    pub allowed_tools: Arc<[String]>,
    /// Unix seconds after which the key is refused; 0: never. The ledger
    /// drops expired keys from the snapshot; this covers the gap between
    /// snapshots.
    pub expires_unix_secs: u64,
    /// The key's own budgets per window, replacing a route policy's limit
    /// for its counters: one for token policies, one for call policies.
    /// 0: the policy's limit.
    pub token_limit: u64,
    pub call_limit: u64,
    /// Labels, sorted by key, for trust rules (`label:owner=hub`).
    pub labels: Arc<[(String, String)]>,
}

impl KeyInfo {
    pub fn live_at(&self, now_unix_secs: u64) -> bool {
        self.expires_unix_secs == 0 || now_unix_secs < self.expires_unix_secs
    }
}

/// `auth.onBehalfOf`: a trusted caller names the user it acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnBehalfOf {
    /// Lower-case header name.
    pub header: Arc<str>,
    /// Keys believed: `name`, `tenant/name`, `tenant/*` (every key of the
    /// tenant) or `label:key=value` (every key carrying that label).
    pub trusted_keys: Arc<[String]>,
}

/// Default header a trusted caller names its user in.
pub const ON_BEHALF_OF_HEADER: &str = "x-portus-on-behalf-of";

impl OnBehalfOf {
    pub fn trusts(&self, info: &KeyInfo) -> bool {
        self.trusted_keys.iter().any(|k| {
            if let Some(label) = k.strip_prefix("label:") {
                let Some((key, value)) = label.split_once('=') else { return false };
                return info.labels.iter().any(|(k, v)| k == key && v == value);
            }
            match k.split_once('/') {
                Some((tenant, "*")) => !tenant.is_empty() && tenant == info.tenant.as_ref(),
                Some((tenant, name)) => tenant == info.tenant.as_ref() && name == info.name.as_ref(),
                None => k == info.name.as_ref(),
            }
        })
    }

    /// The user named in the header when `info` is trusted to name one:
    /// printable, non-empty, at most 64 bytes.
    pub fn user<'h>(&self, headers: &'h (impl RequestHeaders + ?Sized), info: &KeyInfo) -> Option<&'h str> {
        if !self.trusts(info) {
            return None;
        }
        let v = std::str::from_utf8(headers.get(&self.header)?).ok()?.trim();
        (!v.is_empty() && v.len() <= 64 && v.chars().all(|c| !c.is_control())).then_some(v)
    }
}

/// Every live key, by hash, and every OAuth issuer's public keys. Replaced
/// whole on each snapshot.
#[derive(Default)]
pub struct KeySet {
    pub version: u64,
    keys: HashMap<KeyHash, KeyInfo>,
    pub jwks: super::jwt::Jwks,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeySet(v{}, {} keys, {} issuers)", self.version, self.keys.len(), self.jwks.issuer_count())
    }
}

impl KeySet {
    pub fn from_snapshot(snapshot: &KeySnapshot) -> Self {
        let mut keys = HashMap::with_capacity(snapshot.keys.len());
        for k in &snapshot.keys {
            let Ok(hash) = <KeyHash>::try_from(k.hash_sha256.as_slice()) else { continue };
            keys.insert(
                hash,
                KeyInfo {
                    id: k.id,
                    tenant: Arc::from(k.tenant.as_str()),
                    name: Arc::from(k.name.as_str()),
                    allowed_models: Arc::from(k.allowed_models.clone()),
                    allowed_tools: Arc::from(k.allowed_tools.clone()),
                    expires_unix_secs: k.expires_unix_secs,
                    token_limit: k.token_limit,
                    call_limit: k.call_limit,
                    labels: {
                        let mut l: Vec<(String, String)> = k.labels.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
                        l.sort();
                        Arc::from(l)
                    },
                },
            );
        }
        let jwks = super::jwt::Jwks::from_entries(snapshot.issuers.iter().map(|e| (e.issuer.as_str(), e.jwks_json.as_str())));
        Self { version: snapshot.version, keys, jwks }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn lookup(&self, key: &str) -> Option<&KeyInfo> {
        self.keys.get(&hash_key(key))
    }
}

pub fn hash_key(key: &str) -> KeyHash {
    Sha256::digest(key.as_bytes()).into()
}

/// The key a client presented: `x-api-key` (Anthropic clients) or
/// `Authorization: Bearer` (OpenAI clients).
pub fn presented_key(headers: &(impl RequestHeaders + ?Sized)) -> Option<&str> {
    if let Some(v) = headers.get("x-api-key") {
        return std::str::from_utf8(v).ok().map(str::trim).filter(|s| !s.is_empty());
    }
    let auth = std::str::from_utf8(headers.get("authorization")?).ok()?;
    let (scheme, token) = auth.trim().split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim()).filter(|s| !s.is_empty())
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No key, or a key the snapshot does not know.
    Unauthenticated,
    /// A known key that may not use this model.
    ModelNotAllowed,
    /// A known key that may not call this tool.
    ToolNotAllowed,
}

/// What a request wants from the key, for the key's allow lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access<'a> {
    /// An LLM request for `model` (None: no model in the body).
    Model(Option<&'a str>),
    /// An MCP `tools/call` naming `tool` (None: the name could not be read).
    ToolCall(Option<&'a str>),
    /// Anything else: only the key itself is checked.
    Other,
}

impl Refusal {
    pub fn kind(self) -> crate::ai::usage::RefusalKind {
        match self {
            Refusal::Unauthenticated => crate::ai::usage::RefusalKind::Unauthenticated,
            Refusal::ModelNotAllowed => crate::ai::usage::RefusalKind::ModelNotAllowed,
            Refusal::ToolNotAllowed => crate::ai::usage::RefusalKind::ToolNotAllowed,
        }
    }

    /// The error body in the dialect the client speaks, so SDKs surface it
    /// the way they would the provider's own error. `subject` is the model
    /// or tool that was refused; `request_id` the JSON-RPC id (as JSON text)
    /// an MCP refusal echoes.
    pub fn reply(self, dialect: Dialect, subject: Option<&str>, request_id: Option<&str>) -> Reply {
        let subject = subject.unwrap_or("(unspecified)");
        let (status, kind, message) = match self {
            Refusal::Unauthenticated => (401, "authentication_error", "invalid or missing Portus API key".to_string()),
            Refusal::ModelNotAllowed => (403, "permission_error", format!("this API key may not use model {subject}")),
            Refusal::ToolNotAllowed => (403, "permission_error", format!("this API key may not call tool {subject}")),
        };
        let (status, body) = match dialect {
            Dialect::Anthropic => (status, format!(r#"{{"type":"error","error":{{"type":"{kind}","message":"{message}"}}}}"#)),
            Dialect::OpenAi => (status, format!(r#"{{"error":{{"message":"{message}","type":"{kind}","code":null}}}}"#)),
            // Authentication is refused at the transport level (401, as the
            // MCP spec has it); a policy refusal inside a session is a
            // JSON-RPC error on 200 so the client keeps its session.
            Dialect::Mcp => match self {
                Refusal::Unauthenticated => (401, super::mcp::error_body(request_id, super::mcp::CODE_UNAUTHENTICATED, &message)),
                Refusal::ModelNotAllowed | Refusal::ToolNotAllowed => (200, super::mcp::error_body(request_id, super::mcp::CODE_NOT_ALLOWED, &message)),
            },
        };
        Reply::json(status, body)
    }
}

/// `allowed` names `tool` exactly or by `prefix.*`.
fn tool_allowed(allowed: &[String], tool: &str) -> bool {
    allowed.iter().any(|a| a == tool || a.strip_suffix('*').is_some_and(|p| tool.len() > p.len() && tool.starts_with(p)))
}

/// Check a request against the key set at `now_unix_secs`. `Ok` is the
/// key to charge; an expired key is as good as unknown.
pub fn authorize<'k>(
    keys: &'k KeySet,
    headers: &(impl RequestHeaders + ?Sized),
    access: Access<'_>,
    now_unix_secs: u64,
) -> Result<&'k KeyInfo, Refusal> {
    let presented = presented_key(headers).ok_or(Refusal::Unauthenticated)?;
    let info = keys.lookup(presented).filter(|k| k.live_at(now_unix_secs)).ok_or(Refusal::Unauthenticated)?;
    check_access(info, access)?;
    Ok(info)
}

/// Whether a known subject may do what the request wants.
pub fn check_access(info: &KeyInfo, access: Access<'_>) -> Result<(), Refusal> {
    match access {
        Access::Model(model) if !info.allowed_models.is_empty() => {
            let Some(m) = model else { return Err(Refusal::ModelNotAllowed) };
            if !info.allowed_models.iter().any(|a| a == m) {
                return Err(Refusal::ModelNotAllowed);
            }
        }
        Access::ToolCall(tool) if !info.allowed_tools.is_empty() => {
            let Some(t) = tool else { return Err(Refusal::ToolNotAllowed) };
            if !tool_allowed(&info.allowed_tools, t) {
                return Err(Refusal::ToolNotAllowed);
            }
        }
        Access::Model(_) | Access::ToolCall(_) | Access::Other => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portus_types::proto::portus::ledger::v1::KeyEntry;

    fn snapshot() -> KeySnapshot {
        KeySnapshot {
            version: 3,
            issuers: vec![],
            keys: vec![
                KeyEntry { id: 1, hash_sha256: hash_key("portus_sk_any").to_vec(), tenant: "team-a".into(), name: "ci".into(), allowed_models: vec![], allowed_tools: vec![], expires_unix_secs: 0, token_limit: 0, call_limit: 0, labels: Default::default() },
                KeyEntry { id: 5, hash_sha256: hash_key("portus_sk_old").to_vec(), tenant: "team-a".into(), name: "rotated".into(), allowed_models: vec![], allowed_tools: vec![], expires_unix_secs: 1_000, token_limit: 0, call_limit: 0, labels: Default::default() },
                KeyEntry {
                    id: 2,
                    hash_sha256: hash_key("portus_sk_haiku").to_vec(),
                    tenant: "team-b".into(),
                    name: "bot".into(),
                    allowed_models: vec!["claude-haiku-4-5".into()],
                    allowed_tools: vec![],
                    expires_unix_secs: 0,
                    token_limit: 0,
                    call_limit: 0,
                    labels: [("role".to_string(), "hub".to_string())].into_iter().collect(),
                },
                KeyEntry { id: 3, hash_sha256: vec![1, 2, 3], tenant: "bad".into(), name: "short-hash".into(), allowed_models: vec![], allowed_tools: vec![], expires_unix_secs: 0, token_limit: 0, call_limit: 0, labels: Default::default() },
                KeyEntry {
                    id: 4,
                    hash_sha256: hash_key("portus_sk_tools").to_vec(),
                    tenant: "team-c".into(),
                    name: "agent".into(),
                    allowed_models: vec![],
                    allowed_tools: vec!["echo".into(), "github.*".into()],
                    expires_unix_secs: 0,
                    token_limit: 0,
                    call_limit: 0,
                    labels: Default::default(),
                },
            ],
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn snapshots_load_by_hash_and_skip_malformed_entries() {
        let set = KeySet::from_snapshot(&snapshot());
        assert_eq!((set.version, set.len()), (3, 4));
        assert_eq!(set.lookup("portus_sk_any").map(|k| k.id), Some(1));
        assert_eq!(set.lookup("portus_sk_haiku").map(|k| k.tenant.as_ref()), Some("team-b"));
        assert!(set.lookup("portus_sk_nope").is_none());
    }

    #[test]
    fn keys_are_read_from_x_api_key_or_a_bearer_token() {
        assert_eq!(presented_key(&headers(&[("x-api-key", " portus_sk_any ")])), Some("portus_sk_any"));
        assert_eq!(presented_key(&headers(&[("authorization", "Bearer portus_sk_any")])), Some("portus_sk_any"));
        assert_eq!(presented_key(&headers(&[("authorization", "bearer   portus_sk_any")])), Some("portus_sk_any"));
        assert_eq!(presented_key(&headers(&[("authorization", "Basic abc")])), None);
        assert_eq!(presented_key(&headers(&[("x-api-key", "")])), None);
        assert_eq!(presented_key(&headers(&[])), None);
        // x-api-key wins when both are present, as it does at Anthropic.
        assert_eq!(presented_key(&headers(&[("x-api-key", "a"), ("authorization", "Bearer b")])), Some("a"));
    }

    fn authorize<'k>(keys: &'k KeySet, headers: &http::HeaderMap, access: Access<'_>) -> Result<&'k KeyInfo, Refusal> {
        super::authorize(keys, headers, access, 500)
    }

    #[test]
    fn an_expired_key_is_refused_like_an_unknown_one() {
        let set = KeySet::from_snapshot(&snapshot());
        let h = headers(&[("x-api-key", "portus_sk_old")]);
        assert_eq!(super::authorize(&set, &h, Access::Other, 999).map(|k| k.id), Ok(5), "before expiry");
        assert_eq!(super::authorize(&set, &h, Access::Other, 1_000).map(|k| k.id), Err(Refusal::Unauthenticated), "at expiry");
        assert_eq!(super::authorize(&set, &h, Access::Other, 5_000).map(|k| k.id), Err(Refusal::Unauthenticated));
        assert_eq!(super::authorize(&set, &headers(&[("x-api-key", "portus_sk_any")]), Access::Other, u64::MAX).map(|k| k.id), Ok(1), "no expiry: forever");
    }

    #[test]
    fn on_behalf_of_is_believed_from_trusted_keys_only_and_the_name_is_bounded() {
        let set = KeySet::from_snapshot(&snapshot());
        let hub = set.lookup("portus_sk_any").unwrap();
        let bot = set.lookup("portus_sk_haiku").unwrap();
        let policy = OnBehalfOf { header: Arc::from(ON_BEHALF_OF_HEADER), trusted_keys: Arc::from(vec!["team-a/ci".to_string(), "agent".to_string()]) };
        let h = headers(&[("x-portus-on-behalf-of", " alice@example.com ")]);
        assert_eq!(policy.user(&h, hub), Some("alice@example.com"), "tenant/name entry");
        assert_eq!(policy.user(&h, set.lookup("portus_sk_tools").unwrap()), Some("alice@example.com"), "bare name entry");
        assert_eq!(policy.user(&h, bot), None, "an untrusted key cannot name anyone");
        assert_eq!(policy.user(&headers(&[]), hub), None, "no header");
        assert_eq!(policy.user(&headers(&[("x-portus-on-behalf-of", "   ")]), hub), None, "blank");
        assert_eq!(policy.user(&headers(&[("x-portus-on-behalf-of", &"a".repeat(65))]), hub), None, "too long");
        let same_name_other_tenant = KeyInfo { tenant: Arc::from("team-z"), ..hub.clone() };
        assert!(!policy.trusts(&same_name_other_tenant), "team-a/ci does not trust team-z/ci");
    }

    #[test]
    fn whole_tenants_and_labels_can_be_trusted_without_listing_each_key() {
        let set = KeySet::from_snapshot(&snapshot());
        let by = |entries: &[&str]| OnBehalfOf { header: Arc::from(ON_BEHALF_OF_HEADER), trusted_keys: Arc::from(entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()) };
        let hub = set.lookup("portus_sk_any").unwrap(); // team-a/ci
        let bot = set.lookup("portus_sk_haiku").unwrap(); // team-b/bot, labelled role=hub
        assert!(by(&["team-a/*"]).trusts(hub));
        assert!(!by(&["team-a/*"]).trusts(bot), "another tenant");
        assert!(!by(&["/*"]).trusts(&KeyInfo { tenant: Arc::from(""), ..hub.clone() }), "an empty tenant is not a wildcard for tenant-less keys");
        assert!(by(&["label:role=hub"]).trusts(bot));
        assert!(!by(&["label:role=hub"]).trusts(hub), "no such label");
        assert!(!by(&["label:role=agent"]).trusts(bot), "the value must match");
        assert!(!by(&["label:role"]).trusts(bot), "a label rule needs a value");
        // A new key under a trusted tenant is trusted with no route change.
        let fresh = KeyInfo { id: 99, name: Arc::from("haiku-agent-built-live"), ..hub.clone() };
        assert!(by(&["team-a/*"]).trusts(&fresh));
    }

    #[test]
    fn authorize_charges_the_key_and_enforces_its_model_list() {
        let set = KeySet::from_snapshot(&snapshot());
        let id = |r: Result<&KeyInfo, Refusal>| r.map(|k| k.id);
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_any")]), Access::Model(Some("claude-opus-5")))), Ok(1));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_any")]), Access::Model(None))), Ok(1), "no model list: any model, even unknown");
        assert_eq!(id(authorize(&set, &headers(&[("authorization", "Bearer portus_sk_haiku")]), Access::Model(Some("claude-haiku-4-5")))), Ok(2));
        assert_eq!(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), Access::Model(Some("claude-haiku-4-5"))).map(|k| k.tenant.as_ref()), Ok("team-b"));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), Access::Model(Some("claude-opus-5")))), Err(Refusal::ModelNotAllowed));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), Access::Model(None))), Err(Refusal::ModelNotAllowed));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_stolen")]), Access::Model(Some("claude-opus-5")))), Err(Refusal::Unauthenticated));
        assert_eq!(id(authorize(&set, &headers(&[]), Access::Model(Some("claude-opus-5")))), Err(Refusal::Unauthenticated));
        assert_eq!(id(authorize(&KeySet::default(), &headers(&[("x-api-key", "portus_sk_any")]), Access::Model(None))), Err(Refusal::Unauthenticated), "no snapshot yet: fail closed");
    }

    #[test]
    fn tool_allow_lists_apply_to_tool_calls_only_and_accept_prefixes() {
        let set = KeySet::from_snapshot(&snapshot());
        let id = |r: Result<&KeyInfo, Refusal>| r.map(|k| k.id);
        let h = headers(&[("authorization", "Bearer portus_sk_tools")]);
        assert_eq!(id(authorize(&set, &h, Access::ToolCall(Some("echo")))), Ok(4));
        assert_eq!(id(authorize(&set, &h, Access::ToolCall(Some("github.search")))), Ok(4));
        assert_eq!(id(authorize(&set, &h, Access::ToolCall(Some("github.")))), Err(Refusal::ToolNotAllowed), "the prefix alone is not a tool");
        assert_eq!(id(authorize(&set, &h, Access::ToolCall(Some("shell.run")))), Err(Refusal::ToolNotAllowed));
        assert_eq!(id(authorize(&set, &h, Access::ToolCall(None))), Err(Refusal::ToolNotAllowed), "an unreadable tool name is refused when a list exists");
        assert_eq!(id(authorize(&set, &h, Access::Other)), Ok(4), "tools/list and initialize only need the key");
        assert_eq!(id(authorize(&set, &h, Access::Model(None))), Ok(4), "no model list on this key");
        let any = headers(&[("authorization", "Bearer portus_sk_any")]);
        assert_eq!(id(authorize(&set, &any, Access::ToolCall(None))), Ok(1), "no tool list: any tool");
    }

    #[test]
    fn mcp_refusals_are_json_rpc_errors_and_only_authentication_is_non_2xx() {
        let r = Refusal::Unauthenticated.reply(Dialect::Mcp, None, Some("1"));
        assert_eq!(r.status, 401);
        assert_eq!(std::str::from_utf8(&r.body).unwrap(), r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"invalid or missing Portus API key"}}"#);
        let r = Refusal::ToolNotAllowed.reply(Dialect::Mcp, Some("shell.run"), Some("\"abc\""));
        assert_eq!(r.status, 200);
        assert_eq!(std::str::from_utf8(&r.body).unwrap(), r#"{"jsonrpc":"2.0","id":"abc","error":{"code":-32002,"message":"this API key may not call tool shell.run"}}"#);
        let r = Refusal::ToolNotAllowed.reply(Dialect::Mcp, None, None);
        assert!(std::str::from_utf8(&r.body).unwrap().contains(r#""id":null"#));
    }

    #[test]
    fn refusals_speak_the_client_dialect() {
        let r = Refusal::Unauthenticated.reply(Dialect::Anthropic, None, None);
        assert_eq!(r.status, 401);
        assert_eq!(std::str::from_utf8(&r.body).unwrap(), r#"{"type":"error","error":{"type":"authentication_error","message":"invalid or missing Portus API key"}}"#);
        let r = Refusal::ModelNotAllowed.reply(Dialect::OpenAi, Some("gpt-5"), None);
        assert_eq!(r.status, 403);
        assert!(std::str::from_utf8(&r.body).unwrap().contains(r#""type":"permission_error""#));
        assert!(std::str::from_utf8(&r.body).unwrap().contains("gpt-5"));
        assert!(r.headers.iter().any(|(n, v)| n == http::header::CONTENT_TYPE && v == "application/json"));
        assert!(r.headers.iter().any(|(n, v)| n == http::header::CONTENT_LENGTH && v == r.body.len().to_string().as_str()), "the length must match the body or clients read nothing");
    }
}
