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
}

/// Every live key, by hash. Replaced whole on each snapshot.
#[derive(Debug, Default)]
pub struct KeySet {
    pub version: u64,
    keys: HashMap<KeyHash, KeyInfo>,
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
                },
            );
        }
        Self { version: snapshot.version, keys }
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
}

impl Refusal {
    /// The error body in the dialect the client speaks, so SDKs surface it
    /// the way they would the provider's own error.
    pub fn reply(self, dialect: Dialect, model: Option<&str>) -> Reply {
        let (status, kind, message) = match self {
            Refusal::Unauthenticated => (401, "authentication_error", "invalid or missing Portus API key".to_string()),
            Refusal::ModelNotAllowed => {
                (403, "permission_error", format!("this API key may not use model {}", model.unwrap_or("(unspecified)")))
            }
        };
        let body = match dialect {
            Dialect::Anthropic => format!(r#"{{"type":"error","error":{{"type":"{kind}","message":"{message}"}}}}"#),
            Dialect::OpenAi => format!(r#"{{"error":{{"message":"{message}","type":"{kind}","code":null}}}}"#),
        };
        let mut reply = Reply::empty(status).with_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        reply.body = body.into();
        reply
    }
}

/// Check a request against the key set. `Ok` is the key to charge.
pub fn authorize<'k>(
    keys: &'k KeySet,
    headers: &(impl RequestHeaders + ?Sized),
    model: Option<&str>,
) -> Result<&'k KeyInfo, Refusal> {
    let presented = presented_key(headers).ok_or(Refusal::Unauthenticated)?;
    let info = keys.lookup(presented).ok_or(Refusal::Unauthenticated)?;
    if !info.allowed_models.is_empty() {
        let Some(m) = model else { return Err(Refusal::ModelNotAllowed) };
        if !info.allowed_models.iter().any(|a| a == m) {
            return Err(Refusal::ModelNotAllowed);
        }
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use portus_types::proto::portus::ledger::v1::KeyEntry;

    fn snapshot() -> KeySnapshot {
        KeySnapshot {
            version: 3,
            keys: vec![
                KeyEntry { id: 1, hash_sha256: hash_key("portus_sk_any").to_vec(), tenant: "team-a".into(), name: "ci".into(), allowed_models: vec![] },
                KeyEntry {
                    id: 2,
                    hash_sha256: hash_key("portus_sk_haiku").to_vec(),
                    tenant: "team-b".into(),
                    name: "bot".into(),
                    allowed_models: vec!["claude-haiku-4-5".into()],
                },
                KeyEntry { id: 3, hash_sha256: vec![1, 2, 3], tenant: "bad".into(), name: "short-hash".into(), allowed_models: vec![] },
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
        assert_eq!((set.version, set.len()), (3, 2));
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

    #[test]
    fn authorize_charges_the_key_and_enforces_its_model_list() {
        let set = KeySet::from_snapshot(&snapshot());
        let id = |r: Result<&KeyInfo, Refusal>| r.map(|k| k.id);
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_any")]), Some("claude-opus-5"))), Ok(1));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_any")]), None)), Ok(1), "no model list: any model, even unknown");
        assert_eq!(id(authorize(&set, &headers(&[("authorization", "Bearer portus_sk_haiku")]), Some("claude-haiku-4-5"))), Ok(2));
        assert_eq!(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), Some("claude-haiku-4-5")).map(|k| k.tenant.as_ref()), Ok("team-b"));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), Some("claude-opus-5"))), Err(Refusal::ModelNotAllowed));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_haiku")]), None)), Err(Refusal::ModelNotAllowed));
        assert_eq!(id(authorize(&set, &headers(&[("x-api-key", "portus_sk_stolen")]), Some("claude-opus-5"))), Err(Refusal::Unauthenticated));
        assert_eq!(id(authorize(&set, &headers(&[]), Some("claude-opus-5"))), Err(Refusal::Unauthenticated));
        assert_eq!(id(authorize(&KeySet::default(), &headers(&[("x-api-key", "portus_sk_any")]), None)), Err(Refusal::Unauthenticated), "no snapshot yet: fail closed");
    }

    #[test]
    fn refusals_speak_the_client_dialect() {
        let r = Refusal::Unauthenticated.reply(Dialect::Anthropic, None);
        assert_eq!(r.status, 401);
        assert_eq!(std::str::from_utf8(&r.body).unwrap(), r#"{"type":"error","error":{"type":"authentication_error","message":"invalid or missing Portus API key"}}"#);
        let r = Refusal::ModelNotAllowed.reply(Dialect::OpenAi, Some("gpt-5"));
        assert_eq!(r.status, 403);
        assert!(std::str::from_utf8(&r.body).unwrap().contains(r#""type":"permission_error""#));
        assert!(std::str::from_utf8(&r.body).unwrap().contains("gpt-5"));
        assert!(r.headers.iter().any(|(n, v)| n == http::header::CONTENT_TYPE && v == "application/json"));
    }
}
