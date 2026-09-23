//! OAuth bearer tokens (JWTs) as an alternative to Portus API keys, verified
//! on the data plane against the issuer's public keys. The ledger fetches each
//! issuer's JWKS and pushes it in the key snapshot; nothing here calls out.
//! A verified token is cached by its hash for its remaining lifetime, so the
//! hot path is the same hash lookup a Portus key costs.

use std::sync::Arc;

use dashmap::DashMap;
use hashbrown::HashMap;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};

use super::keys::KeyInfo;

/// What an AIRoute accepts: tokens from `issuer`, for `audience` when set,
/// with the tenant and the tool list read from the named claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtPolicy {
    pub issuer: Arc<str>,
    pub audience: Option<Arc<str>>,
    /// Claim naming the tenant (`groups[0]`-style paths are not supported;
    /// a string claim, or the first string of an array claim).
    pub tenant_claim: Arc<str>,
    /// Claim listing the MCP tools the subject may call: an array of
    /// strings or a space-separated string (OAuth `scope` style).
    pub tools_claim: Arc<str>,
}

/// One issuer's public keys.
struct IssuerKeys {
    keys: Vec<(Option<String>, Algorithm, DecodingKey)>,
}

/// Every issuer's keys, as the snapshot carried them.
#[derive(Default)]
pub struct Jwks {
    issuers: HashMap<Arc<str>, IssuerKeys>,
}

impl Jwks {
    /// Build from `(issuer, jwks_json)` pairs; malformed keys are skipped.
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut issuers = HashMap::new();
        for (issuer, json) in entries {
            let Ok(set) = serde_json::from_str::<JwkSet>(json) else {
                log::warn!("issuer {issuer}: JWKS is not valid JSON, its tokens will be refused");
                continue;
            };
            let keys = set
                .keys
                .iter()
                .filter_map(|jwk| {
                    let alg = match (&jwk.algorithm, jwk.common.key_algorithm) {
                        (_, Some(a)) => algorithm(a)?,
                        (AlgorithmParameters::RSA(_), None) => Algorithm::RS256,
                        (AlgorithmParameters::EllipticCurve(p), None) => match p.curve {
                            jsonwebtoken::jwk::EllipticCurve::P256 => Algorithm::ES256,
                            jsonwebtoken::jwk::EllipticCurve::P384 => Algorithm::ES384,
                            _ => return None,
                        },
                        (AlgorithmParameters::OctetKeyPair(_), None) => Algorithm::EdDSA,
                        // Symmetric or unknown keys never belong in a published JWKS.
                        (_, None) => return None,
                    };
                    let key = DecodingKey::from_jwk(jwk).ok()?;
                    Some((jwk.common.key_id.clone(), alg, key))
                })
                .collect();
            issuers.insert(Arc::from(issuer), IssuerKeys { keys });
        }
        Self { issuers }
    }

    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }
}

fn algorithm(a: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    use jsonwebtoken::jwk::KeyAlgorithm as K;
    Some(match a {
        K::RS256 => Algorithm::RS256,
        K::RS384 => Algorithm::RS384,
        K::RS512 => Algorithm::RS512,
        K::PS256 => Algorithm::PS256,
        K::PS384 => Algorithm::PS384,
        K::PS512 => Algorithm::PS512,
        K::ES256 => Algorithm::ES256,
        K::ES384 => Algorithm::ES384,
        K::EdDSA => Algorithm::EdDSA,
        _ => return None,
    })
}

/// Whether a presented credential looks like a JWT (three base64url parts).
pub fn looks_like_jwt(token: &str) -> bool {
    token.len() > 20 && token.bytes().filter(|b| *b == b'.').count() == 2 && !token.contains(' ')
}

/// The subject's key info when `token` is a valid token from the policy's
/// issuer; `None` refuses it.
pub fn verify(token: &str, policy: &JwtPolicy, jwks: &Jwks, now_unix_secs: u64) -> Option<(KeyInfo, u64)> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let issuer = jwks.issuers.get(&policy.issuer)?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[policy.issuer.as_ref()]);
    match &policy.audience {
        Some(aud) => validation.set_audience(&[aud.as_ref()]),
        None => validation.validate_aud = false,
    }
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    let candidates = issuer.keys.iter().filter(|(kid, alg, _)| {
        *alg == header.alg && match (&header.kid, kid) {
            (Some(h), Some(k)) => h == k,
            (Some(_), None) | (None, _) => true,
        }
    });
    let mut claims: Option<serde_json::Map<String, serde_json::Value>> = None;
    for (_, _, key) in candidates {
        if let Ok(data) = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(token, key, &validation) {
            claims = Some(data.claims);
            break;
        }
    }
    let claims = claims?;
    let sub = claims.get("sub")?.as_str()?;
    let exp = claims.get("exp")?.as_u64()?;
    if exp <= now_unix_secs {
        return None;
    }
    let tenant = match claims.get(policy.tenant_claim.as_ref()) {
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(serde_json::Value::Array(a)) => a.first().and_then(|v| v.as_str()).unwrap_or(""),
        _ => "",
    };
    let tools: Vec<String> = match claims.get(policy.tools_claim.as_ref()) {
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect(),
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    };
    let info = KeyInfo {
        id: subject_id(&policy.issuer, sub),
        tenant: Arc::from(tenant),
        name: Arc::from(sub),
        allowed_models: Arc::from(Vec::new()),
        allowed_tools: Arc::from(tools),
    };
    Some((info, exp))
}

/// A stable id for (issuer, subject) that fits the ledger's signed 64-bit
/// key id column.
pub fn subject_id(issuer: &str, sub: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(issuer.as_bytes());
    h.update([0]);
    h.update(sub.as_bytes());
    let d = h.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]) >> 1
}

/// Verified tokens by hash, until they expire.
pub struct TokenCache {
    entries: DashMap<[u8; 32], (KeyInfo, u64)>,
    cap: usize,
}

impl TokenCache {
    pub fn new(cap: usize) -> Self {
        Self { entries: DashMap::new(), cap }
    }

    /// The cached subject for `token`, or verify it now and remember it.
    pub fn get_or_verify(&self, token: &str, policy: &JwtPolicy, jwks: &Jwks, now_unix_secs: u64) -> Option<KeyInfo> {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some(hit) = self.entries.get(&hash) {
            if hit.1 > now_unix_secs {
                return Some(hit.0.clone());
            }
            drop(hit);
            self.entries.remove(&hash);
        }
        let (info, exp) = verify(token, policy, jwks, now_unix_secs)?;
        if self.entries.len() >= self.cap {
            // Simple and rare: forget everything rather than track recency.
            self.entries.clear();
        }
        self.entries.insert(hash, (info.clone(), exp));
        Some(info)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// A P-256 key pair: the private key for signing tests, the public key
    /// as the issuer would publish it.
    fn issuer_keys(kid: &str) -> (EncodingKey, String) {
        let pair = rcgen::KeyPair::generate().expect("p256 key");
        let raw = pair.public_key_raw(); // 0x04 || x || y
        assert_eq!(raw.len(), 65);
        let b64 = |b: &[u8]| base64url(b);
        let jwks = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","alg":"ES256","use":"sig","x":"{}","y":"{}"}}]}}"#,
            b64(&raw[1..33]),
            b64(&raw[33..65])
        );
        (EncodingKey::from_ec_der(&pair.serialize_der()), jwks)
    }

    fn base64url(b: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let n = chunk.iter().fold(0u32, |acc, x| (acc << 8) | u32::from(*x)) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    fn token(key: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, key).expect("sign")
    }

    fn policy(aud: Option<&str>) -> JwtPolicy {
        JwtPolicy {
            issuer: Arc::from("https://dex.example.com"),
            audience: aud.map(Arc::from),
            tenant_claim: Arc::from("groups"),
            tools_claim: Arc::from("scope"),
        }
    }

    #[test]
    fn a_valid_token_yields_the_subject_with_tenant_and_tools_from_its_claims() {
        let (key, jwks) = issuer_keys("k1");
        let set = Jwks::from_entries([("https://dex.example.com", jwks.as_str())]);
        assert_eq!(set.issuer_count(), 1);
        let t = token(&key, "k1", serde_json::json!({"iss":"https://dex.example.com","sub":"alice@example.com","aud":"portus","exp":now()+600,"groups":["team-a","eng"],"scope":"echo github.*"}));
        assert!(looks_like_jwt(&t));
        let (info, exp) = verify(&t, &policy(Some("portus")), &set, now()).expect("valid");
        assert_eq!(exp, now() + 600);
        assert_eq!((info.tenant.as_ref(), info.name.as_ref()), ("team-a", "alice@example.com"));
        assert_eq!(info.allowed_tools.as_ref(), &["echo".to_string(), "github.*".to_string()]);
        assert!(info.allowed_models.is_empty());
        assert_eq!(info.id, subject_id("https://dex.example.com", "alice@example.com"));
        assert!(info.id < 1 << 63);
        // Without an audience requirement the same token also passes.
        assert!(verify(&t, &policy(None), &set, now()).is_some());
    }

    #[test]
    fn wrong_audience_issuer_key_or_expiry_refuses() {
        let (key, jwks) = issuer_keys("k1");
        let (other_key, _) = issuer_keys("k1");
        let set = Jwks::from_entries([("https://dex.example.com", jwks.as_str())]);
        let claims = |aud: &str, iss: &str, exp: u64| serde_json::json!({"iss":iss,"sub":"bob","aud":aud,"exp":exp});
        assert!(verify(&token(&key, "k1", claims("other", "https://dex.example.com", now() + 60)), &policy(Some("portus")), &set, now()).is_none(), "audience");
        assert!(verify(&token(&key, "k1", claims("portus", "https://evil.example.com", now() + 60)), &policy(Some("portus")), &set, now()).is_none(), "issuer");
        assert!(verify(&token(&key, "k1", claims("portus", "https://dex.example.com", now() - 1)), &policy(Some("portus")), &set, now() + 120).is_none(), "expired");
        assert!(verify(&token(&other_key, "k1", claims("portus", "https://dex.example.com", now() + 60)), &policy(Some("portus")), &set, now()).is_none(), "signed by a key the issuer never published");
        let mut unknown_issuer = policy(Some("portus"));
        unknown_issuer.issuer = Arc::from("https://nobody.example.com");
        assert!(verify(&token(&key, "k1", claims("portus", "https://dex.example.com", now() + 60)), &unknown_issuer, &set, now()).is_none(), "no keys for that issuer");
        assert!(verify("not.a.jwt", &policy(None), &set, now()).is_none());
        assert!(!looks_like_jwt("portus_sk_0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn the_cache_answers_repeat_tokens_until_they_expire() {
        let (key, jwks) = issuer_keys("k1");
        let set = Jwks::from_entries([("https://dex.example.com", jwks.as_str())]);
        let cache = TokenCache::new(2);
        let t = token(&key, "k1", serde_json::json!({"iss":"https://dex.example.com","sub":"carol","exp":now()+3}));
        assert_eq!(cache.get_or_verify(&t, &policy(None), &set, now()).unwrap().name.as_ref(), "carol");
        assert_eq!(cache.len(), 1);
        // A hit needs no keys at all.
        assert!(cache.get_or_verify(&t, &policy(None), &Jwks::default(), now()).is_some());
        // Past exp the entry is dropped and re-verification fails on exp.
        assert!(cache.get_or_verify(&t, &policy(None), &set, now() + 4).is_none());
        assert!(cache.is_empty());
        // The cap bounds memory.
        for i in 0..5 {
            let t = token(&key, "k1", serde_json::json!({"iss":"https://dex.example.com","sub":format!("u{i}"),"exp":now()+3}));
            cache.get_or_verify(&t, &policy(None), &set, now());
        }
        assert!(cache.len() <= 2);
    }
}
