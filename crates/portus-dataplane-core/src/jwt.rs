//! JSON Web Tokens: issuers' public keys, signature and claim verification,
//! and the JWTAuthPolicy check a route runs. The controller fetches each
//! issuer's JWKS and ships it in the config (AI routes get theirs from the
//! ledger); nothing here calls out.

use std::sync::Arc;

use dashmap::DashMap;
use hashbrown::HashMap;
use http::{HeaderName, HeaderValue};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};

/// Verified claims of one token.
pub type Claims = serde_json::Map<String, serde_json::Value>;

/// One issuer's public keys.
struct IssuerKeys {
    keys: Vec<(Option<String>, Algorithm, DecodingKey)>,
}

/// Every issuer's keys, as the config or key snapshot carried them.
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

/// The claims and expiry of `token` when it is signed by one of `issuer`'s
/// keys, names that issuer, is unexpired (and not before its `nbf`), has a
/// subject, and carries one of `audiences` (unchecked when empty).
pub fn verify_claims(token: &str, issuer: &str, audiences: &[impl ToString], jwks: &Jwks, now_unix_secs: u64) -> Option<(Claims, u64)> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let keys = jwks.issuers.get(issuer)?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    if audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(audiences);
    }
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    let candidates = keys.keys.iter().filter(|(kid, alg, _)| {
        *alg == header.alg
            && match (&header.kid, kid) {
                (Some(h), Some(k)) => h == k,
                (Some(_), None) | (None, _) => true,
            }
    });
    let claims = candidates
        .filter_map(|(_, _, key)| jsonwebtoken::decode::<Claims>(token, key, &validation).ok())
        .map(|data| data.claims)
        .next()?;
    let exp = claims.get("exp")?.as_u64()?;
    if exp <= now_unix_secs {
        return None;
    }
    Some((claims, exp))
}

/// The bearer token of an `Authorization` value (`Bearer` in any case).
pub fn bearer_token(authorization: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(authorization).ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// One issuer a JWTAuthPolicy trusts.
#[derive(Debug, Clone)]
pub struct Provider {
    pub issuer: Arc<str>,
    pub audiences: Vec<String>,
    /// Claims copied into request headers for the backend.
    pub claim_headers: Vec<(String, HeaderName)>,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtRefusal {
    /// No bearer token.
    Missing,
    /// A token no provider accepts.
    Invalid,
}

/// Headers a verified token sets.
pub type ClaimHeaders = Arc<Vec<(HeaderName, HeaderValue)>>;

/// Verified tokens kept before the cache is cleared.
const TOKEN_CACHE_CAPACITY: usize = 10_000;

/// A route's JWTAuthPolicy: the providers, the headers it owns and the
/// tokens it has already verified.
pub struct JwtAuth {
    pub providers: Vec<Provider>,
    /// Every header any provider sets from a claim. They are removed from the
    /// client's request before the verified values are set, so a client can
    /// never supply them itself.
    pub owned_headers: Arc<Vec<HeaderName>>,
    /// Verified tokens by hash: the headers they set and their expiry.
    cache: DashMap<[u8; 32], (ClaimHeaders, u64)>,
}

impl std::fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuth").field("providers", &self.providers).field("cached_tokens", &self.cache.len()).finish()
    }
}

impl JwtAuth {
    pub fn new(providers: Vec<Provider>) -> Self {
        let mut owned: Vec<HeaderName> = Vec::new();
        for (_, h) in providers.iter().flat_map(|p| &p.claim_headers) {
            if !owned.contains(h) {
                owned.push(h.clone());
            }
        }
        Self { providers, owned_headers: Arc::new(owned), cache: DashMap::new() }
    }

    /// The headers to set for a request carrying `authorization`, or why it
    /// is refused. A token is verified once and then answered from the cache
    /// until it expires.
    pub fn authenticate(&self, authorization: Option<&[u8]>, jwks: &Jwks, now_unix_secs: u64) -> Result<ClaimHeaders, JwtRefusal> {
        let token = authorization.and_then(bearer_token).ok_or(JwtRefusal::Missing)?;
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some(hit) = self.cache.get(&hash) {
            if hit.1 > now_unix_secs {
                return Ok(Arc::clone(&hit.0));
            }
            drop(hit);
            self.cache.remove(&hash);
        }
        let (provider, claims, exp) = self
            .providers
            .iter()
            .find_map(|p| verify_claims(token, &p.issuer, &p.audiences, jwks, now_unix_secs).map(|(c, exp)| (p, c, exp)))
            .ok_or(JwtRefusal::Invalid)?;
        let headers: ClaimHeaders = Arc::new(
            provider
                .claim_headers
                .iter()
                .filter_map(|(claim, header)| Some((header.clone(), claim_value(claims.get(claim)?)?)))
                .collect(),
        );
        if self.cache.len() >= TOKEN_CACHE_CAPACITY {
            // Simple and rare: forget everything rather than track recency.
            self.cache.clear();
        }
        self.cache.insert(hash, (Arc::clone(&headers), exp));
        Ok(headers)
    }
}

/// A claim as a header value: strings as they are, numbers and booleans as
/// JSON text, arrays of those comma-joined. Objects, nulls and values that
/// are not valid header text are left out.
fn claim_value(v: &serde_json::Value) -> Option<HeaderValue> {
    let scalar = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    let text = match v {
        serde_json::Value::Array(items) => items.iter().map(scalar).collect::<Option<Vec<_>>>()?.join(","),
        other => scalar(other)?,
    };
    HeaderValue::from_str(&text).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    pub(crate) fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// A P-256 key pair: the private key for signing tests, the public key
    /// as the issuer would publish it.
    pub(crate) fn issuer_keys(kid: &str) -> (EncodingKey, String) {
        let pair = rcgen::KeyPair::generate().expect("p256 key");
        let raw = pair.public_key_raw(); // 0x04 || x || y
        assert_eq!(raw.len(), 65);
        let jwks = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","alg":"ES256","use":"sig","x":"{}","y":"{}"}}]}}"#,
            base64url(&raw[1..33]),
            base64url(&raw[33..65])
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

    pub(crate) fn token(key: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, key).expect("sign")
    }

    const DEX: &str = "https://dex.example.com";
    const GOOGLE: &str = "https://accounts.example.org";

    fn provider(issuer: &str, audiences: &[&str], headers: &[(&str, &str)]) -> Provider {
        Provider {
            issuer: Arc::from(issuer),
            audiences: audiences.iter().map(|a| a.to_string()).collect(),
            claim_headers: headers.iter().map(|(c, h)| (c.to_string(), HeaderName::from_bytes(h.as_bytes()).unwrap())).collect(),
        }
    }

    fn bearer(t: &str) -> Vec<u8> {
        format!("Bearer {t}").into_bytes()
    }

    #[test]
    fn bearer_tokens_are_read_from_the_authorization_value() {
        assert_eq!(bearer_token(b"Bearer abc.def.ghi"), Some("abc.def.ghi"));
        assert_eq!(bearer_token(b"bearer  abc "), Some("abc"));
        assert_eq!(bearer_token(b"Basic dXNlcjpwdw=="), None);
        assert_eq!(bearer_token(b"Bearer "), None);
        assert_eq!(bearer_token(b"Bearer"), None);
        assert_eq!(bearer_token(&[0xff, b' ', b'x']), None);
    }

    #[test]
    fn a_valid_token_sets_its_claims_as_headers() {
        let (key, jwks) = issuer_keys("k1");
        let set = Jwks::from_entries([(DEX, jwks.as_str())]);
        let auth = JwtAuth::new(vec![provider(DEX, &["api"], &[("sub", "x-user"), ("groups", "x-groups"), ("tier", "x-tier"), ("missing", "x-missing"), ("org", "x-org")])]);
        let t = token(&key, "k1", serde_json::json!({"iss":DEX,"sub":"alice","aud":"api","exp":now()+600,"groups":["eng","ops"],"tier":3,"org":{"id":1}}));
        let headers = auth.authenticate(Some(&bearer(&t)), &set, now()).expect("valid");
        let got: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.to_str().unwrap())).collect();
        assert_eq!(got, vec![("x-user", "alice"), ("x-groups", "eng,ops"), ("x-tier", "3")], "objects and absent claims set nothing");
        assert_eq!(auth.owned_headers.len(), 5, "every configured header is stripped from the client request");
    }

    #[test]
    fn missing_malformed_or_untrusted_tokens_are_refused() {
        let (key, jwks) = issuer_keys("k1");
        let (stranger, _) = issuer_keys("k1");
        let set = Jwks::from_entries([(DEX, jwks.as_str())]);
        let auth = JwtAuth::new(vec![provider(DEX, &["api"], &[])]);
        let claims = |aud: &str, iss: &str, exp: u64| serde_json::json!({"iss":iss,"sub":"bob","aud":aud,"exp":exp});
        let check = |t: &str| auth.authenticate(Some(&bearer(t)), &set, now());
        assert_eq!(auth.authenticate(None, &set, now()).unwrap_err(), JwtRefusal::Missing);
        assert_eq!(auth.authenticate(Some(b"Basic dXNlcjpwdw=="), &set, now()).unwrap_err(), JwtRefusal::Missing);
        assert_eq!(check("not.a.jwt").unwrap_err(), JwtRefusal::Invalid);
        assert_eq!(check(&token(&key, "k1", claims("other", DEX, now() + 60))).unwrap_err(), JwtRefusal::Invalid, "audience");
        assert_eq!(check(&token(&key, "k1", claims("api", "https://evil.example.com", now() + 60))).unwrap_err(), JwtRefusal::Invalid, "issuer");
        assert_eq!(check(&token(&key, "k1", claims("api", DEX, now() - 120))).unwrap_err(), JwtRefusal::Invalid, "expired");
        assert_eq!(check(&token(&stranger, "k1", claims("api", DEX, now() + 60))).unwrap_err(), JwtRefusal::Invalid, "a key the issuer never published");
        let early = token(&key, "k1", serde_json::json!({"iss":DEX,"sub":"bob","aud":"api","exp":now()+600,"nbf":now()+300}));
        assert_eq!(check(&early).unwrap_err(), JwtRefusal::Invalid, "not yet valid");
        let no_sub = token(&key, "k1", serde_json::json!({"iss":DEX,"aud":"api","exp":now()+600}));
        assert_eq!(check(&no_sub).unwrap_err(), JwtRefusal::Invalid, "a subject is required");
        assert!(check(&token(&key, "k1", claims("api", DEX, now() + 60))).is_ok());
        // No keys for the issuer (the controller could not fetch them): closed.
        assert_eq!(auth.authenticate(Some(&bearer(&token(&key, "k1", claims("api", DEX, now() + 60)))), &Jwks::default(), now()).unwrap_err(), JwtRefusal::Invalid);
    }

    #[test]
    fn each_token_is_checked_against_the_provider_that_issued_it() {
        let (dex_key, dex_jwks) = issuer_keys("d1");
        let (org_key, org_jwks) = issuer_keys("g1");
        let set = Jwks::from_entries([(DEX, dex_jwks.as_str()), (GOOGLE, org_jwks.as_str())]);
        let auth = JwtAuth::new(vec![provider(DEX, &[], &[("email", "x-email")]), provider(GOOGLE, &["portus"], &[("sub", "x-user")])]);
        let from_org = token(&org_key, "g1", serde_json::json!({"iss":GOOGLE,"sub":"carol","aud":"portus","exp":now()+600,"email":"c@example.org"}));
        let headers = auth.authenticate(Some(&bearer(&from_org)), &set, now()).expect("second provider");
        assert_eq!(headers.as_slice(), &[(HeaderName::from_static("x-user"), HeaderValue::from_static("carol"))], "the matching provider's headers only");
        let from_dex = token(&dex_key, "d1", serde_json::json!({"iss":DEX,"sub":"dave","exp":now()+600,"email":"d@example.com"}));
        assert!(auth.authenticate(Some(&bearer(&from_dex)), &set, now()).is_ok(), "no audience required by the first provider");
        // A token signed by dex's key but claiming the other issuer fails both.
        let forged = token(&dex_key, "g1", serde_json::json!({"iss":GOOGLE,"sub":"eve","aud":"portus","exp":now()+600}));
        assert_eq!(auth.authenticate(Some(&bearer(&forged)), &set, now()).unwrap_err(), JwtRefusal::Invalid);
    }

    #[test]
    fn verified_tokens_are_cached_until_they_expire() {
        let (key, jwks) = issuer_keys("k1");
        let set = Jwks::from_entries([(DEX, jwks.as_str())]);
        let auth = JwtAuth::new(vec![provider(DEX, &[], &[("sub", "x-user")])]);
        let t = token(&key, "k1", serde_json::json!({"iss":DEX,"sub":"frank","exp":now()+3}));
        assert!(auth.authenticate(Some(&bearer(&t)), &set, now()).is_ok());
        assert!(auth.authenticate(Some(&bearer(&t)), &Jwks::default(), now()).is_ok(), "a hit needs no keys");
        assert_eq!(auth.authenticate(Some(&bearer(&t)), &set, now() + 4).unwrap_err(), JwtRefusal::Invalid, "past exp it is verified again and fails");
        assert_eq!(auth.cache.len(), 0);
    }
}
