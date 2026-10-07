//! Fetching an OAuth issuer's public keys (JWKS), shared by the controller
//! (JWTAuthPolicy) and the ledger (AI routes). The issuer is discovered
//! through its OpenID configuration (`/.well-known/openid-configuration` →
//! `jwks_uri`, falling back to `<issuer>/keys`, dex's path) unless the
//! caller names the JWKS URI itself.

use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The `jwks_uri` of an OpenID configuration document.
pub fn jwks_uri_from_discovery(doc: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(doc).ok()?.get("jwks_uri")?.as_str().map(str::to_string)
}

/// Whether `body` is a JWKS: a JSON object with a non-empty `keys` array.
pub fn looks_like_jwks(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get("keys")?.as_array().map(|a| !a.is_empty())).unwrap_or(false)
}

/// Fetch one issuer's JWKS from `jwks_uri`, or by discovery when it is
/// `None`; the error says what failed.
pub async fn fetch(client: &reqwest::Client, issuer: &str, jwks_uri: Option<&str>) -> Result<String, String> {
    let issuer = issuer.trim_end_matches('/');
    let jwks_uri = match jwks_uri {
        Some(uri) => uri.to_string(),
        None => {
            let discovery = format!("{issuer}/.well-known/openid-configuration");
            match client.get(&discovery).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let doc = resp.text().await.map_err(|e| format!("reading {discovery}: {e}"))?;
                    jwks_uri_from_discovery(&doc).unwrap_or_else(|| format!("{issuer}/keys"))
                }
                _ => format!("{issuer}/keys"),
            }
        }
    };
    let resp = client.get(&jwks_uri).send().await.map_err(|e| format!("GET {jwks_uri}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {jwks_uri}: HTTP {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| format!("reading {jwks_uri}: {e}"))?;
    if !looks_like_jwks(&body) {
        return Err(format!("{jwks_uri} did not return a JWKS"));
    }
    Ok(body)
}

/// A client with the fetch timeout. Installs the process's rustls crypto
/// provider (aws-lc) when nothing has yet, since reqwest needs one.
pub fn client() -> reqwest::Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    reqwest::Client::builder().timeout(FETCH_TIMEOUT).build().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_documents_and_jwks_bodies_are_recognised() {
        assert_eq!(jwks_uri_from_discovery(r#"{"issuer":"https://dex.example.com","jwks_uri":"https://dex.example.com/keys"}"#), Some("https://dex.example.com/keys".into()));
        assert_eq!(jwks_uri_from_discovery("{}"), None);
        assert!(looks_like_jwks(r#"{"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]}"#));
        assert!(!looks_like_jwks(r#"{"keys":[]}"#));
        assert!(!looks_like_jwks("<html>"));
    }
}
