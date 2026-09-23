//! OAuth issuers' public keys for the data planes. Each issuer named in
//! `LEDGER_JWT_ISSUERS` is discovered through its OpenID configuration
//! (`/.well-known/openid-configuration` → `jwks_uri`, falling back to
//! `<issuer>/keys`, dex's path) and its JWKS is fetched every few minutes;
//! a changed set is pushed to the data planes in the next key snapshot.

use std::time::Duration;

use portus_types::proto::portus::ledger::v1::JwksEntry;

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Issuer URLs from the environment value: comma or whitespace separated,
/// trailing slashes dropped, empty entries ignored.
pub fn issuers_from_env(value: &str) -> Vec<String> {
    value
        .split([',', ' ', '\n'])
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The `jwks_uri` of an OpenID configuration document.
pub fn jwks_uri_from_discovery(doc: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(doc).ok()?.get("jwks_uri")?.as_str().map(str::to_string)
}

/// Whether `body` is a JWKS: a JSON object with a `keys` array.
pub fn looks_like_jwks(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get("keys")?.as_array().map(|a| !a.is_empty())).unwrap_or(false)
}

/// Fetch one issuer's JWKS, or say why not.
pub async fn fetch(client: &reqwest::Client, issuer: &str) -> Result<String, String> {
    let discovery = format!("{issuer}/.well-known/openid-configuration");
    let jwks_uri = match client.get(&discovery).send().await {
        Ok(resp) if resp.status().is_success() => {
            let doc = resp.text().await.map_err(|e| format!("reading {discovery}: {e}"))?;
            jwks_uri_from_discovery(&doc).unwrap_or_else(|| format!("{issuer}/keys"))
        }
        _ => format!("{issuer}/keys"),
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

/// Fetch every issuer once. Issuers that fail keep their previous keys.
pub async fn refresh(client: &reqwest::Client, issuers: &[String], current: &[JwksEntry]) -> Vec<JwksEntry> {
    let mut out = Vec::with_capacity(issuers.len());
    for issuer in issuers {
        match fetch(client, issuer).await {
            Ok(jwks_json) => out.push(JwksEntry { issuer: issuer.clone(), jwks_json }),
            Err(e) => {
                log::warn!("issuer {issuer}: {e}");
                if let Some(prev) = current.iter().find(|c| c.issuer == *issuer) {
                    out.push(prev.clone());
                }
            }
        }
    }
    out
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(FETCH_TIMEOUT).build().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuers_parse_from_the_environment_value() {
        assert_eq!(issuers_from_env("https://dex.example.com/, https://accounts.google.com"), vec!["https://dex.example.com".to_string(), "https://accounts.google.com".to_string()]);
        assert!(issuers_from_env("  ").is_empty());
    }

    #[test]
    fn discovery_documents_and_jwks_bodies_are_recognised() {
        assert_eq!(jwks_uri_from_discovery(r#"{"issuer":"https://dex.example.com","jwks_uri":"https://dex.example.com/keys"}"#), Some("https://dex.example.com/keys".into()));
        assert_eq!(jwks_uri_from_discovery("{}"), None);
        assert!(looks_like_jwks(r#"{"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]}"#));
        assert!(!looks_like_jwks(r#"{"keys":[]}"#));
        assert!(!looks_like_jwks("<html>"));
    }
}
