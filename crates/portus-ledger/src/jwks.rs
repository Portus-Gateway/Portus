//! OAuth issuers' public keys for the data planes. Each issuer named in
//! `LEDGER_JWT_ISSUERS` is fetched every few minutes
//! ([`portus_types::jwks::fetch`]); a changed set is pushed to the data
//! planes in the next key snapshot.

use std::time::Duration;

use portus_types::jwks::fetch;
use portus_types::proto::portus::ledger::v1::JwksEntry;

pub use portus_types::jwks::client;

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

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

/// Fetch every issuer once. Issuers that fail keep their previous keys.
pub async fn refresh(client: &reqwest::Client, issuers: &[String], current: &[JwksEntry]) -> Vec<JwksEntry> {
    let mut out = Vec::with_capacity(issuers.len());
    for issuer in issuers {
        match fetch(client, issuer, None).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuers_parse_from_the_environment_value() {
        assert_eq!(issuers_from_env("https://dex.example.com/, https://accounts.google.com"), vec!["https://dex.example.com".to_string(), "https://accounts.google.com".to_string()]);
        assert!(issuers_from_env("  ").is_empty());
    }
}
