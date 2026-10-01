//! ACME challenge responses the data plane serves itself.
//!
//! Standalone mode's ACME client ([`crate::standalone::acme`]) proves control
//! of a domain by answering the CA's validation request on the proxy's own
//! listeners: HTTP-01 on a plain HTTP port, TLS-ALPN-01 (RFC 8737) in the TLS
//! handshake of an HTTPS port. Both lookups sit on the request and handshake
//! paths of whichever network stack runs, so the pending challenges live in
//! process-wide tables rather than in the per-config snapshot: they belong to
//! an order in flight, not to a config.
//!
//! In Kubernetes mode nothing writes here. The HTTP-01 table stays empty, so
//! `/.well-known/acme-challenge/` requests route as before (cert-manager's
//! solver is an ordinary HTTPRoute), and the frontend TLS resolver is built
//! without TLS-ALPN-01 ([`crate::tls::ReloadableCertResolver::answering_tls_alpn01`]).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use rustls::sign::CertifiedKey;

/// Path prefix of an HTTP-01 validation request; the token follows it.
pub const HTTP01_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// ALPN protocol id of a TLS-ALPN-01 validation handshake.
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

static HTTP01: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(Default::default);
static TLS_ALPN01: LazyLock<RwLock<HashMap<String, Arc<CertifiedKey>>>> = LazyLock::new(Default::default);

/// The key authorization to answer an HTTP-01 request for `token` with.
pub fn http01_key_authorization(token: &str) -> Option<String> {
    let table = HTTP01.read().unwrap_or_else(|e| e.into_inner());
    if table.is_empty() {
        return None;
    }
    table.get(token).cloned()
}

pub(crate) fn set_http01(token: &str, key_authorization: &str) {
    HTTP01
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token.to_string(), key_authorization.to_string());
}

pub(crate) fn clear_http01(token: &str) {
    HTTP01.write().unwrap_or_else(|e| e.into_inner()).remove(token);
}

/// The TLS-ALPN-01 challenge certificate pending for `domain`.
pub fn tls_alpn01_cert(domain: &str) -> Option<Arc<CertifiedKey>> {
    TLS_ALPN01.read().unwrap_or_else(|e| e.into_inner()).get(domain).cloned()
}

pub(crate) fn set_tls_alpn01(domain: &str, cert: CertifiedKey) {
    TLS_ALPN01
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(domain.to_string(), Arc::new(cert));
}

pub(crate) fn clear_tls_alpn01(domain: &str) {
    TLS_ALPN01.write().unwrap_or_else(|e| e.into_inner()).remove(domain);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http01_answers_only_registered_tokens() {
        assert_eq!(http01_key_authorization("tok-unit-a"), None);
        set_http01("tok-unit-a", "tok-unit-a.thumb");
        assert_eq!(http01_key_authorization("tok-unit-a").as_deref(), Some("tok-unit-a.thumb"));
        assert_eq!(http01_key_authorization("tok-unit-b"), None);
        clear_http01("tok-unit-a");
        assert_eq!(http01_key_authorization("tok-unit-a"), None);
    }

    #[test]
    fn tls_alpn01_certs_are_per_domain() {
        let (cert, key) = crate::tls::generate_self_signed_cert().unwrap();
        let ck = crate::tls::load_certified_key_from_pem(&cert, &key).unwrap();
        set_tls_alpn01("alpn-unit.example.com", ck);
        assert!(tls_alpn01_cert("alpn-unit.example.com").is_some());
        assert!(tls_alpn01_cert("other.example.com").is_none());
        clear_tls_alpn01("alpn-unit.example.com");
        assert!(tls_alpn01_cert("alpn-unit.example.com").is_none());
    }
}
