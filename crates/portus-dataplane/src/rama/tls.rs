//! Rama's view of the core's TLS material: the per-port frontend
//! `ServerConfig` chooser, and the upstream trust, identity and SAN verifier a
//! BackendTLSPolicy asks for.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use rama::crypto::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::net::stream::SocketInfo;
use rama::tcp::TcpStream;
use rama::tls::client::{ClientAuth, ClientAuthData, TlsServerTrust, TlsServerTrustAnchors};
use rama::tls::rustls::server::{DynamicConfigProvider, RustlsServerConfigExt, TlsAcceptorService, TlsStream};
use rama::tls::server::TlsServerConfig;
use rama::Service;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

use portus_dataplane_core::bootstrap::FrontendTls;
use portus_dataplane_core::router::{BackendTlsInfo, ClientIdentity};

/// Terminates TLS with the `ServerConfig` the core holds for the port the
/// connection arrived on (frontend client-certificate validation is per
/// port), else the default hot-reloaded config. Stores the ClientHello so the
/// request path can read the SNI.
#[derive(Clone)]
pub struct PortTlsAcceptor<S> {
    tls: Arc<FrontendTls>,
    inner: S,
}

impl<S> PortTlsAcceptor<S> {
    pub fn new(tls: Arc<FrontendTls>, inner: S) -> Self {
        Self { tls, inner }
    }
}

impl<S> Service<TcpStream> for PortTlsAcceptor<S>
where
    S: Service<TlsStream<TcpStream>, Error: Into<BoxError>> + Clone,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: TcpStream) -> Result<Self::Output, Self::Error> {
        let port = stream.extensions().get_ref::<SocketInfo>().and_then(|s| s.local_addr()).map(|a| a.port);
        let config = port
            .and_then(|p| self.tls.port_configs.config_for_port(p))
            .unwrap_or_else(|| self.tls.server_config.clone());
        let tls_config = TlsServerConfig::new().with_dynamic_config(Arc::new(Fixed(config)));
        TlsAcceptorService::new(tls_config, self.inner.clone(), true).serve(stream).await
    }
}

/// A "dynamic" provider that always answers with the config chosen from the
/// local port. Rama resolves it after reading the ClientHello, which also
/// gives the request path the SNI.
struct Fixed(Arc<ServerConfig>);

impl DynamicConfigProvider for Fixed {
    async fn get_config(&self, _client_hello: rustls::server::ClientHello<'_>) -> Result<Arc<ServerConfig>, BoxError> {
        Ok(Arc::clone(&self.0))
    }
}

/// What a BackendTLSPolicy becomes for Rama's client: trust anchors, an
/// optional required-SANs verifier and a key that keeps pooled connections
/// verified under one policy from serving another. Built once per policy
/// object and cached on it.
pub struct UpstreamTls {
    pub trust: TlsServerTrust,
    pub verifier: Option<Arc<dyn ServerCertVerifier>>,
    pub key: u64,
}

pub fn upstream_tls_for(info: &BackendTlsInfo) -> Arc<UpstreamTls> {
    info.stack.get_or_init(|| build_upstream_tls(info))
}

fn build_upstream_tls(info: &BackendTlsInfo) -> UpstreamTls {
    let certs: Vec<CertificateDer<'static>> =
        info.ca_certs_der.iter().map(|der| CertificateDer::from(der.clone())).collect();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for der in info.ca_certs_der.iter() {
        der.hash(&mut hasher);
    }
    info.subject_alt_names.hash(&mut hasher);
    let key = hasher.finish();

    let verifier = if info.subject_alt_names.is_empty() {
        None
    } else {
        let mut roots = RootCertStore::empty();
        for cert in &certs {
            let _ = roots.add(cert.clone());
        }
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .ok()
            .map(|delegate| {
                Arc::new(SanCheckingVerifier { delegate, required_sans: Arc::clone(&info.subject_alt_names) })
                    as Arc<dyn ServerCertVerifier>
            })
    };
    let trust = match TlsServerTrustAnchors::try_new(certs) {
        Ok(anchors) => TlsServerTrust::custom(anchors),
        // An empty bundle never reaches here (the config receiver drops it),
        // but if it did the default roots are the safe answer.
        Err(_) => TlsServerTrust::default_roots(),
    };
    UpstreamTls { trust, verifier, key }
}

/// The Gateway's backend client certificate as Rama's `ClientAuth`, built
/// once and cached on the identity.
pub fn client_auth_for(identity: &ClientIdentity) -> Arc<Option<ClientAuth>> {
    identity.stack.get_or_init(|| {
        PrivateKeyDer::try_from(identity.key_der.clone()).ok().map(|private_key| {
            ClientAuth::Single(ClientAuthData {
                private_key,
                cert_chain: identity.cert_chain_der.iter().map(|d| CertificateDer::from(d.clone())).collect(),
            })
        })
    })
}

/// Standard WebPKI validation (chain + hostname) followed by a check that
/// the end-entity certificate carries at least one required SubjectAltName.
#[derive(Debug)]
struct SanCheckingVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    required_sans: Arc<Vec<(String, String)>>, // (type, value)
}

impl ServerCertVerifier for SanCheckingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.delegate.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        if san_matches(end_entity.as_ref(), &self.required_sans) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "backend certificate does not match required SubjectAltNames: {:?}",
                self.required_sans
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

/// At least one required (type, value) SAN appears in the certificate.
fn san_matches(cert_der: &[u8], required: &[(String, String)]) -> bool {
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert_der) else { return false };
    let cert_sans: Vec<(&str, String)> = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::prelude::GeneralName::DNSName(dns) => Some(("Hostname", dns.to_string())),
                    x509_parser::prelude::GeneralName::URI(uri) => Some(("URI", uri.to_string())),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    required.iter().any(|(t, v)| cert_sans.iter().any(|(ct, cv)| ct == t && cv == v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portus_dataplane_core::tls::generate_self_signed_cert;

    fn self_signed_der() -> (Vec<Vec<u8>>, Vec<u8>) {
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        let chain = rustls_pemfile::certs(&mut cert_pem.as_bytes()).map(|c| c.unwrap().to_vec()).collect();
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap().unwrap().secret_der().to_vec();
        (chain, key)
    }

    #[test]
    fn san_check_matches_the_generated_localhost_name_only() {
        let (chain, _) = self_signed_der();
        assert!(san_matches(&chain[0], &[("Hostname".into(), "localhost".into())]));
        assert!(!san_matches(&chain[0], &[("Hostname".into(), "other".into())]));
        assert!(!san_matches(&chain[0], &[("URI".into(), "localhost".into())]), "type must match too");
        assert!(!san_matches(b"not a cert", &[("Hostname".into(), "localhost".into())]));
    }

    #[test]
    fn upstream_tls_views_are_cached_and_keyed_by_policy_content() {
        let (chain, key) = self_signed_der();
        let a = BackendTlsInfo {
            ca_certs_der: Arc::new(chain.clone()),
            hostname: Arc::from("svc"),
            subject_alt_names: Arc::new(vec![("Hostname".into(), "svc".into())]),
            stack: Default::default(),
        };
        let b = BackendTlsInfo {
            ca_certs_der: Arc::new(chain.clone()),
            hostname: Arc::from("svc"),
            subject_alt_names: Arc::new(vec![]),
            stack: Default::default(),
        };
        let va = upstream_tls_for(&a);
        assert!(Arc::ptr_eq(&va, &upstream_tls_for(&a)));
        assert!(va.verifier.is_some(), "required SANs install the verifier");
        let vb = upstream_tls_for(&b);
        assert!(vb.verifier.is_none());
        assert_ne!(va.key, vb.key, "different SAN requirements never share a pooled connection");

        let id = ClientIdentity::new(chain, key);
        let auth = client_auth_for(&id);
        assert!(auth.is_some());
        assert!(Arc::ptr_eq(&auth, &client_auth_for(&id)));
    }
}
