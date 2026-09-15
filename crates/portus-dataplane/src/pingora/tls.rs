//! Pingora's view of the core's TLS material.

use std::sync::Arc;

use pingora_core::listeners::tls::ServerConfigChooser;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::tls::CaType;
use pingora_core::utils::tls::{wrapped_x509_from_der, CertKey};
use rustls::ServerConfig;

use portus_dataplane_core::router::{BackendTlsInfo, ClientIdentity};
use portus_dataplane_core::tls::PortServerConfigs;

/// The per-port `ServerConfig` chooser Pingora asks once the ClientHello is
/// read: local address → port → the core's config for that port.
pub struct PortChooser(pub Arc<PortServerConfigs>);

impl ServerConfigChooser for PortChooser {
    fn choose(
        &self,
        local_addr: Option<&SocketAddr>,
        _client_hello: &rustls::server::ClientHello<'_>,
    ) -> Option<Arc<ServerConfig>> {
        let port = local_addr?.as_inet()?.port();
        self.0.config_for_port(port)
    }
}

/// `CaType` is an unsized slice, so the cache holds it behind its own `Arc`.
struct CaBundle(Arc<CaType>);

/// The BackendTLSPolicy CA bundle as Pingora's `CaType`, built once per
/// policy object and cached on it.
pub fn ca_type_for(info: &BackendTlsInfo) -> Arc<CaType> {
    info.stack
        .get_or_init(|| {
            let wrapped: Vec<_> = info.ca_certs_der.iter().cloned().map(wrapped_x509_from_der).collect();
            CaBundle(Arc::from(wrapped.into_boxed_slice()))
        })
        .0
        .clone()
}

/// The Gateway's backend client certificate as Pingora's `CertKey`, built
/// once and cached on the identity. Part of the peer's reuse hash, so pooled
/// connections never mix identities.
pub fn cert_key_for(identity: &ClientIdentity) -> Arc<CertKey> {
    identity
        .stack
        .get_or_init(|| CertKey::new(identity.cert_chain_der.clone(), identity.key_der.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portus_dataplane_core::tls::{
        build_reloadable_tls_config, generate_self_signed_cert, load_certified_key_from_pem,
        ReloadableCertResolver,
    };

    fn server_config() -> Arc<ServerConfig> {
        let (cert, key) = generate_self_signed_cert().unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(load_certified_key_from_pem(&cert, &key).unwrap()));
        Arc::new(build_reloadable_tls_config(resolver))
    }

    #[test]
    fn chooser_maps_the_local_port_to_the_configured_server_config() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let configs = Arc::new(PortServerConfigs::default());
        let cfg_443 = server_config();
        let cfg_8443 = server_config();
        let mut by_port = hashbrown::HashMap::new();
        by_port.insert(443u16, cfg_443.clone());
        by_port.insert(8443u16, cfg_8443.clone());
        configs.store(by_port);
        let chooser = PortChooser(configs);

        // Exercise the trait through a real ClientHello read by rustls's lazy acceptor.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (picked_8443, picked_443, unknown, no_addr) = rt.block_on(async {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let client_config = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            );
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let client = tokio::spawn(async move {
                let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
                let _ = connector.connect(name, client_io).await;
            });
            let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_io)
                .await
                .unwrap();
            let hello = start.client_hello();
            let addr = |p: u16| SocketAddr::Inet(format!("127.0.0.1:{p}").parse().unwrap());
            let out = (
                chooser.choose(Some(&addr(8443)), &hello).map(|c| Arc::ptr_eq(&c, &cfg_8443)),
                chooser.choose(Some(&addr(443)), &hello).map(|c| Arc::ptr_eq(&c, &cfg_443)),
                chooser.choose(Some(&addr(9443)), &hello).is_none(),
                chooser.choose(None, &hello).is_none(),
            );
            drop(start);
            client.abort();
            out
        });
        assert_eq!(picked_8443, Some(true));
        assert_eq!(picked_443, Some(true));
        assert!(unknown, "ports without validation use the default config");
        assert!(no_addr);
    }

    #[test]
    fn stack_views_are_built_once_per_object() {
        let info = BackendTlsInfo {
            ca_certs_der: Arc::new(vec![]),
            hostname: Arc::from("svc"),
            subject_alt_names: Arc::new(vec![]),
            stack: Default::default(),
        };
        assert!(Arc::ptr_eq(&ca_type_for(&info), &ca_type_for(&info)));
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        let chain: Vec<Vec<u8>> = rustls_pemfile::certs(&mut cert_pem.as_bytes()).map(|c| c.unwrap().to_vec()).collect();
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap().unwrap().secret_der().to_vec();
        let id = ClientIdentity::new(chain, key);
        assert!(Arc::ptr_eq(&cert_key_for(&id), &cert_key_for(&id)));
    }
}
