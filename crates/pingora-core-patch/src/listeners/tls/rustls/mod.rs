// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{
    server::handshake, server::handshake_with_callback, server::handshake_with_chooser, TlsStream,
};
use log::debug;
use pingora_error::ErrorType::InternalError;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ClientCertVerifier;
use pingora_rustls::ServerConfig;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};

use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::{GetSocketDigest, ALPN, IO};

/// Picks the rustls [`ServerConfig`] for one accepted connection.
///
/// Consulted after the ClientHello has been read (via tokio-rustls's
/// `LazyConfigAcceptor`) and before the handshake proceeds, with the local
/// address the connection was accepted on. This is what lets one endpoint that
/// serves many ports (see `ServerAddress::Handoff`) apply a different client
/// certificate policy per port: rustls itself has no notion of the local
/// socket inside a `ClientCertVerifier`.
///
/// Returning `None` falls back to the endpoint's default config.
pub trait ServerConfigChooser: Send + Sync {
    fn choose(
        &self,
        local_addr: Option<&SocketAddr>,
        client_hello: &tokio_rustls::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<ServerConfig>>;
}

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: String,
    key_path: String,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
    /// Pre-built ServerConfig for custom cert resolvers (hot-reload support).
    /// When set, `build()` uses this directly instead of loading certs from files.
    custom_server_config: Option<Arc<ServerConfig>>,
    /// Per-connection config selection; `custom_server_config` is the default.
    config_chooser: Option<Arc<dyn ServerConfigChooser>>,
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
    /// When set, every connection reads its ClientHello first and asks the
    /// chooser which config to continue with (default: `acceptor`'s config).
    chooser: Option<Arc<dyn ServerConfigChooser>>,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor {
        // rustls 0.23+ requires an explicit CryptoProvider.
        pingora_rustls::install_default_crypto_provider();

        // If a pre-built ServerConfig was provided (e.g., with a custom cert
        // resolver for hot-reload), use it directly instead of loading from files.
        if let Some(server_config) = self.custom_server_config {
            return Acceptor {
                acceptor: RusTlsAcceptor::from(server_config),
                callbacks: None,
                chooser: self.config_chooser,
            };
        }

        let Ok(Some((certs, key))) = load_certs_and_key_files(&self.cert_path, &self.key_path)
        else {
            panic!(
                "Failed to load provided certificates \"{}\" or key \"{}\".",
                self.cert_path, self.key_path
            )
        };

        let builder =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13]);
        let builder = if let Some(verifier) = self.client_cert_verifier {
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder
            .with_single_cert(certs, key)
            .explain_err(InternalError, |e| {
                format!("Failed to create server listener config: {e}")
            })
            .unwrap();

        if let Some(alpn_protocols) = self.alpn_protocols {
            config.alpn_protocols = alpn_protocols;
        }

        Acceptor {
            acceptor: RusTlsAcceptor::from(Arc::new(config)),
            callbacks: None,
            chooser: None,
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    pub fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    /// Configure mTLS by providing a rustls client certificate verifier.
    pub fn set_client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) {
        self.client_cert_verifier = Some(verifier);
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            client_cert_verifier: None,
            custom_server_config: None,
            config_chooser: None,
        })
    }

    /// Create TLS settings from a pre-built `ServerConfig`.
    ///
    /// This bypasses the normal cert/key file loading in `build()`, allowing
    /// callers to provide a `ServerConfig` with a custom `ResolvesServerCert`
    /// for dynamic certificate hot-reload.
    ///
    /// Note: `enable_h2()` / `set_alpn()` have no effect when using this
    /// constructor — configure ALPN protocols on the `ServerConfig` directly.
    pub fn from_server_config(config: Arc<ServerConfig>) -> Self {
        TlsSettings {
            alpn_protocols: None,
            cert_path: String::new(),
            key_path: String::new(),
            client_cert_verifier: None,
            custom_server_config: Some(config),
            config_chooser: None,
        }
    }

    /// Like [`Self::from_server_config`], but every connection's ClientHello is
    /// read first and `chooser` may substitute another `ServerConfig` for it
    /// (per local port, per SNI, ...). `default` is used when it returns `None`.
    pub fn from_config_chooser(
        default: Arc<ServerConfig>,
        chooser: Arc<dyn ServerConfigChooser>,
    ) -> Self {
        TlsSettings {
            alpn_protocols: None,
            cert_path: String::new(),
            key_path: String::new(),
            client_cert_verifier: None,
            custom_server_config: Some(default),
            config_chooser: Some(chooser),
        }
    }

    pub fn with_callbacks() -> Result<Self>
    where
        Self: Sized,
    {
        // TODO: verify if/how callback in handshake can be done using Rustls
        Error::e_explain(
            InternalError,
            "Certificate callbacks are not supported with feature \"rustls\".",
        )
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // TODO: be able to offload this handshake in a thread pool
        if let Some(chooser) = self.chooser.as_ref() {
            let local_addr = stream
                .get_socket_digest()
                .and_then(|d| d.local_addr().cloned());
            handshake_with_chooser(self, stream, chooser.as_ref(), local_addr.as_ref()).await
        } else if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(self, stream, cb).await
        } else {
            handshake(self, stream).await
        }
    }

    /// The default `ServerConfig` (used when the chooser declines).
    pub fn default_config(&self) -> &Arc<ServerConfig> {
        self.acceptor.config()
    }
}
