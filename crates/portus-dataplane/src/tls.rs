//! TLS certificate hot-reload module.
//!
//! Provides:
//! - Certificate loading and validation (`load_certified_key`, `load_certified_key_from_pem`)
//! - `ReloadableCertResolver` — a lock-free `rustls::server::ResolvesServerCert`
//!   backed by `ArcSwap` for atomic certificate replacement without restarts
//! - `build_reloadable_tls_config` — constructs a `rustls::ServerConfig` wired to
//!   the resolver, suitable for passing to Pingora's `TlsSettings::from_server_config()`
//! - `start_tls_cert_hot_reload` — background thread woken by `apply_config`
//!   whenever the controller pushes new certs; parses them and atomically swaps
//!   them into the resolver
//! - Self-signed bootstrap cert generation for immediate HTTPS startup

use arc_swap::ArcSwap;
use log::{error, info};
#[cfg(test)]
use log::warn;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::fmt;
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::BufReader;
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;


use crate::config_receiver::{ClientValidationMode, PortClientValidation, TlsCertSlot};
use crate::metrics::ProxyMetrics;

// ---------------------------------------------------------------------------
// ReloadableCertResolver
// ---------------------------------------------------------------------------

/// SNI-based cert map: hostname pattern → certified key.
/// Stored behind ArcSwap for lock-free reads on the TLS handshake path.
struct CertMap {
    /// Exact hostname → cert (e.g., "portus.example.com")
    exact: hashbrown::HashMap<String, Arc<CertifiedKey>>,
    /// Wildcard suffix → cert (e.g., ".example.com" for "*.example.com")
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    /// Default cert when no SNI match (listener with empty hostname)
    default: Option<Arc<CertifiedKey>>,
}

/// Production cert resolver for Pingora's HTTPS listener.
///
/// Implements `rustls::server::ResolvesServerCert` using lock-free `ArcSwap`
/// for atomic cert replacement. Supports SNI-based certificate selection:
/// each HTTPS listener can have a different hostname and cert pair.
///
/// Resolution order:
/// 1. Exact hostname match
/// 2. Wildcard match (e.g., *.example.com matches foo.example.com)
/// 3. Default cert (listener with no hostname restriction)
/// 4. First available cert as fallback
pub(crate) struct ReloadableCertResolver {
    /// Legacy single-cert field, used as bootstrap and by tests.
    pub(crate) certified_key: ArcSwap<CertifiedKey>,
    /// SNI-based cert map for multi-listener support.
    cert_map: ArcSwap<CertMap>,
}

impl ReloadableCertResolver {
    /// Create a new resolver with the given initial certified key.
    pub(crate) fn new(initial: CertifiedKey) -> Self {
        let arc_key = Arc::new(initial);
        let map = CertMap {
            exact: hashbrown::HashMap::new(),
            wildcard: Vec::new(),
            default: Some(Arc::clone(&arc_key)),
        };
        Self {
            certified_key: ArcSwap::from(arc_key),
            cert_map: ArcSwap::from_pointee(map),
        }
    }

    /// Atomically swap the stored certified key (single-cert mode).
    /// Also updates the default in the cert map.
    #[cfg(test)]
    pub(crate) fn swap(&self, new_key: CertifiedKey) {
        let arc_key = Arc::new(new_key);
        self.certified_key.store(Arc::clone(&arc_key));
        // Update default in cert map
        let old_map = self.cert_map.load();
        let new_map = CertMap {
            exact: old_map.exact.clone(),
            wildcard: old_map.wildcard.clone(),
            default: Some(arc_key),
        };
        self.cert_map.store(Arc::new(new_map));
    }

    /// Replace the entire cert map with new entries from multiple listeners.
    pub(crate) fn swap_map(&self, entries: Vec<(String, CertifiedKey)>) {
        let mut exact = hashbrown::HashMap::new();
        let mut wildcard = Vec::new();
        let mut default: Option<Arc<CertifiedKey>> = None;
        let mut first: Option<Arc<CertifiedKey>> = None;

        for (hostname, key) in entries {
            let arc_key = Arc::new(key);
            if first.is_none() {
                first = Some(Arc::clone(&arc_key));
            }

            if hostname.is_empty() {
                default = Some(arc_key);
            } else if hostname.starts_with("*.") {
                // *.example.com → suffix ".example.com"
                let suffix = hostname[1..].to_string();
                wildcard.push((suffix, arc_key));
            } else {
                exact.insert(hostname, arc_key);
            }
        }

        // If no explicit default, use the first cert as fallback
        if default.is_none() {
            default = first;
        }

        // Also update the single-cert field for backward compat
        if let Some(ref d) = default {
            self.certified_key.store(Arc::clone(d));
        }

        let exact_count = exact.len();
        let wildcard_count = wildcard.len();
        let has_default = default.is_some();
        self.cert_map.store(Arc::new(CertMap { exact, wildcard, default }));
        info!("updated TLS cert map: {} exact, {} wildcard, default={}",
            exact_count, wildcard_count, has_default);
    }
}

impl fmt::Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadableCertResolver")
            .field("has_key", &true)
            .finish()
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let map = self.cert_map.load();

        if let Some(sni) = client_hello.server_name() {
            // 1. Exact match
            if let Some(key) = map.exact.get(sni) {
                return Some(Arc::clone(key));
            }
            // 2. Wildcard match: foo.example.com matches suffix ".example.com"
            for (suffix, key) in &map.wildcard {
                if sni.ends_with(suffix.as_str()) {
                    // RFC 6125: wildcard matches exactly one label
                    let prefix = &sni[..sni.len() - suffix.len()];
                    if !prefix.contains('.') && !prefix.is_empty() {
                        return Some(Arc::clone(key));
                    }
                }
            }
        }

        // 3. Default cert
        map.default.as_ref().map(Arc::clone)
    }
}

// ---------------------------------------------------------------------------
// Cert loading
// ---------------------------------------------------------------------------

/// Load a TLS certificate chain and private key from PEM strings (in-memory).
///
/// Used when certificates are delivered via the gRPC config stream from the
/// controller (e.g., from Kubernetes TLS Secrets). Returns a `CertifiedKey`
/// suitable for use with rustls, or a descriptive error string on failure.
pub(crate) fn load_certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<CertifiedKey, String> {
    // Parse certificate chain from PEM string
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certs from PEM string: {}", e))?;
    if certs.is_empty() {
        return Err("no certificates found in PEM string".to_string());
    }

    // Parse private key from PEM string
    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse key from PEM string: {}", e))?
        .ok_or_else(|| "no private key found in PEM string".to_string())?;

    // Convert to signing key
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported private key type in PEM string: {}", e))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Load a TLS certificate chain and private key from PEM files on disk.
///
/// Returns a `CertifiedKey` suitable for use with rustls, or a descriptive
/// error string on failure.
#[cfg(test)]
pub(crate) fn load_certified_key(
    cert_path: &str,
    key_path: &str,
) -> Result<CertifiedKey, String> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .map_err(|e| format!("failed to open cert file '{}': {}", cert_path, e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certs from '{}': {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in '{}'", cert_path));
    }
    if certs.len() == 1 {
        warn!(
            "cert file '{}' contains only a leaf certificate (no intermediates); \
             clients without the issuing CA in their trust store may reject connections",
            cert_path
        );
    }

    // Load private key
    let key_file = File::open(key_path)
        .map_err(|e| format!("failed to open key file '{}': {}", key_path, e))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse key from '{}': {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in '{}'", key_path))?;

    // Convert to signing key
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported private key type in '{}': {}", key_path, e))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

// ---------------------------------------------------------------------------
// TLS config builder
// ---------------------------------------------------------------------------

/// Build a rustls `ServerConfig` using the given `ReloadableCertResolver`.
///
/// Called from `main.rs` to create the `ServerConfig` that is passed to
/// `TlsSettings::from_server_config()` (patched pingora-core). The resolver
/// is consulted on every TLS handshake, enabling lock-free cert hot-reload.
pub(crate) fn build_reloadable_tls_config(
    resolver: Arc<ReloadableCertResolver>,
) -> ServerConfig {
    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

// ---------------------------------------------------------------------------
// Frontend client certificate validation (Gateway spec.tls.frontend)
// ---------------------------------------------------------------------------

/// `ClientCertVerifier` for `AllowInsecureFallback`: the client is asked for a
/// certificate (so mTLS-capable clients present one) but the handshake
/// continues without one, or with one that does not chain to the configured
/// CAs. Invalid certificates are logged and treated as absent.
struct InsecureFallbackVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
}

impl fmt::Debug for InsecureFallbackVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InsecureFallbackVerifier")
    }
}

impl rustls::server::danger::ClientCertVerifier for InsecureFallbackVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match self.inner.verify_client_cert(end_entity, intermediates, now) {
            Ok(v) => Ok(v),
            Err(e) => {
                log::debug!("client certificate did not validate; accepting (AllowInsecureFallback): {e}");
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Fail-closed verifier used when a port's CA bundle cannot be turned into a
/// trust store: every client certificate (and its absence) is rejected, so a
/// broken CA never degrades into "no client authentication".
#[derive(Debug)]
struct RejectAllClientCerts {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::server::danger::ClientCertVerifier for RejectAllClientCerts {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the rustls client certificate verifier for one port's policy.
///
/// The CA bundles are parsed into a `RootCertStore`; certificates that fail to
/// parse are skipped. With no usable trust anchor at all the verifier fails
/// closed (rejects every handshake) and the problem is logged, because the
/// controller only ships validation blocks it has already checked.
pub(crate) fn build_client_cert_verifier(
    spec: &PortClientValidation,
) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    for pem in &spec.ca_cert_pems {
        for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
            match cert {
                Ok(der) => {
                    if let Err(e) = roots.add(der) {
                        error!("port {}: skipping CA certificate that is not a valid trust anchor: {e}", spec.port);
                    }
                }
                Err(e) => error!("port {}: skipping unparseable CA PEM: {e}", spec.port),
            }
        }
    }
    let strict: Arc<dyn rustls::server::danger::ClientCertVerifier> = if roots.is_empty() {
        error!(
            "port {}: client certificate validation has no usable CA certificate; rejecting all client certificates",
            spec.port
        );
        Arc::new(RejectAllClientCerts { provider: Arc::new(provider) })
    } else {
        match rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(provider.clone()))
            .build()
        {
            Ok(v) => v,
            Err(e) => {
                error!("port {}: failed to build client certificate verifier ({e}); rejecting all client certificates", spec.port);
                Arc::new(RejectAllClientCerts { provider: Arc::new(provider) })
            }
        }
    };
    match spec.mode {
        ClientValidationMode::AllowValidOnly => strict,
        ClientValidationMode::AllowInsecureFallback => Arc::new(InsecureFallbackVerifier { inner: strict }),
    }
}

/// Build a `ServerConfig` that shares `resolver` (SNI certificate selection)
/// with the default HTTPS config but additionally requests and validates
/// client certificates with `verifier`.
pub(crate) fn build_client_auth_tls_config(
    resolver: Arc<ReloadableCertResolver>,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> ServerConfig {
    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_client_cert_verifier(verifier)
    .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// One `ServerConfig` per HTTPS listener port that validates client
/// certificates. Ports absent from the map use the default (no client auth).
pub(crate) fn build_port_configs(
    specs: &[PortClientValidation],
    resolver: &Arc<ReloadableCertResolver>,
) -> hashbrown::HashMap<u16, Arc<ServerConfig>> {
    specs
        .iter()
        .map(|spec| {
            let verifier = build_client_cert_verifier(spec);
            (spec.port, Arc::new(build_client_auth_tls_config(Arc::clone(resolver), verifier)))
        })
        .collect()
}

/// Per-port `ServerConfig` selection for Pingora's HTTPS endpoint.
///
/// The listener manager hands every HTTPS port's sockets to one Pingora
/// service, so client certificate policy cannot live in a single
/// `ServerConfig`. Pingora asks this chooser once the ClientHello is read; it
/// answers from the port the connection was accepted on. Swapped atomically by
/// the cert hot-reload thread; handshakes never block on it.
#[derive(Default)]
pub(crate) struct PortServerConfigs {
    by_port: ArcSwap<hashbrown::HashMap<u16, Arc<ServerConfig>>>,
}

impl PortServerConfigs {
    pub(crate) fn store(&self, configs: hashbrown::HashMap<u16, Arc<ServerConfig>>) {
        info!("client certificate validation active on {} HTTPS port(s)", configs.len());
        self.by_port.store(Arc::new(configs));
    }

    pub(crate) fn config_for_port(&self, port: u16) -> Option<Arc<ServerConfig>> {
        self.by_port.load().get(&port).cloned()
    }
}

impl pingora_core::listeners::tls::ServerConfigChooser for PortServerConfigs {
    fn choose(
        &self,
        local_addr: Option<&pingora_core::protocols::l4::socket::SocketAddr>,
        _client_hello: &rustls::server::ClientHello<'_>,
    ) -> Option<Arc<ServerConfig>> {
        let port = local_addr?.as_inet()?.port();
        self.config_for_port(port)
    }
}

/// Order-independent content hash of the per-port client validation policy.
pub(crate) fn client_validation_fingerprint(specs: &[PortClientValidation]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut fp: u64 = 0;
    for spec in specs {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        spec.hash(&mut h);
        fp = fp.wrapping_add(h.finish());
    }
    fp
}

// ---------------------------------------------------------------------------
// Self-signed bootstrap cert
// ---------------------------------------------------------------------------

/// Generate a self-signed TLS certificate for bootstrapping the HTTPS listener.
///
/// **Security note**: This certificate is only used as a placeholder until the
/// controller delivers a real certificate. While this cert is active, the
/// readiness probe returns 503 so that no load balancer or ingress will route
/// real traffic to this instance. The hot-reload thread replaces it as soon as
/// the controller pushes a valid cert.
///
/// Returns (cert_pem, key_pem) as strings.
pub(crate) fn generate_self_signed_cert() -> Result<(String, String), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    Ok((cert_pem, key_pem))
}

// ---------------------------------------------------------------------------
// TLS cert hot-reload from controller config stream
// ---------------------------------------------------------------------------

/// Order-independent content hash of a TLS entry set: hostname, certificate
/// and key bytes all participate, so any rotation changes it.
pub(crate) fn tls_entries_fingerprint(entries: &[crate::config_receiver::TlsCertEntry]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut fp: u64 = 0;
    for e in entries {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        e.hostname.hash(&mut h);
        e.cert_pem.hash(&mut h);
        e.key_pem.hash(&mut h);
        fp = fp.wrapping_add(h.finish());
    }
    fp
}

/// Start a background thread that polls `TlsCertSlot` for new certificates
/// pushed by the gRPC controller, and atomically swaps them into the
/// `ReloadableCertResolver`.
///
/// Supports multiple certificates for SNI-based selection. Each HTTPS listener
/// can have a different hostname and cert pair. The resolver selects the correct
/// cert based on the client's SNI during TLS handshake.
///
/// The thread:
/// 1. Waits on `notify` (woken by `apply_config` after it stores new PEM data);
///    also runs once at startup in case certs arrived before the thread did
/// 2. When new PEM data appears, parses and validates all cert entries
/// 3. On success, calls `resolver.swap_map()` — all new TLS handshakes
///    immediately use the new certs; existing connections are unaffected
/// 4. On failure for individual certs, logs an error but loads the valid ones
/// 5. Updates the `tls_cert_expiry_seconds` Prometheus metric (shortest expiry)
pub(crate) fn start_tls_cert_hot_reload(
    tls_cert: TlsCertSlot,
    notify: Arc<tokio::sync::Notify>,
    resolver: Arc<ReloadableCertResolver>,
    port_configs: Arc<PortServerConfigs>,
    metrics: Arc<ProxyMetrics>,
) {
    std::thread::spawn(move || {
        info!("TLS cert hot-reload thread started");
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                error!("TLS cert hot-reload: failed to build runtime: {e}; certs will not hot-reload");
                return;
            }
        };

        // Track fingerprint of all cert PEMs to detect changes.
        let mut last_fingerprint: Option<u64> = None;
        let mut first_pass = true;

        loop {
            if !first_pass {
                rt.block_on(notify.notified());
            }
            first_pass = false;

            let guard = tls_cert.load();
            let current = match &**guard {
                Some(data) => data,
                None => continue,
            };

            // Content fingerprint of every (hostname, cert, key). A rotated
            // certificate almost always has the same PEM length as the one it
            // replaces, so comparing lengths (the previous rule) silently kept
            // serving the old cert forever.
            let fingerprint = tls_entries_fingerprint(&current.entries)
                .wrapping_add(client_validation_fingerprint(&current.client_validation));

            if last_fingerprint == Some(fingerprint) {
                continue;
            }

            info!("TLS cert hot-reload: {} certificate(s) detected, validating...",
                current.entries.len());

            let mut entries = Vec::new();
            let mut shortest_expiry: Option<f64> = None;

            for entry in &current.entries {
                match load_certified_key_from_pem(&entry.cert_pem, &entry.key_pem) {
                    Ok(certified_key) => {
                        info!("TLS cert hot-reload: loaded cert for hostname='{}'",
                            entry.hostname);
                        if let Some(expiry) = read_cert_expiry_from_pem(&entry.cert_pem) {
                            shortest_expiry = Some(
                                shortest_expiry.map_or(expiry, |prev: f64| prev.min(expiry))
                            );
                        }
                        entries.push((entry.hostname.clone(), certified_key));
                    }
                    Err(e) => {
                        error!(
                            "TLS cert hot-reload: cert for hostname='{}' is INVALID, skipping. \
                             Error: {}",
                            entry.hostname, e
                        );
                    }
                }
            }

            if !entries.is_empty() {
                resolver.swap_map(entries);
                // Per-port client certificate policy shares the resolver, so it
                // is rebuilt whenever the certificate set or the policy changes.
                port_configs.store(build_port_configs(&current.client_validation, &resolver));
                last_fingerprint = Some(fingerprint);

                if let Some(expiry) = shortest_expiry {
                    metrics.tls_cert_expiry_seconds.set(expiry);
                    info!("TLS cert hot-reload: loaded {} cert(s), shortest expiry_ts={}",
                        current.entries.len(), expiry);
                }
            } else {
                error!("TLS cert hot-reload: ALL certificates invalid, keeping current certs");
            }
        }
    });
}

/// Read the expiry timestamp from a PEM certificate string.
/// Returns Unix epoch seconds, or None on parse failure.
fn read_cert_expiry_from_pem(cert_pem: &str) -> Option<f64> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    Some(cert.validity().not_after.timestamp() as f64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUO6iOI0P6T4JEa3FQbF3xvHBRaaswDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTgxNDUwMTlaFw0yNzAzMTgxNDUw
MTlaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC1ZLq3y+22Bhwkm9oK8LnsWVeGrKpoxILfB569DkJ7FITvTsRn18WZZh4P
Egl5crq/o87aYfM2Qx9Ow+iMt+HxOw9j/mpya7cLh2m8zXspv28xKYHbWEDYjjah
Jb1V4ucumfA6hEv+h99k+WzKnrgTg2m1rLv/gtOKu9VbR2Tjv5VA0yA8XLgdHpxr
tR26h14ezPa/9v4YczcD9sgtZCNFwZqYBY7prBR/GrtPBXxKpYq3Meo+vzxGqGlA
h6VxAIoY9BKZM1vdHCHjNnwU0kj3Lztquo88DTLHQyBmfGWrzQrs1vPzuAvD+Arf
XLCeld9H9UYUNYdWT3WfMyZJ07O1AgMBAAGjUzBRMB0GA1UdDgQWBBSPQb95r2Ly
25Qgqmb9qE3KZEODWjAfBgNVHSMEGDAWgBSPQb95r2Ly25Qgqmb9qE3KZEODWjAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8l2bP9UMApJdLrF1B
HXfrM941pdxYjtmNI/oJrQzT00umgOckh+oJC7cncJPYg0jdPg56MLI9MrcBcBaq
AsCstyeQ1rL6EuE/hQGqCR/PQl25ZX/rIRFnTGA30/q0zFeGBGOddTlFvK+uD5O3
EYsgsl7mnTSGpqEW83+tgklXbtwxnf+jOMbahymNvdMV7t1CHgkbx4nRRkEEkzms
fEN9hrnfkBWqXxcQsGe4v+TkTBA7Z28/DU+Op8+HJXJMKgbgKIVHFJhs4gxX2KyG
b7EKBEd98V2A0gT9iRJtX3yROCne72040GT/L58tqmK9AoFEdO63cyNQW7Q+SPX3
HkQ2
-----END CERTIFICATE-----
";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1ZLq3y+22Bhwk
m9oK8LnsWVeGrKpoxILfB569DkJ7FITvTsRn18WZZh4PEgl5crq/o87aYfM2Qx9O
w+iMt+HxOw9j/mpya7cLh2m8zXspv28xKYHbWEDYjjahJb1V4ucumfA6hEv+h99k
+WzKnrgTg2m1rLv/gtOKu9VbR2Tjv5VA0yA8XLgdHpxrtR26h14ezPa/9v4YczcD
9sgtZCNFwZqYBY7prBR/GrtPBXxKpYq3Meo+vzxGqGlAh6VxAIoY9BKZM1vdHCHj
NnwU0kj3Lztquo88DTLHQyBmfGWrzQrs1vPzuAvD+ArfXLCeld9H9UYUNYdWT3Wf
MyZJ07O1AgMBAAECggEAAopkLaWRGfKPairCG1Me6PoVjDPLFiHW1q7aXdzH5zpR
5CWe6m0OyYqZynNWIbnJAotnQdSuSUjpY0Dw1BEu5TlruPH+1DlvohGdMWz0zGHk
S0BA8Ljm5idllQbz1jLAkCuHm2AHKwBKi4awQx6ctTn8a3/O2qNkipAU7ez+szUo
37rLbUKFMZzLAx6m032E/NvO35M8h7/mNxGuM5H1HlQVEoh2+2UxkWFyQA8cdZJW
iaK4HSjaXF07cL6L5QATmgjablwh1H+aX8/PCm9IQZdlb6LK/4JmGfx64GwVSPgV
rvbfiTO09lAsSuHR3Gd4OTvk3/f+oEGbY4aUe4M0BQKBgQDaP21QBmSMcaiYssp/
74a1GLlEFKnPslW9W9UaoqBF4TBlc6fJFd6yUOpuEc4iH2f+hNM06sAGV+ffTTiG
KfCGnxwGtkjMtHe/EaljBmDL1nZ0Bkxe9Lxeo/yg1PLs4owzqs+kxB154KvTkYRV
rm+7LNMQmV8J8rCdZzhzcx//6wKBgQDUxUyxy80lHeM3v3M9Ov8batCcGTtAevAT
cCDRBL/4mBTV5IbuTl2VFVZ2C4XbIdCFIVyfgbgzcCVgMuaWMBMQznnG46WEj/dH
UguUaYBHxHQwP2z45aSBEmemIktpIMyWg+uvnKJ1vUEYGmvPYKd5es/7DTfI80mn
C6TL9s/S3wKBgQCsL2hVv4VqjG1gc4Zx4w7bJ7Na9BZ5J5Cfgakih3V9TEm7cMDK
U/fLpS0fQ+rmXvLUCgT79c0j9AyazziuGL6L51HcNco/vo3O7+c8mhaaGwx/Q0zT
ibBn1mcEmJ1DqQTF6phBvPwoYMoPc/n9A09hU979dJNXrOIMfRg7dXOkmwKBgQDA
9PTqwPKYWJR5OCygOOKl0KbDCbbMcTFLz4JTTEV0gydSGt+rOnJwA1vXzfdklTPv
qCPBm/ia3Xdn2IF5bru7oCScFFNE9vLAQU2zGEJ301ezcbG3vzsCutg4uB0/h7lC
Pvz808YZlLp1y3A+L19yMchv2rreiJQg49ReDMTIbQKBgAVFIvfRHcJGFUBFgib5
stultj5NYwHr8G7RaufGxIjSFBBMCcM1q065B0rIJUAj6rva964eBw4TttbirWcw
pIUuKXreNfPmDYPLcXSYucPu5RcSjRaZkwzic97AN+hP2ouXLtwJAQWyT9qqOJVa
mlMFuOUI1YNH4Hyldg8G3cWE
-----END PRIVATE KEY-----
";

    fn write_temp_file(name: &str, content: &str) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tls-test-{}-{}", name, std::process::id()));
        std::fs::write(&path, content).expect("failed to write temp file");
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_load_certified_key_valid() {
        let cert_path = write_temp_file("cert.pem", TEST_CERT_PEM);
        let key_path = write_temp_file("key.pem", TEST_KEY_PEM);
        let result = load_certified_key(&cert_path, &key_path);
        assert!(result.is_ok(), "should load valid cert+key: {:?}", result.err());
        let ck = result.unwrap();
        assert!(!ck.cert.is_empty(), "cert chain should not be empty");
    }

    #[test]
    fn test_load_certified_key_invalid_cert() {
        let cert_path = write_temp_file("bad-cert.pem", "not a real certificate");
        let key_path = write_temp_file("key-for-bad.pem", TEST_KEY_PEM);
        let result = load_certified_key(&cert_path, &key_path);
        assert!(result.is_err(), "should fail with invalid cert");
    }

    #[test]
    fn test_load_certified_key_missing_file() {
        let result = load_certified_key("/tmp/nonexistent-tls-cert-99999.pem", "/tmp/nonexistent-tls-key-99999.pem");
        assert!(result.is_err(), "should fail with missing files");
    }

    #[test]
    fn test_resolver_returns_cert() {
        let cert_path = write_temp_file("resolver-cert.pem", TEST_CERT_PEM);
        let key_path = write_temp_file("resolver-key.pem", TEST_KEY_PEM);
        let ck = load_certified_key(&cert_path, &key_path).unwrap();
        let resolver = ReloadableCertResolver::new(ck);
        let loaded = resolver.certified_key.load_full();
        assert!(!loaded.cert.is_empty(), "resolver should hold a cert");
    }

    #[test]
    fn test_resolver_swap_updates_cert() {
        let cert_path = write_temp_file("swap-cert.pem", TEST_CERT_PEM);
        let key_path = write_temp_file("swap-key.pem", TEST_KEY_PEM);

        let ck1 = load_certified_key(&cert_path, &key_path).unwrap();
        let ck2 = load_certified_key(&cert_path, &key_path).unwrap();

        let resolver = ReloadableCertResolver::new(ck1);
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        resolver.swap(ck2);
        let after = resolver.certified_key.load_full();
        let after_ptr = Arc::as_ptr(&after);

        assert_ne!(
            before_ptr, after_ptr,
            "swap should produce a different Arc pointer"
        );
    }

    #[test]
    fn test_build_reloadable_tls_config_has_alpn() {
        // ServerConfig::builder requires a crypto provider to be installed
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert_path = write_temp_file("config-cert.pem", TEST_CERT_PEM);
        let key_path = write_temp_file("config-key.pem", TEST_KEY_PEM);
        let ck = load_certified_key(&cert_path, &key_path).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(ck));
        let config = build_reloadable_tls_config(resolver);
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should be [h2, http/1.1]"
        );
    }

    #[test]
    fn test_load_certified_key_from_pem_valid() {
        let result = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM);
        assert!(result.is_ok(), "should load valid cert+key from PEM strings: {:?}", result.err());
        let ck = result.unwrap();
        assert!(!ck.cert.is_empty(), "cert chain should not be empty");
    }

    #[test]
    fn test_load_certified_key_from_pem_invalid_cert() {
        let result = load_certified_key_from_pem("not a real certificate", TEST_KEY_PEM);
        assert!(result.is_err(), "should fail with invalid cert PEM");
    }

    #[test]
    fn test_load_certified_key_from_pem_empty_cert() {
        let result = load_certified_key_from_pem("", TEST_KEY_PEM);
        assert!(result.is_err(), "should fail with empty cert PEM");
    }

    #[test]
    fn test_resolver_swap_with_pem_loaded_key() {
        let ck1 = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM).unwrap();
        let ck2 = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM).unwrap();

        let resolver = ReloadableCertResolver::new(ck1);
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        resolver.swap(ck2);
        let after = resolver.certified_key.load_full();
        let after_ptr = Arc::as_ptr(&after);

        assert_ne!(before_ptr, after_ptr, "swap should produce a different Arc pointer");
    }

    #[test]
    fn test_generate_self_signed_cert_produces_valid_pem() {
        let (cert_pem, key_pem) = generate_self_signed_cert()
            .expect("self-signed cert generation should not fail");
        // Must be loadable as a CertifiedKey
        let ck = load_certified_key_from_pem(&cert_pem, &key_pem)
            .expect("self-signed cert should produce valid CertifiedKey");
        assert!(!ck.cert.is_empty(), "self-signed cert chain should not be empty");
    }

    #[test]
    fn test_self_signed_cert_works_with_resolver() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        let ck = load_certified_key_from_pem(&cert_pem, &key_pem).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(ck));
        let config = build_reloadable_tls_config(resolver.clone());
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
        // Swap in a new self-signed cert
        let (cert2, key2) = generate_self_signed_cert().unwrap();
        let ck2 = load_certified_key_from_pem(&cert2, &key2).unwrap();
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);
        resolver.swap(ck2);
        let after = resolver.certified_key.load_full();
        assert_ne!(Arc::as_ptr(&after), before_ptr, "cert should be swapped");
    }

    #[test]
    fn test_read_cert_expiry_from_pem_returns_timestamp() {
        let expiry = read_cert_expiry_from_pem(TEST_CERT_PEM);
        assert!(expiry.is_some(), "should parse expiry from valid PEM");
        assert!(expiry.unwrap() > 0.0, "expiry should be a positive timestamp");
    }

    #[test]
    fn test_read_cert_expiry_from_pem_invalid() {
        let expiry = read_cert_expiry_from_pem("not a cert");
        assert!(expiry.is_none(), "should return None for invalid PEM");
    }

    /// Test the hot-reload loop directly by simulating the core logic
    /// without spawning a background thread (avoids ProxyMetrics registration
    /// conflicts with other test modules sharing the Prometheus global registry).
    #[test]
    fn test_hot_reload_swaps_cert_from_tls_cert_slot() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Create resolver with self-signed bootstrap cert
        let (boot_cert, boot_key) = generate_self_signed_cert().unwrap();
        let boot_ck = load_certified_key_from_pem(&boot_cert, &boot_key).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(boot_ck));
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        // Simulate what the hot-reload thread does: parse the cert and swap
        let certified_key = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM)
            .expect("test cert should be valid");
        resolver.swap(certified_key);

        let after = resolver.certified_key.load_full();
        let after_ptr = Arc::as_ptr(&after);

        assert_ne!(
            before_ptr, after_ptr,
            "hot-reload swap should have replaced the cert"
        );
        assert!(!after.cert.is_empty(), "new cert should not be empty");
    }

    #[test]
    fn test_hot_reload_ignores_invalid_cert() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Create resolver with a valid cert
        let ck = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(ck));
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        // Simulate what the hot-reload thread does with an invalid cert
        let result = load_certified_key_from_pem("not a real cert", "not a real key");
        assert!(result.is_err(), "invalid PEM should fail validation");

        // Since validation failed, swap is never called — cert is unchanged
        let after = resolver.certified_key.load_full();
        let after_ptr = Arc::as_ptr(&after);

        assert_eq!(
            before_ptr, after_ptr,
            "resolver should still hold the original cert after invalid cert is rejected"
        );
    }

    /// Integration test: start the actual hot-reload thread and verify it
    /// picks up cert changes from the TlsCertSlot.
    #[test]
    fn test_hot_reload_thread_integration() {
        use crate::config_receiver::{TlsCertData, TlsCertEntry};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Use catch_unwind for ProxyMetrics to handle Prometheus global
        // registry conflicts when running the full test suite.
        let metrics = match std::panic::catch_unwind(crate::metrics::ProxyMetrics::new) {
            Ok(m) => Arc::new(m),
            Err(_) => {
                // Metrics already registered by another test — skip this
                // integration test. The unit tests above cover the logic.
                eprintln!(
                    "skipping hot-reload thread integration test \
                     (Prometheus metrics already registered)"
                );
                return;
            }
        };

        let (boot_cert, boot_key) = generate_self_signed_cert().unwrap();
        let boot_ck = load_certified_key_from_pem(&boot_cert, &boot_key).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(boot_ck));
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        let tls_cert: TlsCertSlot = Arc::new(ArcSwap::from_pointee(Some(TlsCertData {
            entries: vec![TlsCertEntry {
                hostname: String::new(),
                cert_pem: TEST_CERT_PEM.to_string(),
                key_pem: TEST_KEY_PEM.to_string(),
            }],
            client_validation: Vec::new(),
        })));

        let notify = Arc::new(tokio::sync::Notify::new());
        start_tls_cert_hot_reload(
            tls_cert,
            notify.clone(),
            resolver.clone(),
            Arc::new(PortServerConfigs::default()),
            metrics,
        );

        // The thread processes whatever is in the slot on its first pass; a
        // notification must also be harmless when nothing changed.
        notify.notify_one();
        std::thread::sleep(Duration::from_millis(500));

        let after = resolver.certified_key.load_full();
        assert_ne!(
            Arc::as_ptr(&after),
            before_ptr,
            "hot-reload thread should have swapped in the new cert"
        );
    }

    #[test]
    fn test_server_config_with_resolver_swap() {
        // Verify that a ServerConfig built with our resolver allows cert swap.
        // Pingora internally wraps this in a TlsAcceptor via
        // TlsAcceptor::from(Arc<ServerConfig>); the resolver's ArcSwap is
        // what makes new handshakes pick up swapped certs.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ck = load_certified_key_from_pem(TEST_CERT_PEM, TEST_KEY_PEM).unwrap();
        let resolver = Arc::new(ReloadableCertResolver::new(ck));
        let config = build_reloadable_tls_config(resolver.clone());

        // Verify ServerConfig has correct ALPN
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );

        // Swap in a new cert
        let (cert2, key2) = generate_self_signed_cert().unwrap();
        let ck2 = load_certified_key_from_pem(&cert2, &key2).unwrap();
        let before = resolver.certified_key.load_full();
        let before_ptr = Arc::as_ptr(&before);
        drop(before);

        resolver.swap(ck2);
        let after = resolver.certified_key.load_full();
        assert_ne!(Arc::as_ptr(&after), before_ptr, "cert should be swapped");
        assert!(!after.cert.is_empty());
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::config_receiver::TlsCertEntry;

    fn entry(host: &str, cert: &str, key: &str) -> TlsCertEntry {
        TlsCertEntry {
            hostname: host.to_string(),
            cert_pem: cert.to_string(),
            key_pem: key.to_string(),
        }
    }

    #[test]
    fn rotated_cert_of_identical_length_changes_the_fingerprint() {
        let a = [entry("", "-----CERT-A-----", "-----KEY-A-----")];
        let b = [entry("", "-----CERT-B-----", "-----KEY-A-----")];
        assert_eq!(a[0].cert_pem.len(), b[0].cert_pem.len(), "same length by construction");
        assert_ne!(tls_entries_fingerprint(&a), tls_entries_fingerprint(&b));
        // Same content, any order => same fingerprint.
        let two = [entry("x", "c1", "k1"), entry("y", "c2", "k2")];
        let two_rev = [entry("y", "c2", "k2"), entry("x", "c1", "k1")];
        assert_eq!(tls_entries_fingerprint(&two), tls_entries_fingerprint(&two_rev));
        assert_eq!(tls_entries_fingerprint(&[]), 0);
    }


    // -----------------------------------------------------------------------
    // Frontend client certificate validation
    // -----------------------------------------------------------------------

    /// A CA plus one leaf it signed: (ca_pem, leaf_cert_pem, leaf_key_pem).
    fn ca_signed_pair(cn: &str, client_auth: bool) -> (String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, format!("{cn} CA"));
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut leaf = CertificateParams::new(vec![cn.to_string()]).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, cn.to_string());
        leaf.extended_key_usages = vec![if client_auth {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        (ca_pem, leaf_cert.pem(), leaf_key.serialize_pem())
    }

    fn spec(port: u16, ca_pems: Vec<String>, mode: ClientValidationMode) -> PortClientValidation {
        PortClientValidation { port, ca_cert_pems: ca_pems, mode }
    }

    /// Run a full TLS handshake over an in-memory pipe. Returns the server
    /// side's view: `Ok(client_presented_certificate)` or the handshake error.
    fn handshake(
        server_config: Arc<ServerConfig>,
        server_ca_pem: &str,
        client_cert: Option<(&str, &str)>,
    ) -> Result<bool, String> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut server_ca_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let client_config = match client_cert {
            Some((cert_pem, key_pem)) => {
                let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes()).map(|c| c.unwrap()).collect();
                let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap().unwrap();
                builder.with_client_auth_cert(certs, key).unwrap()
            }
            None => builder.with_no_client_auth(),
        };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            // The client must outlive the server's post-handshake writes
            // (session tickets), or the server sees a broken pipe instead of
            // the verifier's verdict.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let result = async {
                    let mut s = acceptor.accept(server_io).await.map_err(|e| e.to_string())?;
                    let mut buf = [0u8; 1];
                    tokio::io::AsyncReadExt::read_exact(&mut s, &mut buf).await.map_err(|e| e.to_string())?;
                    Ok::<bool, String>(s.get_ref().1.peer_certificates().is_some())
                }
                .await;
                let _ = done_tx.send(());
                result
            });
            let client = tokio::spawn(async move {
                let mut c = connector.connect(name, client_io).await.map_err(|e| e.to_string())?;
                tokio::io::AsyncWriteExt::write_all(&mut c, b"x").await.map_err(|e| e.to_string())?;
                let _ = done_rx.await;
                Ok::<(), String>(())
            });
            let (server_res, client_res) = tokio::join!(server, client);
            match (server_res.unwrap(), client_res.unwrap()) {
                (Ok(saw_cert), _) => Ok(saw_cert),
                (Err(s), Err(c)) => Err(format!("server: {s}; client: {c}")),
                (Err(s), Ok(())) => Err(format!("server: {s}")),
            }
        })
    }

    struct Fixture {
        server_ca: String,
        resolver: Arc<ReloadableCertResolver>,
        client_ca: String,
        client_cert: String,
        client_key: String,
        other_ca: String,
        other_cert: String,
        other_key: String,
    }

    fn fixture() -> Fixture {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (server_ca, server_cert, server_key) = ca_signed_pair("localhost", false);
        let resolver = Arc::new(ReloadableCertResolver::new(
            load_certified_key_from_pem(&server_cert, &server_key).unwrap(),
        ));
        let (client_ca, client_cert, client_key) = ca_signed_pair("client", true);
        let (other_ca, other_cert, other_key) = ca_signed_pair("per-port-client", true);
        Fixture { server_ca, resolver, client_ca, client_cert, client_key, other_ca, other_cert, other_key }
    }

    #[test]
    fn strict_client_validation_accepts_only_certificates_from_the_configured_ca() {
        let f = fixture();
        let cfg = Arc::new(build_client_auth_tls_config(
            Arc::clone(&f.resolver),
            build_client_cert_verifier(&spec(443, vec![f.client_ca.clone()], ClientValidationMode::AllowValidOnly)),
        ));

        assert_eq!(handshake(cfg.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))), Ok(true));
        let other = handshake(cfg.clone(), &f.server_ca, Some((&f.other_cert, &f.other_key)));
        assert!(other.is_err(), "certificate from another CA must be rejected: {other:?}");
        let none = handshake(cfg, &f.server_ca, None);
        assert!(none.is_err(), "missing certificate must be rejected: {none:?}");
    }

    #[test]
    fn insecure_fallback_accepts_valid_invalid_and_missing_client_certificates() {
        let f = fixture();
        let cfg = Arc::new(build_client_auth_tls_config(
            Arc::clone(&f.resolver),
            build_client_cert_verifier(&spec(443, vec![f.client_ca.clone()], ClientValidationMode::AllowInsecureFallback)),
        ));

        // Valid: accepted and the certificate is visible to the server.
        assert_eq!(handshake(cfg.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))), Ok(true));
        // Wrong CA: still accepted (the certificate is still presented).
        assert_eq!(handshake(cfg.clone(), &f.server_ca, Some((&f.other_cert, &f.other_key))), Ok(true));
        // No certificate: accepted.
        assert_eq!(handshake(cfg, &f.server_ca, None), Ok(false));
    }

    #[test]
    fn default_config_without_client_validation_never_asks_for_a_certificate() {
        let f = fixture();
        let cfg = Arc::new(build_reloadable_tls_config(Arc::clone(&f.resolver)));
        // A client willing to present a certificate is never asked for one.
        assert_eq!(handshake(cfg.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))), Ok(false));
        assert_eq!(handshake(cfg, &f.server_ca, None), Ok(false));
    }

    #[test]
    fn unusable_ca_bundle_fails_closed() {
        let f = fixture();
        let cfg = Arc::new(build_client_auth_tls_config(
            Arc::clone(&f.resolver),
            build_client_cert_verifier(&spec(443, vec!["not a pem".to_string()], ClientValidationMode::AllowValidOnly)),
        ));
        assert!(handshake(cfg.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))).is_err());
        assert!(handshake(cfg, &f.server_ca, None).is_err());
    }

    #[test]
    fn port_server_configs_pick_by_local_port() {
        use pingora_core::listeners::tls::ServerConfigChooser;
        use pingora_core::protocols::l4::socket::SocketAddr;
        let f = fixture();
        let specs = vec![
            spec(443, vec![f.client_ca.clone()], ClientValidationMode::AllowValidOnly),
            spec(8443, vec![f.other_ca.clone()], ClientValidationMode::AllowValidOnly),
        ];
        let configs = build_port_configs(&specs, &f.resolver);
        assert_eq!(configs.len(), 2);
        let chooser = PortServerConfigs::default();
        chooser.store(configs);

        let cfg_443 = chooser.config_for_port(443).expect("443 configured");
        let cfg_8443 = chooser.config_for_port(8443).expect("8443 configured");
        assert!(!Arc::ptr_eq(&cfg_443, &cfg_8443));
        assert!(chooser.config_for_port(9443).is_none(), "ports without validation use the default config");

        // The per-port configs enforce their own CA: the 443 client is rejected on 8443.
        assert_eq!(handshake(cfg_443.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))), Ok(true));
        assert!(handshake(cfg_8443.clone(), &f.server_ca, Some((&f.client_cert, &f.client_key))).is_err());
        assert_eq!(handshake(cfg_8443, &f.server_ca, Some((&f.other_cert, &f.other_key))), Ok(true));

        // Chooser plumbing: local address → port → config. Exercise the trait
        // through a real ClientHello read by rustls's lazy acceptor.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let chosen = rt.block_on(async {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let mut roots = rustls::RootCertStore::empty();
            for c in rustls_pemfile::certs(&mut f.server_ca.as_bytes()) {
                roots.add(c.unwrap()).unwrap();
            }
            let client_config = Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let client = tokio::spawn(async move {
                let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
                let _ = connector.connect(name, client_io).await;
            });
            let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_io)
                .await
                .unwrap();
            let hello = start.client_hello();
            let addr_8443 = SocketAddr::Inet("127.0.0.1:8443".parse().unwrap());
            let addr_9443 = SocketAddr::Inet("127.0.0.1:9443".parse().unwrap());
            let picked = chooser.choose(Some(&addr_8443), &hello).map(|c| Arc::ptr_eq(&c, &cfg_443));
            let none_for_unknown_port = chooser.choose(Some(&addr_9443), &hello).is_none();
            let none_without_addr = chooser.choose(None, &hello).is_none();
            drop(start);
            client.abort();
            (picked, none_for_unknown_port, none_without_addr)
        });
        assert_eq!(chosen.0, Some(false), "8443 must get its own config, not 443's");
        assert!(chosen.1 && chosen.2);
    }

    #[test]
    fn client_validation_fingerprint_tracks_mode_ca_and_port() {
        let base = vec![spec(443, vec!["A".to_string()], ClientValidationMode::AllowValidOnly)];
        let same_other_order = vec![
            spec(8443, vec!["B".to_string()], ClientValidationMode::AllowValidOnly),
            spec(443, vec!["A".to_string()], ClientValidationMode::AllowValidOnly),
        ];
        let two = vec![
            spec(443, vec!["A".to_string()], ClientValidationMode::AllowValidOnly),
            spec(8443, vec!["B".to_string()], ClientValidationMode::AllowValidOnly),
        ];
        assert_eq!(client_validation_fingerprint(&two), client_validation_fingerprint(&same_other_order));
        assert_ne!(client_validation_fingerprint(&base), client_validation_fingerprint(&two));
        let mode = vec![spec(443, vec!["A".to_string()], ClientValidationMode::AllowInsecureFallback)];
        assert_ne!(client_validation_fingerprint(&base), client_validation_fingerprint(&mode));
        let ca = vec![spec(443, vec!["C".to_string()], ClientValidationMode::AllowValidOnly)];
        assert_ne!(client_validation_fingerprint(&base), client_validation_fingerprint(&ca));
        assert_eq!(client_validation_fingerprint(&[]), 0);
    }
}
