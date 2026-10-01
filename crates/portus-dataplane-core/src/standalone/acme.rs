//! ACME certificates for standalone HTTPS listeners.
//!
//! A listener with `tls: { acme: {} }` gets one certificate per domain from an
//! ACME CA (Let's Encrypt by default), proven over HTTP-01 or TLS-ALPN-01 on
//! the proxy's own listeners ([`crate::acme_challenge`]). Certificates and the
//! account key are cached on disk so a restart re-issues nothing; each is
//! renewed two thirds of the way through its lifetime and swapped in through
//! the ordinary config reload. Until a domain's first certificate arrives the
//! listener serves a self-signed placeholder, so it binds at once.
//!
//! Kubernetes users get certificates from cert-manager; this client only runs
//! in standalone mode.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use log::{info, warn};
use serde::Deserialize;

use super::YamlListener;
use crate::acme_challenge;

/// How the CA validates control of a domain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum Challenge {
    /// A token served on a plain HTTP listener (port 80 for a public CA).
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// A certificate presented in the TLS handshake of the HTTPS listener
    /// (port 443 for a public CA); needs no plain HTTP listener.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// Top-level `acme:` block: the account and CA every ACME listener uses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    /// Contact address registered with the account.
    #[serde(default)]
    pub email: Option<String>,
    /// `letsencrypt`, `letsencrypt-staging`, or an ACME directory URL.
    #[serde(default = "default_directory")]
    pub directory: String,
    /// PEM bundle that verifies the directory's TLS certificate, for a private
    /// CA (Pebble, step-ca); the system trust store otherwise.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Where the account key and certificates are kept, one subdirectory per
    /// ACME directory.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    #[serde(default)]
    pub challenge: Challenge,
}

fn default_directory() -> String {
    "letsencrypt".to_string()
}

fn default_cache_dir() -> String {
    "/var/lib/portus/acme".to_string()
}

impl Default for AcmeSettings {
    fn default() -> Self {
        Self {
            email: None,
            directory: default_directory(),
            ca_file: None,
            cache_dir: default_cache_dir(),
            challenge: Challenge::default(),
        }
    }
}

impl AcmeSettings {
    pub fn directory_url(&self) -> &str {
        match self.directory.as_str() {
            "letsencrypt" => LetsEncrypt::Production.url(),
            "letsencrypt-staging" => LetsEncrypt::Staging.url(),
            url => url,
        }
    }
}

/// `tls.acme` on a listener.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerAcme {
    /// Domains to obtain certificates for. Defaults to the listener's
    /// hostname, else every exact host its routes name.
    #[serde(default)]
    pub domains: Vec<String>,
}

/// The ACME work one config asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmePlan {
    pub settings: AcmeSettings,
    pub domains: BTreeSet<String>,
}

/// The domains an ACME listener needs certificates for, in order, validated.
pub fn listener_domains(listener: &YamlListener, acme: &ListenerAcme) -> Result<Vec<String>, String> {
    let port = listener.port;
    if !listener.protocol.eq_ignore_ascii_case("HTTPS") {
        return Err(format!("listener on port {port}: tls.acme needs protocol HTTPS, not {}", listener.protocol));
    }
    let candidates: Vec<String> = if !acme.domains.is_empty() {
        acme.domains.clone()
    } else if let Some(hostname) = &listener.hostname {
        vec![hostname.clone()]
    } else {
        listener
            .routes
            .iter()
            .flat_map(|r| &r.hosts)
            .filter(|h| *h != "*" && !h.starts_with("*."))
            .cloned()
            .collect()
    };
    let mut domains: Vec<String> = Vec::new();
    for domain in candidates {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        validate_domain(&domain).map_err(|e| format!("listener on port {port}: ACME domain '{domain}' {e}"))?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    if domains.is_empty() {
        return Err(format!(
            "listener on port {port}: tls.acme has no domains; set tls.acme.domains, the listener hostname, \
             or exact route hosts"
        ));
    }
    Ok(domains)
}

fn validate_domain(domain: &str) -> Result<(), &'static str> {
    if domain.starts_with("*.") {
        return Err("is a wildcard; HTTP-01 and TLS-ALPN-01 cannot issue wildcards");
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err("is an IP address; only DNS names are supported");
    }
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if domain.len() > 253 || !domain.contains('.') || !domain.split('.').all(valid_label) {
        return Err("is not a valid DNS name");
    }
    Ok(())
}

/// HTTP-01 is answered on plain HTTP listeners only: refuse a config that has
/// none rather than let every order fail validation.
pub fn check_challenge_reachable(config: &super::StandaloneConfig, plan: Option<&AcmePlan>) -> Result<(), String> {
    let Some(plan) = plan else { return Ok(()) };
    if plan.settings.challenge == Challenge::Http01
        && !config.listeners.iter().any(|l| l.protocol.eq_ignore_ascii_case("HTTP"))
    {
        return Err("ACME http-01 needs a plain HTTP listener (port 80 for a public CA) to answer on; \
                    add one or set acme.challenge: tls-alpn-01"
            .to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate cache
// ---------------------------------------------------------------------------

/// The on-disk cache for one ACME directory:
/// `<cache_dir>/<directory host>-<hash>/{account.json, <domain>/certificate.pem}`.
/// `certificate.pem` holds the private key and the chain together, so one
/// rename replaces both and a crash never leaves a mismatched pair.
struct Store {
    dir: PathBuf,
}

impl Store {
    fn new(settings: &AcmeSettings) -> Self {
        use sha2::{Digest, Sha256};
        let url = settings.directory_url();
        let host: String = url
            .split("://")
            .nth(1)
            .unwrap_or(url)
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .collect();
        let digest = Sha256::digest(url.as_bytes());
        let hash: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
        Self { dir: Path::new(&settings.cache_dir).join(format!("{host}-{hash}")) }
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    fn cert_path(&self, domain: &str) -> PathBuf {
        self.dir.join(domain).join("certificate.pem")
    }

    /// `(chain PEM, key PEM)` for `domain`, if a parseable one is cached.
    fn load(&self, domain: &str) -> Option<(String, String)> {
        let bundle = std::fs::read_to_string(self.cert_path(domain)).ok()?;
        split_bundle(&bundle)
    }

    fn save(&self, domain: &str, chain_pem: &str, key_pem: &str) -> Result<(), String> {
        write_private(&self.cert_path(domain), &format!("{key_pem}{chain_pem}"))
    }
}

/// Write `contents` to `path` readable by the owner only, atomically.
fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| format!("no parent directory for '{}'", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create '{}': {e}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp).map_err(|e| format!("failed to write '{}': {e}", tmp.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("failed to write '{}': {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("failed to replace '{}': {e}", path.display()))
}

/// Split a cached bundle into `(chain PEM, key PEM)`.
fn split_bundle(bundle: &str) -> Option<(String, String)> {
    let mut chain = String::new();
    let mut key = String::new();
    for item in pem_blocks(bundle) {
        if item.contains("PRIVATE KEY-----") {
            key.push_str(item);
        } else if item.starts_with("-----BEGIN CERTIFICATE-----") {
            chain.push_str(item);
        }
    }
    (!chain.is_empty() && !key.is_empty()).then_some((chain, key))
}

/// Each `-----BEGIN ...----- ... -----END ...-----` block, newline-terminated.
fn pem_blocks(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let start = rest.find("-----BEGIN ")?;
        let end_marker = rest[start..].find("-----END ")? + start;
        let close = rest[end_marker + 9..].find("-----")? + end_marker + 9 + 5;
        let end = rest[close..].find('\n').map_or(rest.len(), |n| close + n + 1);
        let block = &rest[start..end];
        rest = &rest[end..];
        Some(block)
    })
}

/// Self-signed placeholders, one per domain for the life of the process, so
/// reloads before the first issuance keep serving the same certificate.
static PLACEHOLDERS: LazyLock<Mutex<HashMap<String, (String, String)>>> = LazyLock::new(Default::default);

/// The certificate to serve for `domain` now: the cached ACME certificate,
/// else a self-signed placeholder until the first one is issued.
pub fn current_cert(settings: &AcmeSettings, domain: &str) -> Result<(String, String), String> {
    if let Some(cached) = Store::new(settings).load(domain) {
        return Ok(cached);
    }
    let mut placeholders = PLACEHOLDERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = placeholders.get(domain) {
        return Ok(p.clone());
    }
    let generated = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .map_err(|e| format!("failed to generate placeholder certificate for '{domain}': {e}"))?;
    let pair = (generated.cert.pem(), generated.signing_key.serialize_pem());
    placeholders.insert(domain.to_string(), pair.clone());
    Ok(pair)
}

/// When the leaf certificate in `chain_pem` is due for renewal: two thirds of
/// the way from notBefore to notAfter (day 60 of a 90-day certificate, day 4
/// of a 6-day one).
fn renew_at(chain_pem: &str) -> Option<SystemTime> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    let not_before = u64::try_from(cert.validity().not_before.timestamp()).ok()?;
    let not_after = u64::try_from(cert.validity().not_after.timestamp()).ok()?;
    let lifetime = not_after.checked_sub(not_before)?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(not_before + lifetime * 2 / 3))
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// First retry after a failed order; doubles per failure up to the cap. Let's
/// Encrypt allows five failed validations per hostname per hour.
const RETRY_FIRST: Duration = Duration::from_secs(5 * 60);
const RETRY_MAX: Duration = Duration::from_secs(4 * 60 * 60);
/// Longest sleep between checks with nothing due (catches a cache emptied by hand).
const IDLE_CHECK: Duration = Duration::from_secs(60 * 60);

/// Runs the ACME client on its own thread and follows config changes.
pub struct Manager {
    plan: tokio::sync::watch::Sender<Option<AcmePlan>>,
}

impl Manager {
    /// Start the client. `issued` is called after a new certificate lands in
    /// the cache; the caller recompiles the config to serve it.
    pub fn start(issued: impl Fn() + Send + 'static) -> Result<Self, String> {
        let (plan, rx) = tokio::sync::watch::channel(None);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build the ACME runtime: {e}"))?;
        std::thread::Builder::new()
            .name("acme".to_string())
            .spawn(move || runtime.block_on(manage(rx, issued)))
            .map_err(|e| format!("failed to start the ACME thread: {e}"))?;
        Ok(Self { plan })
    }

    /// Hand the client the plan from the latest config (`None`: no ACME listeners).
    pub fn update(&self, plan: Option<AcmePlan>) {
        self.plan.send_if_modified(|current| {
            let changed = *current != plan;
            *current = plan;
            changed
        });
    }
}

async fn manage(mut plan_rx: tokio::sync::watch::Receiver<Option<AcmePlan>>, issued: impl Fn()) {
    let mut account: Option<(AcmeSettings, Account)> = None;
    // Per-domain retry state after a failure: (not before, next delay).
    let mut retry: HashMap<String, (SystemTime, Duration)> = HashMap::new();
    loop {
        let plan = plan_rx.borrow_and_update().clone();
        let mut next_check = SystemTime::now() + IDLE_CHECK;
        if let Some(plan) = plan {
            let store = Store::new(&plan.settings);
            retry.retain(|domain, _| plan.domains.contains(domain));
            for domain in &plan.domains {
                let now = SystemTime::now();
                let due = store.load(domain).and_then(|(chain, _)| renew_at(&chain)).unwrap_or(now);
                let not_before = retry.get(domain).map_or(due, |(at, _)| due.max(*at));
                if not_before > now {
                    next_check = next_check.min(not_before);
                    continue;
                }
                match issue_one(&plan.settings, &store, &mut account, domain).await {
                    Ok(()) => {
                        retry.remove(domain);
                        issued();
                    }
                    Err(e) => {
                        let delay = retry.get(domain).map_or(RETRY_FIRST, |(_, d)| (*d * 2).min(RETRY_MAX));
                        warn!("ACME: certificate for '{domain}' failed: {e}; retrying in {}s", delay.as_secs());
                        let at = SystemTime::now() + delay;
                        retry.insert(domain.clone(), (at, delay));
                        next_check = next_check.min(at);
                    }
                }
            }
        }
        let sleep = next_check.duration_since(SystemTime::now()).unwrap_or_default();
        tokio::select! {
            changed = plan_rx.changed() => if changed.is_err() { return },
            () = tokio::time::sleep(sleep) => {}
        }
    }
}

async fn issue_one(
    settings: &AcmeSettings,
    store: &Store,
    account: &mut Option<(AcmeSettings, Account)>,
    domain: &str,
) -> Result<(), String> {
    if account.as_ref().is_none_or(|(s, _)| s != settings) {
        *account = Some((settings.clone(), load_or_create_account(settings, store).await?));
    }
    let Some((_, acct)) = account.as_ref() else { return Err("no ACME account".to_string()) };
    info!("ACME: ordering a certificate for '{domain}' from {}", settings.directory_url());
    let (chain, key) = order(acct, settings.challenge, domain).await?;
    store.save(domain, &chain, &key)?;
    info!("ACME: certificate for '{domain}' issued; next renewal around {:?}", renew_at(&chain));
    Ok(())
}

async fn load_or_create_account(settings: &AcmeSettings, store: &Store) -> Result<Account, String> {
    let builder = || match &settings.ca_file {
        Some(ca) => Account::builder_with_root(ca).map_err(|e| format!("failed to load ACME ca_file '{ca}': {e}")),
        None => Account::builder().map_err(|e| format!("failed to build the ACME client: {e}")),
    };
    let path = store.account_path();
    if let Ok(json) = std::fs::read_to_string(&path) {
        let credentials: AccountCredentials = serde_json::from_str(&json)
            .map_err(|e| format!("failed to parse ACME account '{}': {e}", path.display()))?;
        return builder()?
            .from_credentials(credentials)
            .await
            .map_err(|e| format!("failed to load ACME account '{}': {e}", path.display()));
    }
    let contact = settings.email.as_ref().map(|e| format!("mailto:{e}"));
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = builder()?
        .create(
            &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
            settings.directory_url().to_string(),
            None,
        )
        .await
        .map_err(|e| format!("failed to register an ACME account with {}: {e}", settings.directory_url()))?;
    let json = serde_json::to_string(&credentials).map_err(|e| format!("failed to serialize the ACME account: {e}"))?;
    write_private(&path, &json)?;
    info!("ACME: registered account {} with {}", account.id(), settings.directory_url());
    Ok(account)
}

/// Removes this order's challenge responses however the order ends.
struct Responders {
    http01: Vec<String>,
    tls_alpn01: Vec<String>,
}

impl Drop for Responders {
    fn drop(&mut self) {
        self.http01.iter().for_each(|t| acme_challenge::clear_http01(t));
        self.tls_alpn01.iter().for_each(|d| acme_challenge::clear_tls_alpn01(d));
    }
}

/// One order for `domain`: answer its challenge, finalize with a fresh
/// ECDSA P-256 key, and return `(chain PEM, key PEM)`.
async fn order(account: &Account, challenge: Challenge, domain: &str) -> Result<(String, String), String> {
    let identifiers = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("new order: {e}"))?;
    let mut responders = Responders { http01: Vec::new(), tls_alpn01: Vec::new() };
    {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(|e| format!("authorization: {e}"))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(format!("authorization is {other:?}")),
            }
            let kind = match challenge {
                Challenge::Http01 => ChallengeType::Http01,
                Challenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
            };
            let mut ch = authz
                .challenge(kind.clone())
                .ok_or_else(|| format!("the CA offered no {kind:?} challenge"))?;
            let key_authorization = ch.key_authorization();
            match challenge {
                Challenge::Http01 => {
                    acme_challenge::set_http01(&ch.token, key_authorization.as_str());
                    responders.http01.push(ch.token.clone());
                }
                Challenge::TlsAlpn01 => {
                    let cert = tls_alpn01_certificate(domain, key_authorization.digest().as_ref())?;
                    acme_challenge::set_tls_alpn01(domain, cert);
                    responders.tls_alpn01.push(domain.to_string());
                }
            }
            ch.set_ready().await.map_err(|e| format!("challenge ready: {e}"))?;
        }
    }
    let retries = RetryPolicy::new().timeout(Duration::from_secs(120));
    let status = order.poll_ready(&retries).await.map_err(|e| format!("waiting for validation: {e}"))?;
    drop(responders);
    if status != OrderStatus::Ready {
        let problem = order.state().error.as_ref().map(|p| format!(": {p}")).unwrap_or_default();
        return Err(format!("order is {status:?}{problem}"));
    }
    let key = rcgen::KeyPair::generate().map_err(|e| format!("key generation: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| format!("CSR: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).map_err(|e| format!("CSR: {e}"))?;
    order.finalize_csr(csr.der()).await.map_err(|e| format!("finalize: {e}"))?;
    let chain = order.poll_certificate(&retries).await.map_err(|e| format!("certificate download: {e}"))?;
    Ok((chain, key.serialize_pem()))
}

/// The self-signed certificate a TLS-ALPN-01 validation expects (RFC 8737
/// §3): the domain as its only SAN and the key authorization's SHA-256 in a
/// critical acmeIdentifier extension.
fn tls_alpn01_certificate(domain: &str, digest: &[u8]) -> Result<rustls::sign::CertifiedKey, String> {
    let key = rcgen::KeyPair::generate().map_err(|e| format!("challenge key: {e}"))?;
    let mut params =
        rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| format!("challenge certificate: {e}"))?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let cert = params.self_signed(&key).map_err(|e| format!("challenge certificate: {e}"))?;
    crate::tls::load_certified_key_from_pem(&cert.pem(), &key.serialize_pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(yaml: &str) -> YamlListener {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn domains_come_from_tls_acme_first() {
        let l = listener("port: 443\nprotocol: HTTPS\nhostname: a.example.com\ntls: {acme: {domains: [B.Example.com., c.example.com, b.example.com]}}\n");
        let acme = l.tls.as_ref().unwrap().acme.clone().unwrap();
        assert_eq!(listener_domains(&l, &acme).unwrap(), vec!["b.example.com", "c.example.com"]);
    }

    #[test]
    fn domains_default_to_the_listener_hostname() {
        let l = listener("port: 443\nprotocol: HTTPS\nhostname: a.example.com\ntls: {acme: {}}\nroutes: [{hosts: [x.example.com]}]\n");
        assert_eq!(listener_domains(&l, &ListenerAcme::default()).unwrap(), vec!["a.example.com"]);
    }

    #[test]
    fn domains_default_to_exact_route_hosts() {
        let l = listener(
            "port: 443\nprotocol: HTTPS\ntls: {acme: {}}\nroutes: [{hosts: [x.example.com, '*.example.com', '*']}, {hosts: [y.example.com, x.example.com]}]\n",
        );
        assert_eq!(listener_domains(&l, &ListenerAcme::default()).unwrap(), vec!["x.example.com", "y.example.com"]);
    }

    #[test]
    fn domains_reject_wildcards_ips_and_garbage() {
        for bad in ["*.example.com", "10.0.0.1", "localhost", "a..example.com", "-a.example.com", "a_b.example.com"] {
            let l = listener(&format!("port: 443\nprotocol: HTTPS\ntls: {{acme: {{domains: ['{bad}']}}}}\n"));
            let acme = l.tls.as_ref().unwrap().acme.clone().unwrap();
            assert!(listener_domains(&l, &acme).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn domains_need_https_and_at_least_one_name() {
        let http = listener("port: 80\nprotocol: HTTP\nhostname: a.example.com\n");
        assert!(listener_domains(&http, &ListenerAcme::default()).unwrap_err().contains("protocol HTTPS"));
        let none = listener("port: 443\nprotocol: HTTPS\nroutes: [{hosts: ['*']}]\n");
        assert!(listener_domains(&none, &ListenerAcme::default()).unwrap_err().contains("no domains"));
    }

    #[test]
    fn settings_reject_unknown_fields_and_name_the_directories() {
        assert!(serde_yaml_ng::from_str::<AcmeSettings>("emial: a@b.c\n").is_err());
        let s: AcmeSettings = serde_yaml_ng::from_str("directory: letsencrypt-staging\n").unwrap();
        assert_eq!(s.directory_url(), LetsEncrypt::Staging.url());
        assert_eq!(AcmeSettings::default().directory_url(), LetsEncrypt::Production.url());
        let s: AcmeSettings = serde_yaml_ng::from_str("directory: https://localhost:14000/dir\nchallenge: tls-alpn-01\n").unwrap();
        assert_eq!(s.directory_url(), "https://localhost:14000/dir");
        assert_eq!(s.challenge, Challenge::TlsAlpn01);
    }

    #[test]
    fn store_dirs_are_per_directory() {
        let prod = Store::new(&AcmeSettings::default());
        let staging = Store::new(&AcmeSettings { directory: "letsencrypt-staging".into(), ..Default::default() });
        assert_ne!(prod.dir, staging.dir);
        assert!(prod.dir.starts_with("/var/lib/portus/acme"));
        assert!(prod.dir.file_name().unwrap().to_str().unwrap().starts_with("acme-v02.api.letsencrypt.org-"));
    }

    #[test]
    fn store_round_trips_a_private_bundle() {
        let dir = std::env::temp_dir().join(format!("portus-acme-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let settings = AcmeSettings { cache_dir: dir.to_string_lossy().into_owned(), ..Default::default() };
        let store = Store::new(&settings);
        assert!(store.load("a.example.com").is_none());
        let issued = rcgen::generate_simple_self_signed(vec!["a.example.com".to_string()]).unwrap();
        let chain = format!("{}{}", issued.cert.pem(), issued.cert.pem());
        store.save("a.example.com", &chain, &issued.signing_key.serialize_pem()).unwrap();
        let (got_chain, got_key) = store.load("a.example.com").unwrap();
        assert_eq!(got_chain, chain);
        assert_eq!(got_key, issued.signing_key.serialize_pem());
        crate::tls::load_certified_key_from_pem(&got_chain, &got_key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.cert_path("a.example.com")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // current_cert serves the cached certificate, not a placeholder.
        assert_eq!(current_cert(&settings, "a.example.com").unwrap().0, chain);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn placeholder_is_stable_until_a_certificate_is_cached() {
        let settings = AcmeSettings { cache_dir: "/nonexistent/portus-acme".into(), ..Default::default() };
        let first = current_cert(&settings, "placeholder.example.com").unwrap();
        let again = current_cert(&settings, "placeholder.example.com").unwrap();
        assert_eq!(first, again);
        let other = current_cert(&settings, "other-placeholder.example.com").unwrap();
        assert_ne!(first.0, other.0);
        crate::tls::load_certified_key_from_pem(&first.0, &first.1).unwrap();
    }

    #[test]
    fn renewal_is_due_two_thirds_through_the_lifetime() {
        let mut params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 4, 1); // 90 days
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let at = renew_at(&cert.pem()).unwrap();
        let jan1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert_eq!(at.duration_since(jan1).unwrap(), Duration::from_secs(60 * 86_400));
        assert!(renew_at("not a certificate").is_none());
    }

    #[test]
    fn tls_alpn01_certificate_carries_the_acme_identifier() {
        let digest = [7u8; 32];
        let ck = tls_alpn01_certificate("a.example.com", &digest).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        assert!(ext.critical);
        // DER OCTET STRING: tag 0x04, length 32, the digest.
        assert_eq!(ext.value, [&[0x04, 0x20][..], &digest[..]].concat());
        let sans = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(sans.value.general_names.len(), 1);
    }

    #[test]
    fn pem_blocks_split_a_bundle() {
        let bundle = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----";
        let (chain, key) = split_bundle(bundle).unwrap();
        assert_eq!(key, "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n");
        assert!(chain.contains("BBB") && chain.contains("CCC"));
        assert!(split_bundle("-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n").is_none());
    }

    fn acme_config(cache_dir: &Path, challenge: &str, with_http: bool) -> super::super::StandaloneConfig {
        let http = if with_http { "  - port: 80\n    routes: [{hosts: ['*'], redirect: {scheme: https}}]\n" } else { "" };
        serde_yaml_ng::from_str(&format!(
            "acme:\n  cache_dir: {}\n  challenge: {challenge}\nlisteners:\n{http}  - port: 443\n    protocol: HTTPS\n    tls: {{acme: {{domains: [a.example.com, b.example.com]}}}}\n    routes: [{{hosts: [a.example.com, b.example.com], backends: [{{address: '10.0.0.1:8080'}}]}}]\n",
            cache_dir.display()
        ))
        .unwrap()
    }

    fn served_hostnames(state: &crate::config_receiver::ProxyState) -> Vec<(String, String)> {
        let data = state.tls_cert.load();
        let mut v: Vec<(String, String)> = data
            .as_ref()
            .as_ref()
            .map(|d| d.entries.iter().map(|e| (e.hostname.clone(), e.cert_pem.clone())).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// Before issuance every domain gets a placeholder, selected by SNI; once
    /// a certificate is cached, a recompile serves it for that domain only.
    #[test]
    fn acme_listener_serves_placeholders_then_the_issued_certificate() {
        let dir = std::env::temp_dir().join(format!("portus-acme-compile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = acme_config(&dir, "http-01", true);
        let compiled = super::super::to_compiled_config(&config, &Default::default()).unwrap();
        let plan = compiled.acme.clone().unwrap();
        assert_eq!(plan.domains.iter().collect::<Vec<_>>(), ["a.example.com", "b.example.com"]);
        // The listener itself (hostname-less: a.example.com's cert is the
        // default) plus one route-less listener for b.example.com.
        let https: Vec<_> = compiled.config.listeners.iter().filter(|l| l.port == 443).collect();
        assert_eq!(https.len(), 2);
        assert_eq!(https[1].hostname, "b.example.com");
        assert!(compiled.config.routes.iter().all(|r| r.listener_name != https[1].name));

        let state = super::super::test_support::proxy_state();
        crate::config_receiver::apply_config(compiled.config, &state);
        let before = served_hostnames(&state);
        assert_eq!(before.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(), ["", "b.example.com"]);
        let placeholder_a = before[0].1.clone();

        // "Issue" a.example.com's certificate into the cache.
        let issued = rcgen::generate_simple_self_signed(vec!["a.example.com".to_string()]).unwrap();
        Store::new(&plan.settings)
            .save("a.example.com", &issued.cert.pem(), &issued.signing_key.serialize_pem())
            .unwrap();
        let again = super::super::to_compiled_config(&config, &Default::default()).unwrap();
        crate::config_receiver::apply_config(again.config, &state);
        let after = served_hostnames(&state);
        assert_eq!(after[0].1, issued.cert.pem());
        assert_ne!(after[0].1, placeholder_a);
        assert_eq!(after[1], before[1], "b.example.com keeps its placeholder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http01_needs_a_plain_http_listener_tls_alpn01_does_not() {
        let dir = std::env::temp_dir().join("portus-acme-reachable");
        let err = super::super::to_compiled_config(&acme_config(&dir, "http-01", false), &Default::default())
            .err()
            .unwrap();
        assert!(err.contains("plain HTTP listener"), "{err}");
        assert!(super::super::to_compiled_config(&acme_config(&dir, "tls-alpn-01", false), &Default::default()).is_ok());
    }

    #[test]
    fn tls_needs_exactly_files_or_acme() {
        for tls in ["{}", "{cert_file: /c.pem}", "{cert_file: /c.pem, key_file: /k.pem, acme: {}}"] {
            let config: super::super::StandaloneConfig = serde_yaml_ng::from_str(&format!(
                "listeners:\n  - port: 443\n    protocol: HTTPS\n    tls: {tls}\n    hostname: a.example.com\n"
            ))
            .unwrap();
            let err = super::super::to_compiled_config(&config, &Default::default()).err().unwrap();
            assert!(err.contains("either cert_file and key_file, or acme"), "{tls}: {err}");
        }
    }

}
