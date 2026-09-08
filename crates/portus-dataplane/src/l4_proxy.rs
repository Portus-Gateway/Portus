//! L4 proxy for TLS passthrough (SNI peeking), TCP proxying and the listener
//! manager that binds every Gateway listener port (TCP and UDP).
//!
//! Runs as a separate async task alongside the Pingora HTTP proxy.
//! Reads L4Config from an ArcSwap slot populated by config_receiver.
//! TLS passthrough uses SNI extraction from the ClientHello.
//! TCP proxy does raw bidirectional byte copying; UDP is in `udp_proxy`.

use hashbrown::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use log::{info, warn};

use crate::router::ServiceLbMap;

/// Global semaphore limiting concurrent L4 connections to prevent unbounded resource consumption.
static L4_CONNECTION_SEMAPHORE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(10_000)));

/// Default idle timeout for an L4 session. A session is closed only when
/// *neither* direction has carried bytes for this long, so long-lived protocols
/// (MQTT on 8883, database connections over TCPRoute) stay up as long as they
/// exchange keepalives. Override with `L4_IDLE_TIMEOUT_SECS`.
const DEFAULT_L4_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// How long to wait for a complete TLS ClientHello before giving up on SNI
/// extraction. Large ClientHellos (post-quantum key shares are ~1.7 KB) routinely
/// arrive split across TCP segments; a single `peek()` sees only the first one.
const CLIENT_HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on the ClientHello bytes we are willing to peek.
const CLIENT_HELLO_PEEK_BUF: usize = 16 * 1024;

/// Per-direction copy buffer for proxied L4 sessions.
const L4_COPY_BUF: usize = 16 * 1024;

/// Idle timeout for L4 sessions, read once from `L4_IDLE_TIMEOUT_SECS`.
fn l4_idle_timeout() -> std::time::Duration {
    static IDLE: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *IDLE.get_or_init(|| {
        std::env::var("L4_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or(DEFAULT_L4_IDLE_TIMEOUT)
    })
}

/// Copy one direction of a proxied session, tracking activity in `last_activity`
/// (milliseconds since `start`). Returns when the reader hits EOF (after
/// shutting down the writer) or when the whole session has been idle for `idle`.
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle: std::time::Duration,
    start: std::time::Instant,
    last_activity: &std::sync::atomic::AtomicU64,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; L4_COPY_BUF];
    let mut total: u64 = 0;
    loop {
        match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_elapsed) => {
                // This direction is quiet; only give up if the other one is too.
                let since_last = start.elapsed().saturating_sub(
                    std::time::Duration::from_millis(last_activity.load(Ordering::Relaxed)),
                );
                if since_last >= idle {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "L4 session idle timeout",
                    ));
                }
            }
            Ok(Ok(0)) => {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                total += n as u64;
                last_activity.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            Ok(Err(e)) => return Err(e),
        }
    }
}

/// Bidirectional copy between two streams that ends when both directions have
/// been idle for `idle`, when either side closes (the other side's write half is
/// shut down and drained like `tokio::io::copy_bidirectional`), or on I/O error.
pub(crate) async fn copy_bidirectional_idle<A, B>(
    a: A,
    b: B,
    idle: std::time::Duration,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let start = std::time::Instant::now();
    let last_activity = std::sync::atomic::AtomicU64::new(0);
    let (mut ra, mut wa) = tokio::io::split(a);
    let (mut rb, mut wb) = tokio::io::split(b);
    tokio::try_join!(
        pump(&mut ra, &mut wb, idle, start, &last_activity),
        pump(&mut rb, &mut wa, idle, start, &last_activity),
    )
}

/// Proxy a client stream to an upstream until EOF or idle timeout. Idle
/// timeouts are a normal end of session, not an error.
async fn proxy_streams<A, B>(client: A, upstream: B) -> Result<(), Box<dyn std::error::Error>>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::io::ErrorKind;
    match copy_bidirectional_idle(client, upstream, l4_idle_timeout()).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            log::debug!("L4 session closed after {}s idle", l4_idle_timeout().as_secs());
            Ok(())
        }
        // A peer hanging up mid-stream (client closes after the handshake,
        // backend resets) is a normal end of session, not a proxy error.
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::NotConnected
            ) =>
        {
            log::debug!("L4 session ended by peer: {e}");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Result of inspecting the bytes peeked from a new connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloPeek {
    /// A full ClientHello was parsed; carries the lowercased SNI if present.
    Complete(Option<String>),
    /// Looks like TLS so far, but the ClientHello has not fully arrived.
    Incomplete,
    /// Not a TLS ClientHello.
    NotTls,
}

/// Classify a prefix of a connection as a (possibly partial) TLS ClientHello.
pub(crate) fn classify_client_hello(buf: &[u8]) -> ClientHelloPeek {
    let mut acceptor = rustls::server::Acceptor::default();
    match acceptor.read_tls(&mut &buf[..]) {
        Ok(0) => return ClientHelloPeek::Incomplete,
        Ok(_) => {}
        Err(_) => return ClientHelloPeek::NotTls,
    }
    match acceptor.accept() {
        Ok(None) => ClientHelloPeek::Incomplete,
        Ok(Some(accepted)) => ClientHelloPeek::Complete(
            accepted
                .client_hello()
                .server_name()
                .map(|s| s.to_ascii_lowercase()),
        ),
        Err(_) => ClientHelloPeek::NotTls,
    }
}

/// Peek the ClientHello from a fresh connection without consuming it, waiting
/// (up to `CLIENT_HELLO_DEADLINE`) for TCP segmentation to deliver all of it.
///
/// `TcpStream::readable()` fires immediately while any bytes are queued, so a
/// short sleep paces the re-peek when no new bytes have arrived.
pub(crate) async fn peek_client_hello(
    stream: &tokio::net::TcpStream,
) -> std::io::Result<ClientHelloPeek> {
    let mut buf = [0u8; CLIENT_HELLO_PEEK_BUF];
    let deadline = tokio::time::Instant::now() + CLIENT_HELLO_DEADLINE;
    let mut last_n = 0usize;
    loop {
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before ClientHello",
            ));
        }
        match classify_client_hello(&buf[..n]) {
            ClientHelloPeek::Incomplete
                if n < buf.len() && tokio::time::Instant::now() < deadline =>
            {
                if n == last_n {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                last_n = n;
            }
            other => return Ok(other),
        }
    }
}

/// Shared L4 configuration slot, updated atomically from gRPC config stream.
pub(crate) type L4ConfigSlot = Arc<ArcSwap<L4Config>>;

/// L4 routing configuration for TLS passthrough and TCP proxy.
#[derive(Debug, Clone, Default)]
pub(crate) struct L4Config {
    /// Per-listener TLS passthrough routing. Each entry is a listener with its
    /// hostname restriction and its own set of route hostnames → backends.
    /// The SNI mux finds the most specific matching listener first, then looks
    /// up the route within that listener's scope.
    pub(crate) tls_listeners: Vec<TlsPassthroughListener>,
    /// Listener port -> weighted TCP backends (TCPRoute).
    pub(crate) tcp_proxy: HashMap<u16, Arc<L4RouteTarget>>,
    /// UDP listener port -> weighted UDP backends (UDPRoute).
    pub(crate) udp_proxy: HashMap<u16, Arc<L4RouteTarget>>,
    /// Ports with at least one HTTP (plaintext) Gateway listener. Connections
    /// are handed to Pingora's HTTP service as-is.
    pub(crate) http_ports: std::collections::BTreeSet<u16>,
    /// Ports with at least one HTTPS Gateway listener. Connections go through
    /// the SNI decision (TLS passthrough / TLSRoute terminate / HTTPS hand-off).
    pub(crate) https_ports: std::collections::BTreeSet<u16>,
    /// Ports with at least one TLS (TLSRoute) Gateway listener, bound even
    /// before any TLSRoute attaches so the listener is reachable the moment the
    /// Gateway is programmed (SNI decision; no matching route => drop).
    pub(crate) tls_ports: std::collections::BTreeSet<u16>,
    /// Ports with at least one TCP Gateway listener, bound even before a
    /// TCPRoute attaches (connections are dropped until one does).
    pub(crate) tcp_ports: std::collections::BTreeSet<u16>,
    /// Ports with at least one UDP Gateway listener, bound even before a
    /// UDPRoute attaches (datagrams are dropped until one does).
    pub(crate) udp_ports: std::collections::BTreeSet<u16>,
}

/// One TCPRoute/UDPRoute backendRef.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct L4Backend {
    pub(crate) service: String,
    pub(crate) port: u16,
    pub(crate) weight: u32,
}

/// The backends programmed for one TCP or UDP listener port, selected per
/// connection (TCP) or per client session (UDP) by weighted round robin.
/// Backends with weight 0 never receive traffic.
#[derive(Debug)]
pub(crate) struct L4RouteTarget {
    pub(crate) backends: Vec<L4Backend>,
    total_weight: u64,
    counter: std::sync::atomic::AtomicU64,
}

impl L4RouteTarget {
    pub(crate) fn new(backends: Vec<L4Backend>) -> Self {
        let total_weight = backends.iter().map(|b| b.weight as u64).sum();
        Self {
            backends,
            total_weight,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Weighted round-robin choice. Deterministic: over `total_weight`
    /// consecutive connections each backend is chosen exactly `weight` times,
    /// which keeps the conformance suite's ±5% tolerance trivially.
    pub(crate) fn select(&self) -> Option<&L4Backend> {
        if self.total_weight == 0 {
            return None;
        }
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.total_weight;
        let mut cumulative = 0u64;
        self.backends.iter().find(|b| {
            cumulative += b.weight as u64;
            n < cumulative
        })
    }
}

/// TLS mode for a TLS listener.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TlsMode {
    Passthrough,
    Terminate,
}

/// A TLS listener with its hostname restriction and routes.
/// Handles both Passthrough and Terminate modes.
#[derive(Debug, Clone)]
pub(crate) struct TlsPassthroughListener {
    /// Listener hostname restriction (empty = match all).
    pub(crate) hostname: String,
    /// Route hostnames → (backend_service, backend_port) within this listener's scope.
    /// These are effective hostnames (intersection of route and listener hostnames).
    pub(crate) routes: HashMap<String, (String, u16)>,
    /// TLS mode: Passthrough (forward encrypted) or Terminate (decrypt then proxy).
    pub(crate) tls_mode: TlsMode,
    /// For Terminate mode: the TLS certificate for termination.
    pub(crate) cert: Option<Arc<rustls::sign::CertifiedKey>>,
    /// Gateway listener port (used to determine which port to bind).
    pub(crate) listener_port: u16,
}

/// Extract SNI (server_name) from a TLS ClientHello message.
///
/// Uses rustls Acceptor to parse the ClientHello and extract the SNI extension.
/// Returns None if the data is not a valid TLS ClientHello or lacks an SNI extension.
#[cfg(test)]
pub(crate) fn peek_sni(buf: &[u8]) -> Option<String> {
    match classify_client_hello(buf) {
        ClientHelloPeek::Complete(sni) => sni,
        ClientHelloPeek::Incomplete | ClientHelloPeek::NotTls => None,
    }
}

/// SNI multiplexer routing decision.
#[derive(Debug)]
pub(crate) enum MuxDecision {
    /// Forward the connection as-is to the backend (TLS passthrough).
    Passthrough { service: String, port: u16 },
    /// Forward the connection to the internal Pingora HTTPS listener (TLS termination for HTTPS/HTTPRoutes).
    Terminate,
    /// TLS Terminate mode for TLSRoute: decrypt TLS at the proxy and TCP-proxy to backend.
    TlsTerminate { service: String, port: u16, cert: Arc<rustls::sign::CertifiedKey> },
    /// Reject the connection (drop it). Used when SNI matches a TLS Passthrough listener
    /// hostname but no passthrough route exists for it.
    Reject,
}

/// Determine the SNI mux routing decision for a given L4Config and optional SNI hostname.
///
/// Uses per-listener scoped routing:
/// 1. Find the most specific TLS Passthrough listener whose hostname matches the SNI
/// 2. Within that listener's routes, find a matching route (exact then wildcard)
/// 3. If route found → Passthrough to backend
/// 4. If listener matches but no route → Reject (connection dropped)
/// 5. If no listener matches → Terminate (forward to Pingora for HTTPS)
#[cfg(test)]
pub(crate) fn sni_mux_decision(cfg: &L4Config, sni: Option<&str>) -> MuxDecision {
    sni_mux_decision_over(cfg.tls_listeners.iter(), sni)
}

fn sni_mux_decision_over<'a>(
    listeners: impl IntoIterator<Item = &'a TlsPassthroughListener>,
    sni: Option<&str>,
) -> MuxDecision {
    let hostname = match sni {
        Some(h) if !h.is_empty() => h,
        _ => return MuxDecision::Terminate,
    };

    // Find the most specific matching listener.
    // Specificity: exact > *.subdomain > *.tld > empty (match-all).
    // More dots in a wildcard = more specific.
    let best_listener = find_best_matching_listener(hostname, listeners);

    match best_listener {
        Some(listener) => {
            // Listener matched — look up route within this listener's scope
            if let Some((service, port)) = lookup_route_in_listener(hostname, &listener.routes) {
                match listener.tls_mode {
                    TlsMode::Passthrough => MuxDecision::Passthrough {
                        service: service.clone(),
                        port: *port,
                    },
                    TlsMode::Terminate => {
                        if let Some(ref cert) = listener.cert {
                            MuxDecision::TlsTerminate {
                                service: service.clone(),
                                port: *port,
                                cert: cert.clone(),
                            }
                        } else {
                            // Terminate mode but no cert — reject
                            MuxDecision::Reject
                        }
                    }
                }
            } else {
                // Listener matched but no route exists → reject
                MuxDecision::Reject
            }
        }
        None => {
            // No TLS listener matches → forward to Pingora for HTTPS
            MuxDecision::Terminate
        }
    }
}

/// Find the most specific TLS Passthrough listener matching the given SNI hostname.
/// Returns None if no listener matches.
fn find_best_matching_listener<'a>(
    sni: &str,
    listeners: impl IntoIterator<Item = &'a TlsPassthroughListener>,
) -> Option<&'a TlsPassthroughListener> {
    let mut best: Option<&TlsPassthroughListener> = None;
    let mut best_specificity: usize = 0; // higher = more specific

    for listener in listeners {
        let (matches, specificity) = listener_matches_sni(&listener.hostname, sni);
        if matches && specificity >= best_specificity {
            // Prefer more specific (higher specificity), or first match at same level
            if specificity > best_specificity || best.is_none() {
                best = Some(listener);
                best_specificity = specificity;
            }
        }
    }
    best
}

/// Check if a listener hostname matches an SNI, and return specificity score.
/// Empty hostname = match all (specificity 1).
/// Wildcard = match subdomains (specificity = number of dots + 2).
/// Exact = highest (specificity = 1000).
fn listener_matches_sni(listener_hostname: &str, sni: &str) -> (bool, usize) {
    if listener_hostname.is_empty() {
        // Empty = match all
        return (true, 1);
    }
    if listener_hostname.starts_with("*.") {
        let suffix = &listener_hostname[1..]; // ".example.com"
        if sni.ends_with(suffix) && sni.len() > suffix.len() {
            // Gateway API allows multi-level subdomain matching for routing
            // (e.g., *.example.com matches foo.bar.example.com).
            // Note: RFC 6125 single-label restriction applies to cert selection
            // in tls.rs, not to hostname routing here.
            let specificity = suffix.matches('.').count() + 2;
            return (true, specificity);
        }
        return (false, 0);
    }
    // Exact match
    if sni.eq_ignore_ascii_case(listener_hostname) {
        return (true, 1000);
    }
    (false, 0)
}

/// Look up a route within a listener's route map. Tries exact match first,
/// then wildcard matching (*.suffix).
fn lookup_route_in_listener<'a>(
    sni: &str,
    routes: &'a HashMap<String, (String, u16)>,
) -> Option<&'a (String, u16)> {
    // Exact match first
    if let Some(backend) = routes.get(sni) {
        return Some(backend);
    }
    // Wildcard match
    let mut search = sni;
    while let Some(dot) = search.find('.') {
        let wildcard = format!("*.{}", &search[dot + 1..]);
        if let Some(backend) = routes.get(&wildcard) {
            return Some(backend);
        }
        search = &search[dot + 1..];
    }
    None
}

/// Resolve a backend address from the ServiceLbMap.
///
/// Returns the backend address as "ip:port" or None if no endpoints found.
pub(crate) fn resolve_backend(
    lbs: &ServiceLbMap,
    service: &str,
    port: u16,
) -> Option<String> {
    let guard = lbs.load();
    let key = (Arc::from(service), port);
    let lb = guard.get(&key)?;
    let backend = lb.select(b"", 256)?;
    Some(backend.addr.to_string())
}

/// Sender half of a hand-off channel into one of Pingora's services. The
/// listener manager pushes accepted connections here as non-blocking
/// `std::net::TcpStream`s; Pingora accepts them on its own runtime and speaks
/// HTTP (or runs the TLS handshake) on the original socket. No loopback hop, so
/// the peer address Pingora sees is the real client and the local port is the
/// real listener port.
pub(crate) type Handoff = tokio::sync::mpsc::Sender<std::net::TcpStream>;

/// The two Pingora entry points every dynamically bound listener port feeds.
#[derive(Clone)]
pub(crate) struct Handoffs {
    /// Plaintext HTTP service (HTTP listeners).
    pub(crate) http: Handoff,
    /// TLS-terminating HTTPS service (HTTPS listeners, after the SNI decision).
    pub(crate) https: Handoff,
}

/// Perform TLS termination on a raw TCP stream and proxy to a backend.
///
/// 1. Build a rustls ServerConfig with the provided cert
/// 2. Accept the TLS handshake on the incoming stream
/// 3. Connect to the backend as plain TCP
/// 4. Copy bidirectionally between the decrypted TLS stream and the backend
async fn handle_tls_terminate(
    stream: tokio::net::TcpStream,
    cert: Arc<rustls::sign::CertifiedKey>,
    backend_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_rustls::TlsAcceptor;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver(cert)));

    // No ALPN for raw TCP proxy (TLSRoute Terminate just decrypts and forwards TCP)
    server_config.alpn_protocols = Vec::new();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tls_stream = acceptor.accept(stream).await?;
    let upstream = connect_upstream(backend_addr).await?;
    proxy_streams(tls_stream, upstream).await?;
    Ok(())
}

/// A simple cert resolver that always returns the same cert.
struct SingleCertResolver(Arc<rustls::sign::CertifiedKey>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleCertResolver").finish()
    }
}

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Upper bound on connecting to an L4 backend. A backend endpoint that has just
/// gone away (pod terminating, node gone) otherwise leaves the client waiting on
/// the kernel's SYN retries - minutes - with no bytes ever sent, which a TLS
/// client experiences as a handshake that never completes.
pub(crate) const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) async fn connect_upstream(addr: &str) -> std::io::Result<tokio::net::TcpStream> {
    connect_upstream_within(addr, UPSTREAM_CONNECT_TIMEOUT).await
}

pub(crate) async fn connect_upstream_within(
    addr: &str,
    timeout: std::time::Duration,
) -> std::io::Result<tokio::net::TcpStream> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("connect to backend {addr} timed out after {timeout:?}"),
        )),
    }
}

/// Hand an accepted connection to one of Pingora's services without a loopback
/// hop. Any bytes already peeked are still in the kernel receive buffer (peek
/// does not consume), so Pingora sees the stream from its first byte, and the
/// socket's peer/local addresses are the real ones. The stream is converted to
/// the std type because the listener manager and Pingora run on different
/// Tokio runtimes.
pub(crate) async fn hand_off_to_pingora(
    stream: tokio::net::TcpStream,
    target: &Handoff,
) -> std::io::Result<()> {
    let std_stream = stream.into_std()?;
    target.send(std_stream).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Pingora service is not accepting handed-off connections",
        )
    })
}

/// Ports Pingora itself binds (health, metrics); the listener manager must
/// never try to bind them even if a Gateway asks.
const RESERVED_PORTS: [u16; 2] = [8081, 9090];

/// TCP ports the listener manager should be bound to for a given config: every
/// stream listener port the controller has programmed - HTTP, HTTPS, TLS and
/// TCP alike. Nothing is bound until the first config arrives, which matches
/// readiness (`/readyz` needs a config). UDP ports are [`desired_udp_ports`].
pub(crate) fn desired_l4_ports(cfg: &L4Config) -> std::collections::BTreeSet<u16> {
    let mut desired: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    desired.extend(cfg.tcp_proxy.keys().copied());
    desired.extend(cfg.http_ports.iter().copied());
    desired.extend(cfg.https_ports.iter().copied());
    desired.extend(cfg.tls_ports.iter().copied());
    desired.extend(cfg.tcp_ports.iter().copied());
    desired.extend(
        cfg.tls_listeners
            .iter()
            .map(|l| l.listener_port)
            .filter(|p| *p > 0),
    );
    desired.retain(|p| *p != 0 && !RESERVED_PORTS.contains(p));
    desired
}

/// UDP ports the listener manager should be bound to: every UDP listener port,
/// with or without a UDPRoute yet. A UDP port may coincide with a TCP port;
/// the two sockets are independent.
pub(crate) fn desired_udp_ports(cfg: &L4Config) -> std::collections::BTreeSet<u16> {
    let mut desired: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    desired.extend(cfg.udp_proxy.keys().copied());
    desired.extend(cfg.udp_ports.iter().copied());
    desired.retain(|p| *p != 0);
    desired
}

/// Accept loop for one listener port. Runs until aborted.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    port: u16,
    l4_config: L4ConfigSlot,
    lbs: ServiceLbMap,
    handoffs: Handoffs,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("L4 proxy: accept error on port {}: {}", port, e);
                continue;
            }
        };

        let permit = match L4_CONNECTION_SEMAPHORE.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("L4 connection limit reached (10000), dropping connection from {}", peer);
                drop(stream);
                continue;
            }
        };

        let cfg = l4_config.clone();
        let lb = lbs.clone();
        let handoffs = handoffs.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for connection duration
            if let Err(e) = handle_l4_connection(stream, peer, port, &cfg, &lb, &handoffs).await {
                warn!("L4 proxy: connection from {} on port {} failed: {}", peer, port, e);
            }
        });
    }
}

/// The dataplane's listener manager.
///
/// Binds every Gateway listener port in the current config - HTTP, HTTPS, TLS,
/// TCP and UDP - and **follows config changes**: a listener on a new port is
/// bound within a second of the controller programming it and released when it
/// goes away. Health and metrics ports are never touched.
///
/// For each incoming connection:
/// - port has a TCPRoute: pick a weighted backend and proxy raw bytes
/// - UDP port: `udp_proxy::udp_listener_loop` (per-client sessions)
/// - HTTP-only port: hand the socket to Pingora's HTTP service untouched
/// - otherwise: peek the ClientHello, decide per SNI - TLS passthrough,
///   TLSRoute terminate, HTTPS hand-off to Pingora, or reject
pub(crate) async fn run_l4_proxy(l4_config: L4ConfigSlot, lbs: ServiceLbMap, handoffs: Handoffs) {
    let mut bound: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut bound_udp: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut warned_bind_failure: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut warned_udp_bind_failure: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut last_cfg: Option<Arc<L4Config>> = None;

    loop {
        let cfg = l4_config.load_full();
        let cfg_changed = last_cfg.as_ref().is_none_or(|prev| !Arc::ptr_eq(prev, &cfg));
        let any_dead = bound.values().chain(bound_udp.values()).any(|h| h.is_finished());

        if cfg_changed || any_dead {
            // UDP listeners.
            let desired_udp = desired_udp_ports(&cfg);
            let stale_udp: Vec<u16> = bound_udp.keys().copied().filter(|p| !desired_udp.contains(p)).collect();
            for port in stale_udp {
                if let Some(h) = bound_udp.remove(&port) {
                    h.abort();
                    info!("L4 proxy: released UDP port {}", port);
                }
            }
            for port in desired_udp {
                if bound_udp.get(&port).is_some_and(|h| !h.is_finished()) {
                    continue;
                }
                match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
                    Ok(socket) => {
                        info!("L4 proxy: listening on UDP port {}", port);
                        warned_udp_bind_failure.remove(&port);
                        bound_udp.insert(
                            port,
                            tokio::spawn(crate::udp_proxy::udp_listener_loop(
                                Arc::new(socket),
                                port,
                                l4_config.clone(),
                                lbs.clone(),
                            )),
                        );
                    }
                    Err(e) => {
                        if warned_udp_bind_failure.insert(port) {
                            warn!("L4 proxy: failed to bind UDP port {} ({}); will retry", port, e);
                        }
                    }
                }
            }

            let desired = desired_l4_ports(&cfg);

            // Release ports that are no longer wanted.
            let stale: Vec<u16> = bound
                .keys()
                .copied()
                .filter(|p| !desired.contains(p))
                .collect();
            for port in stale {
                if let Some(h) = bound.remove(&port) {
                    h.abort();
                    info!("L4 proxy: released port {}", port);
                }
            }

            // Bind anything new (or whose accept loop died).
            for port in desired {
                if bound.get(&port).is_some_and(|h| !h.is_finished()) {
                    continue;
                }
                match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
                    Ok(listener) => {
                        info!("L4 proxy: listening on port {}", port);
                        warned_bind_failure.remove(&port);
                        bound.insert(
                            port,
                            tokio::spawn(accept_loop(
                                listener,
                                port,
                                l4_config.clone(),
                                lbs.clone(),
                                handoffs.clone(),
                            )),
                        );
                    }
                    Err(e) => {
                        if warned_bind_failure.insert(port) {
                            warn!("L4 proxy: failed to bind port {} ({}); will retry", port, e);
                        }
                    }
                }
            }
            last_cfg = Some(cfg);
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Handle a single L4 connection.
///
/// Peeks the first bytes to detect TLS ClientHello, then routes accordingly.
async fn handle_l4_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    port: u16,
    l4_config: &L4ConfigSlot,
    lbs: &ServiceLbMap,
    handoffs: &Handoffs,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = l4_config.load();

    match port_role(&cfg, port) {
        PortRole::Tcp => {
            let Some(target) = cfg.tcp_proxy.get(&port) else {
                log::debug!("L4 proxy: TCP listener on port {port} has no TCPRoute yet; dropping {peer}");
                drop(stream);
                return Ok(());
            };
            let backend = target
                .select()
                .ok_or_else(|| format!("TCP route on port {port} has no backend with weight > 0"))?;
            let addr = resolve_backend(lbs, &backend.service, backend.port)
                .ok_or_else(|| format!("no endpoints for TCP backend {}:{}", backend.service, backend.port))?;
            info!("L4 proxy: TCP connection from {} -> {} ({})", peer, addr, backend.service);
            let upstream = connect_upstream(&addr).await?;
            proxy_streams(stream, upstream).await?;
            Ok(())
        }
        PortRole::Http => {
            log::debug!("L4 proxy: HTTP {} on port {} -> pingora HTTP", peer, port);
            hand_off_to_pingora(stream, &handoffs.http).await?;
            Ok(())
        }
        PortRole::Tls => {
            // Peek the ClientHello without consuming bytes from the socket,
            // waiting for segmented hellos to arrive in full so SNI routing
            // sees the real name.
            let sni = match peek_client_hello(&stream).await? {
                ClientHelloPeek::Complete(sni) => sni,
                ClientHelloPeek::Incomplete => {
                    log::debug!("L4 proxy: ClientHello from {} incomplete after deadline", peer);
                    None
                }
                ClientHelloPeek::NotTls => None,
            };
            match sni_mux_decision_for_port(&cfg, sni.as_deref(), port) {
                MuxDecision::Passthrough { service, port: backend_port } => {
                    let addr = resolve_backend(lbs, &service, backend_port).ok_or_else(|| {
                        format!("no endpoints for TLS backend {}:{} (SNI={:?})", service, backend_port, sni)
                    })?;
                    info!("L4 proxy: TLS passthrough {:?} {} -> {}", sni, peer, addr);
                    let upstream = connect_upstream(&addr).await?;
                    proxy_streams(stream, upstream).await?;
                }
                MuxDecision::TlsTerminate { service, port: backend_port, cert } => {
                    let addr = resolve_backend(lbs, &service, backend_port).ok_or_else(|| {
                        format!(
                            "no endpoints for TLS terminate backend {}:{} (SNI={:?})",
                            service, backend_port, sni
                        )
                    })?;
                    info!("L4 proxy: TLS terminate {:?} {} -> {}", sni, peer, addr);
                    handle_tls_terminate(stream, cert, &addr).await?;
                }
                MuxDecision::Terminate => {
                    if cfg.https_ports.contains(&port) {
                        log::debug!(
                            "L4 proxy: HTTPS {:?} {} on port {} -> pingora HTTPS",
                            sni.as_deref().unwrap_or("<no SNI>"),
                            peer,
                            port
                        );
                        hand_off_to_pingora(stream, &handoffs.https).await?;
                    } else {
                        warn!(
                            "L4 proxy: no TLS listener claims SNI {:?} from {} on port {} and the port has no HTTPS listener; dropping",
                            sni.as_deref().unwrap_or("<no SNI>"),
                            peer,
                            port
                        );
                        drop(stream);
                    }
                }
                MuxDecision::Reject => {
                    warn!(
                        "L4 proxy: reject {:?} {} on port {} (matches TLS listener but no passthrough route)",
                        sni.as_deref().unwrap_or("<no SNI>"),
                        peer,
                        port
                    );
                    drop(stream);
                }
            }
            Ok(())
        }
    }
}

/// What a bound port is for, decided from the current config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortRole {
    /// A TCPRoute owns the port: raw proxying.
    Tcp,
    /// Only HTTP listeners on the port: straight to Pingora HTTP, no peeking.
    Http,
    /// HTTPS and/or TLS listeners (possibly alongside HTTP, which the
    /// Gateway API forbids but we tolerate by peeking): SNI decision.
    Tls,
}

pub(crate) fn port_role(cfg: &L4Config, port: u16) -> PortRole {
    if cfg.tcp_proxy.contains_key(&port) || cfg.tcp_ports.contains(&port) {
        return PortRole::Tcp;
    }
    let has_tls_listener = cfg
        .tls_listeners
        .iter()
        .any(|l| l.listener_port == port || l.listener_port == 0);
    if cfg.https_ports.contains(&port) || cfg.tls_ports.contains(&port) || has_tls_listener {
        return PortRole::Tls;
    }
    if cfg.http_ports.contains(&port) {
        return PortRole::Http;
    }
    // A bound port whose listener just went away (the release is a config
    // change behind): treat as TLS so the connection is dropped with a clear
    // log line rather than handed to Pingora.
    PortRole::Tls
}

/// `sni_mux_decision` restricted to the TLS listeners bound on `port`
/// (listeners without a recorded port are legacy and match any port).
pub(crate) fn sni_mux_decision_for_port(cfg: &L4Config, sni: Option<&str>, port: u16) -> MuxDecision {
    let on_port = cfg
        .tls_listeners
        .iter()
        .filter(|l| l.listener_port == port || l.listener_port == 0);
    sni_mux_decision_over(on_port, sni)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hand_off_keeps_peeked_bytes_and_peer_addr() {
        use tokio::io::AsyncWriteExt;

        // The mux peeks the ClientHello, then hands the socket to Pingora. The
        // peeked bytes must still be in the socket and the peer must be the
        // real client, or HTTPS would lose client IPs and handshakes.
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = front.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (accepted, _) = front.accept().await.unwrap();
        client.write_all(b"\x16\x03\x01hello").await.unwrap();

        // Peek like the mux does (does not consume).
        let mut peek = [0u8; 8];
        let n = accepted.peek(&mut peek).await.unwrap();
        assert_eq!(&peek[..n], b"\x16\x03\x01hello");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<std::net::TcpStream>(1);
        hand_off_to_pingora(accepted, &tx).await.unwrap();
        let handed = rx.recv().await.expect("stream delivered to the HTTPS service");
        assert_eq!(handed.peer_addr().unwrap(), client_addr);
        let mut handed = tokio::net::TcpStream::from_std(handed).unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::io::AsyncReadExt::read(&mut handed, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"\x16\x03\x01hello", "peeked bytes must survive the hand-off");
    }

    #[test]
    fn desired_ports_include_http_and_https_listeners_and_skip_reserved() {
        let mut cfg = L4Config::default();
        cfg.http_ports.extend([80, 8080, 9090 /* metrics: reserved */]);
        cfg.https_ports.extend([443, 8443]);
        cfg.tcp_proxy.insert(9300, Arc::new(L4RouteTarget::new(vec![])));
        let ports = desired_l4_ports(&cfg);
        assert_eq!(
            ports.into_iter().collect::<Vec<_>>(),
            vec![80, 443, 8080, 8443, 9300],
            "80/443 are ordinary listener ports now; 9090 stays reserved"
        );
    }

    #[test]
    fn tls_and_tcp_listener_ports_bind_before_any_route_attaches() {
        // TLSRouteMixedTermination: Gateway listeners on :8883 exist before the
        // TLSRoutes are accepted; the port must already be bound.
        let mut cfg = L4Config::default();
        cfg.tls_ports.insert(8883);
        cfg.tcp_ports.insert(9300);
        let ports: Vec<u16> = desired_l4_ports(&cfg).into_iter().collect();
        assert_eq!(ports, vec![8883, 9300]);
        assert_eq!(port_role(&cfg, 8883), PortRole::Tls);
        assert_eq!(port_role(&cfg, 9300), PortRole::Tcp);
    }

    #[test]
    fn port_role_follows_listener_protocols() {
        let mut cfg = L4Config::default();
        cfg.http_ports.insert(80);
        cfg.https_ports.insert(443);
        cfg.tcp_proxy.insert(9300, Arc::new(L4RouteTarget::new(vec![])));
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".into(),
            routes: HashMap::new(),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 8443,
        });
        assert_eq!(port_role(&cfg, 80), PortRole::Http);
        assert_eq!(port_role(&cfg, 443), PortRole::Tls);
        assert_eq!(port_role(&cfg, 8443), PortRole::Tls);
        assert_eq!(port_role(&cfg, 9300), PortRole::Tcp);
        // A port that is both HTTP and HTTPS (spec-invalid) is peeked, not blindly plaintext.
        cfg.https_ports.insert(80);
        assert_eq!(port_role(&cfg, 80), PortRole::Tls);
        // Unknown static port: TLS path, so a later passthrough listener works.
        assert_eq!(port_role(&cfg, 8883), PortRole::Tls);
    }

    #[test]
    fn sni_decision_is_scoped_to_the_listener_port() {
        let mut cfg = L4Config::default();
        let mut routes = HashMap::new();
        routes.insert("abc.example.com".to_string(), ("tls-backend".to_string(), 443u16));
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".into(),
            routes,
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 8443,
        });
        cfg.https_ports.insert(443);
        // On the passthrough listener's port the SNI routes to the backend...
        assert!(matches!(
            sni_mux_decision_for_port(&cfg, Some("abc.example.com"), 8443),
            MuxDecision::Passthrough { .. }
        ));
        // ...but on :443, which has no TLS listener, the same SNI is plain HTTPS.
        assert!(matches!(
            sni_mux_decision_for_port(&cfg, Some("abc.example.com"), 443),
            MuxDecision::Terminate
        ));
    }

    #[tokio::test]
    async fn http_port_connection_is_handed_to_pingora_http_untouched() {
        use tokio::io::AsyncWriteExt;
        let mut cfg = L4Config::default();
        cfg.http_ports.insert(8080);
        let slot: L4ConfigSlot = Arc::new(ArcSwap::from_pointee(cfg));
        let lbs: ServiceLbMap = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let (http_tx, mut http_rx) = tokio::sync::mpsc::channel::<std::net::TcpStream>(1);
        let (https_tx, mut https_rx) = tokio::sync::mpsc::channel::<std::net::TcpStream>(1);
        let handoffs = Handoffs { http: http_tx, https: https_tx };

        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = front.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, peer) = front.accept().await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

        handle_l4_connection(accepted, peer, 8080, &slot, &lbs, &handoffs).await.unwrap();
        let handed = http_rx.try_recv().expect("HTTP port goes to the HTTP service");
        assert!(https_rx.try_recv().is_err());
        let mut handed = tokio::net::TcpStream::from_std(handed).unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::io::AsyncReadExt::read(&mut handed, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"GET / HTTP/1.1\r\n", "no bytes consumed before hand-off");
    }

    #[tokio::test]
    async fn backend_connect_is_bounded() {
        // 192.0.2.0/24 (TEST-NET-1) is unroutable: SYNs go unanswered.
        let err = connect_upstream_within("192.0.2.1:9", std::time::Duration::from_millis(200))
            .await
            .expect_err("unanswered SYN must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        // A live listener connects normally.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        connect_upstream_within(&addr, std::time::Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn hand_off_reports_closed_https_service() {
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = front.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = front.accept().await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel::<std::net::TcpStream>(1);
        drop(rx);
        let err = hand_off_to_pingora(accepted, &tx).await.expect_err("closed receiver must error");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// Construct a minimal TLS ClientHello with SNI and supported_versions extensions.
    ///
    /// Includes supported_versions extension (required for rustls to accept the ClientHello)
    /// and the SNI extension with the given hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let host_bytes = hostname.as_bytes();
        let host_len = host_bytes.len();

        // SNI extension
        let sni_list_len = 1 + 2 + host_len;
        let sni_ext_data_len = 2 + sni_list_len;
        let sni_ext_total = 2 + 2 + sni_ext_data_len;

        // supported_versions extension (type 0x002b)
        // Data: 1 byte (list length) + 2 bytes (TLS 1.3 = 0x0304) + 2 bytes (TLS 1.2 = 0x0303)
        let sv_ext_data_len = 1 + 4; // list_len(1) + 2 versions(4)
        let sv_ext_total = 2 + 2 + sv_ext_data_len;

        // signature_algorithms extension (type 0x000d) - required by rustls
        // 2 bytes list len + 2 bytes (rsa_pss_rsae_sha256 = 0x0804)
        let sa_ext_data_len = 2 + 2;
        let sa_ext_total = 2 + 2 + sa_ext_data_len;

        // supported_groups extension (type 0x000a) - required by rustls
        // 2 bytes list len + 2 bytes (x25519 = 0x001d)
        let sg_ext_data_len = 2 + 2;
        let sg_ext_total = 2 + 2 + sg_ext_data_len;

        let extensions_len = sni_ext_total + sv_ext_total + sa_ext_total + sg_ext_total;

        let client_hello_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;

        let handshake_len = 1 + 3 + client_hello_body_len;
        let record_len = handshake_len;

        let mut buf = Vec::with_capacity(5 + record_len);

        // TLS record header
        buf.push(0x16); // ContentType: Handshake
        buf.push(0x03);
        buf.push(0x01); // Version: TLS 1.0 (record layer)
        buf.push((record_len >> 8) as u8);
        buf.push((record_len & 0xFF) as u8);

        // Handshake header
        buf.push(0x01); // HandshakeType: ClientHello
        buf.push(((client_hello_body_len >> 16) & 0xFF) as u8);
        buf.push(((client_hello_body_len >> 8) & 0xFF) as u8);
        buf.push((client_hello_body_len & 0xFF) as u8);

        // ClientVersion: TLS 1.2
        buf.push(0x03);
        buf.push(0x03);

        // Random: 32 zero bytes
        buf.extend_from_slice(&[0u8; 32]);

        // Session ID: length 0
        buf.push(0x00);

        // Cipher Suites: length 2, TLS_AES_128_GCM_SHA256 (0x1301)
        buf.push(0x00);
        buf.push(0x02);
        buf.push(0x13);
        buf.push(0x01);

        // Compression Methods: length 1, null
        buf.push(0x01);
        buf.push(0x00);

        // Extensions length
        buf.push((extensions_len >> 8) as u8);
        buf.push((extensions_len & 0xFF) as u8);

        // SNI Extension (type 0x0000)
        buf.push(0x00);
        buf.push(0x00);
        buf.push((sni_ext_data_len >> 8) as u8);
        buf.push((sni_ext_data_len & 0xFF) as u8);
        buf.push((sni_list_len >> 8) as u8);
        buf.push((sni_list_len & 0xFF) as u8);
        buf.push(0x00); // host_name type
        buf.push((host_len >> 8) as u8);
        buf.push((host_len & 0xFF) as u8);
        buf.extend_from_slice(host_bytes);

        // supported_versions extension (type 0x002b)
        buf.push(0x00);
        buf.push(0x2b);
        buf.push((sv_ext_data_len >> 8) as u8);
        buf.push((sv_ext_data_len & 0xFF) as u8);
        buf.push(0x04); // list length: 4 bytes (2 versions)
        buf.push(0x03);
        buf.push(0x04); // TLS 1.3
        buf.push(0x03);
        buf.push(0x03); // TLS 1.2

        // signature_algorithms extension (type 0x000d)
        buf.push(0x00);
        buf.push(0x0d);
        buf.push((sa_ext_data_len >> 8) as u8);
        buf.push((sa_ext_data_len & 0xFF) as u8);
        buf.push(0x00);
        buf.push(0x02); // list length: 2 bytes
        buf.push(0x08);
        buf.push(0x04); // rsa_pss_rsae_sha256

        // supported_groups extension (type 0x000a)
        buf.push(0x00);
        buf.push(0x0a);
        buf.push((sg_ext_data_len >> 8) as u8);
        buf.push((sg_ext_data_len & 0xFF) as u8);
        buf.push(0x00);
        buf.push(0x02); // list length: 2 bytes
        buf.push(0x00);
        buf.push(0x1d); // x25519

        buf
    }

    #[test]
    fn test_peek_sni_extracts_hostname() {
        let hello = build_client_hello("example.com");
        let sni = peek_sni(&hello);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_peek_sni_extracts_subdomain() {
        let hello = build_client_hello("api.secure.example.com");
        let sni = peek_sni(&hello);
        assert_eq!(sni, Some("api.secure.example.com".to_string()));
    }

    #[test]
    fn test_peek_sni_returns_none_for_non_tls() {
        let garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let sni = peek_sni(garbage);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_peek_sni_returns_none_for_empty() {
        let sni = peek_sni(&[]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_l4_config_tls_passthrough_lookup() {
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("secure.example.com".to_string(), ("backend-svc.default".to_string(), 443)),
                ("api.example.com".to_string(), ("api-svc.default".to_string(), 8443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        let routes = &cfg.tls_listeners[0].routes;
        assert_eq!(
            routes.get("secure.example.com"),
            Some(&("backend-svc.default".to_string(), 443))
        );
        assert_eq!(
            routes.get("api.example.com"),
            Some(&("api-svc.default".to_string(), 8443))
        );
        assert_eq!(routes.get("unknown.example.com"), None);
    }

    fn tcp_target(backends: &[(&str, u16, u32)]) -> Arc<L4RouteTarget> {
        Arc::new(L4RouteTarget::new(
            backends
                .iter()
                .map(|(s, p, w)| L4Backend { service: (*s).to_string(), port: *p, weight: *w })
                .collect(),
        ))
    }

    #[test]
    fn test_l4_config_tcp_proxy_lookup() {
        let mut cfg = L4Config::default();
        cfg.tcp_proxy.insert(5432, tcp_target(&[("pg-svc.default", 5432, 1)]));
        cfg.tcp_proxy.insert(6379, tcp_target(&[("redis-svc.default", 6379, 1)]));

        let pg = cfg.tcp_proxy.get(&5432).unwrap().select().unwrap();
        assert_eq!((pg.service.as_str(), pg.port), ("pg-svc.default", 5432));
        let redis = cfg.tcp_proxy.get(&6379).unwrap().select().unwrap();
        assert_eq!((redis.service.as_str(), redis.port), ("redis-svc.default", 6379));
        assert!(cfg.tcp_proxy.get(&3306).is_none());
    }

    #[test]
    fn test_tcp_target_weighted_round_robin_matches_weights_and_skips_zero() {
        // tcproute-weighted-routing: 70 / 30 / 0 over 500 connections
        let target = tcp_target(&[("v1", 3000, 70), ("v2", 3000, 30), ("v3", 3000, 0)]);
        let mut counts = std::collections::HashMap::new();
        for _ in 0..500 {
            let b = target.select().unwrap();
            *counts.entry(b.service.clone()).or_insert(0u32) += 1;
        }
        assert_eq!(counts.get("v1"), Some(&350));
        assert_eq!(counts.get("v2"), Some(&150));
        assert_eq!(counts.get("v3"), None, "weight 0 must never be selected");
    }

    #[test]
    fn test_tcp_target_all_zero_weights_selects_nothing() {
        let target = tcp_target(&[("v1", 3000, 0)]);
        assert!(target.select().is_none());
        assert!(tcp_target(&[]).select().is_none());
    }

    #[test]
    fn test_desired_l4_ports_follows_config_and_skips_reserved() {
        let mut cfg = L4Config::default();
        cfg.tcp_proxy.insert(9300, tcp_target(&[("a", 3000, 1)]));
        cfg.tcp_proxy.insert(80, tcp_target(&[("b", 3000, 1)])); // a TCPRoute may own :80 now
        cfg.tcp_proxy.insert(9090, tcp_target(&[("c", 3000, 1)])); // metrics port: reserved, skipped
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: String::new(),
            routes: HashMap::new(),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 8443,
        });
        let ports: Vec<u16> = desired_l4_ports(&cfg).into_iter().collect();
        assert_eq!(ports, vec![80, 8443, 9300]);
        // Empty config binds nothing: every port comes from a Gateway listener.
        assert!(desired_l4_ports(&L4Config::default()).is_empty());
    }

    #[test]
    fn test_l4_config_default_is_empty() {
        let cfg = L4Config::default();
        assert!(cfg.tls_listeners.is_empty());
        assert!(cfg.tcp_proxy.is_empty());
        assert!(cfg.udp_proxy.is_empty());
        assert!(desired_udp_ports(&cfg).is_empty());
    }

    #[test]
    fn udp_ports_are_bound_separately_from_tcp_ports() {
        // udproute-simple: a UDP listener on 5300 with (and before) a UDPRoute;
        // a TCP listener on the same number is a different socket.
        let mut cfg = L4Config::default();
        cfg.udp_ports.insert(5300);
        cfg.udp_ports.insert(0);
        cfg.udp_proxy.insert(5301, tcp_target(&[("udp-echo", 8080, 1)]));
        cfg.tcp_ports.insert(5300);
        assert_eq!(desired_udp_ports(&cfg).into_iter().collect::<Vec<_>>(), vec![5300, 5301]);
        assert_eq!(desired_l4_ports(&cfg).into_iter().collect::<Vec<_>>(), vec![5300], "UDP ports are not TCP ports");
    }

    // --- SNI multiplexer decision tests ---

    #[test]
    fn test_sni_mux_passthrough_decision() {
        // Given an L4Config with a TLS passthrough entry for "abc.example.com",
        // the mux_decision function should return Passthrough for that SNI,
        // and Terminate for unknown or missing SNI.
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("abc.example.com".to_string(), ("backend-svc.default".to_string(), 8443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        // SNI matches passthrough route -> Passthrough
        let hello = build_client_hello("abc.example.com");
        let sni = peek_sni(&hello);
        let decision = sni_mux_decision(&cfg, sni.as_deref());
        assert!(
            matches!(decision, MuxDecision::Passthrough { .. }),
            "expected Passthrough for abc.example.com, got {:?}",
            decision
        );
        if let MuxDecision::Passthrough { service, port } = &decision {
            assert_eq!(service, "backend-svc.default");
            assert_eq!(*port, 8443);
        }

        // SNI does NOT match any passthrough route -> Terminate
        let hello2 = build_client_hello("unknown.com");
        let sni2 = peek_sni(&hello2);
        let decision2 = sni_mux_decision(&cfg, sni2.as_deref());
        assert!(
            matches!(decision2, MuxDecision::Terminate),
            "expected Terminate for unknown.com, got {:?}",
            decision2
        );

        // No SNI (non-TLS data) -> Terminate
        let decision3 = sni_mux_decision(&cfg, None);
        assert!(
            matches!(decision3, MuxDecision::Terminate),
            "expected Terminate for no SNI, got {:?}",
            decision3
        );
    }

    #[test]
    fn test_sni_mux_wildcard_passthrough() {
        // Wildcard matching: *.example.com in the config should match
        // foo.example.com, bar.example.com, etc. via SNI.
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("*.example.com".to_string(), ("wildcard-backend".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "exact.other.com".to_string(),
            routes: HashMap::from([
                ("exact.other.com".to_string(), ("exact-backend".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        // Wildcard matches subdomain
        let decision = sni_mux_decision(&cfg, Some("foo.example.com"));
        assert!(matches!(decision, MuxDecision::Passthrough { .. }), "foo.example.com should match *.example.com");
        if let MuxDecision::Passthrough { service, .. } = &decision {
            assert_eq!(service, "wildcard-backend");
        }

        // Gateway API: multi-level subdomain DOES match wildcard for routing
        let decision = sni_mux_decision(&cfg, Some("bar.baz.example.com"));
        assert!(matches!(decision, MuxDecision::Passthrough { .. }), "bar.baz.example.com should match *.example.com for routing");

        // Exact match still works
        let decision = sni_mux_decision(&cfg, Some("exact.other.com"));
        assert!(matches!(decision, MuxDecision::Passthrough { .. }));
        if let MuxDecision::Passthrough { service, .. } = &decision {
            assert_eq!(service, "exact-backend");
        }

        // Non-matching domain → Terminate
        let decision = sni_mux_decision(&cfg, Some("foo.different.com"));
        assert!(matches!(decision, MuxDecision::Terminate), "foo.different.com should not match");

        // Apex domain does NOT match wildcard (*.example.com doesn't match example.com)
        let decision = sni_mux_decision(&cfg, Some("example.com"));
        assert!(matches!(decision, MuxDecision::Terminate), "example.com should not match *.example.com");
    }

    #[test]
    fn test_peek_sni_preserves_stream() {
        // Verify that peek_sni is non-destructive: calling it twice on the
        // same buffer yields the same result (simulates TCP peek semantics).
        let hello = build_client_hello("preserve.example.com");
        let sni1 = peek_sni(&hello);
        let sni2 = peek_sni(&hello);
        assert_eq!(sni1, sni2);
        assert_eq!(sni1, Some("preserve.example.com".to_string()));
    }

    #[test]
    fn test_sni_mux_decision_empty_config() {
        // With no passthrough routes, every SNI should be terminated.
        let cfg = L4Config::default();
        let decision = sni_mux_decision(&cfg, Some("anything.com"));
        assert!(matches!(decision, MuxDecision::Terminate));
    }

    #[test]
    fn test_sni_mux_decision_multiple_routes() {
        // Multiple passthrough routes: each matches only its own hostname.
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("a.example.com".to_string(), ("svc-a.default".to_string(), 443)),
                ("b.example.com".to_string(), ("svc-b.default".to_string(), 8443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        if let MuxDecision::Passthrough { service, port } =
            sni_mux_decision(&cfg, Some("a.example.com"))
        {
            assert_eq!(service, "svc-a.default");
            assert_eq!(port, 443);
        } else {
            panic!("expected Passthrough for a.example.com");
        }

        if let MuxDecision::Passthrough { service, port } =
            sni_mux_decision(&cfg, Some("b.example.com"))
        {
            assert_eq!(service, "svc-b.default");
            assert_eq!(port, 8443);
        } else {
            panic!("expected Passthrough for b.example.com");
        }

        // c.example.com matches the *.example.com listener but has no route → Reject
        assert!(matches!(
            sni_mux_decision(&cfg, Some("c.example.com")),
            MuxDecision::Reject
        ));
    }

    #[test]
    fn test_sni_mux_reject_when_listener_matches_but_no_route() {
        // If the SNI matches a TLS Passthrough listener hostname but there is no
        // passthrough route for it, the connection should be rejected (not forwarded
        // to Pingora for HTTPS termination).
        let mut cfg = L4Config::default();
        // A listener with wildcard hostname that has only one route
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("app.example.com".to_string(), ("app-svc.default".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        // SNI "other.example.com" matches listener *.example.com but has no route → Reject
        let decision = sni_mux_decision(&cfg, Some("other.example.com"));
        assert!(
            matches!(decision, MuxDecision::Reject),
            "expected Reject for SNI matching listener but not route, got {:?}",
            decision
        );

        // SNI "app.example.com" matches a route → Passthrough (not Reject)
        let decision = sni_mux_decision(&cfg, Some("app.example.com"));
        assert!(
            matches!(decision, MuxDecision::Passthrough { .. }),
            "expected Passthrough for app.example.com, got {:?}",
            decision
        );
    }

    #[test]
    fn test_sni_mux_terminate_when_no_listener_match() {
        // If the SNI does not match any TLS Passthrough listener hostname,
        // it should be forwarded to Pingora for HTTPS termination.
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.example.com".to_string(),
            routes: HashMap::from([
                ("app.example.com".to_string(), ("app-svc.default".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 0,
        });

        // SNI "something.other.com" does NOT match listener *.example.com → Terminate
        let decision = sni_mux_decision(&cfg, Some("something.other.com"));
        assert!(
            matches!(decision, MuxDecision::Terminate),
            "expected Terminate for SNI not matching any listener, got {:?}",
            decision
        );

        // No SNI at all → Terminate
        let decision = sni_mux_decision(&cfg, None);
        assert!(
            matches!(decision, MuxDecision::Terminate),
            "expected Terminate for no SNI, got {:?}",
            decision
        );
    }

    #[test]
    fn test_sni_mux_tls_terminate_decision() {
        // A TLS Terminate mode listener should return TlsTerminate (not Passthrough).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = crate::tls::generate_self_signed_cert().unwrap();
        let ck = crate::tls::load_certified_key_from_pem(&cert.0, &cert.1).unwrap();

        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.terminate.com".to_string(),
            routes: HashMap::from([
                ("app.terminate.com".to_string(), ("terminate-backend".to_string(), 9443)),
            ]),
            tls_mode: TlsMode::Terminate,
            cert: Some(Arc::new(ck)),
            listener_port: 8443,
        });

        // SNI matches terminate listener → TlsTerminate
        let decision = sni_mux_decision(&cfg, Some("app.terminate.com"));
        assert!(
            matches!(decision, MuxDecision::TlsTerminate { .. }),
            "expected TlsTerminate, got {:?}",
            decision
        );
        if let MuxDecision::TlsTerminate { service, port, .. } = &decision {
            assert_eq!(service, "terminate-backend");
            assert_eq!(*port, 9443);
        }

        // SNI matches terminate listener but no route → Reject
        let decision = sni_mux_decision(&cfg, Some("other.terminate.com"));
        assert!(
            matches!(decision, MuxDecision::Reject),
            "expected Reject for no route in terminate listener, got {:?}",
            decision
        );

        // Non-matching SNI → Terminate (forward to Pingora)
        let decision = sni_mux_decision(&cfg, Some("something.else.com"));
        assert!(
            matches!(decision, MuxDecision::Terminate),
            "expected Terminate for non-matching SNI, got {:?}",
            decision
        );
    }

    #[test]
    fn test_sni_mux_terminate_no_cert_rejects() {
        // Terminate mode without a cert should reject.
        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.nocert.com".to_string(),
            routes: HashMap::from([
                ("app.nocert.com".to_string(), ("backend".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Terminate,
            cert: None, // No cert
            listener_port: 8443,
        });

        let decision = sni_mux_decision(&cfg, Some("app.nocert.com"));
        assert!(
            matches!(decision, MuxDecision::Reject),
            "expected Reject for terminate without cert, got {:?}",
            decision
        );
    }

    #[test]
    fn test_sni_mux_mixed_passthrough_and_terminate() {
        // Mixed mode: one passthrough listener, one terminate listener.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = crate::tls::generate_self_signed_cert().unwrap();
        let ck = crate::tls::load_certified_key_from_pem(&cert.0, &cert.1).unwrap();

        let mut cfg = L4Config::default();
        // Passthrough listener
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.passthrough.com".to_string(),
            routes: HashMap::from([
                ("app.passthrough.com".to_string(), ("pt-backend".to_string(), 443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 443,
        });
        // Terminate listener
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "*.terminate.com".to_string(),
            routes: HashMap::from([
                ("app.terminate.com".to_string(), ("term-backend".to_string(), 9443)),
            ]),
            tls_mode: TlsMode::Terminate,
            cert: Some(Arc::new(ck)),
            listener_port: 8443,
        });

        // Passthrough SNI
        let decision = sni_mux_decision(&cfg, Some("app.passthrough.com"));
        assert!(matches!(decision, MuxDecision::Passthrough { .. }));

        // Terminate SNI
        let decision = sni_mux_decision(&cfg, Some("app.terminate.com"));
        assert!(matches!(decision, MuxDecision::TlsTerminate { .. }));

        // Unknown SNI → Terminate (forward to Pingora)
        let decision = sni_mux_decision(&cfg, Some("unknown.other.com"));
        assert!(matches!(decision, MuxDecision::Terminate));
    }

    // --- Mixed mode per-listener scoping tests (conformance: TLSRouteMixedTerminationSameNamespace) ---

    #[test]
    fn test_mixed_mode_same_port_correct_listener_selection() {
        // Conformance: TLSRouteMixedTerminationSameNamespace
        // Two listeners on same port 8883:
        //   tls-terminate: hostname=tls.example.com, mode=Terminate → tcp-backend:3000
        //   tls-passthrough: hostname=abc.example.com, mode=Passthrough → tcp-backend:8443
        // SNI abc.example.com should match Passthrough listener (exact), NOT Terminate.
        // SNI tls.example.com should match Terminate listener (exact).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = crate::tls::generate_self_signed_cert().unwrap();
        let ck = crate::tls::load_certified_key_from_pem(&cert.0, &cert.1).unwrap();

        let mut cfg = L4Config::default();
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "tls.example.com".to_string(),
            routes: HashMap::from([
                ("tls.example.com".to_string(), ("tcp-backend".to_string(), 3000)),
            ]),
            tls_mode: TlsMode::Terminate,
            cert: Some(Arc::new(ck)),
            listener_port: 8883,
        });
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "abc.example.com".to_string(),
            routes: HashMap::from([
                ("abc.example.com".to_string(), ("tcp-backend".to_string(), 8443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 8883,
        });

        // abc.example.com → Passthrough (NOT Terminate)
        let decision = sni_mux_decision(&cfg, Some("abc.example.com"));
        match &decision {
            MuxDecision::Passthrough { service, port } => {
                assert_eq!(service, "tcp-backend");
                assert_eq!(*port, 8443);
            }
            other => panic!("abc.example.com should be Passthrough, got {:?}", other),
        }

        // tls.example.com → TlsTerminate
        let decision = sni_mux_decision(&cfg, Some("tls.example.com"));
        assert!(
            matches!(decision, MuxDecision::TlsTerminate { .. }),
            "tls.example.com should be TlsTerminate, got {:?}",
            decision
        );

        // non.matching.com → Reject (matches no listener)
        let decision = sni_mux_decision(&cfg, Some("non.matching.com"));
        assert!(
            matches!(decision, MuxDecision::Terminate),
            "non.matching.com should be Terminate (forward to Pingora), got {:?}",
            decision
        );
    }

    #[test]
    fn test_find_best_listener_exact_over_wildcard() {
        // Exact hostname match should win over wildcard.
        let listeners = vec![
            TlsPassthroughListener {
                hostname: "*.example.com".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Passthrough,
                cert: None,
                listener_port: 443,
            },
            TlsPassthroughListener {
                hostname: "specific.example.com".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Terminate,
                cert: None,
                listener_port: 443,
            },
        ];

        let best = find_best_matching_listener("specific.example.com", &listeners);
        assert!(best.is_some());
        assert_eq!(best.unwrap().hostname, "specific.example.com");
        assert!(matches!(best.unwrap().tls_mode, TlsMode::Terminate));
    }

    #[test]
    fn test_find_best_listener_more_specific_wildcard_wins() {
        // *.example.com (more specific) should win over *.com (less specific).
        let listeners = vec![
            TlsPassthroughListener {
                hostname: "*.com".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Passthrough,
                cert: None,
                listener_port: 443,
            },
            TlsPassthroughListener {
                hostname: "*.example.com".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Terminate,
                cert: None,
                listener_port: 443,
            },
        ];

        let best = find_best_matching_listener("foo.example.com", &listeners);
        assert!(best.is_some());
        assert_eq!(best.unwrap().hostname, "*.example.com");
    }

    #[test]
    fn test_find_best_listener_empty_hostname_is_least_specific() {
        // Empty hostname (match-all) should be least specific.
        let listeners = vec![
            TlsPassthroughListener {
                hostname: "".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Passthrough,
                cert: None,
                listener_port: 443,
            },
            TlsPassthroughListener {
                hostname: "*.example.com".to_string(),
                routes: HashMap::new(),
                tls_mode: TlsMode::Terminate,
                cert: None,
                listener_port: 443,
            },
        ];

        let best = find_best_matching_listener("foo.example.com", &listeners);
        assert!(best.is_some());
        assert_eq!(best.unwrap().hostname, "*.example.com");

        // non-matching.org only matches empty listener
        let best = find_best_matching_listener("non-matching.org", &listeners);
        assert!(best.is_some());
        assert_eq!(best.unwrap().hostname, "");
    }

    #[test]
    fn test_lookup_route_in_listener_exact_and_wildcard() {
        let routes = HashMap::from([
            ("exact.example.com".to_string(), ("svc-exact".to_string(), 443)),
            ("*.example.com".to_string(), ("svc-wildcard".to_string(), 443)),
        ]);

        // Exact match wins
        let r = lookup_route_in_listener("exact.example.com", &routes);
        assert!(r.is_some());
        assert_eq!(r.unwrap().0, "svc-exact");

        // Wildcard match
        let r = lookup_route_in_listener("other.example.com", &routes);
        assert!(r.is_some());
        assert_eq!(r.unwrap().0, "svc-wildcard");

        // No match
        let r = lookup_route_in_listener("other.different.com", &routes);
        assert!(r.is_none());
    }

    // --- Conformance: TLSRouteMixedTerminationSameNamespace — L4 proxy decision ---

    /// Create L4Config matching the conformance scenario with 2 listeners on
    /// port 8883 (Terminate tls.example.com and Passthrough abc.example.com).
    /// Verify sni_mux_decision produces the correct routing for each SNI.
    #[test]
    fn test_l4_mixed_mode_sni_routing_conformance() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = crate::tls::generate_self_signed_cert().unwrap();
        let ck = crate::tls::load_certified_key_from_pem(&cert.0, &cert.1).unwrap();

        let mut cfg = L4Config::default();

        // Terminate listener for tls.example.com → tcp-backend:3000
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "tls.example.com".to_string(),
            routes: HashMap::from([
                ("tls.example.com".to_string(), ("tcp-backend".to_string(), 3000)),
            ]),
            tls_mode: TlsMode::Terminate,
            cert: Some(Arc::new(ck)),
            listener_port: 8883,
        });

        // Passthrough listener for abc.example.com → tcp-backend:8443
        cfg.tls_listeners.push(TlsPassthroughListener {
            hostname: "abc.example.com".to_string(),
            routes: HashMap::from([
                ("abc.example.com".to_string(), ("tcp-backend".to_string(), 8443)),
            ]),
            tls_mode: TlsMode::Passthrough,
            cert: None,
            listener_port: 8883,
        });

        // abc.example.com → Passthrough to tcp-backend:8443
        let decision = sni_mux_decision(&cfg, Some("abc.example.com"));
        match &decision {
            MuxDecision::Passthrough { service, port } => {
                assert_eq!(service, "tcp-backend", "abc.example.com service mismatch");
                assert_eq!(*port, 8443, "abc.example.com port mismatch");
            }
            other => panic!(
                "abc.example.com should be Passthrough, got {:?}",
                other
            ),
        }

        // tls.example.com → TlsTerminate to tcp-backend:3000
        let decision = sni_mux_decision(&cfg, Some("tls.example.com"));
        match &decision {
            MuxDecision::TlsTerminate { service, port, .. } => {
                assert_eq!(service, "tcp-backend", "tls.example.com service mismatch");
                assert_eq!(*port, 3000, "tls.example.com port mismatch");
            }
            other => panic!(
                "tls.example.com should be TlsTerminate, got {:?}",
                other
            ),
        }

        // non.matching.com → Terminate (forward to Pingora, no TLS listener matches)
        let decision = sni_mux_decision(&cfg, Some("non.matching.com"));
        assert!(
            matches!(decision, MuxDecision::Terminate),
            "non.matching.com should be Terminate (forward to Pingora), got {:?}",
            decision
        );
    }

    // --- Segmented ClientHello handling (B1) ---

    #[test]
    fn classify_full_client_hello_is_complete_with_lowercased_sni() {
        let hello = build_client_hello("Foo.Example.COM");
        assert_eq!(
            classify_client_hello(&hello),
            ClientHelloPeek::Complete(Some("foo.example.com".to_string()))
        );
    }

    #[test]
    fn classify_truncated_client_hello_is_incomplete_at_every_cut() {
        let hello = build_client_hello("foo.example.com");
        // Every proper prefix must be reported as Incomplete, never as
        // Complete(None) (which would silently misroute to the HTTPS handler).
        for cut in 1..hello.len() {
            assert_eq!(
                classify_client_hello(&hello[..cut]),
                ClientHelloPeek::Incomplete,
                "prefix of {cut} bytes"
            );
        }
    }

    #[test]
    fn classify_non_tls_bytes_is_not_tls() {
        assert_eq!(
            classify_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            ClientHelloPeek::NotTls
        );
    }

    #[tokio::test]
    async fn peek_client_hello_waits_for_second_tcp_segment() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hello = build_client_hello("split.example.com");
        let (head, tail) = hello.split_at(hello.len() / 2);
        let (head, tail) = (head.to_vec(), tail.to_vec());

        let client = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.set_nodelay(true).unwrap();
            c.write_all(&head).await.unwrap();
            c.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            c.write_all(&tail).await.unwrap();
            c.flush().await.unwrap();
            // Keep the socket open until the server has peeked.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });

        let (server, _) = listener.accept().await.unwrap();
        let result = peek_client_hello(&server).await.unwrap();
        assert_eq!(
            result,
            ClientHelloPeek::Complete(Some("split.example.com".to_string()))
        );
        // Nothing was consumed: the full hello is still readable.
        let mut buf = vec![0u8; hello.len()];
        let n = server.peek(&mut buf).await.unwrap();
        assert_eq!(n, hello.len());
        client.await.unwrap();
    }

    #[tokio::test]
    async fn peek_client_hello_reports_not_tls_immediately() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(b"PING\r\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (server, _) = listener.accept().await.unwrap();
        let started = std::time::Instant::now();
        assert_eq!(peek_client_hello(&server).await.unwrap(), ClientHelloPeek::NotTls);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        client.await.unwrap();
    }

    // --- Idle-aware bidirectional copy (B2) ---

    #[tokio::test]
    async fn copy_bidirectional_idle_times_out_only_when_both_directions_idle() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, client_far) = tokio::io::duplex(1024);
        let (upstream, upstream_far) = tokio::io::duplex(1024);
        let idle = std::time::Duration::from_millis(100);
        let proxy = tokio::spawn(copy_bidirectional_idle(client, upstream, idle));

        // Traffic in one direction every 40 ms for 400 ms keeps the whole
        // session alive even though the other direction is silent.
        let (mut cf_r, mut cf_w) = tokio::io::split(client_far);
        let (mut uf_r, _uf_w) = tokio::io::split(upstream_far);
        for i in 0..10u8 {
            cf_w.write_all(&[i]).await.unwrap();
            let mut b = [0u8; 1];
            uf_r.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i);
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
        assert!(!proxy.is_finished(), "session must survive 400ms of one-way traffic");

        // Now go silent on both sides: the session closes with TimedOut.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), proxy)
            .await
            .expect("proxy must end after idle timeout")
            .unwrap();
        let err = result.expect_err("idle session must end with an error");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        let _ = cf_r.read(&mut [0u8; 1]).await;
    }

    #[tokio::test]
    async fn copy_bidirectional_idle_propagates_eof_and_returns_byte_counts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, client_far) = tokio::io::duplex(1024);
        let (upstream, upstream_far) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(copy_bidirectional_idle(
            client,
            upstream,
            std::time::Duration::from_secs(5),
        ));
        let (mut cf_r, mut cf_w) = tokio::io::split(client_far);
        let (mut uf_r, mut uf_w) = tokio::io::split(upstream_far);

        cf_w.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 5];
        uf_r.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");
        uf_w.write_all(b"world!!").await.unwrap();
        let mut b = [0u8; 7];
        cf_r.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"world!!");

        // Client closes its write side; upstream must see EOF, and once the
        // upstream closes too the proxy finishes with both byte counts.
        cf_w.shutdown().await.unwrap();
        let mut rest = Vec::new();
        uf_r.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        uf_w.shutdown().await.unwrap();
        let (a_to_b, b_to_a) = tokio::time::timeout(std::time::Duration::from_secs(2), proxy)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!((a_to_b, b_to_a), (5, 7));
    }
}
