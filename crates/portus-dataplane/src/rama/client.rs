//! The upstream HTTP client: our own connector over Rama's TCP and TLS
//! connectors and its HTTP/1 and HTTP/2 client connections.
//!
//! One request does exactly this: read the [`UpstreamTarget`] the proxy put
//! on it, take an idle connection for that target from the target's shard
//! (or dial and handshake one), send, and return the connection when the
//! response body has been consumed. There is no adapter chain, no
//! per-request extension cloning and no global pool lock. A connection
//! verified under one BackendTLSPolicy never serves another because the TLS
//! fingerprint is part of the shard key, and the HTTP version is pinned per
//! target (TLS ALPN included) so an HTTP/1 route never lands on an h2
//! connection.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use log::debug;
use prometheus::{IntCounterVec, Opts};
use rama::error::BoxError;
use rama::extensions::{Extension, ExtensionsRef};
use rama::http::body::GuardedBody;
use rama::http::core::client::conn::{http1, http2};
use rama::http::io::upgrade::OnUpgrade;
use rama::http::layer::version_adapter::adapt_request_version;
use rama::http::{Body, Request, Response, Version};
use rama::net::address::HostWithPort;
use rama::net::client::{ConnectRequest, ConnectorService, EstablishedClientConnection};
use rama::net::http::TargetHttpVersion;
use rama::net::Protocol;
use rama::rt::Executor;
use rama::tcp::client::service::TcpConnector;
use rama::tcp::client::TcpStreamConnector;
use rama::tcp::TcpStream;
use rama::tls::client::TlsClientConfig;
use rama::tls::rustls::client::TlsConnector;
use rama::Service;

use portus_dataplane_core::h2::{UPSTREAM_H2_CONNECTION_WINDOW, UPSTREAM_H2_STREAM_WINDOW};

/// Idle HTTP/1 upstream connections kept per pod across all targets; the
/// Pingora stack keeps 2048. At 64 KiB of read buffer each this is 64 MiB
/// worst case, and a full budget evicts the oldest idle connection rather
/// than dropping a live one.
const MAX_IDLE_TOTAL: usize = 1024;
/// Idle HTTP/1 connections kept per target.
const MAX_IDLE_PER_TARGET: usize = 256;
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// hyper grows the HTTP/1 read buffer to 400 KiB per connection; 64 KiB is
/// plenty for a response head and keeps 256 idle connections at 16 MiB.
const H1_CLIENT_MAX_BUF: usize = 64 * 1024;
/// Streams a gRPC or h2c backend may have in flight on one connection.
const H2_MAX_CONCURRENT_STREAMS: u32 = 200;
const H2_KEEPALIVE: Duration = Duration::from_secs(30);
/// Multiplexed connections per HTTP/2 target. One connection serialises
/// every stream through one socket and one driver task; a small set spreads
/// the load the way a pool of HTTP/1 connections does.
const H2_CONNS_PER_TARGET: usize = 32;
/// How often idle connections nobody asks for any more are evicted, so a
/// target that stopped receiving traffic does not hold the pod's idle budget.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Where a request goes and under what identity, set by the proxy service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
pub struct UpstreamTarget {
    pub addr: SocketAddr,
    pub tls: bool,
    /// Fingerprint of the TLS verification parameters and client identity;
    /// zero for plaintext.
    pub tls_key: u64,
    /// The backend speaks HTTP/2 (gRPC, h2c): one multiplexed connection.
    pub h2: bool,
}

/// Dials upstreams with TCP_NODELAY, as Pingora's connector does. Rama's
/// default connector leaves Nagle on, which stalls request/response bodies
/// written in two segments behind delayed ACKs.
#[derive(Debug, Clone, Default)]
struct NoDelayConnector;

impl TcpStreamConnector for NoDelayConnector {
    type Error = std::io::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream.into())
    }
}

enum Sender {
    H1(tokio::sync::Mutex<http1::SendRequest<Body>>),
    H2(http2::SendRequest<Body>),
}

/// One established upstream connection.
struct Conn {
    sender: Sender,
    version: Version,
    /// Set by the connection driver when the connection ends and by a send
    /// that failed; a broken connection is never handed out again.
    broken: Arc<AtomicBool>,
}

impl Conn {
    /// Marked broken, or closed by the peer (an upstream `Connection: close`
    /// lands here before the driver task has observed the end).
    fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
            || match &self.sender {
                Sender::H1(sender) => sender.try_lock().is_ok_and(|s| s.is_closed()),
                Sender::H2(sender) => sender.is_closed(),
            }
    }

    fn mark_broken(&self) {
        self.broken.store(true, Ordering::Relaxed);
    }
}

struct Idle {
    conn: Arc<Conn>,
    since: Instant,
}

/// Idle HTTP/1 connections, one shard per target.
struct Pool {
    shards: DashMap<UpstreamTarget, VecDeque<Idle>>,
    idle_total: AtomicUsize,
    /// `proxy_upstream_pool_events_total{event}`: every decision the pool
    /// takes, so connection churn is visible on :9090 instead of in `ss`.
    events: IntCounterVec,
}

impl Pool {
    fn new() -> Self {
        let events = IntCounterVec::new(
            Opts::new("proxy_upstream_pool_events_total", "Upstream connection pool decisions by event"),
            &["event"],
        )
        .expect("static metric definition");
        // A second Upstream in one process (tests) shares the registry; the
        // counters still work unregistered.
        let _ = prometheus::register(Box::new(events.clone()));
        Self { shards: DashMap::new(), idle_total: AtomicUsize::new(0), events }
    }

    fn event(&self, name: &str) {
        self.events.with_label_values(&[name]).inc();
    }

    /// A healthy, unexpired idle connection for `target`, if any.
    fn take(&self, target: &UpstreamTarget) -> Option<Arc<Conn>> {
        let Some(mut shard) = self.shards.get_mut(target) else {
            self.event("miss_no_shard");
            return None;
        };
        while let Some(idle) = shard.pop_front() {
            self.idle_total.fetch_sub(1, Ordering::Relaxed);
            if idle.since.elapsed() >= IDLE_TIMEOUT {
                self.event("idle_expired");
            } else if idle.conn.broken() {
                self.event("idle_broken");
            } else {
                self.event("reuse");
                return Some(idle.conn);
            }
        }
        self.event("miss_empty");
        None
    }

    /// Drop idle connections older than `max_age` from every shard and
    /// forget empty shards. `take` only evicts from the shard it is asked
    /// for, so without this a target that stopped receiving traffic would
    /// keep its expired connections counted against the pod's budget.
    fn evict_idle_older_than(&self, max_age: Duration) -> usize {
        let mut evicted = 0;
        self.shards.retain(|_, shard| {
            let before = shard.len();
            shard.retain(|idle| idle.since.elapsed() < max_age);
            evicted += before - shard.len();
            !shard.is_empty()
        });
        if evicted > 0 {
            self.idle_total.fetch_sub(evicted, Ordering::Relaxed);
            self.events.with_label_values(&["idle_expired"]).inc_by(evicted as u64);
        }
        evicted
    }

    /// Drop the idle connection that has waited longest, whichever target
    /// it belongs to. Runs only when the pod's budget is full, so a
    /// connection that just finished a request displaces a stale one.
    fn evict_oldest(&self) -> bool {
        let oldest = self
            .shards
            .iter()
            .filter_map(|shard| shard.front().map(|idle| (idle.since, *shard.key())))
            .min_by_key(|(since, _)| *since)
            .map(|(_, key)| key);
        let Some(key) = oldest else { return false };
        let Some(mut shard) = self.shards.get_mut(&key) else { return false };
        if shard.pop_front().is_none() {
            return false;
        }
        self.idle_total.fetch_sub(1, Ordering::Relaxed);
        self.event("evicted_oldest");
        true
    }

    /// Return a connection; when the pod's budget is full the oldest idle
    /// connection makes room, and a full target drops it.
    fn put(&self, target: UpstreamTarget, conn: Arc<Conn>) {
        if self.idle_total.load(Ordering::Relaxed) >= MAX_IDLE_TOTAL
            && self.evict_idle_older_than(IDLE_TIMEOUT) == 0
            && !self.evict_oldest()
        {
            self.event("return_dropped_pod_full");
            return;
        }
        let mut shard = self.shards.entry(target).or_default();
        if shard.len() >= MAX_IDLE_PER_TARGET {
            self.event("return_dropped_target_full");
            return;
        }
        shard.push_back(Idle { conn, since: Instant::now() });
        self.idle_total.fetch_add(1, Ordering::Relaxed);
        self.event("returned");
    }
}

/// A connection on loan for one request. Returns to the pool on drop, which
/// the response body's guard delays until the body has been consumed.
struct Lease {
    conn: Arc<Conn>,
    target: UpstreamTarget,
    pool: Arc<Pool>,
    reusable: AtomicBool,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.reusable.load(Ordering::Relaxed) {
            self.pool.event("return_skipped_not_reusable");
        } else if self.conn.broken() {
            self.pool.event("return_skipped_broken");
        } else {
            self.pool.put(self.target, Arc::clone(&self.conn));
        }
    }
}

type Dialer = TlsConnector<TcpConnector<NoDelayConnector>>;

pub struct Upstream {
    dialer: Dialer,
    exec: Executor,
    pool: Arc<Pool>,
    /// Multiplexed HTTP/2 connections per target, used round-robin.
    h2: Mutex<HashMap<UpstreamTarget, Vec<Arc<Conn>>>>,
    h2_next: AtomicUsize,
}

impl Upstream {
    pub fn new(exec: Executor) -> Self {
        let tcp = TcpConnector::new().with_connector(NoDelayConnector);
        let dialer = TlsConnector::auto(tcp).with_base_config(TlsClientConfig::default_http());
        let pool = Arc::new(Pool::new());
        let sweeper = Arc::clone(&pool);
        exec.spawn_task(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                sweeper.evict_idle_older_than(IDLE_TIMEOUT);
            }
        });
        Self { dialer, exec, pool, h2: Mutex::new(HashMap::new()), h2_next: AtomicUsize::new(0) }
    }

    /// Dial `target` and complete the handshake for the target's protocol.
    async fn connect(&self, req: &Request, target: UpstreamTarget) -> Result<Arc<Conn>, BoxError> {
        // The TLS connector reads its per-request parameters (server name,
        // trust anchors, client identity, verifier) from the connect request's
        // extensions, so they are forked from the request only when dialling.
        // TargetHttpVersion pins the ALPN offer to the one protocol the
        // handshake below speaks.
        let extensions = req.extensions().fork();
        extensions.insert(TargetHttpVersion(if target.h2 { Version::HTTP_2 } else { Version::HTTP_11 }));
        let connect_req = ConnectRequest::new_with_extensions(HostWithPort::from(target.addr), extensions)
            .with_application_protocol(if target.tls { Protocol::HTTPS } else { Protocol::HTTP });
        self.pool.event("dial");
        let EstablishedClientConnection { conn: io, .. } = self.dialer.connect(connect_req).await?;
        let broken = Arc::new(AtomicBool::new(false));

        if target.h2 {
            let mut builder = http2::Builder::new(self.exec.clone());
            builder.set_initial_stream_window_size(UPSTREAM_H2_STREAM_WINDOW);
            builder.set_initial_connection_window_size(UPSTREAM_H2_CONNECTION_WINDOW);
            builder.set_max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
            builder.set_keep_alive_interval(H2_KEEPALIVE);
            let (sender, conn) = builder.handshake(io).await?;
            let flag = Arc::clone(&broken);
            let pool = Arc::clone(&self.pool);
            self.exec.spawn_task(async move {
                match conn.await {
                    Ok(()) => pool.event("h2_conn_ended"),
                    Err(e) => {
                        debug!("upstream h2 connection ended: {e}");
                        pool.event("h2_conn_error");
                    }
                }
                flag.store(true, Ordering::Relaxed);
            });
            Ok(Arc::new(Conn { sender: Sender::H2(sender), version: Version::HTTP_2, broken }))
        } else {
            let mut builder = http1::Builder::new();
            builder.try_set_max_buf_size(H1_CLIENT_MAX_BUF)?;
            let (sender, conn) = builder.handshake(io).await?;
            let conn = conn.with_upgrades();
            let flag = Arc::clone(&broken);
            let pool = Arc::clone(&self.pool);
            self.exec.spawn_task(async move {
                match conn.await {
                    Ok(()) => pool.event("h1_conn_ended"),
                    Err(e) => {
                        debug!("upstream h1 connection ended: {e}");
                        pool.event("h1_conn_error");
                    }
                }
                flag.store(true, Ordering::Relaxed);
            });
            Ok(Arc::new(Conn {
                sender: Sender::H1(tokio::sync::Mutex::new(sender)),
                version: Version::HTTP_11,
                broken,
            }))
        }
    }

    fn poisoned<T>(_: T) -> BoxError {
        BoxError::from("upstream h2 connection map poisoned")
    }

    async fn lease(&self, req: &Request, target: UpstreamTarget) -> Result<Lease, BoxError> {
        let pool = Arc::clone(&self.pool);
        if target.h2 {
            // Fill the target's set first, then rotate through it. Broken
            // connections leave the set when they are next seen.
            let existing = {
                let mut map = self.h2.lock().map_err(Self::poisoned)?;
                let conns = map.entry(target).or_default();
                conns.retain(|c| !c.broken());
                if conns.len() >= H2_CONNS_PER_TARGET {
                    let i = self.h2_next.fetch_add(1, Ordering::Relaxed) % conns.len();
                    Some(Arc::clone(&conns[i]))
                } else {
                    None
                }
            };
            let conn = match existing {
                Some(c) => {
                    self.pool.event("h2_reuse");
                    c
                }
                None => {
                    let c = self.connect(req, target).await?;
                    let mut map = self.h2.lock().map_err(Self::poisoned)?;
                    let conns = map.entry(target).or_default();
                    if conns.len() < H2_CONNS_PER_TARGET {
                        conns.push(Arc::clone(&c));
                    }
                    c
                }
            };
            // Shared, never returned to the HTTP/1 idle list.
            return Ok(Lease { conn, target, pool, reusable: AtomicBool::new(false) });
        }
        let conn = match self.pool.take(&target) {
            Some(c) => c,
            None => self.connect(req, target).await?,
        };
        Ok(Lease { conn, target, pool, reusable: AtomicBool::new(true) })
    }
}

impl Service<Request> for Upstream {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request) -> Result<Response, BoxError> {
        let target = *req
            .extensions()
            .get_ref::<UpstreamTarget>()
            .ok_or_else(|| BoxError::from("upstream request without a target"))?;
        let lease = self.lease(&req, target).await?;
        let conn = &lease.conn;
        adapt_request_version(&mut req, conn.version)?;

        let sent = match &conn.sender {
            Sender::H1(sender) => {
                let mut sender = sender.lock().await;
                match sender.ready().await {
                    Ok(()) => sender.send_request(req).await,
                    Err(e) => Err(e),
                }
            }
            Sender::H2(sender) => {
                let mut sender = sender.clone();
                match sender.ready().await {
                    Ok(()) => sender.send_request(req).await,
                    Err(e) => Err(e),
                }
            }
        };
        let resp = match sent {
            Ok(resp) => resp,
            Err(e) => {
                conn.mark_broken();
                self.pool.event("send_failed");
                return Err(e.into());
            }
        };
        // An upgraded HTTP/1 connection belongs to the two byte streams now.
        if resp.extensions().contains::<OnUpgrade>() {
            lease.reusable.store(false, Ordering::Relaxed);
        }
        Ok(resp.map(|body| Body::new(GuardedBody::new(body, lease))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::extensions::Extensions;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    /// A duplex stream with extensions: what the handshakes need from IO.
    struct TestIo(DuplexStream, Extensions);

    impl ExtensionsRef for TestIo {
        fn extensions(&self) -> &Extensions {
            &self.1
        }
    }
    impl AsyncRead for TestIo {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for TestIo {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    fn target(port: u16, tls_key: u64, h2: bool) -> UpstreamTarget {
        UpstreamTarget { addr: format!("10.0.0.1:{port}").parse().unwrap(), tls: tls_key != 0, tls_key, h2 }
    }

    /// An HTTP/1 connection whose peer never answers: enough for the pool.
    async fn conn() -> Arc<Conn> {
        let (a, b) = tokio::io::duplex(4096);
        // Keep the peer open and drive the connection so it counts as live.
        tokio::spawn(async move {
            let _peer = b;
            std::future::pending::<()>().await
        });
        let (sender, conn) = http1::Builder::new().handshake::<_, Body>(TestIo(a, Extensions::new())).await.unwrap();
        tokio::spawn(conn);
        Arc::new(Conn {
            sender: Sender::H1(tokio::sync::Mutex::new(sender)),
            version: Version::HTTP_11,
            broken: Arc::new(AtomicBool::new(false)),
        })
    }

    #[tokio::test]
    async fn pool_keys_on_target_tls_identity_and_protocol() {
        let pool = Pool::new();
        let a = target(8080, 0, false);
        let b = target(8080, 7, false);
        let c = target(8080, 0, true);
        pool.put(a, conn().await);
        assert!(pool.take(&b).is_none(), "another TLS policy never gets this connection");
        assert!(pool.take(&c).is_none(), "another protocol never gets this connection");
        assert!(pool.take(&a).is_some());
        assert!(pool.take(&a).is_none(), "taken");
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn pool_discards_broken_connections_and_caps_each_target() {
        let pool = Pool::new();
        let a = target(8080, 0, false);
        let broken = conn().await;
        broken.mark_broken();
        pool.put(a, broken);
        assert!(pool.take(&a).is_none(), "a broken connection is discarded on take");
        for _ in 0..(MAX_IDLE_PER_TARGET + 5) {
            pool.put(a, conn().await);
        }
        assert_eq!(pool.shards.get(&a).unwrap().len(), MAX_IDLE_PER_TARGET);
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), MAX_IDLE_PER_TARGET);
    }

    #[tokio::test]
    async fn expired_idle_connections_of_a_quiet_target_free_the_pod_budget() {
        let pool = Pool::new();
        let quiet = target(8080, 0, false);
        let busy = target(8081, 0, false);
        for _ in 0..3 {
            pool.put(quiet, conn().await);
        }
        assert_eq!(pool.evict_idle_older_than(IDLE_TIMEOUT), 0, "fresh connections stay");
        assert_eq!(pool.evict_idle_older_than(Duration::ZERO), 3, "expired ones go, whoever asks");
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 0);
        assert!(!pool.shards.contains_key(&quiet), "empty shards are forgotten");
        // A pod-full return evicts expired idle connections before giving up.
        let quiet_targets: Vec<_> = (0..MAX_IDLE_TOTAL / MAX_IDLE_PER_TARGET).map(|i| target(9000 + i as u16, 0, false)).collect();
        for t in &quiet_targets {
            for _ in 0..MAX_IDLE_PER_TARGET {
                pool.put(*t, conn().await);
            }
        }
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), MAX_IDLE_TOTAL, "pod budget is full");
        pool.shards.iter_mut().for_each(|mut shard| shard.iter_mut().for_each(|i| i.since -= IDLE_TIMEOUT * 2));
        pool.put(busy, conn().await);
        assert_eq!(pool.shards.get(&busy).unwrap().len(), 1, "the live connection is kept");
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_full_pod_budget_evicts_the_oldest_idle_connection_not_the_returning_one() {
        let pool = Pool::new();
        let targets: Vec<_> = (0..MAX_IDLE_TOTAL / MAX_IDLE_PER_TARGET).map(|i| target(9000 + i as u16, 0, false)).collect();
        for t in &targets {
            for _ in 0..MAX_IDLE_PER_TARGET {
                pool.put(*t, conn().await);
            }
        }
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), MAX_IDLE_TOTAL);
        // Make one specific connection the oldest without expiring anything.
        pool.shards.get_mut(&targets[1]).unwrap().front_mut().unwrap().since -= Duration::from_secs(1);
        let newcomer = target(8081, 0, false);
        pool.put(newcomer, conn().await);
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), MAX_IDLE_TOTAL, "budget holds");
        assert_eq!(pool.shards.get(&newcomer).unwrap().len(), 1, "the returning connection is kept");
        assert_eq!(pool.shards.get(&targets[1]).unwrap().len(), MAX_IDLE_PER_TARGET - 1, "the oldest one left");
    }

    #[tokio::test]
    async fn a_lease_returns_its_connection_only_when_reusable_and_healthy() {
        let pool = Arc::new(Pool::new());
        let a = target(8080, 0, false);
        drop(Lease { conn: conn().await, target: a, pool: Arc::clone(&pool), reusable: AtomicBool::new(true) });
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 1);
        drop(Lease { conn: conn().await, target: a, pool: Arc::clone(&pool), reusable: AtomicBool::new(false) });
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 1, "an upgraded connection is not pooled");
        let broken = conn().await;
        broken.mark_broken();
        drop(Lease { conn: broken, target: a, pool: Arc::clone(&pool), reusable: AtomicBool::new(true) });
        assert_eq!(pool.idle_total.load(Ordering::Relaxed), 1, "a broken connection is not pooled");
    }

    /// A plaintext HTTP/1 server that answers every request with a 1 KiB
    /// body on the same connection and counts the connections it accepted.
    async fn echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            buf.drain(..end + 4);
                            let mut resp = b"HTTP/1.1 200 OK\r\ncontent-length: 1024\r\n\r\n".to_vec();
                            resp.extend(std::iter::repeat_n(b'x', 1024));
                            if sock.write_all(&resp).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        (addr, accepted)
    }

    fn get(addr: SocketAddr) -> Request {
        let req = Request::builder().uri(format!("http://{addr}/")).body(Body::empty()).unwrap();
        req.extensions().insert(UpstreamTarget { addr, tls: false, tls_key: 0, h2: false });
        req
    }

    #[tokio::test]
    async fn sequential_requests_to_one_target_reuse_the_connection() {
        use rama::http::body::util::BodyExt;
        let (addr, accepted) = echo_server().await;
        let upstream = Upstream::new(Executor::default());
        for _ in 0..5 {
            let resp = upstream.serve(get(addr)).await.unwrap();
            assert_eq!(resp.status(), 200);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), 1024);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "five sequential requests must ride one connection");
        assert_eq!(upstream.pool.idle_total.load(Ordering::Relaxed), 1);
    }

    /// The real shape: a Rama HTTP/1 server forwards through `Upstream`
    /// and a keep-alive client sends requests back to back. The upstream
    /// connection must be back in the pool before the next request lands.
    #[tokio::test]
    async fn back_to_back_proxied_requests_reuse_the_upstream_connection() {
        use rama::http::server::HttpServer;
        use rama::rt::Executor;
        use rama::service::service_fn;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, accepted) = echo_server().await;
        let upstream = Arc::new(Upstream::new(Executor::default()));
        let forward = {
            let upstream = Arc::clone(&upstream);
            service_fn(move |req: Request| {
                let upstream = Arc::clone(&upstream);
                async move {
                    req.extensions().insert(UpstreamTarget { addr, tls: false, tls_key: 0, h2: false });
                    Ok::<_, std::convert::Infallible>(match upstream.serve(req).await {
                        Ok(resp) => resp,
                        Err(e) => Response::builder().status(502).body(Body::from(e.to_string())).unwrap(),
                    })
                }
            })
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let server = HttpServer::auto(Executor::default()).service(forward);
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                let server = server.clone();
                tokio::spawn(async move {
                    let _ = server.serve(rama::tcp::TcpStream::new(sock)).await;
                });
            }
        });

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = vec![0u8; 8192];
        for _ in 0..8 {
            client.write_all(b"GET /echo HTTP/1.1\r\nhost: bench\r\n\r\n").await.unwrap();
            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == b"\r\n\r\n") || got.len() < head_len(&got) + 1024 {
                let n = client.read(&mut buf).await.unwrap();
                assert!(n > 0, "proxy closed the connection");
                got.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "eight back-to-back requests must ride one upstream connection");
    }

    fn head_len(bytes: &[u8]) -> usize {
        bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(usize::MAX / 2)
    }

    #[tokio::test]
    async fn a_request_without_a_target_is_refused() {
        let upstream = Upstream::new(Executor::default());
        let err = upstream.serve(Request::new(Body::empty())).await.expect_err("refused");
        assert!(err.to_string().contains("without a target"), "{err}");
    }
}
