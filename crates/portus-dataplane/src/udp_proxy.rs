//! UDP proxy (UDPRoute).
//!
//! Pingora has no UDP path, so UDP listeners are served here. The listener
//! manager binds one `UdpSocket` per UDP listener port in the config (and
//! releases it when the listener goes away) and runs [`udp_listener_loop`] on
//! it. Every client, identified by its source address, gets a session: a
//! connected upstream socket to the backend chosen by weighted round robin
//! when the client's first datagram arrives, plus a task that copies the
//! backend's replies back to the client through the listener socket, so the
//! client sees answers from the address it sent to. A session ends after
//! `UDP_IDLE_TIMEOUT_SECS` (default 60) without traffic in either direction,
//! or when the upstream socket errors (ICMP port unreachable).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use log::{debug, info, warn};
use tokio::net::UdpSocket;

use crate::l4_proxy::{resolve_backend, L4ConfigSlot, L4RouteTarget};
use crate::router::ServiceLbMap;

/// Default idle timeout for a UDP session. Far shorter than the TCP default:
/// there is no close to observe, so idle is the only way a session ends.
/// Override with `UDP_IDLE_TIMEOUT_SECS`.
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on live sessions per listener port; new clients beyond it are
/// dropped until sessions expire.
pub(crate) const MAX_UDP_SESSIONS: usize = 65_536;

/// Largest UDP payload.
const DATAGRAM_MAX: usize = 65_535;

/// How often idle sessions are reaped.
const REAP_INTERVAL: Duration = Duration::from_secs(1);

/// Idle timeout for UDP sessions, read once from `UDP_IDLE_TIMEOUT_SECS`.
fn udp_idle_timeout() -> Duration {
    static IDLE: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *IDLE.get_or_init(|| {
        std::env::var("UDP_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT)
    })
}

/// State shared between a session's owner (the listener loop) and its reply
/// pump.
struct Activity {
    /// Milliseconds since the session table's `start` of the last datagram in
    /// either direction.
    last_ms: AtomicU64,
    /// Set by the reply pump when the upstream socket fails; the session is
    /// replaced on the client's next datagram and reaped otherwise.
    dead: AtomicBool,
}

struct Session {
    upstream: Arc<UdpSocket>,
    activity: Arc<Activity>,
    reply_pump: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.reply_pump.abort();
    }
}

/// The sessions of one UDP listener port.
pub(crate) struct Sessions {
    start: Instant,
    idle: Duration,
    max: usize,
    table: HashMap<SocketAddr, Session>,
}

impl Sessions {
    pub(crate) fn new(idle: Duration, max: usize) -> Self {
        Self {
            start: Instant::now(),
            idle,
            max,
            table: HashMap::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Forward one client datagram to its session's backend, opening the
    /// session (weighted backend choice, connected upstream socket, reply pump)
    /// for a peer that has none.
    pub(crate) async fn forward(
        &mut self,
        listener: &Arc<UdpSocket>,
        port: u16,
        peer: SocketAddr,
        payload: &[u8],
        target: &L4RouteTarget,
        lbs: &ServiceLbMap,
    ) -> Result<(), String> {
        let now = self.now_ms();
        if let Some(session) = self.table.get(&peer) {
            if session.activity.dead.load(Ordering::Relaxed) {
                self.table.remove(&peer);
            } else {
                session.activity.last_ms.store(now, Ordering::Relaxed);
                return session
                    .upstream
                    .send(payload)
                    .await
                    .map(drop)
                    .map_err(|e| format!("send to backend for {peer} failed: {e}"));
            }
        }

        if self.table.len() >= self.max {
            return Err(format!(
                "UDP session limit ({}) reached on port {port}; dropping datagram from {peer}",
                self.max
            ));
        }
        let backend = target
            .select()
            .ok_or_else(|| format!("UDP route on port {port} has no backend with weight > 0"))?;
        let addr = resolve_backend(lbs, &backend.service, backend.port)
            .ok_or_else(|| format!("no endpoints for UDP backend {}:{}", backend.service, backend.port))?;
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("bad backend address {addr} for {}: {e}", backend.service))?;
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let upstream = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("bind upstream UDP socket: {e}"))?;
        upstream
            .connect(addr)
            .await
            .map_err(|e| format!("connect upstream UDP socket to {addr}: {e}"))?;
        upstream
            .send(payload)
            .await
            .map_err(|e| format!("send to backend {addr} for {peer} failed: {e}"))?;
        let upstream = Arc::new(upstream);
        let activity = Arc::new(Activity {
            last_ms: AtomicU64::new(now),
            dead: AtomicBool::new(false),
        });
        let reply_pump = tokio::spawn(reply_pump(
            Arc::clone(&upstream),
            Arc::clone(listener),
            peer,
            Arc::clone(&activity),
            self.start,
        ));
        info!(
            "UDP proxy: session {peer} on port {port} -> {addr} ({})",
            backend.service
        );
        self.table.insert(peer, Session { upstream, activity, reply_pump });
        Ok(())
    }

    /// Drop sessions that are dead or idle for longer than the timeout.
    /// Returns how many were removed.
    pub(crate) fn reap(&mut self) -> usize {
        let now = self.now_ms();
        let idle_ms = u64::try_from(self.idle.as_millis()).unwrap_or(u64::MAX);
        let before = self.table.len();
        self.table.retain(|_, s| {
            !s.activity.dead.load(Ordering::Relaxed)
                && now.saturating_sub(s.activity.last_ms.load(Ordering::Relaxed)) < idle_ms
        });
        before - self.table.len()
    }
}

/// Copy backend replies to the client until the upstream socket fails.
async fn reply_pump(
    upstream: Arc<UdpSocket>,
    listener: Arc<UdpSocket>,
    peer: SocketAddr,
    activity: Arc<Activity>,
    start: Instant,
) {
    let mut buf = vec![0u8; DATAGRAM_MAX];
    loop {
        match upstream.recv(&mut buf).await {
            Ok(n) => {
                activity.last_ms.store(
                    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                if let Err(e) = listener.send_to(&buf[..n], peer).await {
                    debug!("UDP proxy: reply to {peer} failed: {e}");
                    break;
                }
            }
            Err(e) => {
                debug!("UDP proxy: backend for {peer} unreachable: {e}");
                break;
            }
        }
    }
    activity.dead.store(true, Ordering::Relaxed);
}

/// Serve one UDP listener port until aborted: forward every datagram through
/// its client's session to the backends of the UDPRoute programmed for `port`,
/// reaping idle sessions once a second. Datagrams arriving before a route is
/// programmed are dropped.
pub(crate) async fn udp_listener_loop(
    socket: Arc<UdpSocket>,
    port: u16,
    l4_config: L4ConfigSlot,
    lbs: ServiceLbMap,
) {
    let mut sessions = Sessions::new(udp_idle_timeout(), MAX_UDP_SESSIONS);
    let mut buf = vec![0u8; DATAGRAM_MAX];
    let mut reap = tokio::time::interval(REAP_INTERVAL);
    loop {
        tokio::select! {
            _ = reap.tick() => {
                let reaped = sessions.reap();
                if reaped > 0 {
                    debug!("UDP proxy: port {port}: reaped {reaped} idle sessions, {} live", sessions.len());
                }
            }
            received = socket.recv_from(&mut buf) => match received {
                Ok((n, peer)) => {
                    let target = l4_config.load().udp_proxy.get(&port).cloned();
                    let Some(target) = target else {
                        debug!("UDP proxy: UDP listener on port {port} has no UDPRoute yet; dropping datagram from {peer}");
                        continue;
                    };
                    if let Err(e) = sessions.forward(&socket, port, peer, &buf[..n], &target, &lbs).await {
                        warn!("UDP proxy: port {port}: {e}");
                    }
                }
                Err(e) => {
                    warn!("UDP proxy: recv error on port {port}: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4_proxy::{L4Backend, L4Config};
    use arc_swap::ArcSwap;
    use pingora_load_balancing::selection::RoundRobin;
    use pingora_load_balancing::{Backend, LoadBalancer};

    /// A UDP echo server that prefixes replies with its name so tests can tell
    /// backends apart.
    async fn echo_backend(name: &'static str) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else { break };
                let mut reply = name.as_bytes().to_vec();
                reply.push(b':');
                reply.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        addr
    }

    fn lbs_for(services: &[(&str, u16, SocketAddr)]) -> ServiceLbMap {
        let mut map = HashMap::new();
        for (svc, port, addr) in services {
            let lb = LoadBalancer::<RoundRobin>::try_from_iter([Backend::new(&addr.to_string()).unwrap()])
                .unwrap();
            map.insert((Arc::from(*svc), *port), Arc::new(lb));
        }
        Arc::new(ArcSwap::from_pointee(map))
    }

    fn target(backends: &[(&str, u16, u32)]) -> Arc<L4RouteTarget> {
        Arc::new(L4RouteTarget::new(
            backends
                .iter()
                .map(|(s, p, w)| L4Backend { service: (*s).to_string(), port: *p, weight: *w })
                .collect(),
        ))
    }

    async fn ask(listener: SocketAddr, msg: &[u8]) -> Vec<u8> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(msg, listener).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("reply within 2s")
            .unwrap();
        assert_eq!(from, listener, "the reply must come from the listener address, not the backend");
        buf[..n].to_vec()
    }

    #[tokio::test]
    async fn datagrams_are_proxied_and_replies_return_through_the_listener() {
        let backend = echo_backend("dns").await;
        let lbs = lbs_for(&[("coredns", 53, backend)]);
        let mut cfg = L4Config::default();
        cfg.udp_proxy.insert(5300, target(&[("coredns", 53, 1)]));
        let slot: L4ConfigSlot = Arc::new(ArcSwap::from_pointee(cfg));

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listener = socket.local_addr().unwrap();
        let loop_task = tokio::spawn(udp_listener_loop(socket, 5300, slot, lbs));

        assert_eq!(ask(listener, b"foo.bar.com").await, b"dns:foo.bar.com");
        // A second datagram from a new client works too (new session).
        assert_eq!(ask(listener, b"again").await, b"dns:again");
        loop_task.abort();
    }

    #[tokio::test]
    async fn a_client_keeps_its_backend_and_new_clients_follow_the_weights() {
        // udproute-weighted-routing: 2 / 1 / 0 across new clients; weight 0
        // never receives traffic.
        let v1 = echo_backend("v1").await;
        let v2 = echo_backend("v2").await;
        let v3 = echo_backend("v3").await;
        let lbs = lbs_for(&[("v1", 8080, v1), ("v2", 8080, v2), ("v3", 8080, v3)]);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut sessions = Sessions::new(Duration::from_secs(60), MAX_UDP_SESSIONS);
        let target = target(&[("v1", 8080, 2), ("v2", 8080, 1), ("v3", 8080, 0)]);

        let mut clients = Vec::new();
        let mut counts = std::collections::HashMap::new();
        for i in 0..30u8 {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = client.local_addr().unwrap();
            sessions.forward(&socket, 9999, peer, &[i], &target, &lbs).await.unwrap();
            let mut buf = [0u8; 64];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();
            let name = String::from_utf8_lossy(&buf[..n]).split(':').next().unwrap().to_string();
            *counts.entry(name).or_insert(0u32) += 1;
            clients.push((client, peer));
        }
        assert_eq!(counts.get("v1"), Some(&20));
        assert_eq!(counts.get("v2"), Some(&10));
        assert_eq!(counts.get("v3"), None, "weight 0 must never be selected");
        assert_eq!(sessions.len(), 30);

        // An existing client's second datagram reuses its session: same backend,
        // no new session.
        let (client, peer) = &clients[0];
        sessions.forward(&socket, 9999, *peer, b"x", &target, &lbs).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"v1:x");
        assert_eq!(sessions.len(), 30);
    }

    #[tokio::test]
    async fn idle_sessions_are_reaped_and_the_limit_is_enforced() {
        let backend = echo_backend("b").await;
        let lbs = lbs_for(&[("b", 1, backend)]);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = target(&[("b", 1, 1)]);
        let mut sessions = Sessions::new(Duration::from_millis(50), 1);

        let first: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        sessions.forward(&socket, 1, first, b"a", &target, &lbs).await.unwrap();
        let err = sessions.forward(&socket, 1, second, b"b", &target, &lbs).await.unwrap_err();
        assert!(err.contains("session limit"), "{err}");
        assert_eq!(sessions.reap(), 0, "fresh session is not idle");

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(sessions.reap(), 1);
        assert_eq!(sessions.len(), 0);
        sessions.forward(&socket, 1, second, b"b", &target, &lbs).await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn no_backend_with_weight_and_no_endpoints_are_errors_not_sessions() {
        let lbs = lbs_for(&[]);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: SocketAddr = "127.0.0.1:40003".parse().unwrap();
        let mut sessions = Sessions::new(Duration::from_secs(1), 10);

        let err = sessions.forward(&socket, 5300, peer, b"x", &target(&[("z", 1, 0)]), &lbs).await.unwrap_err();
        assert!(err.contains("weight > 0"), "{err}");
        let err = sessions.forward(&socket, 5300, peer, b"x", &target(&[("z", 1, 1)]), &lbs).await.unwrap_err();
        assert!(err.contains("no endpoints"), "{err}");
        assert_eq!(sessions.len(), 0);
    }
}
