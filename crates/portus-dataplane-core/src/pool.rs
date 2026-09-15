//! Per-(service, port) endpoint pools: round-robin selection over the
//! endpoints that are both healthy and enabled, with optional active HTTP
//! health checks.
//!
//! This is the network-stack-independent replacement for the load balancer the
//! data plane used to borrow from its proxy framework. The semantics are the
//! ones the rest of the data plane was written against:
//!
//! - an endpoint starts healthy and enabled;
//! - `ready` = healthy (active checks) AND enabled (passive ejection, see
//!   [`crate::outlier`]);
//! - health flips only after `consecutive_failure` failed checks in a row, or
//!   `consecutive_success` passed checks in a row, and the run counter resets
//!   whenever a check agrees with the current state;
//! - a health check is a plain `GET` to the configured path; any status other
//!   than `200` is a failure, as is a connect, read or timeout error.
//!
//! Selection is one atomic increment plus at most one pass over the pool, and
//! never allocates.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Active HTTP health check for every endpoint of a [`Pool`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    /// `Host` header sent with the probe (the Service name).
    pub host: String,
    /// Request path; `/` when the policy leaves it empty.
    pub path: String,
    /// Connect and read timeout for one probe.
    pub timeout: Duration,
    /// Passed checks in a row that flip an unhealthy endpoint to healthy.
    pub consecutive_success: usize,
    /// Failed checks in a row that flip a healthy endpoint to unhealthy.
    pub consecutive_failure: usize,
}

/// One backend address with its readiness state.
#[derive(Debug)]
pub struct Endpoint {
    pub addr: SocketAddr,
    /// Active health (set by [`Pool::run_health_check`]). Starts healthy.
    healthy: AtomicBool,
    /// Passive enable flag (outlier ejection). Starts enabled.
    enabled: AtomicBool,
    /// Checks in a row that disagree with `healthy`.
    consecutive: AtomicUsize,
}

impl Endpoint {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            healthy: AtomicBool::new(true),
            enabled: AtomicBool::new(true),
            consecutive: AtomicUsize::new(0),
        }
    }

    /// Healthy and enabled.
    #[inline]
    pub fn ready(&self) -> bool {
        self.healthy.load(Ordering::Relaxed) && self.enabled.load(Ordering::Relaxed)
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Record one health observation. Returns true when `healthy` flipped.
    fn observe(&self, healthy: bool, flip_threshold: usize) -> bool {
        if self.healthy.load(Ordering::Relaxed) == healthy {
            self.consecutive.store(0, Ordering::Relaxed);
            return false;
        }
        let run = self.consecutive.fetch_add(1, Ordering::Relaxed) + 1;
        if run >= flip_threshold.max(1) {
            self.healthy.store(healthy, Ordering::Relaxed);
            self.consecutive.store(0, Ordering::Relaxed);
            return true;
        }
        false
    }
}

/// Round-robin pool over the endpoints of one Service port.
#[derive(Debug)]
pub struct Pool {
    /// Sorted by address, duplicates removed, so two pools built from the same
    /// endpoint set iterate in the same order.
    endpoints: Vec<Endpoint>,
    next: AtomicUsize,
    health_check: Option<HealthCheck>,
}

impl Pool {
    /// A pool over `addrs` (order and duplicates do not matter).
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>, health_check: Option<HealthCheck>) -> Self {
        let mut addrs: Vec<SocketAddr> = addrs.into_iter().collect();
        addrs.sort_unstable();
        addrs.dedup();
        Self {
            endpoints: addrs.into_iter().map(Endpoint::new).collect(),
            next: AtomicUsize::new(0),
            health_check,
        }
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn health_check(&self) -> Option<&HealthCheck> {
        self.health_check.as_ref()
    }

    /// Next ready endpoint in round-robin order, or None when none is ready.
    pub fn select(&self) -> Option<SocketAddr> {
        let n = self.endpoints.len();
        if n == 0 {
            return None;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        (0..n)
            .map(|i| &self.endpoints[(start + i) % n])
            .find(|ep| ep.ready())
            .map(|ep| ep.addr)
    }

    fn endpoint(&self, addr: &SocketAddr) -> Option<&Endpoint> {
        self.endpoints.iter().find(|ep| ep.addr == *addr)
    }

    /// True when `addr` is in the pool and ready. An address that is not in
    /// the pool is not ready.
    pub fn ready(&self, addr: &SocketAddr) -> bool {
        self.endpoint(addr).is_some_and(Endpoint::ready)
    }

    pub fn ready_count(&self) -> usize {
        self.endpoints.iter().filter(|ep| ep.ready()).count()
    }

    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.endpoint(addr).is_some()
    }

    /// Passive enable flag for `addr`. Returns false when `addr` is not in
    /// the pool.
    pub fn set_enabled(&self, addr: &SocketAddr, enabled: bool) -> bool {
        match self.endpoint(addr) {
            Some(ep) => {
                ep.enabled.store(enabled, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Probe every endpoint once and update health. A no-op for a pool
    /// without a health check.
    pub async fn run_health_check(&self) {
        let Some(check) = &self.health_check else { return };
        for ep in &self.endpoints {
            let result = probe(ep.addr, check).await;
            let healthy = result.is_ok();
            let threshold = if healthy { check.consecutive_success } else { check.consecutive_failure };
            if ep.observe(healthy, threshold) {
                match result {
                    Ok(()) => info!("{} ({}) becomes healthy", ep.addr, check.host),
                    Err(e) => warn!("{} ({}) becomes unhealthy: {e}", ep.addr, check.host),
                }
            }
        }
    }
}

/// One `GET path` over a fresh TCP connection; Ok on a `200` status line.
async fn probe(addr: SocketAddr, check: &HealthCheck) -> Result<(), String> {
    let connect = tokio::net::TcpStream::connect(addr);
    let mut stream = tokio::time::timeout(check.timeout, connect)
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {e}"))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: portus-health\r\nConnection: close\r\n\r\n",
        check.path, check.host
    );
    let exchange = async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        let mut buf = [0u8; 64];
        let mut filled = 0;
        while filled < buf.len() {
            let n = stream
                .read(&mut buf[filled..])
                .await
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            filled += n;
            if buf[..filled].contains(&b'\n') {
                break;
            }
        }
        status_of(&buf[..filled])
    };
    let status = tokio::time::timeout(check.timeout, exchange)
        .await
        .map_err(|_| "read timed out".to_string())??;
    if status == 200 { Ok(()) } else { Err(format!("non-200 status {status}")) }
}

/// Status code from an HTTP/1.x status line prefix.
fn status_of(head: &[u8]) -> Result<u16, String> {
    let line = head.split(|b| *b == b'\n').next().unwrap_or(head);
    let line = std::str::from_utf8(line).map_err(|_| "status line is not UTF-8".to_string())?;
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(version), Some(code)) if version.starts_with("HTTP/1.") => {
            code.parse::<u16>().map_err(|_| format!("bad status code {code:?}"))
        }
        _ => Err(format!("not an HTTP status line: {line:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn pool(addrs: &[&str]) -> Pool {
        Pool::new(addrs.iter().map(|a| addr(a)), None)
    }

    #[test]
    fn round_robin_cycles_over_a_sorted_deduplicated_set() {
        let p = pool(&["10.0.0.2:80", "10.0.0.1:80", "10.0.0.2:80"]);
        assert_eq!(p.endpoints().len(), 2);
        let picks: Vec<_> = (0..4).map(|_| p.select().unwrap()).collect();
        assert_eq!(
            picks,
            vec![addr("10.0.0.1:80"), addr("10.0.0.2:80"), addr("10.0.0.1:80"), addr("10.0.0.2:80")]
        );
    }

    #[test]
    fn selection_skips_disabled_and_unhealthy_endpoints() {
        let p = pool(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
        assert!(p.set_enabled(&addr("10.0.0.2:80"), false));
        p.endpoint(&addr("10.0.0.3:80")).unwrap().healthy.store(false, Ordering::Relaxed);
        for _ in 0..6 {
            assert_eq!(p.select(), Some(addr("10.0.0.1:80")));
        }
        assert_eq!(p.ready_count(), 1);
        assert!(!p.ready(&addr("10.0.0.2:80")));
        assert!(!p.ready(&addr("10.0.0.3:80")));
        assert!(p.set_enabled(&addr("10.0.0.2:80"), true));
        assert!(p.ready(&addr("10.0.0.2:80")));
    }

    #[test]
    fn nothing_ready_selects_none_and_empty_pools_select_none() {
        let p = pool(&["10.0.0.1:80"]);
        p.set_enabled(&addr("10.0.0.1:80"), false);
        assert_eq!(p.select(), None);
        assert!(pool(&[]).select().is_none());
        assert!(pool(&[]).is_empty());
    }

    #[test]
    fn unknown_addresses_are_not_ready_and_cannot_be_toggled() {
        let p = pool(&["10.0.0.1:80"]);
        assert!(!p.ready(&addr("10.9.9.9:80")));
        assert!(!p.set_enabled(&addr("10.9.9.9:80"), false));
        assert!(!p.contains(&addr("10.9.9.9:80")));
        assert!(p.contains(&addr("10.0.0.1:80")));
    }

    #[test]
    fn health_flips_only_after_a_full_run_and_a_break_resets_the_run() {
        let ep = Endpoint::new(addr("10.0.0.1:80"));
        assert!(!ep.observe(false, 3));
        assert!(!ep.observe(false, 3));
        assert!(!ep.observe(true, 3), "a pass in between resets the failure run");
        assert!(ep.healthy());
        assert!(!ep.observe(false, 3));
        assert!(!ep.observe(false, 3));
        assert!(ep.observe(false, 3), "third failure in a row flips");
        assert!(!ep.healthy());
        assert!(ep.observe(true, 1), "threshold 1 flips on the first pass");
        assert!(ep.healthy());
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(status_of(b"HTTP/1.1 200 OK\r\n"), Ok(200));
        assert_eq!(status_of(b"HTTP/1.0 503 Service Unavailable\r\nX: y\r\n"), Ok(503));
        assert!(status_of(b"garbage").is_err());
        assert!(status_of(b"HTTP/1.1 abc\r\n").is_err());
        assert!(status_of(b"").is_err());
    }

    async fn http_server(status: u16) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
                        .await;
                });
            }
        });
        addr
    }

    fn check(threshold: usize) -> HealthCheck {
        HealthCheck {
            host: "svc".into(),
            path: "/healthz".into(),
            timeout: Duration::from_millis(500),
            consecutive_success: threshold,
            consecutive_failure: threshold,
        }
    }

    #[tokio::test]
    async fn health_checks_take_failing_endpoints_out_and_bring_them_back() {
        let good = http_server(200).await;
        let bad = http_server(500).await;
        // A refused connection: bind and drop so nothing listens on the port.
        let refused = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let p = Pool::new([good, bad, refused], Some(check(2)));
        p.run_health_check().await;
        assert_eq!(p.ready_count(), 3, "one failure is not a run of two");
        p.run_health_check().await;
        assert!(p.ready(&good));
        assert!(!p.ready(&bad), "500 twice in a row is unhealthy");
        assert!(!p.ready(&refused), "refused twice in a row is unhealthy");
        assert_eq!(p.select(), Some(good));
    }

    #[tokio::test]
    async fn a_pool_without_a_health_check_never_probes() {
        let refused = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let p = Pool::new([refused], None);
        p.run_health_check().await;
        assert!(p.ready(&refused));
    }

    #[tokio::test]
    async fn probe_times_out_on_a_silent_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut c = check(1);
        c.timeout = Duration::from_millis(100);
        let err = probe(silent, &c).await.unwrap_err();
        assert!(err.contains("timed out"), "{err}");
    }
}
