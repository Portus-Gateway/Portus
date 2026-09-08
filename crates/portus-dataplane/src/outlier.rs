//! Passive outlier ejection.
//!
//! Round robin on its own keeps sending a share of requests to an endpoint
//! that refuses connections until Kubernetes takes it out of the EndpointSlice,
//! which for a pod that is up but broken (or blackholed) can be never. This
//! module watches what requests actually experience and takes a failing
//! endpoint out of rotation for a while: a connect failure ejects at once
//! (there is no ambiguity in a refused connection), a run of 5xx responses
//! ejects after [`OutlierConfig::consecutive_5xx`] in a row. Each further
//! ejection of the same endpoint lasts longer, up to a cap, and the count
//! decays once it has behaved for the cap's length. The last ready endpoint of
//! a pool is never ejected: a slow answer beats none.
//!
//! Ejection uses the load balancer's own enable flag, so selection stays a
//! single `ready()` check per candidate and an active `HealthCheckPolicy` on
//! the same pool composes with it (ready = healthy and enabled). A pool rebuilt
//! because its endpoints changed starts with everything enabled; an endpoint
//! that is still failing is simply ejected again on its next failure.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;

/// When an endpoint is ejected and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlierConfig {
    /// 5xx responses in a row that eject an endpoint. A connect failure always
    /// ejects on the first occurrence.
    pub consecutive_5xx: u32,
    /// First ejection lasts this long; the n-th lasts n times as long.
    pub base_ejection: Duration,
    /// Longest a single ejection lasts; also how long an endpoint must behave
    /// before its ejection count resets.
    pub max_ejection: Duration,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self {
            consecutive_5xx: 5,
            base_ejection: Duration::from_secs(10),
            max_ejection: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
struct EndpointRecord {
    consecutive_5xx: u32,
    ejections: u32,
    ejected_until: Option<Instant>,
    last_seen: Instant,
}

impl Default for EndpointRecord {
    fn default() -> Self {
        Self { consecutive_5xx: 0, ejections: 0, ejected_until: None, last_seen: Instant::now() }
    }
}

/// Records kept before stale endpoints (not seen for an hour) are dropped.
const PRUNE_ABOVE: usize = 4096;
const STALE_AFTER: Duration = Duration::from_secs(3600);

/// Per-endpoint failure history for every pool the data plane talks to.
pub struct Outliers {
    config: OutlierConfig,
    endpoints: DashMap<SocketAddr, EndpointRecord>,
}

impl Outliers {
    pub fn new(config: OutlierConfig) -> Self {
        Self { config, endpoints: DashMap::new() }
    }

    /// A connect to `addr` failed. Ejects it unless it is the pool's last
    /// ready endpoint or already out; returns how long it is out for.
    pub fn connect_failed(&self, lb: &Arc<LoadBalancer<RoundRobin>>, addr: &SocketAddr) -> Option<Duration> {
        self.eject(lb, addr)
    }

    /// `addr` answered `status`. A 5xx counts towards ejection; anything else
    /// clears the run and, after a long enough quiet spell, the ejection count.
    pub fn responded(&self, lb: &Arc<LoadBalancer<RoundRobin>>, addr: &SocketAddr, status: u16) -> Option<Duration> {
        let now = Instant::now();
        let eject = {
            let mut rec = self.endpoints.entry(addr.clone()).or_default();
            rec.last_seen = now;
            if status >= 500 {
                rec.consecutive_5xx += 1;
                rec.consecutive_5xx >= self.config.consecutive_5xx
            } else {
                rec.consecutive_5xx = 0;
                if rec.ejections > 0
                    && rec.ejected_until.is_some_and(|until| now.saturating_duration_since(until) >= self.config.max_ejection)
                {
                    rec.ejections = 0;
                    rec.ejected_until = None;
                }
                false
            }
        };
        if eject { self.eject(lb, addr) } else { None }
    }

    /// Remaining ejection time for `addr`, if it is currently out.
    #[cfg(test)]
    pub fn ejected_for(&self, addr: &SocketAddr) -> Option<Duration> {
        let until = self.endpoints.get(addr)?.ejected_until?;
        until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
    }

    fn eject(&self, lb: &Arc<LoadBalancer<RoundRobin>>, addr: &SocketAddr) -> Option<Duration> {
        let backends = lb.backends().get_backend();
        let backend = backends.iter().find(|b| b.addr == *addr)?;
        // Never empty the pool: with one endpoint left, a failing answer is
        // still better than "no ready endpoints".
        let ready = backends.iter().filter(|b| lb.backends().ready(b)).count();
        if ready <= 1 {
            return None;
        }
        let now = Instant::now();
        let duration = {
            let mut rec = self.endpoints.entry(addr.clone()).or_default();
            rec.last_seen = now;
            if rec.ejected_until.is_some_and(|until| until > now) {
                return None;
            }
            rec.ejections += 1;
            rec.consecutive_5xx = 0;
            let duration = self.config.base_ejection.saturating_mul(rec.ejections).min(self.config.max_ejection);
            rec.ejected_until = Some(now + duration);
            duration
        };
        lb.backends().set_enable(backend, false);
        let lb = Arc::clone(lb);
        let backend = backend.clone();
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            // A pool rebuilt meanwhile no longer holds this Arc; re-enabling the
            // old one is harmless and the new one started fully enabled.
            lb.backends().set_enable(&backend, true);
        });
        self.prune(now);
        Some(duration)
    }

    fn prune(&self, now: Instant) {
        if self.endpoints.len() > PRUNE_ABOVE {
            self.endpoints.retain(|_, rec| now.saturating_duration_since(rec.last_seen) < STALE_AFTER);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_load_balancing::Backend;

    fn pool(addrs: &[&str]) -> Arc<LoadBalancer<RoundRobin>> {
        Arc::new(LoadBalancer::try_from_iter(addrs.iter().copied()).unwrap())
    }

    fn backend(addr: &str) -> Backend {
        Backend::new(addr).unwrap()
    }

    fn ready(lb: &LoadBalancer<RoundRobin>, addr: &str) -> bool {
        lb.backends().ready(&backend(addr))
    }

    fn quick() -> Outliers {
        Outliers::new(OutlierConfig {
            consecutive_5xx: 3,
            base_ejection: Duration::from_millis(50),
            max_ejection: Duration::from_millis(120),
        })
    }

    #[tokio::test]
    async fn a_connect_failure_ejects_at_once_and_the_endpoint_comes_back() {
        let lb = pool(&["10.0.0.1:80", "10.0.0.2:80"]);
        let outliers = quick();
        let bad = backend("10.0.0.1:80").addr;
        let out = outliers.connect_failed(&lb, &bad).expect("ejected");
        assert_eq!(out, Duration::from_millis(50));
        assert!(!ready(&lb, "10.0.0.1:80"));
        assert!(ready(&lb, "10.0.0.2:80"));
        // Selection never lands on it while it is out.
        for _ in 0..20 {
            assert_eq!(lb.select(b"", 16).unwrap().addr, backend("10.0.0.2:80").addr);
        }
        // Already out: a second failure does not stack another ejection.
        assert!(outliers.connect_failed(&lb, &bad).is_none());
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert!(ready(&lb, "10.0.0.1:80"), "re-enabled when the ejection ends");
        assert!(outliers.ejected_for(&bad).is_none());
    }

    #[tokio::test]
    async fn repeated_ejections_grow_to_the_cap_and_decay_after_good_behaviour() {
        let lb = pool(&["10.0.0.1:80", "10.0.0.2:80"]);
        let outliers = quick();
        let bad = backend("10.0.0.1:80").addr;
        assert_eq!(outliers.connect_failed(&lb, &bad), Some(Duration::from_millis(50)));
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(outliers.connect_failed(&lb, &bad), Some(Duration::from_millis(100)));
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(outliers.connect_failed(&lb, &bad), Some(Duration::from_millis(120)), "capped");
        // Quiet for longer than the cap after the ejection ended: the count resets.
        tokio::time::sleep(Duration::from_millis(260)).await;
        assert!(outliers.responded(&lb, &bad, 200).is_none());
        assert_eq!(outliers.connect_failed(&lb, &bad), Some(Duration::from_millis(50)));
    }

    #[tokio::test]
    async fn the_last_ready_endpoint_is_never_ejected() {
        let lb = pool(&["10.0.0.1:80", "10.0.0.2:80"]);
        let outliers = quick();
        assert!(outliers.connect_failed(&lb, &backend("10.0.0.1:80").addr).is_some());
        assert!(outliers.connect_failed(&lb, &backend("10.0.0.2:80").addr).is_none());
        assert!(ready(&lb, "10.0.0.2:80"));
        assert!(lb.select(b"", 16).is_some());
        // A pool of one is never touched at all.
        let single = pool(&["10.0.0.9:80"]);
        assert!(outliers.connect_failed(&single, &backend("10.0.0.9:80").addr).is_none());
        assert!(ready(&single, "10.0.0.9:80"));
    }

    #[tokio::test]
    async fn five_xx_eject_only_in_a_run_and_a_success_clears_it() {
        let lb = pool(&["10.0.0.1:80", "10.0.0.2:80"]);
        let outliers = quick();
        let flaky = backend("10.0.0.1:80").addr;
        assert!(outliers.responded(&lb, &flaky, 503).is_none());
        assert!(outliers.responded(&lb, &flaky, 500).is_none());
        assert!(outliers.responded(&lb, &flaky, 204).is_none(), "a success ends the run");
        assert!(outliers.responded(&lb, &flaky, 502).is_none());
        assert!(outliers.responded(&lb, &flaky, 502).is_none());
        assert!(ready(&lb, "10.0.0.1:80"));
        assert!(outliers.responded(&lb, &flaky, 502).is_some(), "third in a row");
        assert!(!ready(&lb, "10.0.0.1:80"));
        // 4xx are the client's problem, not the endpoint's.
        let other = backend("10.0.0.2:80").addr;
        for _ in 0..10 {
            assert!(outliers.responded(&lb, &other, 404).is_none());
        }
        assert!(ready(&lb, "10.0.0.2:80"));
    }

    #[tokio::test]
    async fn an_address_not_in_the_pool_is_ignored() {
        let lb = pool(&["10.0.0.1:80", "10.0.0.2:80"]);
        let outliers = quick();
        assert!(outliers.connect_failed(&lb, &backend("10.9.9.9:80").addr).is_none());
        assert!(ready(&lb, "10.0.0.1:80") && ready(&lb, "10.0.0.2:80"));
    }
}
