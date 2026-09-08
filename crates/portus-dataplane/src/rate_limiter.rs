//! Token bucket rate limiter with shared (per-route) and per-client-IP modes.
//!
//! Shared mode: one bucket per route, all clients share it (default).
//! Per-client mode: each client IP gets its own bucket with time-based eviction.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Lock-free token bucket using a single AtomicU64.
///
/// Layout: upper 32 bits = seconds since `epoch` of last refill,
///         lower 32 bits = remaining tokens.
pub(crate) struct AtomicTokenBucket {
    state: AtomicU64,
    pub(crate) rps: u32,
    epoch: Instant,
}

impl AtomicTokenBucket {
    pub(crate) fn new(rps: u32) -> Self {
        Self {
            state: AtomicU64::new(rps as u64),
            rps,
            epoch: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed.
    pub(crate) fn try_acquire(&self) -> bool {
        let now_secs = self.epoch.elapsed().as_secs() as u32;

        loop {
            let current = self.state.load(Ordering::Relaxed);
            let old_secs = (current >> 32) as u32;
            let old_tokens = (current & 0xFFFF_FFFF) as u32;

            let elapsed_secs = now_secs.wrapping_sub(old_secs);
            let refill = if elapsed_secs >= 1 {
                ((elapsed_secs as u64) * (self.rps as u64)).min(self.rps as u64) as u32
            } else {
                0
            };

            let new_secs = if refill > 0 { now_secs } else { old_secs };

            let available = old_tokens.saturating_add(refill).min(self.rps);

            if available == 0 {
                return false;
            }

            let new_tokens = available - 1;
            let new_state = ((new_secs as u64) << 32) | (new_tokens as u64);

            match self.state.compare_exchange_weak(
                current,
                new_state,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

/// Per-IP rate limiter. Each client IP gets its own token bucket.
/// Buckets unused for longer than the eviction threshold are cleaned up
/// periodically to prevent unbounded memory growth.
pub(crate) struct PerIpRateLimiter {
    buckets: DashMap<IpAddr, (AtomicTokenBucket, AtomicU64)>, // (bucket, last_access_epoch_ms)
    pub(crate) rps: u32,
    epoch: Instant,
}

impl PerIpRateLimiter {
    pub(crate) fn new(rps: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            rps,
            epoch: Instant::now(),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr) -> bool {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        // Fast path: a shard *read* lock. The entry API below takes the shard
        // write lock, which would serialise every request from hot IPs on the
        // same shard even though the bucket itself is lock-free.
        if let Some(entry) = self.buckets.get(&ip) {
            entry.value().1.store(now_ms, Ordering::Relaxed);
            return entry.value().0.try_acquire();
        }
        let entry = self.buckets.entry(ip).or_insert_with(|| {
            (AtomicTokenBucket::new(self.rps), AtomicU64::new(now_ms))
        });
        entry.value().1.store(now_ms, Ordering::Relaxed);
        entry.value().0.try_acquire()
    }

    pub(crate) fn evict_idle(&self, max_idle: Duration) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let max_idle_ms = max_idle.as_millis() as u64;
        self.buckets.retain(|_, (_, last_access)| {
            now_ms.saturating_sub(last_access.load(Ordering::Relaxed)) < max_idle_ms
        });
    }
}

/// Rate limiter mode for a route.
#[derive(Clone)]
pub(crate) enum RateLimiterMode {
    /// Shared bucket: all clients share one token bucket (default).
    Shared(std::sync::Arc<AtomicTokenBucket>),
    /// Per-IP: each client IP gets its own token bucket.
    PerIp(std::sync::Arc<PerIpRateLimiter>),
}

impl RateLimiterMode {
    pub(crate) fn rps(&self) -> u32 {
        match self {
            RateLimiterMode::Shared(b) => b.rps,
            RateLimiterMode::PerIp(p) => p.rps,
        }
    }

    pub(crate) fn is_per_ip(&self) -> bool {
        matches!(self, RateLimiterMode::PerIp(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn basic_acquire_and_exhaust() {
        let bucket = AtomicTokenBucket::new(3);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn zero_rps_always_rejects() {
        let bucket = AtomicTokenBucket::new(0);
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn refill_after_one_second() {
        let bucket = AtomicTokenBucket::new(2);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(bucket.try_acquire());
    }

    #[test]
    fn concurrent_acquires_respect_limit() {
        let bucket = Arc::new(AtomicTokenBucket::new(100));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let b = Arc::clone(&bucket);
            handles.push(thread::spawn(move || {
                let mut count = 0u32;
                for _ in 0..100 {
                    if b.try_acquire() {
                        count += 1;
                    }
                }
                count
            }));
        }
        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn boundary_rps_one() {
        let bucket = AtomicTokenBucket::new(1);
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn per_ip_independent_buckets() {
        let limiter = PerIpRateLimiter::new(2);
        let ip_a: IpAddr = "1.2.3.4".parse().unwrap();
        let ip_b: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(limiter.try_acquire(ip_a));
        assert!(limiter.try_acquire(ip_a));
        assert!(!limiter.try_acquire(ip_a)); // exhausted for ip_a
        assert!(limiter.try_acquire(ip_b)); // ip_b still has tokens
        assert!(limiter.try_acquire(ip_b));
        assert!(!limiter.try_acquire(ip_b));
    }

    #[test]
    fn per_ip_eviction() {
        let limiter = PerIpRateLimiter::new(10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        limiter.try_acquire(ip);
        assert_eq!(limiter.buckets.len(), 1);
        // Evict with 0 max_idle — everything should be evicted
        std::thread::sleep(std::time::Duration::from_millis(10));
        limiter.evict_idle(std::time::Duration::from_millis(1));
        assert_eq!(limiter.buckets.len(), 0);
    }
}
