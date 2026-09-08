use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

/// Runtime configuration for a circuit breaker instance.
pub(crate) struct CircuitBreakerConfig {
    pub(crate) failure_threshold: u16,
    pub(crate) success_threshold: u16,
    pub(crate) timeout_secs: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 1,
            timeout_secs: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// Bit-packing helpers for the AtomicU64 state word
// ---------------------------------------------------------------------------
//
// Layout:
//   Bits 63-62: state enum (0=Closed, 1=Open, 2=HalfOpen) [2 bits]
//   Bits 61-32: seconds since epoch (Instant-based)        [30 bits]
//   Bits 31-16: consecutive failure count                   [16 bits]
//   Bits 15-0:  consecutive success count                   [16 bits]

fn pack(state: CircuitState, timestamp: u32, failures: u16, successes: u16) -> u64 {
    let s = (state as u64) << 62;
    let t = ((timestamp as u64) & 0x3FFF_FFFF) << 32;
    let f = (failures as u64) << 16;
    let sc = successes as u64;
    s | t | f | sc
}

fn extract_state(packed: u64) -> CircuitState {
    match packed >> 62 {
        0 => CircuitState::Closed,
        1 => CircuitState::Open,
        2 => CircuitState::HalfOpen,
        _ => CircuitState::Closed, // unreachable in practice
    }
}

fn extract_timestamp(packed: u64) -> u32 {
    ((packed >> 32) & 0x3FFF_FFFF) as u32
}

fn extract_failures(packed: u64) -> u16 {
    ((packed >> 16) & 0xFFFF) as u16
}

fn extract_successes(packed: u64) -> u16 {
    (packed & 0xFFFF) as u16
}

/// Lock-free circuit breaker using a single AtomicU64 with CAS-loop transitions.
///
/// Follows the standard Closed -> Open -> HalfOpen -> Closed pattern.
/// State, counters, and timestamps are packed into one atomic word to avoid
/// locks on the request hot path.
pub(crate) struct CircuitBreaker {
    pub(crate) config: CircuitBreakerConfig,
    state: AtomicU64,
    epoch: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker in the Closed state with all counters zeroed.
    pub(crate) fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU64::new(pack(CircuitState::Closed, 0, 0, 0)),
            config,
            epoch: Instant::now(),
        }
    }

    /// Returns the current elapsed seconds since this circuit breaker's epoch.
    fn now_secs(&self) -> u32 {
        self.epoch.elapsed().as_secs() as u32
    }

    /// Check whether the current request should be allowed through.
    ///
    /// - **Closed:** always allows.
    /// - **Open:** if timeout has elapsed, transitions to HalfOpen and allows
    ///   one probe request; otherwise rejects.
    /// - **HalfOpen:** rejects (only one probe at a time).
    pub(crate) fn allow_request(&self) -> bool {
        // PERF-15: Relaxed load for the Closed fast-path — no synchronization needed
        // when the breaker is closed (the common case). Only re-read with Acquire
        // on the slow path where CAS consistency matters.
        let current = self.state.load(Ordering::Relaxed);
        let st = extract_state(current);
        if st == CircuitState::Closed {
            return true;
        }
        loop {
            let current = self.state.load(Ordering::Acquire);
            let st = extract_state(current);

            match st {
                CircuitState::Closed => return true,
                CircuitState::Open => {
                    let ts = extract_timestamp(current);
                    let elapsed = self.now_secs().wrapping_sub(ts);
                    if elapsed >= self.config.timeout_secs {
                        // Try to transition Open -> HalfOpen (probe request)
                        let new = pack(CircuitState::HalfOpen, self.now_secs(), 0, 0);
                        match self.state.compare_exchange_weak(
                            current,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return true,
                            Err(_) => continue, // retry
                        }
                    } else {
                        return false;
                    }
                }
                CircuitState::HalfOpen => return false,
            }
        }
    }

    /// Record a successful response. Resets failure count in Closed state,
    /// and transitions HalfOpen -> Closed when success_threshold is met.
    pub(crate) fn record_success(&self) {
        loop {
            let current = self.state.load(Ordering::Acquire);
            let st = extract_state(current);

            match st {
                CircuitState::Closed => {
                    // Reset failure count to 0
                    let successes = extract_successes(current);
                    let new = pack(CircuitState::Closed, extract_timestamp(current), 0, successes.saturating_add(1));
                    match self.state.compare_exchange_weak(
                        current,
                        new,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return,
                        Err(_) => continue,
                    }
                }
                CircuitState::HalfOpen => {
                    let successes = extract_successes(current).saturating_add(1);
                    if successes >= self.config.success_threshold {
                        // Transition HalfOpen -> Closed with counters reset
                        let new = pack(CircuitState::Closed, self.now_secs(), 0, 0);
                        match self.state.compare_exchange_weak(
                            current,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return,
                            Err(_) => continue,
                        }
                    } else {
                        let new = pack(CircuitState::HalfOpen, extract_timestamp(current), 0, successes);
                        match self.state.compare_exchange_weak(
                            current,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return,
                            Err(_) => continue,
                        }
                    }
                }
                CircuitState::Open => {
                    // Unusual: success while open -- ignore
                    return;
                }
            }
        }
    }

    /// Record a failed response. Increments failure count in Closed state
    /// and transitions to Open when threshold is reached. In HalfOpen state,
    /// immediately transitions back to Open.
    pub(crate) fn record_failure(&self) {
        loop {
            let current = self.state.load(Ordering::Acquire);
            let st = extract_state(current);

            match st {
                CircuitState::Closed => {
                    let failures = extract_failures(current).saturating_add(1);
                    if failures >= self.config.failure_threshold {
                        // Transition Closed -> Open
                        let new = pack(CircuitState::Open, self.now_secs(), failures, 0);
                        match self.state.compare_exchange_weak(
                            current,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return,
                            Err(_) => continue,
                        }
                    } else {
                        let new = pack(CircuitState::Closed, extract_timestamp(current), failures, 0);
                        match self.state.compare_exchange_weak(
                            current,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return,
                            Err(_) => continue,
                        }
                    }
                }
                CircuitState::HalfOpen => {
                    // Transition HalfOpen -> Open with new timestamp
                    let new = pack(CircuitState::Open, self.now_secs(), 0, 0);
                    match self.state.compare_exchange_weak(
                        current,
                        new,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return,
                        Err(_) => continue,
                    }
                }
                CircuitState::Open => {
                    // Already open -- ignore
                    return;
                }
            }
        }
    }

    /// Read the current circuit state.
    pub(crate) fn current_state(&self) -> CircuitState {
        extract_state(self.state.load(Ordering::Acquire))
    }
}

/// Lock-free connection limiter using an AtomicU32 counter.
///
/// Each call to `try_acquire` atomically increments the counter if below `max`;
/// `release` decrements it. Used to cap active connections per service.
pub(crate) struct ConnectionLimiter {
    active: AtomicU32,
    pub(crate) max: u32,
}

impl ConnectionLimiter {
    pub(crate) fn new(max: u32) -> Self {
        Self {
            active: AtomicU32::new(0),
            max,
        }
    }

    /// Try to acquire a connection slot. Returns true if under the limit.
    pub(crate) fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::Acquire);
            if current >= self.max {
                return false;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Release a connection slot.
    ///
    /// Uses a CAS loop to saturate at zero, preventing underflow if `release`
    /// is called without a matching `try_acquire`.
    pub(crate) fn release(&self) {
        loop {
            let current = self.active.load(Ordering::Acquire);
            if current == 0 {
                log::warn!("ConnectionLimiter::release called with active=0 (double release?)");
                return;
            }
            match self.active.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(_) => continue, // CAS retry
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_closed_allows_request() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert!(cb.allow_request());
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_open_rejects_request() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        // Record 3 consecutive failures to trip the breaker
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_open_to_halfopen_after_timeout() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            timeout_secs: 0, // immediate timeout for test
            ..Default::default()
        });
        cb.record_failure(); // trips to Open
        assert_eq!(cb.current_state(), CircuitState::Open);

        // With timeout_secs=0, the next allow_request should transition to HalfOpen
        assert!(cb.allow_request()); // probe allowed
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_halfopen_success_closes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_secs: 0,
        });
        cb.record_failure(); // -> Open
        cb.allow_request(); // -> HalfOpen (probe)
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.record_success(); // -> Closed
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_halfopen_failure_reopens() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_secs: 0,
        });
        cb.record_failure(); // -> Open
        cb.allow_request(); // -> HalfOpen (probe)
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.record_failure(); // -> Open again
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        // Record 2 failures (below threshold)
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);

        // Success resets counter
        cb.record_success();

        // Now 2 more failures should not trip (counter was reset)
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);

        // One more should trip it (3 consecutive)
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn test_halfopen_rejects_non_probe() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            timeout_secs: 0,
            ..Default::default()
        });
        cb.record_failure(); // -> Open
        assert!(cb.allow_request()); // probe -> HalfOpen
        // Second request while HalfOpen should be rejected
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_concurrent_circuit_breaker() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 100,
            success_threshold: 1,
            timeout_secs: 0,
        }));
        let mut handles = Vec::new();

        for i in 0..10 {
            let cb_clone = Arc::clone(&cb);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    cb_clone.allow_request();
                    if i % 2 == 0 {
                        cb_clone.record_success();
                    } else {
                        cb_clone.record_failure();
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap(); // must not panic or deadlock
        }

        // State should be valid
        let state = cb.current_state();
        assert!(
            state == CircuitState::Closed
                || state == CircuitState::Open
                || state == CircuitState::HalfOpen
        );
    }

    #[test]
    fn test_conn_limiter_basic() {
        let limiter = ConnectionLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // at capacity
    }

    #[test]
    fn test_conn_limiter_release() {
        let limiter = ConnectionLimiter::new(1);
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // full
        limiter.release();
        assert!(limiter.try_acquire()); // slot freed
    }

    #[test]
    fn test_conn_limiter_concurrent() {
        let limiter = Arc::new(ConnectionLimiter::new(100));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let l = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                let mut count = 0u32;
                for _ in 0..100 {
                    if l.try_acquire() {
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
    fn test_current_state() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_secs: 0,
        });
        assert_eq!(cb.current_state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);

        cb.allow_request(); // probe -> HalfOpen
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_connection_limiter_release_underflow_protection() {
        let limiter = ConnectionLimiter::new(5);
        // Release without any acquire — should not underflow
        limiter.release();
        // Counter should still be 0, not u32::MAX
        assert!(limiter.try_acquire()); // should succeed since active == 0
        // Acquire then release normally
        limiter.release();
        // Again release with nothing held — verify no panic/underflow
        limiter.release();
        // Verify the limiter is still functional
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire()); // at capacity
    }
}
