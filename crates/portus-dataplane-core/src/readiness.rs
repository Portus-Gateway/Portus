//! Liveness and readiness state shared between the config receiver (which
//! sets it) and whichever network stack serves the health port (which reads it).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long a data plane keeps serving after losing the controller stream.
const STALE_CONFIG_GRACE_SECS: u64 = 120;

#[derive(Debug, Default)]
pub struct Readiness {
    /// The controller stream is up (always true in standalone mode).
    pub grpc_connected: AtomicBool,
    /// At least one config has been applied.
    pub config_received: AtomicBool,
    /// Unix seconds of the last applied config.
    pub last_config_time: AtomicU64,
}

impl Readiness {
    /// Mark a config as applied now, with the stream considered connected.
    pub fn mark_configured(&self) {
        self.config_received.store(true, Ordering::Release);
        self.grpc_connected.store(true, Ordering::Release);
        self.last_config_time.store(unix_now(), Ordering::Release);
    }

    /// Readiness logic:
    /// - Not ready if config has NEVER been received (cold start)
    /// - Ready if config has been received AND stream is connected
    /// - Ready if stream disconnected but last config is less than 120s old (stale grace period)
    /// - Not ready if stream disconnected AND last config is older than 120s
    pub fn is_ready(&self) -> bool {
        if !self.config_received.load(Ordering::Relaxed) {
            return false;
        }
        if self.grpc_connected.load(Ordering::Relaxed) {
            return true;
        }
        let last_config = self.last_config_time.load(Ordering::Relaxed);
        unix_now().saturating_sub(last_config) < STALE_CONFIG_GRACE_SECS
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readiness(connected: bool, received: bool, last_config_secs_ago: u64) -> Readiness {
        Readiness {
            grpc_connected: AtomicBool::new(connected),
            config_received: AtomicBool::new(received),
            last_config_time: AtomicU64::new(unix_now().saturating_sub(last_config_secs_ago)),
        }
    }

    #[test]
    fn test_cold_start_not_ready() {
        assert!(!readiness(false, false, 0).is_ready());
    }

    #[test]
    fn test_connected_and_received_ready() {
        assert!(readiness(true, true, 5).is_ready());
    }

    #[test]
    fn test_disconnected_within_grace_period_ready() {
        assert!(readiness(false, true, 60).is_ready());
    }

    #[test]
    fn test_disconnected_past_grace_period_not_ready() {
        assert!(!readiness(false, true, 130).is_ready());
    }

    #[test]
    fn mark_configured_makes_a_cold_instance_ready() {
        let r = Readiness::default();
        assert!(!r.is_ready());
        r.mark_configured();
        assert!(r.is_ready());
    }
}
