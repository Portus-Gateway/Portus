use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct HealthHandler {
    pub(crate) grpc_connected: Arc<AtomicBool>,
    pub(crate) config_received: Arc<AtomicBool>,
    pub(crate) last_config_time: Arc<AtomicU64>,
}

impl HealthHandler {
    /// Readiness logic:
    /// - Not ready if config has NEVER been received (cold start)
    /// - Ready if config has been received AND stream is connected
    /// - Ready if stream disconnected but last config is less than 120s old (stale grace period)
    /// - Not ready if stream disconnected AND last config is older than 120s
    pub(crate) fn is_ready(&self) -> bool {
        let config_received = self.config_received.load(Ordering::Relaxed);
        if !config_received {
            return false; // cold start: never received config
        }
        let grpc_connected = self.grpc_connected.load(Ordering::Relaxed);
        if grpc_connected {
            return true; // stream active: always ready
        }
        // Stream disconnected: check staleness
        let last_config = self.last_config_time.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(last_config) < 120 // 2-minute grace period
    }
}

#[async_trait]
impl ProxyHttp for HealthHandler {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let path = session.req_header().uri.path();
        let (status, body) = match path {
            "/healthz" => (200, "ok"),
            "/readyz" => {
                if self.is_ready() {
                    (200, "ready")
                } else {
                    (503, "not ready")
                }
            }
            _ => (404, "not found"),
        };
        let mut header = pingora_http::ResponseHeader::build(status, None)?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(pingora_core::Error::explain(
            pingora_core::ErrorType::HTTPStatus(500),
            "health handler should not proxy",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler(connected: bool, received: bool, last_config_secs_ago: u64) -> HealthHandler {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        HealthHandler {
            grpc_connected: Arc::new(AtomicBool::new(connected)),
            config_received: Arc::new(AtomicBool::new(received)),
            last_config_time: Arc::new(AtomicU64::new(now.saturating_sub(last_config_secs_ago))),
        }
    }

    #[test]
    fn test_cold_start_not_ready() {
        let h = make_handler(false, false, 0);
        assert!(!h.is_ready());
    }

    #[test]
    fn test_connected_and_received_ready() {
        let h = make_handler(true, true, 5);
        assert!(h.is_ready());
    }

    #[test]
    fn test_disconnected_within_grace_period_ready() {
        let h = make_handler(false, true, 60); // 60s ago, within 120s grace
        assert!(h.is_ready());
    }

    #[test]
    fn test_disconnected_past_grace_period_not_ready() {
        let h = make_handler(false, true, 130); // 130s ago, past 120s grace
        assert!(!h.is_ready());
    }

}
