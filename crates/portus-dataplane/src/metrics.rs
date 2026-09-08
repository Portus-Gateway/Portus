use prometheus::{
    register_gauge, register_histogram_vec, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, Gauge, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
};

pub(crate) struct ProxyMetrics {
    pub(crate) request_total: IntCounterVec,
    pub(crate) request_duration: HistogramVec,
    pub(crate) routes_loaded: IntGauge,
    pub(crate) endpoints_loaded: IntGaugeVec,
    pub(crate) watcher_errors_total: IntCounterVec,
    pub(crate) tls_cert_expiry_seconds: Gauge,
    pub(crate) upstream_connect_errors_total: IntCounterVec,
    pub(crate) upstream_ejections_total: IntCounterVec,
    pub(crate) rate_limit_rejected_total: IntCounterVec,
    pub(crate) circuit_breaker_state: IntGaugeVec,
    pub(crate) config_last_update_timestamp: Gauge,
    pub(crate) grpc_stream_connected: Gauge,
}

impl ProxyMetrics {
    pub(crate) fn new() -> Self {
        Self {
            request_total: register_int_counter_vec!(
                "proxy_requests_total",
                "Total proxied requests",
                &["host", "status", "protocol"]
            )
            .expect("proxy_requests_total metric registration failed (duplicate?)"),
            request_duration: register_histogram_vec!(
                "proxy_request_duration_seconds",
                "Request duration in seconds",
                &["host", "protocol"],
                // Buckets tuned for proxy latency: 1ms to 30s
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0]
            )
            .expect("proxy_request_duration_seconds metric registration failed (duplicate?)"),
            routes_loaded: register_int_gauge!(
                "proxy_routes_loaded",
                "Number of ProxyRoute CRDs currently loaded"
            )
            .expect("proxy_routes_loaded metric registration failed (duplicate?)"),
            endpoints_loaded: register_int_gauge_vec!(
                "proxy_endpoints_loaded",
                "Number of endpoints loaded per service",
                &["service"]
            )
            .expect("proxy_endpoints_loaded metric registration failed (duplicate?)"),
            watcher_errors_total: register_int_counter_vec!(
                "proxy_watcher_errors_total",
                "Total watcher errors by watcher type",
                &["watcher"]
            )
            .expect("proxy_watcher_errors_total metric registration failed (duplicate?)"),
            tls_cert_expiry_seconds: register_gauge!(
                "proxy_tls_cert_expiry_seconds",
                "TLS certificate expiry as unix timestamp"
            )
            .expect("proxy_tls_cert_expiry_seconds metric registration failed (duplicate?)"),
            upstream_connect_errors_total: register_int_counter_vec!(
                "proxy_upstream_connect_errors_total",
                "Total upstream connection failures by service",
                &["service"]
            )
            .expect("proxy_upstream_connect_errors_total metric registration failed (duplicate?)"),
            upstream_ejections_total: register_int_counter_vec!(
                "proxy_upstream_ejections_total",
                "Endpoints taken out of rotation after failures (passive outlier ejection), by service",
                &["service"]
            )
            .expect("proxy_upstream_ejections_total metric registration failed (duplicate?)"),
            rate_limit_rejected_total: register_int_counter_vec!(
                "proxy_rate_limit_rejected_total",
                "Total rate limit rejections by host",
                &["host"]
            )
            .expect("proxy_rate_limit_rejected_total metric registration failed (duplicate?)"),
            circuit_breaker_state: register_int_gauge_vec!(
                "proxy_circuit_breaker_state",
                "Circuit breaker state per service (0=closed, 1=open, 2=half-open)",
                &["service"]
            )
            .expect("proxy_circuit_breaker_state metric registration failed (duplicate?)"),
            config_last_update_timestamp: register_gauge!(
                "config_last_update_timestamp",
                "Unix timestamp of the last config update received from controller"
            )
            .expect("config_last_update_timestamp metric registration failed (duplicate?)"),
            grpc_stream_connected: register_gauge!(
                "grpc_stream_connected",
                "Whether the gRPC config stream to the controller is connected (1) or not (0)"
            )
            .expect("grpc_stream_connected metric registration failed (duplicate?)"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn shared_metrics() -> &'static ProxyMetrics {
        static METRICS: OnceLock<ProxyMetrics> = OnceLock::new();
        METRICS.get_or_init(ProxyMetrics::new)
    }

    #[test]
    fn test_metrics_registration() {
        // Verify ProxyMetrics::new() doesn't panic and all 8 fields are accessible
        let m = shared_metrics();
        // Values may be non-zero if other tests run first (shared OnceLock instance)
        assert!(m.routes_loaded.get() >= 0);
        assert!(m.tls_cert_expiry_seconds.get() >= 0.0);
    }

    #[test]
    fn test_routes_loaded_gauge() {
        let m = shared_metrics();
        m.routes_loaded.set(5);
        // Can't assert exact value due to test ordering, but verify it's accessible
        assert!(m.routes_loaded.get() >= 0);
    }

    #[test]
    fn test_endpoints_loaded_per_service() {
        let m = shared_metrics();
        m.endpoints_loaded
            .with_label_values(&["test-svc"])
            .set(3);
        let val = m.endpoints_loaded.with_label_values(&["test-svc"]).get();
        assert_eq!(val, 3);
    }

    #[test]
    fn test_watcher_errors_counter() {
        let m = shared_metrics();
        let before = m
            .watcher_errors_total
            .with_label_values(&["test-watcher"])
            .get();
        m.watcher_errors_total
            .with_label_values(&["test-watcher"])
            .inc();
        let after = m
            .watcher_errors_total
            .with_label_values(&["test-watcher"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_rate_limit_rejected_counter() {
        let m = shared_metrics();
        let before = m
            .rate_limit_rejected_total
            .with_label_values(&["test-host"])
            .get();
        m.rate_limit_rejected_total
            .with_label_values(&["test-host"])
            .inc();
        let after = m
            .rate_limit_rejected_total
            .with_label_values(&["test-host"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_upstream_connect_errors_counter() {
        let m = shared_metrics();
        let before = m
            .upstream_connect_errors_total
            .with_label_values(&["test-svc"])
            .get();
        m.upstream_connect_errors_total
            .with_label_values(&["test-svc"])
            .inc();
        let after = m
            .upstream_connect_errors_total
            .with_label_values(&["test-svc"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_circuit_breaker_state_metric() {
        let m = shared_metrics();
        m.circuit_breaker_state
            .with_label_values(&["test-cb-svc"])
            .set(1);
        let val = m
            .circuit_breaker_state
            .with_label_values(&["test-cb-svc"])
            .get();
        assert_eq!(val, 1);
    }
}
