//! Everything a data plane does before its network stack starts serving:
//! shared state, the first config (controller stream or standalone file),
//! the health-check loop, the listener manager and the frontend TLS material.
//!
//! A stack adapter calls [`bootstrap`] once and receives the handles it needs
//! to serve traffic; nothing in here depends on which stack that is.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hashbrown::HashMap;
use log::{error, info, warn};
use rustls::ServerConfig;

use crate::config_receiver::{config_stream_loop, ProxyState, TlsCertSlot};
use crate::l4_proxy::{self, Handoffs, L4Config, L4ConfigSlot};
use crate::metrics::ProxyMetrics;
use crate::outlier::{OutlierConfig, Outliers};
use crate::readiness::Readiness;
use crate::router::{ProxySnapshot, ServiceLbMap, SnapshotSlot};
use crate::tls::{
    build_reloadable_tls_config, generate_self_signed_cert, load_certified_key_from_pem,
    start_tls_cert_hot_reload, PortServerConfigs, ReloadableCertResolver,
};
use crate::{router, standalone};

/// Bound on accepted connections not yet picked up by the network stack (one
/// queue each for HTTP and HTTPS). Beyond this the listener manager
/// back-pressures instead of buffering sockets.
pub const HANDOFF_QUEUE: usize = 4096;

/// How long to wait for the controller's first config before giving up.
const FIRST_CONFIG_TIMEOUT: Duration = Duration::from_secs(60);

/// Frontend TLS: the SNI-aware certificate resolver, the default
/// `ServerConfig` built on it and the per-port configs for listeners with
/// client certificate validation. All three are hot-reloaded by the thread
/// [`bootstrap`] starts.
pub struct FrontendTls {
    pub resolver: Arc<ReloadableCertResolver>,
    pub server_config: Arc<ServerConfig>,
    pub port_configs: Arc<PortServerConfigs>,
}

/// Handles a network stack needs to serve one Gateway.
pub struct Bootstrap {
    pub state: Arc<ProxyState>,
    pub snapshot: SnapshotSlot,
    pub lbs: ServiceLbMap,
    pub l4_config: L4ConfigSlot,
    pub readiness: Arc<Readiness>,
    pub metrics: Arc<ProxyMetrics>,
    pub outliers: Arc<Outliers>,
    pub tls: FrontendTls,
    /// Plain HTTP connections accepted by the listener manager, on the
    /// original socket (real peer address and listener port).
    pub http_handoff: tokio::sync::mpsc::Receiver<std::net::TcpStream>,
    /// HTTPS connections the SNI mux decided to terminate here.
    pub https_handoff: tokio::sync::mpsc::Receiver<std::net::TcpStream>,
}

/// Read the environment, load the first config and start the background
/// tasks. Errors are fatal for the process: the caller logs and exits.
pub fn bootstrap() -> Result<Bootstrap, String> {
    router::set_access_log(router::access_log_from_env_value(
        std::env::var("PORTUS_ACCESS_LOG").ok().as_deref(),
    ));

    let controller_addr =
        std::env::var("CONTROLLER_ADDR").unwrap_or_else(|_| "portus-controller:50051".to_string());

    // Single atomic snapshot for all per-request config maps; a separate LB
    // map for the L4 proxy and the health-check loop (not on the HTTP hot path).
    let snapshot: SnapshotSlot = Arc::new(ArcSwap::from_pointee(ProxySnapshot::default()));
    let lbs: ServiceLbMap = Arc::new(ArcSwap::from_pointee(HashMap::new()));
    let l4_config: L4ConfigSlot = Arc::new(ArcSwap::from_pointee(L4Config::default()));
    let readiness = Arc::new(Readiness::default());
    let health_check_min_interval = Arc::new(AtomicU32::new(10));
    let metrics = Arc::new(ProxyMetrics::new());
    let tls_cert: TlsCertSlot = Arc::new(ArcSwap::from_pointee(None));
    let tls_cert_notify = Arc::new(tokio::sync::Notify::new());

    let state = Arc::new(ProxyState {
        snapshot: snapshot.clone(),
        lbs: lbs.clone(),
        l4_config: l4_config.clone(),
        tls_cert: tls_cert.clone(),
        tls_cert_notify: tls_cert_notify.clone(),
        health_check_min_interval: health_check_min_interval.clone(),
    });

    if let Ok(config_path) = std::env::var("PORTUS_CONFIG_FILE") {
        info!("standalone mode: loading config from {}", config_path);
        standalone::load_and_apply(&config_path, &state)
            .map_err(|e| format!("failed to load initial standalone config {config_path}: {e}"))?;
        let watch_state = state.clone();
        let watch_path = config_path.clone();
        std::thread::spawn(move || standalone::watch_config_file(&watch_path, watch_state));
        readiness.mark_configured();
        info!("standalone mode: config loaded");
    } else {
        let config_handle = {
            let state = state.clone();
            let readiness = readiness.clone();
            let metrics = metrics.clone();
            let addr = controller_addr.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("config receiver runtime")
                    .block_on(config_stream_loop(addr, state, readiness, metrics));
            })
        };

        info!("waiting for first config from controller at {}", controller_addr);
        let deadline = std::time::Instant::now() + FIRST_CONFIG_TIMEOUT;
        loop {
            if readiness.config_received.load(Ordering::Acquire) {
                info!("first config received");
                break;
            }
            if std::time::Instant::now() > deadline {
                return Err(format!(
                    "timed out waiting for first config after {}s",
                    FIRST_CONFIG_TIMEOUT.as_secs()
                ));
            }
            if config_handle.is_finished() {
                return Err("gRPC config receiver thread died before first config".to_string());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // Active health checks: every pool with a HealthCheckPolicy is probed at
    // the smallest configured interval; unhealthy endpoints leave rotation.
    {
        let hc_lbs = lbs.clone();
        let hc_interval = health_check_min_interval;
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("health check runtime")
                .block_on(async move {
                    loop {
                        let secs = hc_interval.load(Ordering::Relaxed).max(1) as u64;
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        let lb_map = hc_lbs.load();
                        for ((svc, port), lb) in lb_map.iter() {
                            lb.run_health_check().await;
                            log::trace!("ran health check for {}:{}", svc, port);
                        }
                    }
                });
        });
    }

    // Listener manager: binds every Gateway listener port from the config
    // (HTTP, HTTPS, TLS, TCP, UDP), follows config changes, and hands HTTP and
    // HTTPS connections to the network stack over in-process channels on the
    // original socket, so the stack sees the real client address and port.
    let (http_tx, http_handoff) = tokio::sync::mpsc::channel::<std::net::TcpStream>(HANDOFF_QUEUE);
    let (https_tx, https_handoff) = tokio::sync::mpsc::channel::<std::net::TcpStream>(HANDOFF_QUEUE);
    {
        let l4_cfg = l4_config.clone();
        let l4_lbs = lbs.clone();
        let handoffs = Handoffs { http: http_tx, https: https_tx };
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("listener manager runtime")
                .block_on(l4_proxy::run_l4_proxy(l4_cfg, l4_lbs, handoffs));
        });
    }

    let outliers = Arc::new(Outliers::new(OutlierConfig::default()));
    let tls = frontend_tls(&tls_cert, &tls_cert_notify, &metrics)?;

    Ok(Bootstrap {
        state,
        snapshot,
        lbs,
        l4_config,
        readiness,
        metrics,
        outliers,
        tls,
        http_handoff,
        https_handoff,
    })
}

/// Initial HTTPS material and the hot-reload thread that follows the config.
///
/// The first config has already been applied, and `apply_config` fills the TLS
/// slot before flagging the config as received, so an empty slot here means
/// the Gateway has no HTTPS listener with a certificate: a self-signed
/// bootstrap certificate holds the listener until one arrives, and readiness
/// is unaffected (HTTP-only and TLS-passthrough Gateways never wait).
fn frontend_tls(
    tls_cert: &TlsCertSlot,
    notify: &Arc<tokio::sync::Notify>,
    metrics: &Arc<ProxyMetrics>,
) -> Result<FrontendTls, String> {
    let initial_key = {
        let guard = tls_cert.load();
        if let Some(ref data) = **guard {
            info!("HTTPS: using TLS certificate from controller");
            let first = data
                .entries
                .first()
                .ok_or_else(|| "controller provided TLS cert data with no entries".to_string())?;
            load_certified_key_from_pem(&first.cert_pem, &first.key_pem)
                .map_err(|e| format!("controller provided invalid TLS cert at startup: {e}"))?
        } else {
            warn!(
                "HTTPS listener using self-signed bootstrap certificate — no HTTPS listener \
                 certificate in the current config; replaced as soon as one arrives"
            );
            let (cert_pem, key_pem) =
                generate_self_signed_cert().map_err(|e| format!("failed to generate bootstrap cert: {e}"))?;
            load_certified_key_from_pem(&cert_pem, &key_pem)
                .map_err(|e| format!("failed to parse self-signed bootstrap cert: {e}"))?
        }
    };

    let resolver = Arc::new(ReloadableCertResolver::new(initial_key));
    let server_config = Arc::new(build_reloadable_tls_config(resolver.clone()));
    // Frontend mTLS: ports whose Gateway configures client certificate
    // validation get their own ServerConfig (same certs, plus a verifier),
    // picked per connection from the local port.
    let port_configs = Arc::new(PortServerConfigs::default());
    start_tls_cert_hot_reload(
        tls_cert.clone(),
        notify.clone(),
        resolver.clone(),
        port_configs.clone(),
        metrics.clone(),
    );
    Ok(FrontendTls { resolver, server_config, port_configs })
}

/// Log a fatal bootstrap error the way the process always has.
pub fn fatal(e: &str) -> ! {
    error!("{e}");
    std::process::exit(1)
}
