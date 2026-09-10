pub mod auth;
mod types;
mod circuit_breaker;
mod config_receiver;
mod health;
mod l4_proxy;
mod metrics;
mod outlier;
mod rate_limiter;
mod router;
mod standalone;
mod tls;
mod udp_proxy;

use log::{error, info};
use pingora_core::apps::HttpServerOptions;
use pingora_core::protocols::http::v2::server::default_h2_options;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::server::Server;
use hashbrown::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::config_receiver::{config_stream_loop, ProxyState};
use crate::health::HealthHandler;
use crate::l4_proxy::{L4Config, L4ConfigSlot};
use crate::metrics::ProxyMetrics;
use crate::router::{ProxySnapshot, Router, ServiceLbMap, SnapshotSlot};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Bound on accepted connections not yet picked up by a Pingora service (one
/// queue each for HTTP and HTTPS). Beyond this the listener manager
/// back-pressures instead of buffering sockets.
const HTTPS_HANDOFF_QUEUE: usize = 4096;

/// Number of Pingora worker threads.
///
/// `available_parallelism()` reports the *node's* CPUs, which is wrong for a
/// container with a CPU limit: several dataplanes on one node would each spawn
/// node-many threads and oversubscribe it (twelve per-Gateway dataplanes on a
/// 10-CPU node asked for 120 worker threads, and the resulting scheduling
/// delays showed up as multi-second stalls). `DATAPLANE_THREADS` (set by the
/// provisioner from the pod's CPU request) wins; otherwise fall back to the
/// cgroup v2 CPU quota, then to the node's CPU count.
fn worker_threads() -> usize {
    let host = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if let Ok(v) = std::env::var("DATAPLANE_THREADS")
        && let Ok(n) = v.trim().parse::<usize>()
        && n > 0
    {
        return n.min(host);
    }
    if let Some(n) = cgroup_cpu_quota() {
        return n.clamp(1, host);
    }
    host
}

/// CPU count implied by the cgroup v2 quota (`/sys/fs/cgroup/cpu.max`), rounded
/// up. Returns None when unlimited or unreadable (non-Linux, cgroup v1).
fn cgroup_cpu_quota() -> Option<usize> {
    let raw = std::fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    let mut parts = raw.split_whitespace();
    let quota = parts.next()?;
    if quota == "max" {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    let period: u64 = parts.next()?.parse().ok()?;
    if period == 0 {
        return None;
    }
    Some(quota.div_ceil(period).max(1) as usize)
}

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");
    // Lock-free logging: tracing-subscriber replaces env_logger.
    // env_logger acquires a stderr mutex on EVERY log level check, even when
    // filtered out — profiling showed 13% of CPU burned on mutex contention.
    // tracing-subscriber's EnvFilter uses lock-free atomics for level filtering:
    // filtered-out messages have zero contention across worker threads.
    // LogTracer bridges Pingora's log:: macros through tracing's filter path.
    {
        use tracing_subscriber::{fmt, EnvFilter};
        use tracing_subscriber::prelude::*;

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .with_ansi(false))
            .init();

        tracing_log::LogTracer::init().ok();
    }

    let controller_addr =
        std::env::var("CONTROLLER_ADDR").unwrap_or_else(|_| "portus-controller:50051".to_string());

    // PERF-9: Single atomic snapshot for all per-request config maps.
    // Reduces per-request atomic operations from 8-18 to 2-3.
    let snapshot: SnapshotSlot = Arc::new(ArcSwap::from_pointee(ProxySnapshot::default()));
    // Separate LB map for L4 proxy and health check (not on HTTP hot path).
    let lbs: ServiceLbMap = Arc::new(ArcSwap::from_pointee(HashMap::new()));
    let l4_config: L4ConfigSlot = Arc::new(ArcSwap::from_pointee(L4Config::default()));

    let grpc_connected = Arc::new(AtomicBool::new(false));
    let config_received = Arc::new(AtomicBool::new(false));
    let last_config_time = Arc::new(AtomicU64::new(0));
    let health_check_min_interval = Arc::new(AtomicU32::new(10));
    let metrics = Arc::new(ProxyMetrics::new());

    let tls_cert: crate::config_receiver::TlsCertSlot =
        Arc::new(ArcSwap::from_pointee(None));
    let tls_cert_notify = Arc::new(tokio::sync::Notify::new());

    let state = Arc::new(ProxyState {
        snapshot: snapshot.clone(),
        lbs: lbs.clone(),
        l4_config: l4_config.clone(),
        tls_cert: tls_cert.clone(),
        tls_cert_notify: tls_cert_notify.clone(),
        health_check_min_interval: health_check_min_interval.clone(),
    });

    // Standalone YAML config mode: skip gRPC entirely, load config from file.
    let standalone_config_path = std::env::var("PORTUS_CONFIG_FILE").ok();

    if let Some(ref config_path) = standalone_config_path {
        info!("standalone mode: loading config from {}", config_path);
        standalone::load_and_apply(config_path, &state)
            .expect("failed to load initial standalone config");

        // Spawn file watcher for hot-reload
        let watch_state = state.clone();
        let watch_path = config_path.clone();
        std::thread::spawn(move || {
            standalone::watch_config_file(&watch_path, watch_state);
        });

        // Signal that config is loaded (no gRPC needed)
        config_received.store(true, std::sync::atomic::Ordering::Release);
        // Mark gRPC as "connected" so health checks pass in standalone mode
        grpc_connected.store(true, std::sync::atomic::Ordering::Release);
        last_config_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            std::sync::atomic::Ordering::Release,
        );

        info!("standalone mode: config loaded, starting Pingora server");
    } else {
        // --- gRPC controller mode ---

        // Spawn gRPC config receiver on a background tokio runtime
        let config_handle = {
            let state = state.clone();
            let connected = grpc_connected.clone();
            let received = config_received.clone();
            let last_time = last_config_time.clone();
            let m = metrics.clone();
            let addr = controller_addr.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(config_stream_loop(
                        addr, state, connected, received, last_time, m,
                    ));
            })
        };

        // Wait for first config with a 60s deadline
        info!(
            "waiting for first config from controller at {}",
            controller_addr
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if config_received.load(std::sync::atomic::Ordering::Acquire) {
                info!("first config received, starting Pingora server");
                break;
            }
            if std::time::Instant::now() > deadline {
                error!("timed out waiting for first config after 60s");
                std::process::exit(1);
            }
            if config_handle.is_finished() {
                error!("gRPC config receiver thread died before first config");
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // Spawn background health check task.
    // Periodically runs health checks on all LoadBalancers that have a health
    // check configured (from HealthCheckPolicy). Unhealthy backends are excluded
    // from round-robin selection by Pingora's LoadBalancer.
    {
        let hc_lbs = lbs.clone();
        let hc_interval = health_check_min_interval.clone();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    loop {
                        // Use the minimum configured health check interval across
                        // all backends. Updated atomically on each config apply.
                        let secs = hc_interval
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .max(1) as u64;
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        let lb_map = hc_lbs.load();
                        for ((svc, port), lb) in lb_map.iter() {
                            lb.backends().run_health_check(false).await;
                            log::trace!("ran health check for {}:{}", svc, port);
                        }
                    }
                });
        });
    }

    // Listener manager: binds every Gateway listener port from the config
    // (HTTP, HTTPS, TLS, TCP), follows config changes, and hands HTTP/HTTPS
    // connections to Pingora's services over in-process channels on the
    // original socket, so Pingora sees the real client address and port.
    let (http_handoff_tx, http_handoff_rx) =
        tokio::sync::mpsc::channel::<std::net::TcpStream>(HTTPS_HANDOFF_QUEUE);
    let (https_handoff_tx, https_handoff_rx) =
        tokio::sync::mpsc::channel::<std::net::TcpStream>(HTTPS_HANDOFF_QUEUE);
    {
        let l4_cfg = l4_config.clone();
        let l4_lbs = lbs.clone();
        let handoffs = l4_proxy::Handoffs {
            http: http_handoff_tx,
            https: https_handoff_tx,
        };
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(l4_proxy::run_l4_proxy(l4_cfg, l4_lbs, handoffs));
        });
    }

    let outliers = Arc::new(outlier::Outliers::new(outlier::OutlierConfig::default()));
    let router = Router {
        snapshot: snapshot.clone(),
        metrics: metrics.clone(),
        outliers: outliers.clone(),
    };

    let opt = Opt::parse_args();
    let conf = ServerConf {
        threads: worker_threads(),
        work_stealing: true,
        upstream_keepalive_pool_size: 1024,
        ..ServerConf::default()
    };
    info!(
        "server config: {} worker threads, work_stealing=true",
        conf.threads
    );

    let mut server = Server::new_with_opt_and_conf(opt, conf);
    server.bootstrap();

    // Main proxy on port 80 with h2c for gRPC
    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, router);
    if let Some(app) = proxy.app_logic_mut() {
        // HttpServerOptions is #[non_exhaustive]; field assignment is the only way.
        let mut opts = HttpServerOptions::default();
        opts.h2c = true;
        app.server_options = Some(opts);
        // Bound HTTP/2 SETTINGS advertised to clients (max concurrent streams,
        // decoded header-list size). h2c on a public port must never run with
        // the h2 crate's unbounded defaults — that is a memory-exhaustion vector.
        app.h2_options = Some(default_h2_options());
    }
    // No socket of its own: HTTP listener ports are bound by the listener
    // manager from the Gateway config and handed over here.
    proxy.add_handoff(
        "handoff:http",
        pingora_core::listeners::HandoffSource::new(http_handoff_rx),
    );
    server.add_service(proxy);
    info!("HTTP proxy accepting connections handed off by the listener manager");

    // HTTPS proxy on port 443 with dynamic TLS certificate hot-reload.
    //
    // Architecture:
    // 1. Generate a self-signed bootstrap cert OR use the controller cert if
    //    already available (brief wait at startup)
    // 2. Create a ReloadableCertResolver backed by ArcSwap for lock-free reads
    // 3. Build a rustls ServerConfig with with_cert_resolver() — every new TLS
    //    handshake calls resolve(), reading the current cert atomically
    // 4. Pass the ServerConfig to Pingora via TlsSettings::from_server_config()
    //    (patched pingora-core)
    // 5. Start a background thread that polls TlsCertSlot and calls
    //    resolver.swap() when the controller pushes new certs
    //
    // Result: zero-downtime cert rotation. No restarts, no SIGQUIT, no disk I/O
    // on the hot path. Existing connections are unaffected.
    {
        use crate::tls::{
            build_reloadable_tls_config, generate_self_signed_cert, load_certified_key_from_pem,
            start_tls_cert_hot_reload, PortServerConfigs, ReloadableCertResolver,
        };

        // Determine initial cert: prefer controller cert if available quickly.
        // The first config has already been applied by this point (see the
        // wait above), and apply_config fills the TLS slot before flagging the
        // config as received. So an empty slot here means the Gateway has no
        // HTTPS listener with a certificate; waiting longer would only delay
        // the health port (and hence pod readiness) by the full timeout, which
        // every HTTP-only or TLS-passthrough Gateway paid before.
        let initial_key = {
            if tls_cert.load().is_none() && !config_received.load(std::sync::atomic::Ordering::Acquire) {
                info!("HTTPS: waiting briefly for TLS certificate from controller...");
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while tls_cert.load().is_none()
                    && !config_received.load(std::sync::atomic::Ordering::Acquire)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            let guard = tls_cert.load();
            if let Some(ref data) = **guard {
                info!("HTTPS: using TLS certificate from controller");
                let first = data.entries.first()
                    .expect("controller provided TLS cert data with no entries");
                load_certified_key_from_pem(&first.cert_pem, &first.key_pem)
                    .expect("controller provided invalid TLS cert at startup")
            } else {
                log::warn!(
                    "HTTPS listener using self-signed bootstrap certificate — no HTTPS listener \
                     certificate in the current config; replaced as soon as one arrives"
                );
                let (cert_pem, key_pem) =
                    generate_self_signed_cert().expect("failed to generate bootstrap cert");
                load_certified_key_from_pem(&cert_pem, &key_pem)
                    .expect("failed to parse self-signed bootstrap cert")
            }
        };

        let resolver = Arc::new(ReloadableCertResolver::new(initial_key));
        let server_config = Arc::new(build_reloadable_tls_config(resolver.clone()));

        // Frontend mTLS: ports whose Gateway configures client certificate
        // validation get their own ServerConfig (same certs, plus a verifier),
        // picked per connection from the local port. Everything else uses the
        // default config above.
        let port_configs = Arc::new(PortServerConfigs::default());
        let tls_settings = pingora_core::listeners::tls::TlsSettings::from_config_chooser(
            server_config,
            port_configs.clone(),
        );

        let https_router = Router {
            snapshot: snapshot.clone(),
            metrics: metrics.clone(),
            outliers: outliers.clone(),
        };

        let mut https_proxy =
            pingora_proxy::http_proxy_service(&server.configuration, https_router);
        if let Some(app) = https_proxy.app_logic_mut() {
            app.h2_options = Some(default_h2_options());
        }
        https_proxy.add_tls_handoff(
            "handoff:https",
            pingora_core::listeners::HandoffSource::new(https_handoff_rx),
            tls_settings,
        );
        server.add_service(https_proxy);

        // Start background cert hot-reload thread
        start_tls_cert_hot_reload(
            tls_cert.clone(),
            tls_cert_notify.clone(),
            resolver,
            port_configs,
            metrics.clone(),
        );

        info!("HTTPS proxy accepting connections handed off by the listener manager");
    }

    // Health/readiness on port 8081
    let health = HealthHandler {
        grpc_connected: grpc_connected.clone(),
        config_received: config_received.clone(),
        last_config_time: last_config_time.clone(),
    };
    let mut health_svc = pingora_proxy::http_proxy_service(&server.configuration, health);
    health_svc.add_tcp("0.0.0.0:8081");
    server.add_service(health_svc);

    // Prometheus metrics on port 9090 (the provisioner's pods carry the scrape
    // annotations, so this must listen on the pod address, not loopback).
    let mut prom_svc = pingora_prometheus::prometheus_http_service();
    prom_svc.add_tcp("0.0.0.0:9090");
    server.add_service(prom_svc);
    info!("Prometheus metrics on :9090");

    server.run_forever();
}
