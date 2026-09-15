//! The Pingora network stack: turns a [`Bootstrap`] into a running proxy.

mod health;
mod proxy;
mod tls;

use log::info;
use pingora_core::apps::HttpServerOptions;
use pingora_core::listeners::HandoffSource;
use pingora_core::protocols::http::v2::server::{default_h2_options, H2Options};
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::server::Server;

use portus_dataplane_core::bootstrap::Bootstrap;
use portus_dataplane_core::h2::{H2_CONNECTION_WINDOW, H2_STREAM_WINDOW};
use portus_dataplane_core::runtime::worker_threads;

use self::health::HealthHandler;
use self::proxy::Router;
use self::tls::PortChooser;

/// Pingora's bounded HTTP/2 SETTINGS (max concurrent streams, header-list size)
/// with the flow-control windows every stack advertises.
fn h2_server_options() -> H2Options {
    let mut options = default_h2_options();
    options.initial_window_size(H2_STREAM_WINDOW);
    options.initial_connection_window_size(H2_CONNECTION_WINDOW);
    options
}

/// Idle upstream connections to keep per worker thread. Pingora's pool cap is
/// this times the thread count, so it shrinks as threads grow and the total
/// stays at about 2,048 idle connections per pod whatever the thread count.
pub fn keepalive_pool_size_for(threads: usize) -> usize {
    (2048 / threads.max(1)).max(64)
}

/// Serve forever on Pingora.
pub fn run(boot: Bootstrap) -> ! {
    let Bootstrap { snapshot, readiness, metrics, outliers, tls, http_handoff, https_handoff, .. } = boot;

    let opt = Opt::parse_args();
    let threads = worker_threads();
    let conf = ServerConf {
        threads,
        work_stealing: true,
        upstream_keepalive_pool_size: keepalive_pool_size_for(threads),
        ..ServerConf::default()
    };
    info!(
        "server config: {} worker threads, work_stealing=true, keepalive pool {} per thread",
        conf.threads, conf.upstream_keepalive_pool_size
    );

    let mut server = Server::new_with_opt_and_conf(opt, conf);
    server.bootstrap();

    // Plain HTTP with h2c (gRPC). No socket of its own: listener ports are
    // bound by the listener manager from the Gateway config and handed over.
    let router = Router { snapshot: snapshot.clone(), metrics: metrics.clone(), outliers: outliers.clone() };
    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, router);
    if let Some(app) = proxy.app_logic_mut() {
        // HttpServerOptions is #[non_exhaustive]; field assignment is the only way.
        let mut opts = HttpServerOptions::default();
        opts.h2c = true;
        app.server_options = Some(opts);
        // Bound HTTP/2 SETTINGS advertised to clients (max concurrent streams,
        // decoded header-list size). h2c on a public port must never run with
        // the h2 crate's unbounded defaults — that is a memory-exhaustion vector.
        app.h2_options = Some(h2_server_options());
    }
    proxy.add_handoff("handoff:http", HandoffSource::new(http_handoff));
    server.add_service(proxy);
    info!("HTTP proxy accepting connections handed off by the listener manager");

    // HTTPS: the core's hot-reloaded ServerConfig, with per-port configs for
    // listeners that validate client certificates (patched pingora-core).
    let tls_settings = pingora_core::listeners::tls::TlsSettings::from_config_chooser(
        tls.server_config,
        std::sync::Arc::new(PortChooser(tls.port_configs)),
    );
    let https_router = Router { snapshot, metrics: metrics.clone(), outliers };
    let mut https_proxy = pingora_proxy::http_proxy_service(&server.configuration, https_router);
    if let Some(app) = https_proxy.app_logic_mut() {
        app.h2_options = Some(h2_server_options());
    }
    https_proxy.add_tls_handoff("handoff:https", HandoffSource::new(https_handoff), tls_settings);
    server.add_service(https_proxy);
    info!("HTTPS proxy accepting connections handed off by the listener manager");

    // Health and metrics answer a few requests a second: one thread each keeps
    // the worker pools for the proxies.
    let mut health_svc =
        pingora_proxy::http_proxy_service(&server.configuration, HealthHandler { readiness });
    health_svc.threads = Some(1);
    health_svc.add_tcp("0.0.0.0:8081");
    server.add_service(health_svc);

    // Prometheus metrics on port 9090 (the provisioner's pods carry the scrape
    // annotations, so this must listen on the pod address, not loopback).
    let mut prom_svc = pingora_prometheus::prometheus_http_service();
    prom_svc.threads = Some(1);
    prom_svc.add_tcp("0.0.0.0:9090");
    server.add_service(prom_svc);
    info!("Prometheus metrics on :9090");

    server.run_forever()
}

#[cfg(test)]
mod tests {
    #[test]
    fn keepalive_pool_cap_stays_near_2048_per_pod() {
        assert_eq!(super::keepalive_pool_size_for(2), 1024);
        assert_eq!(super::keepalive_pool_size_for(10), 204);
        assert_eq!(super::keepalive_pool_size_for(64), 64, "floor");
        assert_eq!(super::keepalive_pool_size_for(0), 2048, "no division by zero");
    }
}
