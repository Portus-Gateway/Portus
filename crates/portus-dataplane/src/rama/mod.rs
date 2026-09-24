//! The Rama network stack: turns a [`Bootstrap`] into a running proxy on one
//! multi-thread tokio runtime.
//!
//! Experimental: compared against the Pingora stack on the same benchmarks
//! and conformance suite. Selected with `PORTUS_NETWORK_STACK=rama`.

mod body;
mod client;
mod federation;
mod usage;
mod health;
mod proxy;
mod serve;
mod tls;

use std::sync::Arc;

use log::{error, info};
use rama::http::server::HttpServer;
use rama::rt::Executor;
use rama::tcp::server::TcpListener;

use portus_dataplane_core::bootstrap::{fatal, Bootstrap};
use portus_dataplane_core::h2::{H2_CONNECTION_WINDOW, H2_STREAM_WINDOW};
use portus_dataplane_core::runtime::worker_threads;

use self::health::{HealthService, MetricsService};
use self::proxy::ProxyService;
use self::tls::PortTlsAcceptor;

/// Bounds on HTTP/2 SETTINGS advertised to clients: h2c on a public port must
/// never run with unbounded defaults (memory-exhaustion vector).
const H2_MAX_CONCURRENT_STREAMS: u32 = 100;
const H2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
/// Larger frames than the 16 KiB default for the large-body rungs.
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;
const H1_MAX_BUF_SIZE: usize = 64 * 1024;


/// Serve forever on Rama.
pub fn run(boot: Bootstrap) -> ! {
    let threads = worker_threads();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal(&format!("rama: failed to build the tokio runtime: {e}")));
    info!("rama: {threads} worker threads");

    let exit_code = runtime.block_on(async move {
        let Bootstrap { snapshot, readiness, metrics, outliers, tls, http_handoff, https_handoff, .. } = boot;
        // SIGTERM/SIGINT: stop accepting, let requests in flight finish, then
        // exit. The graceful executor and every task it spawns hold the
        // shutdown guard, so only the accept loops and the connections they
        // hand out may use it; the upstream client, health, metrics and this
        // scope run without one or the drain would never complete.
        let shutdown = rama::graceful::Shutdown::default();
        let exec = Executor::graceful(shutdown.guard());
        let plain = Executor::default();
        // An HTTP/1.1 + HTTP/2 (prior knowledge or ALPN) server with the
        // windows every stack advertises.
        let http_server = |exec: Executor| {
            let mut server = HttpServer::auto(exec);
            let h2 = server.h2_mut();
            h2.set_initial_stream_window_size(H2_STREAM_WINDOW);
            h2.set_initial_connection_window_size(H2_CONNECTION_WINDOW);
            h2.set_max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
            h2.set_max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
            h2.set_max_frame_size(H2_MAX_FRAME_SIZE);
            h2.set_adaptive_window(true);
            // hyper grows the HTTP/1 read buffer to 400 KiB per connection under
            // load; 64 KiB keeps 256 connections at 16 MiB instead of 100.
            if let Err(e) = server.http1_mut().try_set_max_buf_size(H1_MAX_BUF_SIZE) {
                fatal(&format!("rama: http1 max_buf_size: {e}"));
            }
            server
        };

        // Usage records for AI routes go to the ledger when one is configured.
        let ledger = portus_dataplane_core::ai::ledger::LedgerReporter::from_env();
        let proxy = Arc::new(ProxyService::new(snapshot, metrics, outliers, client::Upstream::new(plain.clone()), ledger));

        let http = http_server(exec.clone()).service(proxy.clone());
        let https = PortTlsAcceptor::new(Arc::new(tls), http_server(exec.clone()).service(proxy));

        exec.spawn_task(serve::handoff_loop(http_handoff, http, exec.clone(), shutdown.guard()));
        exec.spawn_task(serve::handoff_loop(https_handoff, https, exec.clone(), shutdown.guard()));
        drop(exec);
        info!("rama: HTTP and HTTPS proxies accepting connections handed off by the listener manager");

        // Health and metrics on their own ports, bound here like every stack.
        // They answer until the process exits; readiness flips to false the
        // moment the drain starts so the Service stops sending new connections.
        for (addr, what) in [("0.0.0.0:8081", "health"), ("0.0.0.0:9090", "metrics")] {
            let listener = TcpListener::bind_address(addr, plain.clone())
                .await
                .unwrap_or_else(|e| fatal(&format!("rama: bind {what} on {addr}: {e}")));
            match what {
                "health" => {
                    let svc = HttpServer::auto(plain.clone()).service(HealthService(readiness.clone()));
                    plain.spawn_task(listener.serve(svc));
                }
                _ => {
                    let svc = HttpServer::auto(plain.clone()).service(MetricsService);
                    plain.spawn_task(listener.serve(svc));
                }
            }
            info!("rama: {what} on {addr}");
        }
        let draining = shutdown.guard_weak();
        plain.spawn_task(async move {
            draining.cancelled().await;
            readiness.start_draining();
        });

        // The pod's terminationGracePeriodSeconds must exceed this.
        let drain = std::env::var("PORTUS_DRAIN_SECONDS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(DRAIN_SECONDS);
        match shutdown.shutdown_with_limit(std::time::Duration::from_secs(drain)).await {
            Ok(elapsed) => {
                info!("rama: drained in {elapsed:?}, exiting");
                0
            }
            Err(e) => {
                error!("rama: drain did not finish within {drain}s ({e}); exiting with requests in flight");
                1
            }
        }
    });
    std::process::exit(exit_code)
}

/// Seconds to wait for in-flight requests after SIGTERM; LLM responses can
/// stream for a while. Override with `PORTUS_DRAIN_SECONDS`.
const DRAIN_SECONDS: u64 = 25;
