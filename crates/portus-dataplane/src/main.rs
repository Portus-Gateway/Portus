//! Portus data plane: `portus-dataplane-core` bootstrapped onto the Rama
//! network stack.

mod rama;

use portus_dataplane_core::bootstrap::{bootstrap, fatal};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn init_logging() {
    // Lock-free logging: tracing-subscriber replaces env_logger.
    // env_logger acquires a stderr mutex on EVERY log level check, even when
    // filtered out — profiling showed 13% of CPU burned on mutex contention.
    // tracing-subscriber's EnvFilter uses lock-free atomics for level filtering:
    // filtered-out messages have zero contention across worker threads.
    // LogTracer bridges the log:: macros (core and Rama) through tracing's filter path.
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr).with_target(true).with_ansi(false))
        .init();
    tracing_log::LogTracer::init().ok();
}

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");
    init_logging();

    let boot = bootstrap().unwrap_or_else(|e| fatal(&e));
    rama::run(boot);
}
