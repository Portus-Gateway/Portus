//! Portus data plane: `portus-dataplane-core` bootstrapped onto a network stack.

#[cfg(feature = "pingora")]
mod pingora;
mod stack;

use log::{error, info};

use portus_dataplane_core::bootstrap::{bootstrap, fatal};

use crate::stack::NetworkStack;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn init_logging() {
    // Lock-free logging: tracing-subscriber replaces env_logger.
    // env_logger acquires a stderr mutex on EVERY log level check, even when
    // filtered out — profiling showed 13% of CPU burned on mutex contention.
    // tracing-subscriber's EnvFilter uses lock-free atomics for level filtering:
    // filtered-out messages have zero contention across worker threads.
    // LogTracer bridges the stacks' log:: macros through tracing's filter path.
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

    let stack = NetworkStack::from_env().unwrap_or_else(|e| fatal(&e));
    let boot = bootstrap().unwrap_or_else(|e| fatal(&e));
    info!("starting the {} network stack", stack.name());
    match stack {
        NetworkStack::Pingora => {
            #[cfg(feature = "pingora")]
            pingora::run(boot);
            #[cfg(not(feature = "pingora"))]
            {
                drop(boot);
                error!("the pingora network stack is not built into this binary");
                std::process::exit(1)
            }
        }
        NetworkStack::Rama => {
            drop(boot);
            error!("the rama network stack is not built into this binary");
            std::process::exit(1)
        }
    }
}
