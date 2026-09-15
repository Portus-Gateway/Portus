//! Network-stack-independent core of the Portus data plane.
//!
//! Everything a Portus data plane does apart from speaking HTTP on a socket
//! lives here: receiving `CompiledConfig` slices from the controller (or a YAML
//! file in standalone mode), building the route tables and endpoint pools,
//! matching requests, policies (auth, rate limits, circuit breakers, CORS,
//! outlier ejection), TLS material and hot reload, the SNI mux and the L4/UDP
//! proxies, metrics and readiness.
//!
//! A network stack adapter (Pingora today) turns a [`bootstrap::Bootstrap`] into
//! a running proxy: it accepts the connections the listener manager hands off,
//! drives one request through [`router`]'s decisions and talks to the backend
//! the [`pool::Pool`] picked. Nothing in this crate names a proxy framework.

pub mod auth;
pub mod bootstrap;
pub mod circuit_breaker;
pub mod config_receiver;
pub mod h2;
pub mod l4_proxy;
pub mod metrics;
pub mod outlier;
pub mod plan;
pub mod pool;
pub mod rate_limiter;
pub mod readiness;
pub mod router;
pub mod runtime;
pub mod stack;
pub mod standalone;
pub mod tls;
pub mod types;
pub mod udp_proxy;
