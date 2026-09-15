//! HTTP/2 flow-control windows every network stack advertises. The h2 crate's
//! 64 KiB defaults make large responses window-bound; 1 MiB per stream and
//! 4 MiB per connection match what hyper-based proxies advertise.

/// Per-stream window offered to downstream clients.
pub const H2_STREAM_WINDOW: u32 = 1 << 20;
/// Per-connection window offered to downstream clients.
pub const H2_CONNECTION_WINDOW: u32 = 4 << 20;

/// Per-stream window on upstream connections (gRPC and h2c backends).
pub const UPSTREAM_H2_STREAM_WINDOW: u32 = 1 << 20;
/// Per-connection window on upstream connections.
pub const UPSTREAM_H2_CONNECTION_WINDOW: u32 = 4 << 20;
