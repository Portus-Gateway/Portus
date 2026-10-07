#[cfg(feature = "jwks")]
pub mod jwks;

pub mod proto {
    pub mod portus {
        pub mod config {
            pub mod v1 {
                tonic::include_proto!("portus.config.v1");
            }
        }
        pub mod ledger {
            pub mod v1 {
                tonic::include_proto!("portus.ledger.v1");
            }
        }
    }

    /// OTLP (vendored opentelemetry-proto), for exporting traces.
    pub mod opentelemetry {
        pub mod proto {
            pub mod common {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.common.v1");
                }
            }
            pub mod resource {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.resource.v1");
                }
            }
            pub mod trace {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.trace.v1");
                }
            }
            pub mod collector {
                pub mod trace {
                    pub mod v1 {
                        tonic::include_proto!("opentelemetry.proto.collector.trace.v1");
                    }
                }
            }
        }
    }
}

// Re-export for convenience
pub use proto::portus::config::v1::*;
