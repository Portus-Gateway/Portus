pub mod proto {
    pub mod portus {
        pub mod config {
            pub mod v1 {
                tonic::include_proto!("portus.config.v1");
            }
        }
    }
}

// Re-export for convenience
pub use proto::portus::config::v1::*;
