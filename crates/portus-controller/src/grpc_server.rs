use std::sync::Arc;

use futures::{Stream, StreamExt};
use portus_types::proto::portus::config::v1::config_distribution_server::ConfigDistribution;
use portus_types::{AppliedAck, AppliedReport, CompiledConfig, ConfigRequest};
use std::pin::Pin;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tonic::{Request, Response, Status};

use crate::store::{ConfigStore, NamespacedName};

/// Gateway a data plane says it is dedicated to; None for a shared data plane.
fn gateway_ref(namespace: &str, name: &str) -> Option<NamespacedName> {
    if namespace.is_empty() || name.is_empty() {
        None
    } else {
        Some(NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }
}

pub struct ConfigServer {
    pub tx: watch::Sender<CompiledConfig>,
    pub store: Arc<ConfigStore>,
}

/// Removes the data plane from the store when its config stream ends (pod
/// gone, connection dropped). Lives inside the stream so it fires exactly when
/// tonic drops the response stream.
struct DataPlaneSession {
    store: Arc<ConfigStore>,
    node_id: String,
}

impl Drop for DataPlaneSession {
    fn drop(&mut self) {
        log::info!("data plane disconnected: node_id={}", self.node_id);
        self.store.forget_data_plane(&self.node_id);
    }
}

/// Attach a [`DataPlaneSession`] to a stream so it is dropped with it.
fn with_session<S>(stream: S, session: DataPlaneSession) -> impl Stream<Item = S::Item>
where
    S: Stream + Unpin,
{
    futures::stream::unfold((stream, session), |(mut stream, session)| async move {
        let item = stream.next().await?;
        Some((item, (stream, session)))
    })
}

#[tonic::async_trait]
impl ConfigDistribution for ConfigServer {
    type StreamConfigStream = Pin<Box<dyn Stream<Item = Result<CompiledConfig, Status>> + Send>>;

    async fn stream_config(
        &self,
        request: Request<ConfigRequest>,
    ) -> Result<Response<Self::StreamConfigStream>, Status> {
        let req = request.into_inner();
        let Some(gateway) = gateway_ref(&req.gateway_namespace, &req.gateway_name) else {
            return Err(Status::invalid_argument(
                "ConfigRequest must name the Gateway this data plane serves (gateway_namespace/gateway_name)",
            ));
        };
        log::info!(
            "data plane connected: node_id={}, gateway={}/{}, schema_version={}, last_applied_fingerprint={:#x}",
            req.node_id,
            gateway.namespace,
            gateway.name,
            req.schema_version,
            req.last_applied_fingerprint,
        );

        // Validate schema version compatibility (major version must match)
        let our_major = "1"; // hardcoded for Phase 6
        let their_major = req.schema_version.split('.').next().unwrap_or("0");
        if their_major != our_major && !req.schema_version.is_empty() {
            return Err(Status::failed_precondition(format!(
                "incompatible schema version: {} (expected major version {})",
                req.schema_version, our_major
            )));
        }

        if self.store.accepts_data_plane(&req.node_id) {
            // A reconnecting data plane tells us what it is running right now;
            // that is a Programmed ACK for that content.
            self.store
                .record_applied(&req.node_id, gateway.clone(), req.last_applied_fingerprint);
        } else {
            log::warn!(
                "rejecting data plane registration for node_id '{}': max {} nodes reached",
                req.node_id,
                ConfigStore::MAX_DATA_PLANE_NODES
            );
        }

        // WatchStream::new yields the current value immediately, then yields
        // on each subsequent change. This replaces the old broadcast+initial-config
        // pattern — the data plane always gets the latest config on connect, and
        // can never miss an update (watch never lags).
        let rx = self.tx.subscribe();
        let session = DataPlaneSession {
            store: Arc::clone(&self.store),
            node_id: req.node_id.clone(),
        };
        // Stream only this Gateway's slice, with the slice's own fingerprint so
        // unrelated Gateways never churn it.
        let stream: Self::StreamConfigStream = Box::pin(with_session(
            Box::pin(WatchStream::new(rx).map(move |cfg| {
                if cfg.version == 0 {
                    return Ok(cfg); // sentinel "no config yet"
                }
                Ok(crate::compiler::scope_config(&cfg, &gateway.namespace, &gateway.name))
            })),
            session,
        ));

        Ok(Response::new(stream))
    }

    async fn report_applied(
        &self,
        request: Request<AppliedReport>,
    ) -> Result<Response<AppliedAck>, Status> {
        let report = request.into_inner();
        if report.fingerprint == 0 {
            return Err(Status::invalid_argument("fingerprint must be non-zero"));
        }
        let Some(gateway) = gateway_ref(&report.gateway_namespace, &report.gateway_name) else {
            return Err(Status::invalid_argument(
                "AppliedReport must name the Gateway this data plane serves (gateway_namespace/gateway_name)",
            ));
        };
        if !self.store.record_applied(&report.node_id, gateway, report.fingerprint) {
            return Err(Status::resource_exhausted(format!(
                "max {} data plane nodes reached",
                ConfigStore::MAX_DATA_PLANE_NODES
            )));
        }
        log::debug!(
            "data plane {} applied config v{} (fingerprint {:#x}); programmed={}",
            report.node_id,
            report.version,
            report.fingerprint,
            self.store.is_programmed()
        );
        Ok(Response::new(AppliedAck {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_config_watch() {
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        let server = ConfigServer {
            tx: tx.clone(),
            store: Arc::clone(&store),
        };

        let request = Request::new(ConfigRequest {
            node_id: "test-node".to_string(),
            last_known_version: 0,
            schema_version: "1.0.0".to_string(),
            last_applied_version: 0,
            last_applied_fingerprint: 0,
            gateway_namespace: "ns".to_string(),
            gateway_name: "gw".to_string(),
        });

        let response = server.stream_config(request).await.unwrap();
        let mut stream = response.into_inner();

        // WatchStream yields the current (default) value immediately
        let initial = futures::StreamExt::next(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(initial.version, 0); // default config

        // Send a real config
        let config = CompiledConfig {
            schema_version: "1.0.0".to_string(),
            version: 42,
            ..Default::default()
        };
        tx.send(config).unwrap();

        // Client should receive it
        let received = futures::StreamExt::next(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.version, 42);
        assert_eq!(received.schema_version, "1.0.0");
    }

    #[tokio::test]
    async fn test_stream_config_records_applied_fingerprint_on_connect() {
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        store
            .compiled_fingerprint
            .store(0x5150, std::sync::atomic::Ordering::Release);
        store.compiled_gateway_fingerprints.insert(
            crate::store::NamespacedName { namespace: "ns".into(), name: "gw".into() },
            0x5150,
        );

        let server = ConfigServer {
            tx: tx.clone(),
            store: Arc::clone(&store),
        };

        let request = Request::new(ConfigRequest {
            node_id: "test-node".to_string(),
            last_known_version: 0,
            schema_version: "1.0.0".to_string(),
            last_applied_version: 0,
            last_applied_fingerprint: 0x5150,
            gateway_namespace: "ns".to_string(),
            gateway_name: "gw".to_string(),
        });

        let _response = server.stream_config(request).await.unwrap();

        assert_eq!(store.data_plane_applied.get("test-node").unwrap().value().fingerprint, 0x5150);
        assert!(store.is_programmed());
    }

    #[tokio::test]
    async fn test_stream_config_scopes_to_the_requesting_gateway() {
        use portus_types::{Listener, RouteConfig};
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        let server = ConfigServer {
            tx: tx.clone(),
            store: Arc::clone(&store),
        };
        let request = Request::new(ConfigRequest {
            node_id: "dp-a".to_string(),
            last_known_version: 0,
            schema_version: "1.0.0".to_string(),
            last_applied_version: 0,
            last_applied_fingerprint: 0,
            gateway_namespace: "ns".to_string(),
            gateway_name: "a".to_string(),
        });
        let mut stream = server.stream_config(request).await.unwrap().into_inner();
        let sentinel = futures::StreamExt::next(&mut stream).await.unwrap().unwrap();
        assert_eq!(sentinel.version, 0);

        let mk_route = |gw: &str, svc: &str| RouteConfig {
            host: "*".into(),
            service_name: svc.into(),
            port: 8080,
            gateway_namespace: "ns".into(),
            gateway_name: gw.into(),
            ..Default::default()
        };
        let mk_listener = |gw: &str| Listener {
            name: "http".into(),
            port: 80,
            protocol: "HTTP".into(),
            gateway_namespace: "ns".into(),
            gateway_name: gw.into(),
            ..Default::default()
        };
        tx.send(CompiledConfig {
            schema_version: "1.0.0".into(),
            version: 7,
            fingerprint: 0xffff,
            routes: vec![mk_route("a", "svc-a"), mk_route("b", "svc-b")],
            listeners: vec![mk_listener("a"), mk_listener("b")],
            ..Default::default()
        })
        .unwrap();
        let scoped = futures::StreamExt::next(&mut stream).await.unwrap().unwrap();
        assert_eq!(scoped.version, 7);
        assert_eq!(scoped.routes.len(), 1);
        assert_eq!(scoped.routes[0].service_name, "svc-a");
        assert_eq!(scoped.listeners.len(), 1);
        assert_ne!(scoped.fingerprint, 0xffff, "slice carries its own fingerprint");
        assert_ne!(scoped.fingerprint, 0);
    }

    #[tokio::test]
    async fn test_dropping_the_stream_forgets_the_data_plane() {
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        store
            .compiled_fingerprint
            .store(0x77, std::sync::atomic::Ordering::Release);
        store.compiled_gateway_fingerprints.insert(
            crate::store::NamespacedName { namespace: "ns".into(), name: "gw".into() },
            0x77,
        );
        let server = ConfigServer {
            tx: tx.clone(),
            store: Arc::clone(&store),
        };
        let request = Request::new(ConfigRequest {
            node_id: "dp-gone".to_string(),
            last_known_version: 0,
            schema_version: "1.0.0".to_string(),
            last_applied_version: 0,
            last_applied_fingerprint: 0x77,
            gateway_namespace: "ns".to_string(),
            gateway_name: "gw".to_string(),
        });
        let mut stream = server.stream_config(request).await.unwrap().into_inner();
        let _ = futures::StreamExt::next(&mut stream).await;
        assert!(store.is_programmed());

        drop(stream);

        assert!(store.data_plane_applied.get("dp-gone").is_none(), "node forgotten on disconnect");
        assert!(!store.is_programmed());
        // The cap is free again for the replacement pod.
        assert!(store.accepts_data_plane("dp-replacement"));
    }

    #[tokio::test]
    async fn test_report_applied_updates_programmed_state() {
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        store
            .compiled_fingerprint
            .store(0xbeef, std::sync::atomic::Ordering::Release);
        store.compiled_gateway_fingerprints.insert(
            crate::store::NamespacedName { namespace: "ns".into(), name: "gw".into() },
            0xbeef,
        );
        let server = ConfigServer {
            tx,
            store: Arc::clone(&store),
        };

        // Stale content: recorded, not programmed.
        server
            .report_applied(Request::new(AppliedReport {
                node_id: "dp-1".into(),
                fingerprint: 0xdead,
                version: 3,
                gateway_namespace: "ns".into(),
                gateway_name: "gw".into(),
            }))
            .await
            .unwrap();
        assert!(!store.is_programmed());

        // Current content: programmed.
        server
            .report_applied(Request::new(AppliedReport {
                node_id: "dp-1".into(),
                fingerprint: 0xbeef,
                version: 4,
                gateway_namespace: "ns".into(),
                gateway_name: "gw".into(),
            }))
            .await
            .unwrap();
        assert!(store.is_programmed());

        // A report that names no Gateway is rejected.
        let err = server
            .report_applied(Request::new(AppliedReport {
                node_id: "dp-1".into(),
                fingerprint: 0xbeef,
                version: 5,
                gateway_namespace: String::new(),
                gateway_name: String::new(),
            }))
            .await
            .expect_err("rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // Zero is not a fingerprint.
        let err = server
            .report_applied(Request::new(AppliedReport {
                node_id: "dp-1".into(),
                fingerprint: 0,
                version: 4,
                gateway_namespace: "ns".into(),
                gateway_name: "gw".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_stream_config_rejects_a_data_plane_without_a_gateway() {
        let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());
        let store = Arc::new(ConfigStore::new());
        let server = ConfigServer { tx, store: Arc::clone(&store) };
        let request = Request::new(ConfigRequest {
            node_id: "anon".to_string(),
            last_known_version: 0,
            schema_version: "1.0.0".to_string(),
            last_applied_version: 0,
            last_applied_fingerprint: 0,
            gateway_namespace: String::new(),
            gateway_name: String::new(),
        });
        let err = server.stream_config(request).await.err().expect("must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(store.data_plane_applied.is_empty());
    }
}
