pub mod compiler;
#[cfg(test)]
mod conformance_tests;
pub mod gateway_types;
mod grpc_server;
mod triggers;
pub mod leader_election;
pub mod policy_types;
pub mod reconcilers;
pub mod status;
pub mod registry;
pub mod store;

use std::sync::Arc;

use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::Api;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::Controller;
use portus_types::proto::portus::config::v1::config_distribution_server::ConfigDistributionServer;
use portus_types::*;
use tokio::sync::watch;

use crate::gateway_types::{GRPCRoute, Gateway, GatewayClass, HTTPRoute, ListenerSet, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute};
use crate::policy_types::{
    APIKeyAuthPolicy, BasicAuthPolicy, CORSPolicy, CircuitBreakerPolicy, ConnectionPolicy,
    HealthCheckPolicy, IPAllowlistPolicy, RateLimitPolicy, RequestBodySizeLimitPolicy,
    RetryPolicy, TimeoutPolicy,
};
use crate::gateway_types::BackendTLSPolicy;
use crate::reconcilers::backend_tls_policy::reconcile_backend_tls_policy;
use crate::reconcilers::configmap::{reconcile_configmap, reconcile_configmap_inner};
use crate::reconcilers::api_key_auth_policy::reconcile_api_key_auth_policy;
use crate::reconcilers::basic_auth_policy::reconcile_basic_auth_policy;
use crate::reconcilers::circuit_breaker_policy::reconcile_circuit_breaker_policy;
use crate::reconcilers::connection_policy::reconcile_connection_policy;
use crate::reconcilers::cors_policy::reconcile_cors_policy;
use crate::reconcilers::endpointslice::reconcile_endpointslice;
use crate::reconcilers::gateway::reconcile_gateway;
use crate::reconcilers::gateway_class::reconcile_gateway_class;
use crate::reconcilers::grpc_route::reconcile_grpc_route;
use crate::reconcilers::health_check_policy::reconcile_health_check_policy;
use crate::reconcilers::http_route::reconcile_http_route;
use crate::reconcilers::listener_set::reconcile_listener_set;
use crate::reconcilers::namespace::reconcile_namespace;
use crate::reconcilers::ip_allowlist_policy::reconcile_ip_allowlist_policy;
use crate::reconcilers::rate_limit_policy::reconcile_rate_limit_policy;
use crate::reconcilers::reference_grant::reconcile_reference_grant;
use crate::reconcilers::request_body_size_limit_policy::reconcile_request_body_size_limit_policy;
use crate::reconcilers::retry_policy::reconcile_retry_policy;
use crate::reconcilers::secret::{reconcile_inner as reconcile_secret_inner, reconcile_secret};
use crate::reconcilers::service::reconcile_service;
use crate::reconcilers::l4_route::reconcile_l4_route;
use crate::reconcilers::timeout_policy::reconcile_timeout_policy;
use crate::reconcilers::tls_route::reconcile_tls_route;
use crate::reconcilers::ReconcileContext;
use crate::reconcilers::endpointslice::reconcile_endpointslice_inner;
use crate::registry::{cache_then, controller, gone_map, spawn};
use crate::store::{ConfigStore, Event, RouteKind};
use crate::triggers::{backend_tls_policies_for, gateways_for, listener_sets_for, on_events, policies_for, routes_for, PolicyRefs, RouteRefs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider before any TLS operations (required by tonic TLS feature)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");
    env_logger::init();

    // kube-client 4 defaults `read_timeout` to None. Restore the kube 3 safety net
    // so a dead connection cannot hang a request indefinitely; watches are bounded
    // by the 290 s server-side timeout and bookmarks, so a healthy stream never
    // trips it. Individual writes get a much tighter bound via
    // `status::with_write_timeout`.
    let mut kube_config = kube::Config::infer().await?;
    kube_config.read_timeout = Some(std::time::Duration::from_secs(295));
    let client = kube::Client::try_from(kube_config)?;

    // --- Leader election: block until this instance holds the lease ---
    let leader_config = leader_election::LeaderElectionConfig::from_env()?;
    leader_election::acquire_lease(client.clone(), &leader_config).await?;
    let mut leader_lost_rx = leader_election::spawn_renewal_task(client.clone(), &leader_config);

    let store = Arc::new(ConfigStore::new());
    let (tx, _rx) = watch::channel::<CompiledConfig>(CompiledConfig {
        schema_version: "1.0.0".to_string(),
        ..Default::default()
    });

    let ctx = Arc::new(ReconcileContext {
        store: Arc::clone(&store),
        client: client.clone(),
    });

    // Run compilation loop on a dedicated thread with its own tokio runtime.
    // This guarantees it can never be starved by reconciler tasks flooding
    // the main runtime's worker threads during heavy resource churn.
    let comp_store = Arc::clone(&store);
    let comp_tx = tx.clone();
    std::thread::Builder::new()
        .name("compilation-loop".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build compilation runtime");
            rt.block_on(async move {
                compiler::compilation_loop(comp_store, comp_tx).await;
                log::error!("BUG: compilation_loop exited — no more configs will be sent to data planes");
            });
        })
        .expect("failed to spawn compilation thread");

    // ── Controllers ─────────────────────────────────────────────────────────
    // Every kind goes through `registry::spawn`: shared error policy (404 →
    // evict, else requeue), ObjectNotFound eviction, per-kind timing. A kind
    // re-reconciles on its own watch and on the store's dependency events
    // (`triggers`): the reconciler owning some state publishes an event right
    // after writing it, and the controllers deriving status from that state
    // map the event to their objects. Kubernetes `watches` remain only where
    // the dependency is a Kubernetes object we do not otherwise reconcile in
    // order (ConfigMap, Secret, the dataplane's EndpointSlice), wrapped in
    // `cache_then` so the cache is written before the dependent runs.
    let gc_reader = spawn(
        "GatewayClass",
        controller::<GatewayClass>(&client),
        reconcile_gateway_class,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, _ns: Option<&str>, name: &str| reconcilers::gateway_class::forget(store, name))),
    );

    // Gateway: owns its provisioned Service/Deployment; re-run on the
    // ConfigMaps/Secrets its spec.tls names and on the EndpointSlice of its
    // dataplane Service (address publication); everything else (class, routes,
    // ListenerSets, Programmed acks, ReferenceGrants, Namespace labels) arrives
    // as store events.
    let gw_ctrl = controller::<Gateway>(&client)
        .owns(Api::<Service>::all(client.clone()), Default::default())
        .owns(Api::<k8s_openapi::api::apps::v1::Deployment>::all(client.clone()), Default::default());
    let gw_reader_for_cm = gw_ctrl.store();
    let gw_reader_for_secret = gw_ctrl.store();
    let gw_reader_for_events = gw_ctrl.store();
    let gw_event_store = ctx.store.clone();
    let gw_ctrl = gw_ctrl
        .watches(Api::<k8s_openapi::api::core::v1::ConfigMap>::all(client.clone()), Default::default(), cache_then(ctx.store.clone(), reconcile_configmap_inner, move |cm| {
            let (Some(ns), Some(name)) = (cm.metadata.namespace.as_deref(), cm.metadata.name.as_deref()) else {
                return Vec::new();
            };
            gw_reader_for_cm
                .state()
                .iter()
                .filter(|gw| gateway_references_ca_config_map(gw, ns, name))
                .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                .collect::<Vec<_>>()
        }))
        .watches(Api::<Secret>::all(client.clone()), Default::default(), cache_then(ctx.store.clone(), reconcile_secret_inner, move |secret| {
            let (Some(ns), Some(name)) = (secret.metadata.namespace.as_deref(), secret.metadata.name.as_deref()) else {
                return Vec::new();
            };
            // The gRPC TLS material is copied into every Gateway's namespace, so
            // rotating it re-provisions them all.
            let tls_source = reconcilers::gateway::dataplane_template().is_grpc_tls_source(ns, name);
            gw_reader_for_secret
                .state()
                .iter()
                .filter(|gw| tls_source || gateway_references_client_cert_secret(gw, ns, name))
                .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                .collect::<Vec<_>>()
        }))
        .watches(Api::<EndpointSlice>::all(client.clone()), Default::default(), cache_then(ctx.store.clone(), reconcile_endpointslice_inner, |eps| {
            let labels = eps.metadata.labels.as_ref();
            match (
                labels.and_then(|l| l.get(reconcilers::provisioner::LABEL_GATEWAY_NAME)),
                labels.and_then(|l| l.get(reconcilers::provisioner::LABEL_GATEWAY_NAMESPACE)),
            ) {
                (Some(name), Some(ns)) => vec![ObjectRef::new(name).within(ns)],
                _ => Vec::new(),
            }
        }))
        .reconcile_on(on_events(&ctx.store, gw_reader_for_events, move |event, reader| {
            gateways_for(event, &reader.state(), &gw_event_store)
        }));
    let gw_reader = spawn(
        "Gateway",
        gw_ctrl,
        reconcile_gateway,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, ns: Option<&str>, name: &str| {
            let key = crate::store::NamespacedName { namespace: ns.unwrap_or_default().to_string(), name: name.to_string() };
            store.gateway_tls.remove(&key);
            let removed = store.remove_and_notify(&store.gateways, &key).is_some();
            if removed {
                store.publish(Event::Gateway(key));
            }
            removed
        })),
    );

    let ls_ctrl = controller::<ListenerSet>(&client);
    let ls_event_reader = ls_ctrl.store();
    let ls_ctrl = ls_ctrl.reconcile_on(on_events(&ctx.store, ls_event_reader, |event, reader| listener_sets_for(event, &reader.state())));
    let ls_reader = spawn(
        "ListenerSet",
        ls_ctrl,
        reconcile_listener_set,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, ns: Option<&str>, name: &str| {
            let key = crate::store::NamespacedName { namespace: ns.unwrap_or_default().to_string(), name: name.to_string() };
            match store.remove_and_notify(&store.listener_sets, &key) {
                Some((_, gone)) => {
                    store.publish(Event::ListenerSet { key, parent: gone.parent_gateway });
                    true
                }
                None => false,
            }
        })),
    );

    let hr_reader = spawn("HTTPRoute", route_controller::<HTTPRoute>(&client, &ctx.store), reconcile_http_route, ctx.clone(), Some(gone_route(|s| &s.http_routes, RouteKind::Http)));
    let grpc_reader = spawn("GRPCRoute", route_controller::<GRPCRoute>(&client, &ctx.store), reconcile_grpc_route, ctx.clone(), Some(gone_route(|s| &s.grpc_routes, RouteKind::Grpc)));
    let tls_reader = spawn("TLSRoute", route_controller::<TLSRoute>(&client, &ctx.store), reconcile_tls_route, ctx.clone(), Some(gone_route(|s| &s.tls_routes, RouteKind::Tls)));
    let tcp_reader = spawn("TCPRoute", route_controller::<TCPRoute>(&client, &ctx.store), reconcile_l4_route::<TCPRoute>, ctx.clone(), Some(gone_route(|s| &s.tcp_routes, RouteKind::Tcp)));
    let udp_reader = spawn("UDPRoute", route_controller::<UDPRoute>(&client, &ctx.store), reconcile_l4_route::<UDPRoute>, ctx.clone(), Some(gone_route(|s| &s.udp_routes, RouteKind::Udp)));

    // Caches the routes, Gateways and ListenerSets read from: each publishes
    // its own event on change.
    spawn(
        "Namespace",
        controller::<k8s_openapi::api::core::v1::Namespace>(&client),
        reconcile_namespace,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, _ns: Option<&str>, name: &str| reconcilers::namespace::forget(store, name))),
    );
    let rg_reader = spawn(
        "ReferenceGrant",
        controller::<ReferenceGrant>(&client),
        reconcile_reference_grant,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, ns: Option<&str>, name: &str| {
            let namespace = ns.unwrap_or_default().to_string();
            let key = crate::store::NamespacedName { namespace: namespace.clone(), name: name.to_string() };
            let removed = store.remove_and_notify(&store.reference_grants, &key).is_some();
            if removed {
                store.publish(Event::ReferenceGrant { namespace });
            }
            removed
        })),
    );
    // EndpointSlices are keyed by their Service; the eviction hook only knows the
    // slice name, so deleted slices are reconciled away by the periodic prune of
    // `store.endpoints` against live Services (below) and by the reconciler
    // storing an empty set when the slice reports none.
    spawn(
        "EndpointSlice",
        controller::<EndpointSlice>(&client),
        reconcile_endpointslice,
        ctx.clone(),
        None,
    );
    spawn(
        "Service",
        controller::<Service>(&client),
        reconcile_service,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, ns: Option<&str>, name: &str| reconcilers::service::forget(store, ns.unwrap_or_default(), name))),
    );

    // Policies: re-run on data plane acks (Programmed) and when a sibling on
    // the same target changes (conflict resolution).
    let rlp_reader = spawn("RateLimitPolicy", policy_controller::<RateLimitPolicy>(&client, &ctx.store), reconcile_rate_limit_policy, ctx.clone(), Some(gone_policy("RateLimitPolicy", |s| &s.rate_limit_policies)));
    let cbp_reader = spawn("CircuitBreakerPolicy", policy_controller::<CircuitBreakerPolicy>(&client, &ctx.store), reconcile_circuit_breaker_policy, ctx.clone(), Some(gone_policy("CircuitBreakerPolicy", |s| &s.circuit_breaker_policies)));
    let cp_reader = spawn("ConnectionPolicy", policy_controller::<ConnectionPolicy>(&client, &ctx.store), reconcile_connection_policy, ctx.clone(), Some(gone_policy("ConnectionPolicy", |s| &s.connection_policies)));
    let bap_reader = spawn("BasicAuthPolicy", policy_controller::<BasicAuthPolicy>(&client, &ctx.store), reconcile_basic_auth_policy, ctx.clone(), Some(gone_policy("BasicAuthPolicy", |s| &s.basic_auth_policies)));
    let akp_reader = spawn("APIKeyAuthPolicy", policy_controller::<APIKeyAuthPolicy>(&client, &ctx.store), reconcile_api_key_auth_policy, ctx.clone(), Some(gone_policy("APIKeyAuthPolicy", |s| &s.api_key_auth_policies)));
    let rp_reader = spawn("RetryPolicy", policy_controller::<RetryPolicy>(&client, &ctx.store), reconcile_retry_policy, ctx.clone(), Some(gone_policy("RetryPolicy", |s| &s.retry_policies)));
    let iap_reader = spawn("IPAllowlistPolicy", policy_controller::<IPAllowlistPolicy>(&client, &ctx.store), reconcile_ip_allowlist_policy, ctx.clone(), Some(gone_policy("IPAllowlistPolicy", |s| &s.ip_allowlist_policies)));
    let bsl_reader = spawn("RequestBodySizeLimitPolicy", policy_controller::<RequestBodySizeLimitPolicy>(&client, &ctx.store), reconcile_request_body_size_limit_policy, ctx.clone(), Some(gone_policy("RequestBodySizeLimitPolicy", |s| &s.request_body_size_limit_policies)));
    let hcp_reader = spawn("HealthCheckPolicy", policy_controller::<HealthCheckPolicy>(&client, &ctx.store), reconcile_health_check_policy, ctx.clone(), Some(gone_policy("HealthCheckPolicy", |s| &s.health_check_policies)));
    let cors_reader = spawn("CORSPolicy", policy_controller::<CORSPolicy>(&client, &ctx.store), reconcile_cors_policy, ctx.clone(), Some(gone_policy("CORSPolicy", |s| &s.cors_policies)));
    let tp_reader = spawn("TimeoutPolicy", policy_controller::<TimeoutPolicy>(&client, &ctx.store), reconcile_timeout_policy, ctx.clone(), Some(gone_policy("TimeoutPolicy", |s| &s.timeout_policies)));

    // BackendTLSPolicy: re-run when the ConfigMap holding its CA changes, and
    // (as store events) on acks, siblings, and routes using its target Service
    // (ancestors).
    let btls_ctrl = controller::<BackendTLSPolicy>(&client);
    let btls_cm_reader = btls_ctrl.store();
    let btls_event_reader = btls_ctrl.store();
    let btls_ctrl = btls_ctrl
        .watches(Api::<k8s_openapi::api::core::v1::ConfigMap>::all(client.clone()), Default::default(), cache_then(ctx.store.clone(), reconcile_configmap_inner, move |cm| {
            let (Some(ns), Some(name)) = (cm.metadata.namespace.as_deref(), cm.metadata.name.as_deref()) else {
                return Vec::new();
            };
            btls_cm_reader
                .state()
                .iter()
                .filter(|p| {
                    p.metadata.namespace.as_deref() == Some(ns)
                        && p.spec.validation.ca_certificate_refs.iter().any(|r| {
                            r.name == name && (r.kind.is_empty() || r.kind == "ConfigMap") && r.group.is_empty()
                        })
                })
                .map(|p| ObjectRef::from_obj(p.as_ref()))
                .collect::<Vec<_>>()
        }))
        .reconcile_on(on_events(&ctx.store, btls_event_reader, |event, reader| backend_tls_policies_for(event, &reader.state())));
    let btls_reader = spawn("BackendTLSPolicy", btls_ctrl, reconcile_backend_tls_policy, ctx.clone(), Some(gone_policy("BackendTLSPolicy", |s| &s.backend_tls_policies)));

    let cm_reader = spawn(
        "ConfigMap",
        controller::<k8s_openapi::api::core::v1::ConfigMap>(&client),
        reconcile_configmap,
        ctx.clone(),
        Some(Arc::new(|store: &ConfigStore, ns: Option<&str>, name: &str| {
            let key = crate::store::NamespacedName { namespace: ns.unwrap_or_default().to_string(), name: name.to_string() };
            let removed = store.config_maps.remove(&key).is_some();
            if removed {
                store.notify_change();
            }
            removed
        })),
    );
    let secret_reader = spawn("Secret", controller::<Secret>(&client), reconcile_secret, ctx.clone(), Some(gone_map(|s| &s.secrets)));

    // Periodic store pruning. kube-rs doesn't always emit ObjectNotFound for
    // deleted objects (e.g. deleted with no requeue pending), so every two
    // minutes each ConfigStore map is checked against the controllers' own
    // reflector caches (no LISTs against the API server).
    {
        let prune_store = Arc::clone(&store);
        let readers = PruneReaders {
            http_routes: hr_reader,
            gateways: gw_reader,
            listener_sets: ls_reader,
            reference_grants: rg_reader,
            grpc_routes: grpc_reader,
            tls_routes: tls_reader,
            tcp_routes: tcp_reader,
            udp_routes: udp_reader,
            rate_limit_policies: rlp_reader,
            circuit_breaker_policies: cbp_reader,
            connection_policies: cp_reader,
            basic_auth_policies: bap_reader,
            api_key_auth_policies: akp_reader,
            retry_policies: rp_reader,
            ip_allowlist_policies: iap_reader,
            request_body_size_limit_policies: bsl_reader,
            health_check_policies: hcp_reader,
            backend_tls_policies: btls_reader,
            cors_policies: cors_reader,
            timeout_policies: tp_reader,
            secrets: secret_reader,
            config_maps: cm_reader,
            gateway_classes: gc_reader,
        };
        tokio::spawn(async move {
            // Never prune against a cache that has not finished its initial
            // list: an empty store would look like "everything was deleted".
            if let Err(e) = readers.wait_until_ready().await {
                log::warn!("prune: reflector store closed before ready ({e}); pruning disabled");
                return;
            }
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                let pruned = readers.prune(&prune_store);
                if pruned > 0 {
                    log::info!("prune: removed {pruned} stale entries from store");
                    prune_store.notify_change();
                }
            }
        });
    }

    // Start gRPC server on a dedicated tokio runtime so reconciler bursts
    // cannot starve h2 keepalive processing (which caused KeepAliveTimedOut
    // errors and broken-pipe disconnects under heavy resource churn).
    let grpc_store = Arc::clone(&store);
    // The gRPC thread runs for the life of the process; nothing joins it.
    let _grpc_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("grpc-server")
            .enable_all()
            .build()
            .expect("failed to build gRPC runtime");
        rt.block_on(async move {
            let addr: std::net::SocketAddr = "[::]:50051".parse().unwrap();
            let server = grpc_server::ConfigServer {
                tx,
                store: grpc_store,
            };
            let mut builder = tonic::transport::Server::builder()
                .http2_keepalive_interval(Some(std::time::Duration::from_secs(15)))
                .http2_keepalive_timeout(Some(std::time::Duration::from_secs(60)))
                .http2_adaptive_window(Some(true));

            // SEC-1: Optional TLS on gRPC server.
            // Set GRPC_TLS_CERT and GRPC_TLS_KEY to enable server-side TLS.
            // Set GRPC_TLS_CA to additionally require client certificates (mTLS / SEC-2).
            if let (Ok(cert_path), Ok(key_path)) = (
                std::env::var("GRPC_TLS_CERT"),
                std::env::var("GRPC_TLS_KEY"),
            ) {
                let cert = std::fs::read_to_string(&cert_path)
                    .unwrap_or_else(|e| panic!("failed to read GRPC_TLS_CERT at {}: {}", cert_path, e));
                let key = std::fs::read_to_string(&key_path)
                    .unwrap_or_else(|e| panic!("failed to read GRPC_TLS_KEY at {}: {}", key_path, e));
                let identity = tonic::transport::Identity::from_pem(cert, key);

                let mut tls_config = tonic::transport::ServerTlsConfig::new()
                    .identity(identity);

                if let Ok(ca_path) = std::env::var("GRPC_TLS_CA") {
                    let ca_cert = std::fs::read_to_string(&ca_path)
                        .unwrap_or_else(|e| panic!("failed to read GRPC_TLS_CA at {}: {}", ca_path, e));
                    let ca = tonic::transport::Certificate::from_pem(ca_cert);
                    tls_config = tls_config.client_ca_root(ca);
                    log::info!("gRPC server mTLS enabled (client certs required)");
                }

                builder = builder
                    .tls_config(tls_config)
                    .expect("failed to configure gRPC server TLS");
                log::info!("gRPC server TLS enabled");
            } else {
                log::error!("gRPC server running WITHOUT TLS — TLS private keys and auth credentials will transit in plaintext. Set GRPC_TLS_CERT and GRPC_TLS_KEY to enable.");
            }

            log::info!("controller gRPC server listening on {} (dedicated runtime)", addr);
            builder
                .add_service(
                    ConfigDistributionServer::new(server)
                        .max_encoding_message_size(64 * 1024 * 1024) // 64MB — compiled config can include TLS certs
                )
                .serve(addr)
                .await
                .expect("gRPC server failed");
        });
    });

    // Minimal HTTP health endpoint for liveness/readiness probes.
    // /healthz: always 200 (process is alive)
    // /readyz: 200 only after first config is compiled (compiled_version > 0)
    // /metrics: per-kind reconcile counters and durations (Prometheus text)
    tokio::spawn(async {
        let listener = match tokio::net::TcpListener::bind("[::]:8082").await {
            Ok(l) => l,
            Err(e) => {
                log::error!("failed to bind health endpoint on :8082: {}", e);
                return;
            }
        };
        log::info!("controller health endpoint listening on :8082");
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 512];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    let response = if req.starts_with("GET /healthz") || req.starts_with("GET /readyz") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()
                    } else if req.starts_with("GET /metrics") {
                        let body = crate::registry::STATS.render();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    // Wait for shutdown signal OR leadership loss.
    // grpc_handle.join() is a blocking call that would steal a tokio worker thread,
    // starving the compilation loop and reconcilers under heavy load.
    // Kubernetes stops pods with SIGTERM; SIGINT covers local runs.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut still_leader = true;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("received SIGINT, exiting");
        }
        _ = sigterm.recv() => {
            log::info!("received SIGTERM, exiting");
        }
        _ = async {
            // Wait until the leader_lost_rx flips to false
            loop {
                leader_lost_rx.changed().await.ok();
                if !*leader_lost_rx.borrow() {
                    break;
                }
            }
        } => {
            still_leader = false;
            log::error!("leadership lost, shutting down to allow new leader to take over");
        }
    }
    if still_leader {
        // Hand the lease over now rather than making the successor wait for expiry.
        leader_election::release_lease(client.clone(), &leader_config).await;
    }
    Ok(())
}

/// Reflector stores for every kind the prune task reconciles against.
struct PruneReaders {
    http_routes: kube::runtime::reflector::Store<HTTPRoute>,
    gateways: kube::runtime::reflector::Store<Gateway>,
    listener_sets: kube::runtime::reflector::Store<ListenerSet>,
    reference_grants: kube::runtime::reflector::Store<ReferenceGrant>,
    grpc_routes: kube::runtime::reflector::Store<GRPCRoute>,
    tls_routes: kube::runtime::reflector::Store<TLSRoute>,
    tcp_routes: kube::runtime::reflector::Store<TCPRoute>,
    udp_routes: kube::runtime::reflector::Store<UDPRoute>,
    rate_limit_policies: kube::runtime::reflector::Store<RateLimitPolicy>,
    circuit_breaker_policies: kube::runtime::reflector::Store<CircuitBreakerPolicy>,
    connection_policies: kube::runtime::reflector::Store<ConnectionPolicy>,
    basic_auth_policies: kube::runtime::reflector::Store<BasicAuthPolicy>,
    api_key_auth_policies: kube::runtime::reflector::Store<APIKeyAuthPolicy>,
    retry_policies: kube::runtime::reflector::Store<RetryPolicy>,
    ip_allowlist_policies: kube::runtime::reflector::Store<IPAllowlistPolicy>,
    request_body_size_limit_policies: kube::runtime::reflector::Store<RequestBodySizeLimitPolicy>,
    health_check_policies: kube::runtime::reflector::Store<HealthCheckPolicy>,
    backend_tls_policies: kube::runtime::reflector::Store<BackendTLSPolicy>,
    cors_policies: kube::runtime::reflector::Store<CORSPolicy>,
    timeout_policies: kube::runtime::reflector::Store<TimeoutPolicy>,
    secrets: kube::runtime::reflector::Store<Secret>,
    config_maps: kube::runtime::reflector::Store<k8s_openapi::api::core::v1::ConfigMap>,
    gateway_classes: kube::runtime::reflector::Store<GatewayClass>,
}

/// Live (namespace, name) pairs from a reflector store.
fn live_names<K>(reader: &kube::runtime::reflector::Store<K>) -> std::collections::HashSet<(String, String)>
where
    K: kube::Resource<DynamicType = ()> + Clone + 'static,
{
    use kube::ResourceExt;
    reader
        .state()
        .iter()
        .map(|r| (r.namespace().unwrap_or_default(), r.name_any()))
        .collect()
}

/// Remove entries from `map` whose (namespace, name) is no longer in the live set.
fn prune_map<V>(
    map: &dashmap::DashMap<crate::store::NamespacedName, V>,
    live: &std::collections::HashSet<(String, String)>,
    label: &str,
) -> usize {
    let stale: Vec<_> = map
        .iter()
        .filter(|entry| {
            let key = entry.key();
            !live.contains(&(key.namespace.clone(), key.name.clone()))
        })
        .map(|entry| entry.key().clone())
        .collect();
    for key in &stale {
        map.remove(key);
        log::info!("pruned stale {label} {key} from store");
    }
    stale.len()
}

impl PruneReaders {
    async fn wait_until_ready(&self) -> Result<(), kube::runtime::reflector::store::WriterDropped> {
        self.http_routes.wait_until_ready().await?;
        self.gateways.wait_until_ready().await?;
        self.listener_sets.wait_until_ready().await?;
        self.reference_grants.wait_until_ready().await?;
        self.grpc_routes.wait_until_ready().await?;
        self.tls_routes.wait_until_ready().await?;
        self.tcp_routes.wait_until_ready().await?;
        self.udp_routes.wait_until_ready().await?;
        self.rate_limit_policies.wait_until_ready().await?;
        self.circuit_breaker_policies.wait_until_ready().await?;
        self.connection_policies.wait_until_ready().await?;
        self.basic_auth_policies.wait_until_ready().await?;
        self.api_key_auth_policies.wait_until_ready().await?;
        self.retry_policies.wait_until_ready().await?;
        self.ip_allowlist_policies.wait_until_ready().await?;
        self.request_body_size_limit_policies.wait_until_ready().await?;
        self.health_check_policies.wait_until_ready().await?;
        self.backend_tls_policies.wait_until_ready().await?;
        self.cors_policies.wait_until_ready().await?;
        self.timeout_policies.wait_until_ready().await?;
        self.secrets.wait_until_ready().await?;
        self.config_maps.wait_until_ready().await?;
        self.gateway_classes.wait_until_ready().await?;
        Ok(())
    }

    /// One prune cycle. Returns how many entries were removed.
    fn prune(&self, store: &ConfigStore) -> usize {
        let mut pruned = 0;
        pruned += prune_map(&store.http_routes, &live_names(&self.http_routes), "HTTPRoute");
        pruned += prune_map(&store.gateways, &live_names(&self.gateways), "Gateway");
        pruned += prune_map(&store.listener_sets, &live_names(&self.listener_sets), "ListenerSet");
        pruned += prune_map(&store.reference_grants, &live_names(&self.reference_grants), "ReferenceGrant");
        pruned += prune_map(&store.grpc_routes, &live_names(&self.grpc_routes), "GRPCRoute");
        pruned += prune_map(&store.tls_routes, &live_names(&self.tls_routes), "TLSRoute");
        pruned += prune_map(&store.tcp_routes, &live_names(&self.tcp_routes), "TCPRoute");
        pruned += prune_map(&store.udp_routes, &live_names(&self.udp_routes), "UDPRoute");
        pruned += prune_map(&store.rate_limit_policies, &live_names(&self.rate_limit_policies), "RateLimitPolicy");
        pruned += prune_map(&store.circuit_breaker_policies, &live_names(&self.circuit_breaker_policies), "CircuitBreakerPolicy");
        pruned += prune_map(&store.connection_policies, &live_names(&self.connection_policies), "ConnectionPolicy");
        pruned += prune_map(&store.basic_auth_policies, &live_names(&self.basic_auth_policies), "BasicAuthPolicy");
        pruned += prune_map(&store.api_key_auth_policies, &live_names(&self.api_key_auth_policies), "ApiKeyAuthPolicy");
        pruned += prune_map(&store.retry_policies, &live_names(&self.retry_policies), "RetryPolicy");
        pruned += prune_map(&store.ip_allowlist_policies, &live_names(&self.ip_allowlist_policies), "IPAllowlistPolicy");
        pruned += prune_map(&store.request_body_size_limit_policies, &live_names(&self.request_body_size_limit_policies), "RequestBodySizeLimitPolicy");
        pruned += prune_map(&store.health_check_policies, &live_names(&self.health_check_policies), "HealthCheckPolicy");
        pruned += prune_map(&store.backend_tls_policies, &live_names(&self.backend_tls_policies), "BackendTLSPolicy");
        pruned += prune_map(&store.cors_policies, &live_names(&self.cors_policies), "CORSPolicy");
        pruned += prune_map(&store.timeout_policies, &live_names(&self.timeout_policies), "TimeoutPolicy");
        // Secrets/ConfigMaps deleted from Kubernetes must not linger in memory.
        pruned += prune_map(&store.secrets, &live_names(&self.secrets), "Secret");
        pruned += prune_map(&store.config_maps, &live_names(&self.config_maps), "ConfigMap");

        // GatewayClass is cluster-scoped and keyed by name.
        let live_gc: std::collections::HashSet<String> = {
            use kube::ResourceExt;
            self.gateway_classes.state().iter().map(|gc| gc.name_any()).collect()
        };
        let stale: Vec<String> = store
            .gateway_classes
            .iter()
            .filter(|entry| !live_gc.contains(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();
        for key in &stale {
            store.gateway_classes.remove(key);
            log::info!("pruned stale GatewayClass {key} from store");
        }
        pruned + stale.len()
    }
}

/// True when `gw.spec.tls.frontend` names ConfigMap `ns/name` as a CA source
/// (default or any per-port block; refs without a namespace are in the
/// Gateway's namespace).
fn gateway_references_ca_config_map(gw: &Gateway, ns: &str, name: &str) -> bool {
    let Some(frontend) = gw.spec.tls.as_ref().and_then(|t| t.frontend.as_ref()) else {
        return false;
    };
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    std::iter::once(&frontend.default)
        .chain(frontend.per_port.iter().map(|pp| &pp.tls))
        .filter_map(|cfg| cfg.validation.as_ref())
        .flat_map(|v| v.ca_certificate_refs.iter())
        .any(|r| {
            r.name == name
                && r.group.is_empty()
                && (r.kind.is_empty() || r.kind == "ConfigMap")
                && r.namespace.as_deref().unwrap_or(gw_ns) == ns
        })
}

/// True when `gw.spec.tls.backend.clientCertificateRef` names Secret `ns/name`.
fn gateway_references_client_cert_secret(gw: &Gateway, ns: &str, name: &str) -> bool {
    let Some(r) = gw
        .spec
        .tls
        .as_ref()
        .and_then(|t| t.backend.as_ref())
        .and_then(|b| b.client_certificate_ref.as_ref())
    else {
        return false;
    };
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    r.name == name
        && r.group.as_deref().unwrap_or("").is_empty()
        && r.kind.as_deref().unwrap_or("Secret") == "Secret"
        && r.namespace.as_deref().unwrap_or(gw_ns) == ns
}

/// The controller shape shared by every route kind: its own watch plus the
/// store events its status depends on (`triggers::routes_for`).
fn route_controller<K>(client: &kube::Client, store: &Arc<ConfigStore>) -> Controller<K>
where
    K: RouteRefs + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let ctrl = controller::<K>(client);
    let reader = ctrl.store();
    ctrl.reconcile_on(on_events(store, reader, |event, reader| routes_for(event, &reader.state())))
}

/// The controller shape shared by every single-target policy kind
/// (`triggers::policies_for`).
fn policy_controller<K>(client: &kube::Client, store: &Arc<ConfigStore>) -> Controller<K>
where
    K: PolicyRefs + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let ctrl = controller::<K>(client);
    let reader = ctrl.store();
    ctrl.reconcile_on(on_events(store, reader, |event, reader| policies_for(event, &reader.state())))
}

/// Eviction hook for a route kind: drop the state and tell its parents.
fn gone_route<S>(map: fn(&ConfigStore) -> &dashmap::DashMap<crate::store::NamespacedName, S>, kind: RouteKind) -> registry::Gone
where
    S: crate::store::RouteState + Send + Sync + 'static,
{
    Arc::new(move |store, ns, name| {
        let key = crate::store::NamespacedName { namespace: ns.unwrap_or_default().to_string(), name: name.to_string() };
        reconcilers::remove_route(store, map(store), kind, &key)
    })
}

/// Eviction hook for a policy kind: drop the state and tell its siblings.
fn gone_policy<S>(kind: &'static str, map: fn(&ConfigStore) -> &dashmap::DashMap<crate::store::NamespacedName, S>) -> registry::Gone
where
    S: reconcilers::policy_common::PolicyState + Send + Sync + 'static,
{
    Arc::new(move |store, ns, name| {
        let key = crate::store::NamespacedName { namespace: ns.unwrap_or_default().to_string(), name: name.to_string() };
        match store.remove_and_notify(map(store), &key) {
            Some((_, gone)) => {
                store.publish(Event::Policy { kind, key, target: gone.target().clone() });
                true
            }
            None => false,
        }
    })
}
