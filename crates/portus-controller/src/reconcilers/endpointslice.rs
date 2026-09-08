//! EndpointSlice watcher that populates store.endpoints with backend addresses.
//!
//! Watches EndpointSlice resources (k8s-openapi native type) and extracts ready
//! endpoint addresses keyed by ServiceKey{namespace, name, port}. Without this,
//! all BackendGroups would have zero endpoints and traffic cannot be proxied.
//!
//! Uses the `kubernetes.io/service-name` label to identify the owning Service.

use super::{ReconcileContext, ReconcileError};
use crate::store::{ConfigStore, ServiceKey};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::controller::Action;
use portus_types::BackendEndpoint;
use std::sync::Arc;

/// Label key used by Kubernetes to link EndpointSlice to its owning Service.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// Core reconciliation logic for EndpointSlice resources.
/// Separated from the async function for unit testability without a kube Client.
pub fn reconcile_endpointslice_inner(
    eps: &EndpointSlice,
    store: &ConfigStore,
) -> Result<(), ReconcileError> {
    let namespace = eps
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;

    // Extract owning service name from label
    let service_name = match eps
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SERVICE_NAME_LABEL))
    {
        Some(name) => name.clone(),
        None => return Ok(()), // Not service-backed, skip
    };

    // Process each port in the EndpointSlice
    let mut changed = false;
    let ports = eps.ports.as_deref().unwrap_or(&[]);
    for ep_port in ports {
        let port_number = match ep_port.port {
            Some(p) => p as u16,
            None => continue, // No port number, skip
        };

        let service_key = ServiceKey {
            namespace: namespace.to_string(),
            name: service_name.clone(),
            port: port_number,
        };

        // Collect ready endpoint addresses
        let mut endpoints = Vec::new();
        for endpoint in eps.endpoints.iter().flatten() {
            // Check readiness: ready if conditions.ready is true or conditions is absent
            let is_ready = endpoint
                .conditions
                .as_ref()
                .and_then(|c| c.ready)
                .unwrap_or(true); // Default to ready when conditions absent

            if !is_ready {
                continue;
            }

            for address in &endpoint.addresses {
                endpoints.push(BackendEndpoint {
                    address: address.clone(),
                    port: port_number as u32,
                });
            }
        }

        // Insert or remove based on whether we have endpoints. Only a change
        // wakes the compiler: pod churn re-lists slices whose ready set is the
        // same, and each wake is a full recompile.
        endpoints.sort_by(|a, b| (&a.address, a.port).cmp(&(&b.address, b.port)));
        if endpoints.is_empty() {
            changed |= store.endpoints.remove(&service_key).is_some();
        } else if store.endpoints.get(&service_key).is_none_or(|existing| *existing != endpoints) {
            store.endpoints.insert(service_key, endpoints);
            changed = true;
        }
    }

    if changed {
        store.notify_change();
    }
    Ok(())
}

/// Main reconcile function for EndpointSlice resources.
pub async fn reconcile_endpointslice(
    eps: Arc<EndpointSlice>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    reconcile_endpointslice_inner(&eps, &ctx.store)?;
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;
    use k8s_openapi::api::discovery::v1::{
        Endpoint, EndpointConditions, EndpointPort, EndpointSlice,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_store() -> Arc<ConfigStore> {
        Arc::new(ConfigStore::new())
    }

    fn make_endpoint_slice(
        name: &str,
        namespace: &str,
        service_name: &str,
        ports: Vec<EndpointPort>,
        endpoints: Vec<Endpoint>,
    ) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert(SERVICE_NAME_LABEL.to_string(), service_name.to_string());

        EndpointSlice {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            ports: Some(ports),
            endpoints: Some(endpoints),
        }
    }

    fn make_ready_endpoint(addresses: Vec<&str>) -> Endpoint {
        Endpoint {
            addresses: addresses.into_iter().map(String::from).collect(),
            conditions: Some(EndpointConditions {
                ready: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_not_ready_endpoint(addresses: Vec<&str>) -> Endpoint {
        Endpoint {
            addresses: addresses.into_iter().map(String::from).collect(),
            conditions: Some(EndpointConditions {
                ready: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn an_unchanged_slice_does_not_wake_the_compiler() {
        let store = make_store();
        store.take_dirty();
        let slice = make_endpoint_slice(
            "svc-abc",
            "default",
            "svc",
            vec![EndpointPort { port: Some(8080), ..Default::default() }],
            vec![make_ready_endpoint(vec!["10.0.0.2"]), make_ready_endpoint(vec!["10.0.0.1"])],
        );
        reconcile_endpointslice_inner(&slice, &store).unwrap();
        assert!(store.take_dirty(), "first sight of the endpoints compiles");
        // The informer re-delivers the slice (resync, unrelated field change):
        // same ready set, no compile.
        reconcile_endpointslice_inner(&slice, &store).unwrap();
        assert!(!store.take_dirty());
        // Same addresses in another order are the same set.
        let reordered = make_endpoint_slice(
            "svc-abc",
            "default",
            "svc",
            vec![EndpointPort { port: Some(8080), ..Default::default() }],
            vec![make_ready_endpoint(vec!["10.0.0.1"]), make_ready_endpoint(vec!["10.0.0.2"])],
        );
        reconcile_endpointslice_inner(&reordered, &store).unwrap();
        assert!(!store.take_dirty());
        // One pod goes not-ready: that is a change.
        let one_down = make_endpoint_slice(
            "svc-abc",
            "default",
            "svc",
            vec![EndpointPort { port: Some(8080), ..Default::default() }],
            vec![make_ready_endpoint(vec!["10.0.0.1"]), make_not_ready_endpoint(vec!["10.0.0.2"])],
        );
        reconcile_endpointslice_inner(&one_down, &store).unwrap();
        assert!(store.take_dirty());
    }

    fn make_no_conditions_endpoint(addresses: Vec<&str>) -> Endpoint {
        Endpoint {
            addresses: addresses.into_iter().map(String::from).collect(),
            conditions: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_ready_endpoints_populate_store() {
        let store = make_store();
        let eps = make_endpoint_slice(
            "backend-svc-abc",
            "default",
            "backend-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![
                make_ready_endpoint(vec!["10.0.0.1"]),
                make_ready_endpoint(vec!["10.0.0.2"]),
            ],
        );

        let result = reconcile_endpointslice_inner(&eps, &store);
        assert!(result.is_ok());

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend-svc".to_string(),
            port: 8080,
        };
        let entry = store.endpoints.get(&key).expect("endpoints should be stored");
        assert_eq!(entry.len(), 2);
        assert_eq!(entry[0].address, "10.0.0.1");
        assert_eq!(entry[0].port, 8080);
        assert_eq!(entry[1].address, "10.0.0.2");
        assert_eq!(entry[1].port, 8080);
    }

    #[test]
    fn test_service_key_correct_for_port() {
        let store = make_store();
        let eps = make_endpoint_slice(
            "backend-svc-abc",
            "default",
            "backend-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![make_ready_endpoint(vec!["10.0.0.1"])],
        );

        reconcile_endpointslice_inner(&eps, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend-svc".to_string(),
            port: 8080,
        };
        assert!(store.endpoints.get(&key).is_some());
    }

    #[test]
    fn test_multiple_ports_create_separate_entries() {
        let store = make_store();
        let eps = make_endpoint_slice(
            "multi-port-svc-abc",
            "default",
            "multi-port-svc",
            vec![
                EndpointPort {
                    port: Some(8080),
                    name: Some("http".to_string()),
                    ..Default::default()
                },
                EndpointPort {
                    port: Some(9090),
                    name: Some("grpc".to_string()),
                    ..Default::default()
                },
            ],
            vec![make_ready_endpoint(vec!["10.0.0.1"])],
        );

        reconcile_endpointslice_inner(&eps, &store).unwrap();

        let key_http = ServiceKey {
            namespace: "default".to_string(),
            name: "multi-port-svc".to_string(),
            port: 8080,
        };
        let key_grpc = ServiceKey {
            namespace: "default".to_string(),
            name: "multi-port-svc".to_string(),
            port: 9090,
        };
        assert!(store.endpoints.get(&key_http).is_some());
        assert!(store.endpoints.get(&key_grpc).is_some());

        let http_eps = store.endpoints.get(&key_http).unwrap();
        assert_eq!(http_eps[0].port, 8080);

        let grpc_eps = store.endpoints.get(&key_grpc).unwrap();
        assert_eq!(grpc_eps[0].port, 9090);
    }

    #[test]
    fn test_no_ready_endpoints_removes_entry() {
        let store = make_store();

        // First, populate with a ready endpoint
        let eps_ready = make_endpoint_slice(
            "backend-svc-abc",
            "default",
            "backend-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![make_ready_endpoint(vec!["10.0.0.1"])],
        );
        reconcile_endpointslice_inner(&eps_ready, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend-svc".to_string(),
            port: 8080,
        };
        assert!(store.endpoints.get(&key).is_some());

        // Now reconcile with only not-ready endpoints
        let eps_not_ready = make_endpoint_slice(
            "backend-svc-abc",
            "default",
            "backend-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![make_not_ready_endpoint(vec!["10.0.0.1"])],
        );
        reconcile_endpointslice_inner(&eps_not_ready, &store).unwrap();

        assert!(
            store.endpoints.get(&key).is_none(),
            "entry should be removed when no ready endpoints"
        );
    }

    #[test]
    fn test_only_ready_endpoints_included() {
        let store = make_store();
        let eps = make_endpoint_slice(
            "mixed-svc-abc",
            "default",
            "mixed-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![
                make_ready_endpoint(vec!["10.0.0.1"]),
                make_not_ready_endpoint(vec!["10.0.0.2"]),
                make_ready_endpoint(vec!["10.0.0.3"]),
            ],
        );

        reconcile_endpointslice_inner(&eps, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "mixed-svc".to_string(),
            port: 8080,
        };
        let entry = store.endpoints.get(&key).unwrap();
        assert_eq!(entry.len(), 2);
        let addrs: Vec<&str> = entry.iter().map(|e| e.address.as_str()).collect();
        assert!(addrs.contains(&"10.0.0.1"));
        assert!(addrs.contains(&"10.0.0.3"));
        assert!(!addrs.contains(&"10.0.0.2"));
    }

    #[test]
    fn test_conditions_absent_means_ready() {
        let store = make_store();
        let eps = make_endpoint_slice(
            "no-cond-svc-abc",
            "default",
            "no-cond-svc",
            vec![EndpointPort {
                port: Some(8080),
                name: Some("http".to_string()),
                ..Default::default()
            }],
            vec![make_no_conditions_endpoint(vec!["10.0.0.5"])],
        );

        reconcile_endpointslice_inner(&eps, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "no-cond-svc".to_string(),
            port: 8080,
        };
        let entry = store.endpoints.get(&key).expect("absent conditions = ready");
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0].address, "10.0.0.5");
    }

    #[test]
    fn test_no_service_label_skips() {
        let store = make_store();
        let eps = EndpointSlice {
            metadata: ObjectMeta {
                name: Some("orphan-slice".to_string()),
                namespace: Some("default".to_string()),
                labels: None, // no labels at all
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            ports: Some(vec![EndpointPort {
                port: Some(8080),
                ..Default::default()
            }]),
            endpoints: Some(vec![make_ready_endpoint(vec!["10.0.0.1"])]),
        };

        let result = reconcile_endpointslice_inner(&eps, &store);
        assert!(result.is_ok());
        assert!(store.endpoints.is_empty(), "no service label = skip");
    }
}
