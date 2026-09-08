//! Service reconciler that populates service_port_map with port mappings.
//!
//! Watches Service resources and extracts (service_port → target_port) mappings.
//! The compiler uses these mappings to translate service ports (referenced in
//! HTTPRoute backendRefs) to endpoint ports (stored by EndpointSlice reconciler).
//!
//! Without this, backends with port != targetPort (e.g., Service port 8080 →
//! container port 3000) produce empty BackendGroups and 503 responses.

use super::{ReconcileContext, ReconcileError};
use crate::store::{ConfigStore, Event, NamespacedName, ServiceKey};
use k8s_openapi::api::core::v1::Service;
use kube::runtime::controller::Action;
use std::sync::Arc;

/// Core reconciliation logic for Service resources.
/// Separated from the async function for unit testability.
pub fn reconcile_service_inner(
    svc: &Service,
    store: &ConfigStore,
) -> Result<(), ReconcileError> {
    let namespace = svc
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let name = svc
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;

    // Handle deletion: remove all port mappings for this service
    if svc.metadata.deletion_timestamp.is_some() {
        forget(store, namespace, name);
        return Ok(());
    }

    let before = snapshot(store, namespace, name);

    let spec = match &svc.spec {
        Some(s) => s,
        None => return Ok(()),
    };

    // Collect current service port keys so we can remove stale mappings
    let mut current_keys = Vec::new();

    for port in spec.ports.as_deref().unwrap_or(&[]) {
        let service_port = match port.port {
            p if p > 0 => p as u16,
            _ => continue,
        };

        // Resolve target port: can be a number or a named port.
        // For our purposes, we only handle numeric target ports.
        // If targetPort is unset, it defaults to the service port.
        let target_port = match &port.target_port {
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(p)) => *p as u16,
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(_)) => {
                // Named target port — we can't resolve this without pod spec.
                // Skip; the EndpointSlice already uses the resolved numeric port.
                // Fall back to assuming service_port == target_port.
                service_port
            }
            None => service_port,
        };

        let key = ServiceKey {
            namespace: namespace.to_string(),
            name: name.to_string(),
            port: service_port,
        };
        store.service_port_map.insert(key.clone(), target_port);

        // Store appProtocol if present (used for H2C, WebSocket backend detection)
        if let Some(ref app_protocol) = port.app_protocol {
            store.service_app_protocols.insert(key.clone(), app_protocol.clone());
        } else {
            store.service_app_protocols.remove(&key);
        }

        // Store port name if present (used for BackendTLSPolicy sectionName resolution)
        if let Some(ref port_name) = port.name
            && !port_name.is_empty() {
                store.service_port_names.insert(key.clone(), port_name.clone());
            }

        current_keys.push(key);
    }

    // Remove stale mappings for ports that no longer exist on this service
    store.service_port_map.retain(|key, _| {
        if key.namespace == namespace && key.name == name {
            current_keys.contains(key)
        } else {
            true
        }
    });
    store.service_app_protocols.retain(|key, _| {
        if key.namespace == namespace && key.name == name {
            current_keys.contains(key)
        } else {
            true
        }
    });
    store.service_port_names.retain(|key, _| {
        if key.namespace == namespace && key.name == name {
            current_keys.contains(key)
        } else {
            true
        }
    });

    if snapshot(store, namespace, name) != before {
        store.notify_change();
        store.publish(Event::Service(NamespacedName { namespace: namespace.to_string(), name: name.to_string() }));
    }
    Ok(())
}

/// Everything the store holds for one Service, for change detection.
fn snapshot(store: &ConfigStore, namespace: &str, name: &str) -> Vec<(u16, u16, Option<String>, Option<String>)> {
    let mut v: Vec<_> = store
        .service_port_map
        .iter()
        .filter(|e| e.key().namespace == namespace && e.key().name == name)
        .map(|e| {
            (
                e.key().port,
                *e.value(),
                store.service_app_protocols.get(e.key()).map(|p| p.clone()),
                store.service_port_names.get(e.key()).map(|p| p.clone()),
            )
        })
        .collect();
    v.sort();
    v
}

/// Drop a Service's port mappings (deleted); routes naming it re-run.
pub fn forget(store: &ConfigStore, namespace: &str, name: &str) -> bool {
    let mine = |key: &ServiceKey| key.namespace == namespace && key.name == name;
    let before = store.service_port_map.len() + store.service_app_protocols.len() + store.service_port_names.len();
    store.service_port_map.retain(|k, _| !mine(k));
    store.service_app_protocols.retain(|k, _| !mine(k));
    store.service_port_names.retain(|k, _| !mine(k));
    let removed = store.service_port_map.len() + store.service_app_protocols.len() + store.service_port_names.len() < before;
    if removed {
        store.notify_change();
        store.publish(Event::Service(NamespacedName { namespace: namespace.to_string(), name: name.to_string() }));
    }
    removed
}

/// Main reconcile function for Service resources.
pub async fn reconcile_service(
    svc: Arc<Service>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    reconcile_service_inner(&svc, &ctx.store)?;
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::sync::Arc;

    fn make_store() -> Arc<ConfigStore> {
        Arc::new(ConfigStore::new())
    }

    fn make_service(name: &str, namespace: &str, ports: Vec<ServicePort>) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(ports),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_basic_port_mapping() {
        let store = make_store();
        let svc = make_service(
            "backend",
            "default",
            vec![ServicePort {
                port: 8080,
                target_port: Some(IntOrString::Int(3000)),
                ..Default::default()
            }],
        );

        reconcile_service_inner(&svc, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8080,
        };
        assert_eq!(*store.service_port_map.get(&key).unwrap(), 3000);
    }

    #[test]
    fn test_same_port_mapping() {
        let store = make_store();
        let svc = make_service(
            "backend",
            "default",
            vec![ServicePort {
                port: 8080,
                target_port: Some(IntOrString::Int(8080)),
                ..Default::default()
            }],
        );

        reconcile_service_inner(&svc, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8080,
        };
        assert_eq!(*store.service_port_map.get(&key).unwrap(), 8080);
    }

    #[test]
    fn test_no_target_port_defaults_to_service_port() {
        let store = make_store();
        let svc = make_service(
            "backend",
            "default",
            vec![ServicePort {
                port: 9090,
                target_port: None,
                ..Default::default()
            }],
        );

        reconcile_service_inner(&svc, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 9090,
        };
        assert_eq!(*store.service_port_map.get(&key).unwrap(), 9090);
    }

    #[test]
    fn test_multiple_ports() {
        let store = make_store();
        let svc = make_service(
            "multi",
            "default",
            vec![
                ServicePort {
                    port: 8080,
                    target_port: Some(IntOrString::Int(3000)),
                    ..Default::default()
                },
                ServicePort {
                    port: 8443,
                    target_port: Some(IntOrString::Int(3443)),
                    ..Default::default()
                },
            ],
        );

        reconcile_service_inner(&svc, &store).unwrap();

        let key1 = ServiceKey {
            namespace: "default".to_string(),
            name: "multi".to_string(),
            port: 8080,
        };
        let key2 = ServiceKey {
            namespace: "default".to_string(),
            name: "multi".to_string(),
            port: 8443,
        };
        assert_eq!(*store.service_port_map.get(&key1).unwrap(), 3000);
        assert_eq!(*store.service_port_map.get(&key2).unwrap(), 3443);
    }

    #[test]
    fn test_stale_ports_removed_on_update() {
        let store = make_store();
        // First: service with 2 ports
        let svc1 = make_service(
            "backend",
            "default",
            vec![
                ServicePort {
                    port: 8080,
                    target_port: Some(IntOrString::Int(3000)),
                    ..Default::default()
                },
                ServicePort {
                    port: 9090,
                    target_port: Some(IntOrString::Int(4000)),
                    ..Default::default()
                },
            ],
        );
        reconcile_service_inner(&svc1, &store).unwrap();
        assert_eq!(store.service_port_map.len(), 2);

        // Update: remove port 9090
        let svc2 = make_service(
            "backend",
            "default",
            vec![ServicePort {
                port: 8080,
                target_port: Some(IntOrString::Int(3000)),
                ..Default::default()
            }],
        );
        reconcile_service_inner(&svc2, &store).unwrap();

        assert_eq!(store.service_port_map.len(), 1);
        let removed = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 9090,
        };
        assert!(store.service_port_map.get(&removed).is_none());
    }

    #[test]
    fn test_app_protocol_stored() {
        let store = make_store();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("backend".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![
                    ServicePort {
                        port: 8081,
                        target_port: Some(IntOrString::Int(3001)),
                        app_protocol: Some("kubernetes.io/h2c".to_string()),
                        ..Default::default()
                    },
                    ServicePort {
                        port: 8082,
                        target_port: Some(IntOrString::Int(3000)),
                        app_protocol: Some("kubernetes.io/ws".to_string()),
                        ..Default::default()
                    },
                    ServicePort {
                        port: 8080,
                        target_port: Some(IntOrString::Int(3000)),
                        app_protocol: None,
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        reconcile_service_inner(&svc, &store).unwrap();

        let h2c_key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8081,
        };
        assert_eq!(
            store.service_app_protocols.get(&h2c_key).map(|v| v.clone()),
            Some("kubernetes.io/h2c".to_string()),
            "should store h2c appProtocol"
        );

        let ws_key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8082,
        };
        assert_eq!(
            store.service_app_protocols.get(&ws_key).map(|v| v.clone()),
            Some("kubernetes.io/ws".to_string()),
            "should store ws appProtocol"
        );

        let http_key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8080,
        };
        assert!(
            store.service_app_protocols.get(&http_key).is_none(),
            "should not store appProtocol for ports without one"
        );
    }

    #[test]
    fn test_port_name_stored() {
        let store = make_store();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("backend".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![
                    ServicePort {
                        name: Some("https".to_string()),
                        port: 443,
                        target_port: Some(IntOrString::Int(8443)),
                        ..Default::default()
                    },
                    ServicePort {
                        name: Some("http".to_string()),
                        port: 80,
                        target_port: Some(IntOrString::Int(8080)),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        reconcile_service_inner(&svc, &store).unwrap();

        let https_key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 443,
        };
        assert_eq!(
            store.service_port_names.get(&https_key).map(|v| v.clone()),
            Some("https".to_string()),
            "should store port name 'https' for port 443"
        );

        let http_key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 80,
        };
        assert_eq!(
            store.service_port_names.get(&http_key).map(|v| v.clone()),
            Some("http".to_string()),
            "should store port name 'http' for port 80"
        );
    }

    #[test]
    fn test_named_target_port_falls_back_to_service_port() {
        let store = make_store();
        let svc = make_service(
            "backend",
            "default",
            vec![ServicePort {
                port: 8080,
                target_port: Some(IntOrString::String("http".to_string())),
                ..Default::default()
            }],
        );

        reconcile_service_inner(&svc, &store).unwrap();

        let key = ServiceKey {
            namespace: "default".to_string(),
            name: "backend".to_string(),
            port: 8080,
        };
        // Named target port can't be resolved, defaults to service port
        assert_eq!(*store.service_port_map.get(&key).unwrap(), 8080);
    }
}
