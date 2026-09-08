//! ReferenceGrant watcher that stores grant state and triggers route re-reconciliation.
//!
//! When a ReferenceGrant is created/updated/deleted, it is stored in (or removed from)
//! ConfigStore.reference_grants; the compiler is woken and `Event::ReferenceGrant`
//! re-runs the routes and Gateways that reach into the grant's namespace.

use super::{ReconcileContext, ReconcileError};
use crate::gateway_types::ReferenceGrant;
use crate::store::{Event, NamespacedName, ReferenceGrantFrom, ReferenceGrantState, ReferenceGrantTo};
use kube::runtime::controller::Action;
use std::sync::Arc;

/// Core reconciliation logic for ReferenceGrant resources.
/// Separated from the async function for unit testability without a kube Client.
pub fn reconcile_reference_grant_inner(
    grant: &ReferenceGrant,
    store: &crate::store::ConfigStore,
) -> Result<(), ReconcileError> {
    let name = grant
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = grant
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    // Check for deletion -- if deletion_timestamp is set, remove from store
    if grant.metadata.deletion_timestamp.is_some() {
        if store.remove_and_notify(&store.reference_grants, &key).is_some() {
            store.publish(Event::ReferenceGrant { namespace: namespace.to_string() });
        }
        return Ok(());
    }

    // Convert CRD from/to entries to store state
    let from: Vec<ReferenceGrantFrom> = grant
        .spec
        .from
        .iter()
        .map(|f| ReferenceGrantFrom {
            group: f.group.clone(),
            kind: f.kind.clone(),
            namespace: f.namespace.clone(),
        })
        .collect();

    let to: Vec<ReferenceGrantTo> = grant
        .spec
        .to
        .iter()
        .map(|t| ReferenceGrantTo {
            group: t.group.clone(),
            kind: t.kind.clone(),
            name: t.name.clone(),
        })
        .collect();

    let state = ReferenceGrantState {
        namespace: namespace.to_string(),
        from,
        to,
    };

    if store.insert_and_notify(&store.reference_grants, key, state) {
        store.publish(Event::ReferenceGrant { namespace: namespace.to_string() });
    }

    Ok(())
}

/// Main reconcile function for ReferenceGrant resources.
pub async fn reconcile_reference_grant(
    grant: Arc<ReferenceGrant>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    reconcile_reference_grant_inner(&grant, &ctx.store)?;
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{ReferenceGrantFromCRD, ReferenceGrantSpec, ReferenceGrantToCRD};
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::sync::Arc;

    fn make_store() -> Arc<ConfigStore> {
        Arc::new(ConfigStore::new())
    }

    fn make_grant(
        name: &str,
        namespace: &str,
        from: Vec<ReferenceGrantFromCRD>,
        to: Vec<ReferenceGrantToCRD>,
    ) -> ReferenceGrant {
        ReferenceGrant {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec { from, to },
        }
    }

    #[test]
    fn test_grant_stored_with_correct_from_to() {
        let store = make_store();
        let grant = make_grant(
            "allow-app",
            "backend-ns",
            vec![ReferenceGrantFromCRD {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: "app-ns".to_string(),
            }],
            vec![ReferenceGrantToCRD {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: Some("backend-svc".to_string()),
            }],
        );

        let result = reconcile_reference_grant_inner(&grant, &store);
        assert!(result.is_ok());

        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-app".to_string(),
        };
        let entry = store.reference_grants.get(&key).expect("grant should be stored");
        assert_eq!(entry.namespace, "backend-ns");
        assert_eq!(entry.from.len(), 1);
        assert_eq!(entry.from[0].group, "gateway.networking.k8s.io");
        assert_eq!(entry.from[0].kind, "HTTPRoute");
        assert_eq!(entry.from[0].namespace, "app-ns");
        assert_eq!(entry.to.len(), 1);
        assert_eq!(entry.to[0].kind, "Service");
        assert_eq!(entry.to[0].name, Some("backend-svc".to_string()));
    }

    #[test]
    fn test_grant_with_httproute_and_service() {
        let store = make_store();
        let grant = make_grant(
            "allow-routes",
            "backend-ns",
            vec![ReferenceGrantFromCRD {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: "namespace-a".to_string(),
            }],
            vec![ReferenceGrantToCRD {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: Some("backend-svc".to_string()),
            }],
        );

        let result = reconcile_reference_grant_inner(&grant, &store);
        assert!(result.is_ok());

        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-routes".to_string(),
        };
        let entry = store.reference_grants.get(&key).unwrap();
        assert_eq!(entry.from[0].kind, "HTTPRoute");
        assert_eq!(entry.from[0].namespace, "namespace-a");
        assert_eq!(entry.to[0].name, Some("backend-svc".to_string()));
    }

    #[test]
    fn test_grant_deleted_removes_from_store() {
        let store = make_store();

        // First, insert a grant
        let grant = make_grant(
            "to-delete",
            "backend-ns",
            vec![ReferenceGrantFromCRD {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "GRPCRoute".to_string(),
                namespace: "app-ns".to_string(),
            }],
            vec![ReferenceGrantToCRD {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: None,
            }],
        );
        reconcile_reference_grant_inner(&grant, &store).unwrap();

        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "to-delete".to_string(),
        };
        assert!(store.reference_grants.get(&key).is_some());

        // Now simulate deletion by setting deletion_timestamp
        let deleted_grant = ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("to-delete".to_string()),
                namespace: Some("backend-ns".to_string()),
                deletion_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::now(),
                )),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![],
                to: vec![],
            },
        };

        let result = reconcile_reference_grant_inner(&deleted_grant, &store);
        assert!(result.is_ok());
        assert!(store.reference_grants.get(&key).is_none(), "grant should be removed after deletion");
    }

    #[test]
    fn test_grant_update_replaces_existing() {
        let store = make_store();

        // Insert initial grant
        let grant_v1 = make_grant(
            "evolving-grant",
            "ns",
            vec![ReferenceGrantFromCRD {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: "old-ns".to_string(),
            }],
            vec![ReferenceGrantToCRD {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: None,
            }],
        );
        reconcile_reference_grant_inner(&grant_v1, &store).unwrap();

        // Update with different from namespace
        let grant_v2 = make_grant(
            "evolving-grant",
            "ns",
            vec![ReferenceGrantFromCRD {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "GRPCRoute".to_string(),
                namespace: "new-ns".to_string(),
            }],
            vec![ReferenceGrantToCRD {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: Some("specific-svc".to_string()),
            }],
        );
        reconcile_reference_grant_inner(&grant_v2, &store).unwrap();

        let key = NamespacedName {
            namespace: "ns".to_string(),
            name: "evolving-grant".to_string(),
        };
        let entry = store.reference_grants.get(&key).unwrap();
        assert_eq!(entry.from[0].kind, "GRPCRoute");
        assert_eq!(entry.from[0].namespace, "new-ns");
        assert_eq!(entry.to[0].name, Some("specific-svc".to_string()));
    }
}
