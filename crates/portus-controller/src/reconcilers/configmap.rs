//! ConfigMap reconciler.
//!
//! Caches every ConfigMap's data in `store.config_maps` so BackendTLSPolicy and
//! Gateway frontend validation can resolve CA certificate references at
//! reconcile and compile time.

use super::{ReconcileContext, ReconcileError};
use crate::store::{ConfigStore, NamespacedName, SecretState};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::controller::Action;
use std::collections::HashMap;
use std::sync::Arc;

pub fn reconcile_configmap_inner(
    cm: &ConfigMap,
    store: &ConfigStore,
) -> Result<(), ReconcileError> {
    let namespace = cm
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let name = cm
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    // Handle deletion
    if cm.metadata.deletion_timestamp.is_some() {
        if store.config_maps.remove(&key).is_some() {
            store.notify_change();
        }
        return Ok(());
    }

    // Store every ConfigMap that could be a CA-cert source: the referencing
    // BackendTLSPolicy may reconcile after the ConfigMap, so filtering by current
    // policies here would drop certs. Entries are small (just ca.crt data) and
    // the prune loop evicts deleted ones.
    let data: HashMap<String, String> = cm
        .data
        .as_ref()
        .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    let is_new_or_changed = store.config_maps.get(&key)
        .map(|existing| existing.data != data)
        .unwrap_or(true);
    store.config_maps.insert(key, SecretState { data });
    // Only notify when data actually changed to avoid flooding the compilation loop
    // with irrelevant ConfigMap updates (kube-system, helm releases, etc.)
    if is_new_or_changed {
        store.notify_change();
    }
    Ok(())
}

pub async fn reconcile_configmap(
    cm: Arc<ConfigMap>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    // Consumers (BackendTLSPolicy CA refs, Gateway frontend validation) watch
    // ConfigMaps on their own controllers and re-reconcile themselves; this
    // reconciler only keeps the store's copy of the data current.
    reconcile_configmap_inner(&cm, &ctx.store)?;
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_configmap(name: &str, ns: &str, data: HashMap<String, String>) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            data: Some(data.into_iter().collect()),
            ..Default::default()
        }
    }

    #[test]
    fn test_configmap_stored() {
        let store = ConfigStore::new();
        let mut data = HashMap::new();
        data.insert("ca.crt".to_string(), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_string());

        let cm = make_configmap("tls-ca", "default", data);
        reconcile_configmap_inner(&cm, &store).unwrap();

        let key = NamespacedName { namespace: "default".to_string(), name: "tls-ca".to_string() };
        let stored = store.config_maps.get(&key).unwrap();
        assert!(stored.data.contains_key("ca.crt"));
        assert!(stored.data["ca.crt"].contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_empty_configmap_stored() {
        let store = ConfigStore::new();
        let cm = make_configmap("empty-cm", "default", HashMap::new());
        reconcile_configmap_inner(&cm, &store).unwrap();

        let key = NamespacedName { namespace: "default".to_string(), name: "empty-cm".to_string() };
        let stored = store.config_maps.get(&key).unwrap();
        assert!(stored.data.is_empty());
    }
}
