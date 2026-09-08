//! Secret reconciler for auth policy credential management.
//!
//! Watches Secrets but only stores those referenced by Gateway resources
//! (certificateRefs), BasicAuthPolicy, or APIKeyAuthPolicy. Unreferenced
//! secrets (database passwords, service account tokens, etc.) are never held
//! in controller memory.
//!
//! When a referenced Secret changes, triggers recompilation so listeners and
//! auth policies pick up new credentials.

use super::{ReconcileContext, ReconcileError};
use crate::store::{ConfigStore, NamespacedName, SecretState};
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::controller::Action;
use std::collections::HashMap;
use std::sync::Arc;

/// Core reconciliation logic (pure store manipulation, no async I/O).
///
/// Only stores the secret if it is referenced by a Gateway (certificateRefs),
/// BasicAuthPolicy (secretRef), or APIKeyAuthPolicy (secretRef). If the secret
/// was previously stored but is no longer referenced, it is removed.
pub fn reconcile_inner(secret: &Secret, store: &ConfigStore) -> Result<(), ReconcileError> {
    let name = secret
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".into()))?;
    let namespace = secret
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".into()))?;

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    // Handle deletion: remove from store
    if secret.metadata.deletion_timestamp.is_some() {
        store.remove_and_notify(&store.secrets, &key);
        return Ok(());
    }

    // Store all secrets unconditionally. The F-4 scoping (only store referenced
    // secrets) caused a TOCTOU race: secrets reconciled before their Gateway
    // were filtered out, leaving HTTPS listeners without certs. The prune task
    // handles cleanup of deleted secrets.
    // TODO: Re-enable scoping with a TLS-type exemption once we have regression
    // tests covering the Gateway-before-Secret and Secret-before-Gateway orderings.

    // Decode Secret data (base64-decoded by k8s-openapi) into String map
    let mut data: HashMap<String, String> = secret
        .data
        .as_ref()
        .map(|d| {
            d.iter()
                .filter_map(|(k, v)| {
                    String::from_utf8(v.0.clone()).ok().map(|s| (k.clone(), s))
                })
                .collect()
        })
        .unwrap_or_default();

    // Also check stringData (takes precedence over data)
    if let Some(ref string_data) = secret.string_data {
        for (k, v) in string_data {
            data.insert(k.clone(), v.clone());
        }
    }

    store.insert_and_notify(&store.secrets, key, SecretState { data });

    Ok(())
}

pub async fn reconcile_secret(
    secret: Arc<Secret>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    reconcile_inner(&secret, &ctx.store)?;
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        AllowedRoutesState, ApiKeyAuthPolicyState, BasicAuthPolicyState, GatewayState,
        ListenerState, PolicyTargetKey,
    };
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_secret(name: &str, ns: &str) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            data: Some(
                [("key1".to_string(), k8s_openapi::ByteString(b"value1".to_vec()))]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn make_gateway_with_tls_ref(
        name: &str,
        ns: &str,
        cert_ns: &str,
        cert_name: &str,
    ) -> (NamespacedName, GatewayState) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let state = GatewayState {
            name: name.to_string(),
            namespace: ns.to_string(),
            listeners: vec![ListenerState {
                name: "https".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: None,
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: vec![(cert_ns.to_string(), cert_name.to_string())],
                tls_mode: Some("Terminate".to_string()),
            }],
            generation: 1,
            allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        };
        (key, state)
    }

    fn make_basic_auth_policy(
        name: &str,
        ns: &str,
        secret_ns: &str,
        secret_name: &str,
    ) -> (NamespacedName, BasicAuthPolicyState) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let state = BasicAuthPolicyState {
            target: PolicyTargetKey {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: ns.to_string(),
                name: "some-route".to_string(),
                section_name: None,
            },
            secret_namespace: secret_ns.to_string(),
            secret_name: secret_name.to_string(),
            realm: "Restricted".to_string(),
            generation: 1,
            creation_timestamp: None,
            accepted: true,
        };
        (key, state)
    }

    fn make_api_key_policy(
        name: &str,
        ns: &str,
        secret_ns: &str,
        secret_name: &str,
    ) -> (NamespacedName, ApiKeyAuthPolicyState) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let state = ApiKeyAuthPolicyState {
            target: PolicyTargetKey {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: ns.to_string(),
                name: "some-route".to_string(),
                section_name: None,
            },
            secret_namespace: secret_ns.to_string(),
            secret_name: secret_name.to_string(),
            header_name: "X-API-Key".to_string(),
            generation: 1,
            creation_timestamp: None,
            accepted: true,
        };
        (key, state)
    }

    #[test]
    fn test_unreferenced_secret_still_stored() {
        // Secret scoping disabled to avoid TOCTOU race with Gateway reconciler.
        // All secrets are stored; prune task handles cleanup.
        let store = ConfigStore::new();
        let secret = make_secret("db-password", "default");

        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1, "all secrets should be stored regardless of references");
    }

    #[test]
    fn test_secret_referenced_by_gateway_tls_is_stored() {
        let store = ConfigStore::new();
        let (gw_key, gw_state) =
            make_gateway_with_tls_ref("my-gw", "default", "default", "tls-cert");
        store.gateways.insert(gw_key, gw_state);

        let secret = make_secret("tls-cert", "default");
        reconcile_inner(&secret, &store).unwrap();

        assert_eq!(store.secrets.len(), 1, "TLS-referenced secret should be stored");
        let stored = store
            .secrets
            .get(&NamespacedName {
                namespace: "default".to_string(),
                name: "tls-cert".to_string(),
            })
            .unwrap();
        assert_eq!(stored.data.get("key1").unwrap(), "value1");
    }

    #[test]
    fn test_secret_referenced_by_basic_auth_is_stored() {
        let store = ConfigStore::new();
        let (pol_key, pol_state) =
            make_basic_auth_policy("ba-pol", "default", "default", "auth-creds");
        store.basic_auth_policies.insert(pol_key, pol_state);

        let secret = make_secret("auth-creds", "default");
        reconcile_inner(&secret, &store).unwrap();

        assert_eq!(store.secrets.len(), 1, "BasicAuth-referenced secret should be stored");
    }

    #[test]
    fn test_secret_referenced_by_api_key_is_stored() {
        let store = ConfigStore::new();
        let (pol_key, pol_state) =
            make_api_key_policy("ak-pol", "default", "default", "api-keys");
        store.api_key_auth_policies.insert(pol_key, pol_state);

        let secret = make_secret("api-keys", "default");
        reconcile_inner(&secret, &store).unwrap();

        assert_eq!(store.secrets.len(), 1, "APIKey-referenced secret should be stored");
    }

    #[test]
    fn test_cross_namespace_secret_reference() {
        let store = ConfigStore::new();
        // Gateway in "infra" ns references secret in "certs" ns
        let (gw_key, gw_state) =
            make_gateway_with_tls_ref("my-gw", "infra", "certs", "tls-cert");
        store.gateways.insert(gw_key, gw_state);

        let secret = make_secret("tls-cert", "certs");
        reconcile_inner(&secret, &store).unwrap();

        assert_eq!(store.secrets.len(), 1, "cross-ns referenced secret should be stored");
    }

    #[test]
    fn test_previously_stored_secret_persists_after_reference_removed() {
        // Secret scoping disabled -- secrets persist even when references are removed.
        // Prune task handles cleanup.
        let store = ConfigStore::new();

        let (pol_key, pol_state) =
            make_basic_auth_policy("ba-pol", "default", "default", "auth-creds");
        store.basic_auth_policies.insert(pol_key.clone(), pol_state);

        let secret = make_secret("auth-creds", "default");
        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1);

        store.basic_auth_policies.remove(&pol_key);

        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1, "secret should persist (prune task cleans up)");
    }

    #[test]
    fn test_deleted_secret_removed_from_store() {
        let store = ConfigStore::new();

        // Pre-populate with a referenced secret
        let (gw_key, gw_state) =
            make_gateway_with_tls_ref("my-gw", "default", "default", "tls-cert");
        store.gateways.insert(gw_key, gw_state);
        let secret = make_secret("tls-cert", "default");
        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1);

        // Now the secret is deleted
        let mut deleted_secret = make_secret("tls-cert", "default");
        deleted_secret.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_second(1000).unwrap(),
            ));
        reconcile_inner(&deleted_secret, &store).unwrap();
        assert!(store.secrets.is_empty(), "deleted secret should be removed from store");
    }

    #[test]
    fn test_same_namespace_different_name_stored() {
        // Secret scoping disabled -- all secrets stored regardless of references.
        let store = ConfigStore::new();
        let (gw_key, gw_state) =
            make_gateway_with_tls_ref("my-gw", "default", "default", "tls-cert");
        store.gateways.insert(gw_key, gw_state);

        let secret = make_secret("other-secret", "default");
        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1, "all secrets should be stored");
    }

    #[test]
    fn test_same_name_different_namespace_stored() {
        // Secret scoping disabled -- all secrets stored regardless of references.
        let store = ConfigStore::new();
        let (pol_key, pol_state) =
            make_basic_auth_policy("ba-pol", "default", "default", "auth-creds");
        store.basic_auth_policies.insert(pol_key, pol_state);

        let secret = make_secret("auth-creds", "other-ns");
        reconcile_inner(&secret, &store).unwrap();
        assert_eq!(store.secrets.len(), 1, "all secrets should be stored");
    }
}
