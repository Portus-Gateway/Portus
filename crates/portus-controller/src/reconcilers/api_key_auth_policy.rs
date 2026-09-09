//! APIKeyAuthPolicy reconciler.
//!
//! Watches APIKeyAuthPolicy resources, validates targetRef, validates Secret
//! existence, resolves conflicts (oldest-timestamp-wins), stores state in
//! ConfigStore, writes status conditions.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{is_reference_allowed, ReconcileContext, ReconcileError};
use crate::policy_types::APIKeyAuthPolicy;
use crate::status;
use crate::store::{ApiKeyAuthPolicyState, ConfigStore, NamespacedName, PolicyTargetKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Core reconciliation logic (pure store manipulation, no async I/O).
///
/// Validates that the referenced Secret exists in the ConfigStore. If missing,
/// the policy is not accepted (InvalidSecret). Otherwise proceeds with normal
/// conflict resolution.
pub fn reconcile_inner(
    policy: &APIKeyAuthPolicy,
    store: &ConfigStore,
) -> Result<Vec<Condition>, ReconcileError> {
    let name = policy
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = policy
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let generation = policy.metadata.generation.unwrap_or(0);
    let creation_ts = policy.metadata.creation_timestamp.clone();

    let target_ref = &policy.spec.target_ref;
    let target = PolicyTargetKey {
        group: target_ref.group.clone(),
        kind: target_ref.kind.clone(),
        namespace: namespace.to_string(),
        name: target_ref.name.clone(),
        section_name: target_ref.section_name.clone(),
    };

    let my_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    let secret_name = &policy.spec.api_key.secret_ref.name;
    let secret_ns = policy
        .spec
        .api_key
        .secret_ref
        .namespace
        .as_deref()
        .unwrap_or(namespace);
    let header_name = policy
        .spec
        .api_key
        .header_name
        .as_deref()
        .unwrap_or("X-API-Key");

    // Cross-namespace secret reference requires a ReferenceGrant
    if secret_ns != namespace
        && !is_reference_allowed(
            &store.reference_grants,
            namespace,
            "APIKeyAuthPolicy",
            secret_ns,
            "Secret",
            Some(secret_name),
        )
    {
        let state = ApiKeyAuthPolicyState {
            target: target.clone(),
            secret_namespace: secret_ns.to_string(),
            secret_name: secret_name.to_string(),
            header_name: header_name.to_string(),
            generation,
            creation_timestamp: creation_ts,
            accepted: false,
        };
        store.api_key_auth_policies.insert(my_key, state);

        let programmed = store.is_programmed();
        store.notify_change();

        return Ok(vec![
            status::build_condition(
                "Accepted",
                false,
                "RefNotPermitted",
                &format!(
                    "Cross-namespace secret reference {}/{} not permitted by ReferenceGrant",
                    secret_ns, secret_name
                ),
                generation,
            ),
            status::build_condition(
                "Programmed",
                programmed,
                if programmed { "Programmed" } else { "NotProgrammed" },
                if programmed {
                    "Configuration programmed in data plane"
                } else {
                    "Waiting for data plane to apply configuration"
                },
                generation,
            ),
        ]);
    }

    // Check if the referenced Secret exists in the store
    let secret_key = NamespacedName {
        namespace: secret_ns.to_string(),
        name: secret_name.to_string(),
    };
    let secret_exists = store.secrets.get(&secret_key).is_some();

    let state = ApiKeyAuthPolicyState {
        target: target.clone(),
        secret_namespace: secret_ns.to_string(),
        secret_name: secret_name.to_string(),
        header_name: header_name.to_string(),
        generation,
        creation_timestamp: creation_ts,
        accepted: false, // set below
    };

    store.api_key_auth_policies.insert(my_key.clone(), state);

    let mut conditions = Vec::new();

    if !secret_exists {
        // Secret not found -- reject the policy
        if let Some(mut entry) = store.api_key_auth_policies.get_mut(&my_key) {
            entry.accepted = false;
        }
        conditions.push(status::build_condition(
            "Accepted",
            false,
            "InvalidSecret",
            &format!(
                "Referenced Secret {}/{} not found",
                secret_ns, secret_name
            ),
            generation,
        ));
    } else {
        // Secret exists -- proceed with conflict resolution
        if let Some(mut entry) = store.api_key_auth_policies.get_mut(&my_key) {
            entry.accepted = true;
        }
        resolve_conflicts(&my_key, &target, &store.api_key_auth_policies);

        let accepted = store
            .api_key_auth_policies
            .get(&my_key)
            .map(|s| s.accepted)
            .unwrap_or(false);

        if accepted {
            conditions.push(status::build_condition(
                "Accepted",
                true,
                "Accepted",
                "Policy accepted",
                generation,
            ));
        } else {
            let winner_msg = find_winner_key(&target, &my_key, &store.api_key_auth_policies)
                .map(|k| format!("Older APIKeyAuthPolicy {} takes precedence", k))
                .unwrap_or_else(|| "Conflicted with another policy".to_string());
            conditions.push(status::build_condition(
                "Accepted",
                false,
                "Conflicted",
                &winner_msg,
                generation,
            ));
        }
    }

    let programmed = store.is_programmed();
    store.notify_change();

    conditions.push(status::build_condition(
        "Programmed",
        programmed,
        if programmed { "Programmed" } else { "NotProgrammed" },
        if programmed {
            "Configuration programmed in data plane"
        } else {
            "Waiting for data plane to apply configuration"
        },
        generation,
    ));

    Ok(conditions)
}

/// Main reconcile function for APIKeyAuthPolicy resources.
pub async fn reconcile_api_key_auth_policy(
    policy: Arc<APIKeyAuthPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.api_key_auth_policies,
        "APIKeyAuthPolicy",
        &policy.metadata,
        || reconcile_inner(&policy, &ctx.store),
    )?;

    let name = policy.metadata.name.as_deref().unwrap_or_default();
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();

    let current_conditions: Vec<Condition> = policy
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1alpha1",
        "kind": "APIKeyAuthPolicy",
        "metadata": { "name": name, "namespace": namespace },
        "status": { "conditions": desired_conditions.iter().map(|c| json!({
            "type": c.type_,
            "status": c.status,
            "reason": c.reason,
            "message": c.message,
            "observedGeneration": c.observed_generation,
            "lastTransitionTime": c.last_transition_time.0.to_string(),
        })).collect::<Vec<_>>() }
    });

    let api: Api<APIKeyAuthPolicy> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(
        &api,
        name,
        desired_status,
        &current_conditions,
        &desired_conditions,
    )
    .await
    {
        log::warn!(
            "failed to write APIKeyAuthPolicy status for {}/{}: {}; retrying",
            namespace,
            name,
            e
        );
        return Err(e.into());
    }

    // Siblings on the same target and data plane acks re-run this policy
    // through the store's events.
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_types::{
        APIKeyAuthPolicySpec, ApiKeySpec, PolicyTargetRef, SecretRef,
    };
    use crate::store::{ConfigStore, SecretState};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::HashMap;

    fn make_policy(name: &str, ns: &str, target_name: &str, secret_name: &str) -> APIKeyAuthPolicy {
        APIKeyAuthPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: APIKeyAuthPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                api_key: ApiKeySpec {
                    secret_ref: SecretRef {
                        name: secret_name.to_string(),
                        namespace: None,
                    },
                    header_name: None,
                },
            },
            status: None,
        }
    }

    #[test]
    fn test_accepted_when_secret_exists() {
        let store = ConfigStore::new();
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "api-keys".to_string(),
            },
            SecretState {
                data: HashMap::new(),
            },
        );

        let policy = make_policy("ak1", "default", "my-route", "api-keys");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
    }

    #[test]
    fn test_rejected_when_secret_missing() {
        let store = ConfigStore::new();
        let policy = make_policy("ak1", "default", "my-route", "missing-secret");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "InvalidSecret");
        assert!(conditions[0]
            .message
            .contains("default/missing-secret"));
    }

    #[test]
    fn test_conflict_older_wins() {
        let store = ConfigStore::new();
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "api-keys".to_string(),
            },
            SecretState {
                data: HashMap::new(),
            },
        );

        // Older policy (epoch 1000)
        let mut older = make_policy("ak-older", "default", "my-route", "api-keys");
        older.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::from_second(1000).unwrap(),
        ));

        // Newer policy (epoch 2000)
        let mut newer = make_policy("ak-newer", "default", "my-route", "api-keys");
        newer.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::from_second(2000).unwrap(),
        ));

        // Reconcile both
        reconcile_inner(&older, &store).unwrap();
        reconcile_inner(&newer, &store).unwrap();

        let older_key = NamespacedName {
            namespace: "default".to_string(),
            name: "ak-older".to_string(),
        };
        let newer_key = NamespacedName {
            namespace: "default".to_string(),
            name: "ak-newer".to_string(),
        };

        let older_state = store.api_key_auth_policies.get(&older_key).unwrap();
        let newer_state = store.api_key_auth_policies.get(&newer_key).unwrap();

        assert!(older_state.accepted, "older policy should be accepted");
        assert!(!newer_state.accepted, "newer policy should NOT be accepted");
    }

    #[test]
    fn test_default_header_name() {
        let store = ConfigStore::new();
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "api-keys".to_string(),
            },
            SecretState {
                data: HashMap::new(),
            },
        );

        let policy = make_policy("ak1", "default", "my-route", "api-keys");
        reconcile_inner(&policy, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "ak1".to_string(),
        };
        let stored = store.api_key_auth_policies.get(&key).unwrap();
        assert_eq!(stored.header_name, "X-API-Key");
    }
}
