//! ConnectionPolicy reconciler.
//!
//! Watches ConnectionPolicy resources, validates targetRef, resolves conflicts
//! (oldest-timestamp-wins), stores state in ConfigStore, writes status conditions.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::policy_types::ConnectionPolicy;
use crate::status;
use crate::store::{ConfigStore, ConnectionPolicyState, NamespacedName, PolicyTargetKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Core reconciliation logic (pure store manipulation, no async I/O).
pub fn reconcile_inner(
    policy: &ConnectionPolicy,
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

    let state = ConnectionPolicyState {
        target: target.clone(),
        max_connections: policy.spec.max_connections,
        generation,
        creation_timestamp: creation_ts,
        accepted: true,
    };

    store.connection_policies.insert(my_key.clone(), state);
    resolve_conflicts(&my_key, &target, &store.connection_policies);

    let accepted = store
        .connection_policies
        .get(&my_key)
        .map(|s| s.accepted)
        .unwrap_or(false);

    let programmed = store.is_programmed();
    store.notify_change();

    let mut conditions = Vec::new();

    if accepted {
        conditions.push(status::build_condition(
            "Accepted",
            true,
            "Accepted",
            "Policy accepted",
            generation,
        ));
    } else {
        let winner_msg = find_winner_key(&target, &my_key, &store.connection_policies)
            .map(|k| format!("Older ConnectionPolicy {} takes precedence", k))
            .unwrap_or_else(|| "Conflicted with another policy".to_string());
        conditions.push(status::build_condition(
            "Accepted",
            false,
            "Conflicted",
            &winner_msg,
            generation,
        ));
    }

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

/// Main reconcile function for ConnectionPolicy resources.
pub async fn reconcile_connection_policy(
    policy: Arc<ConnectionPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.connection_policies,
        "ConnectionPolicy",
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
        "kind": "ConnectionPolicy",
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

    let api: Api<ConnectionPolicy> = Api::namespaced(ctx.client.clone(), namespace);
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
            "failed to write ConnectionPolicy status for {}/{}: {}; retrying",
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
    use crate::policy_types::{ConnectionPolicySpec, PolicyTargetRef};
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn make_policy(name: &str, ns: &str, target_name: &str, max_conn: u32, ts: Option<Time>) -> ConnectionPolicy {
        ConnectionPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                creation_timestamp: ts,
                ..Default::default()
            },
            spec: ConnectionPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                max_connections: max_conn,
            },
            status: None,
        }
    }

    #[test]
    fn test_single_policy_accepted() {
        let store = ConfigStore::new();
        let policy = make_policy("cp1", "default", "my-route", 1000, None);
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
    }

    #[test]
    fn test_conflict_older_wins() {
        let store = ConfigStore::new();
        let older_ts = Time(k8s_openapi::jiff::Timestamp::from_second(1000).unwrap());
        let newer_ts = Time(k8s_openapi::jiff::Timestamp::from_second(2000).unwrap());

        let older = make_policy("cp-old", "default", "my-route", 500, Some(older_ts));
        let newer = make_policy("cp-new", "default", "my-route", 1000, Some(newer_ts));

        reconcile_inner(&older, &store).unwrap();
        let conds = reconcile_inner(&newer, &store).unwrap();

        assert_eq!(conds[0].status, "False");
        assert_eq!(conds[0].reason, "Conflicted");
    }
}
