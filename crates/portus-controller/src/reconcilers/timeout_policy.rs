//! TimeoutPolicy reconciler.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::policy_types::TimeoutPolicy;
use crate::status;
use crate::store::{ConfigStore, NamespacedName, PolicyTargetKey, TimeoutPolicyState};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

pub fn reconcile_inner(
    policy: &TimeoutPolicy,
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

    let t = &policy.spec.timeout;
    let state = TimeoutPolicyState {
        target: target.clone(),
        request_timeout_ms: t.request_timeout_ms,
        backend_request_timeout_ms: t.backend_request_timeout_ms,
        connect_timeout_ms: t.connect_timeout_ms,
        generation,
        creation_timestamp: creation_ts.clone(),
        accepted: true,
    };

    store.timeout_policies.insert(my_key.clone(), state);
    resolve_conflicts(&my_key, &target, &store.timeout_policies);

    let accepted = store
        .timeout_policies
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
        let winner_msg = find_winner_key(&target, &my_key, &store.timeout_policies)
            .map(|k| format!("Older TimeoutPolicy {} takes precedence", k))
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

pub async fn reconcile_timeout_policy(
    policy: Arc<TimeoutPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.timeout_policies,
        "TimeoutPolicy",
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
        "kind": "TimeoutPolicy",
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

    let api: Api<TimeoutPolicy> = Api::namespaced(ctx.client.clone(), namespace);
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
            "failed to write TimeoutPolicy status for {}/{}: {}; retrying",
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
    use crate::policy_types::{PolicyTargetRef, TimeoutPolicySpec, TimeoutSpec};
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn make_policy(name: &str, ns: &str, target_name: &str) -> TimeoutPolicy {
        TimeoutPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: TimeoutPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                timeout: TimeoutSpec {
                    request_timeout_ms: 5000,
                    backend_request_timeout_ms: 3000,
                    connect_timeout_ms: 1000,
                },
            },
            status: None,
        }
    }

    #[test]
    fn test_single_policy_accepted() {
        let store = ConfigStore::new();
        let policy = make_policy("tp1", "default", "my-route");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
    }

    #[test]
    fn test_different_targets_no_conflict() {
        let store = ConfigStore::new();
        let p1 = make_policy("tp1", "default", "route-a");
        let p2 = make_policy("tp2", "default", "route-b");

        let c1 = reconcile_inner(&p1, &store).unwrap();
        let c2 = reconcile_inner(&p2, &store).unwrap();

        assert_eq!(c1[0].status, "True");
        assert_eq!(c2[0].status, "True");
    }

    #[test]
    fn test_conflict_older_wins() {
        let store = ConfigStore::new();
        let older_ts = Time(k8s_openapi::jiff::Timestamp::from_second(1000).unwrap());
        let newer_ts = Time(k8s_openapi::jiff::Timestamp::from_second(2000).unwrap());

        let mut older = make_policy("tp-old", "default", "my-route");
        older.metadata.creation_timestamp = Some(older_ts);
        let mut newer = make_policy("tp-new", "default", "my-route");
        newer.metadata.creation_timestamp = Some(newer_ts);

        let conds1 = reconcile_inner(&older, &store).unwrap();
        assert_eq!(conds1[0].status, "True");

        let conds2 = reconcile_inner(&newer, &store).unwrap();
        assert_eq!(conds2[0].type_, "Accepted");
        assert_eq!(conds2[0].status, "False");
        assert_eq!(conds2[0].reason, "Conflicted");

        let old_key = NamespacedName {
            namespace: "default".to_string(),
            name: "tp-old".to_string(),
        };
        let new_key = NamespacedName {
            namespace: "default".to_string(),
            name: "tp-new".to_string(),
        };
        assert!(store.timeout_policies.get(&old_key).unwrap().accepted);
        assert!(!store.timeout_policies.get(&new_key).unwrap().accepted);
    }
}
