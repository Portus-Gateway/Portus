//! HealthCheckPolicy reconciler.
//!
//! Watches HealthCheckPolicy resources. These target Services (not Routes),
//! configuring active health checking on backend endpoints.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::policy_types::HealthCheckPolicy;
use crate::status;
use crate::store::{ConfigStore, HealthCheckPolicyState, NamespacedName, PolicyTargetKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

pub fn reconcile_inner(
    policy: &HealthCheckPolicy,
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

    let hc = &policy.spec.health_check;
    let state = HealthCheckPolicyState {
        target: target.clone(),
        path: hc.path.clone(),
        interval_secs: hc.interval_secs,
        timeout_secs: hc.timeout_secs,
        healthy_threshold: hc.healthy_threshold,
        unhealthy_threshold: hc.unhealthy_threshold,
        generation,
        creation_timestamp: creation_ts.clone(),
        accepted: true,
    };

    store.health_check_policies.insert(my_key.clone(), state);
    resolve_conflicts(&my_key, &target, &store.health_check_policies);

    let accepted = store
        .health_check_policies
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
        let winner_msg = find_winner_key(&target, &my_key, &store.health_check_policies)
            .map(|k| format!("Older HealthCheckPolicy {} takes precedence", k))
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

pub async fn reconcile_health_check_policy(
    policy: Arc<HealthCheckPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.health_check_policies,
        "HealthCheckPolicy",
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
        "kind": "HealthCheckPolicy",
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

    let api: Api<HealthCheckPolicy> = Api::namespaced(ctx.client.clone(), namespace);
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
            "failed to write HealthCheckPolicy status for {}/{}: {}; retrying",
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
    use crate::policy_types::{PolicyTargetRef, HealthCheckPolicySpec, HealthCheckSpec};
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn make_policy(name: &str, ns: &str, target_name: &str) -> HealthCheckPolicy {
        HealthCheckPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: HealthCheckPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                health_check: HealthCheckSpec {
                    path: "/healthz".to_string(),
                    interval_secs: 10,
                    timeout_secs: 5,
                    healthy_threshold: 1,
                    unhealthy_threshold: 3,
                },
            },
            status: None,
        }
    }

    #[test]
    fn test_single_policy_accepted() {
        let store = ConfigStore::new();
        let policy = make_policy("hc1", "default", "my-service");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
    }

    #[test]
    fn test_different_targets_no_conflict() {
        let store = ConfigStore::new();
        let p1 = make_policy("hc1", "default", "svc-a");
        let p2 = make_policy("hc2", "default", "svc-b");

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

        let mut older = make_policy("hc-old", "default", "my-service");
        older.metadata.creation_timestamp = Some(older_ts);
        let mut newer = make_policy("hc-new", "default", "my-service");
        newer.metadata.creation_timestamp = Some(newer_ts);

        let conds1 = reconcile_inner(&older, &store).unwrap();
        assert_eq!(conds1[0].status, "True");

        let conds2 = reconcile_inner(&newer, &store).unwrap();
        assert_eq!(conds2[0].type_, "Accepted");
        assert_eq!(conds2[0].status, "False");
        assert_eq!(conds2[0].reason, "Conflicted");

        let old_key = NamespacedName {
            namespace: "default".to_string(),
            name: "hc-old".to_string(),
        };
        let new_key = NamespacedName {
            namespace: "default".to_string(),
            name: "hc-new".to_string(),
        };
        assert!(store.health_check_policies.get(&old_key).unwrap().accepted);
        assert!(!store.health_check_policies.get(&new_key).unwrap().accepted);
    }
}
