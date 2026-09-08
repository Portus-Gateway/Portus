//! RetryPolicy reconciler.
//!
//! Watches RetryPolicy resources, validates targetRef, resolves conflicts
//! (oldest-timestamp-wins), stores state in ConfigStore, writes status conditions.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::policy_types::RetryPolicy;
use crate::status;
use crate::store::{ConfigStore, NamespacedName, PolicyTargetKey, RetryPolicyState};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Core reconciliation logic (pure store manipulation, no async I/O).
pub fn reconcile_inner(
    policy: &RetryPolicy,
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

    // Validate retry_on conditions before accepting the policy.
    let valid_conditions = ["connect-failure", "gateway-error"];
    for condition in &policy.spec.retry.retry_on {
        if !valid_conditions.contains(&condition.as_str()) {
            let mut conditions = Vec::new();
            conditions.push(status::build_condition(
                "Accepted",
                false,
                "InvalidRetryCondition",
                &format!(
                    "Unsupported retry condition: {}. Supported: connect-failure, gateway-error",
                    condition
                ),
                generation,
            ));
            store.retry_policies.insert(
                my_key.clone(),
                RetryPolicyState {
                    target: target.clone(),
                    max_retries: policy.spec.retry.max_retries,
                    retry_on: policy.spec.retry.retry_on.clone(),
                    generation,
                    creation_timestamp: creation_ts.clone(),
                    accepted: false,
                },
            );
            store.notify_change();
            let programmed = store.is_programmed();
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
            return Ok(conditions);
        }
    }

    let state = RetryPolicyState {
        target: target.clone(),
        max_retries: policy.spec.retry.max_retries,
        retry_on: policy.spec.retry.retry_on.clone(),
        generation,
        creation_timestamp: creation_ts.clone(),
        accepted: true,
    };

    store.retry_policies.insert(my_key.clone(), state);
    resolve_conflicts(&my_key, &target, &store.retry_policies);

    let accepted = store
        .retry_policies
        .get(&my_key)
        .map(|s| s.accepted)
        .unwrap_or(false);

    let programmed = store.is_programmed();
    store.notify_change();

    let mut conditions = Vec::new();

    if accepted {
        // The dataplane retries at connection-establishment time only (Pingora's
        // fail_to_connect); a response that has already started cannot be
        // replayed. Say so in the status rather than let `gateway-error` look
        // like response-level retry.
        let message = if policy
            .spec
            .retry
            .retry_on
            .iter()
            .any(|c| c == "gateway-error")
        {
            "Policy accepted. Note: gateway-error retries apply to upstream connection \
             failures only; responses already received from the backend are not retried"
        } else {
            "Policy accepted"
        };
        conditions.push(status::build_condition(
            "Accepted",
            true,
            "Accepted",
            message,
            generation,
        ));
    } else {
        let winner_msg = find_winner_key(&target, &my_key, &store.retry_policies)
            .map(|k| format!("Older RetryPolicy {} takes precedence", k))
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

pub async fn reconcile_retry_policy(
    policy: Arc<RetryPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.retry_policies,
        "RetryPolicy",
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
        "kind": "RetryPolicy",
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

    let api: Api<RetryPolicy> = Api::namespaced(ctx.client.clone(), namespace);
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
            "failed to write RetryPolicy status for {}/{}: {}; will retry on next reconcile",
            namespace,
            name,
            e
        );
    }

    // Siblings on the same target and data plane acks re-run this policy
    // through the store's events.
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_types::{PolicyTargetRef, RetryPolicySpec, RetrySpec};
    use crate::store::ConfigStore;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn make_policy(name: &str, ns: &str, target_name: &str, retries: u32) -> RetryPolicy {
        RetryPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: RetryPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                retry: RetrySpec {
                    max_retries: retries,
                    retry_on: vec!["connect-failure".to_string()],
                },
            },
            status: None,
        }
    }

    #[test]
    fn reconcile_publishing_publishes_on_change_only() {
        use crate::reconcilers::policy_common::reconcile_publishing;
        use crate::store::Event;
        let store = ConfigStore::new();
        let mut events = store.events.subscribe();
        let policy = make_policy("rp1", "default", "my-route", 3);
        let run = |store: &ConfigStore, policy: &RetryPolicy| {
            reconcile_publishing(store, &store.retry_policies, "RetryPolicy", &policy.metadata, || reconcile_inner(policy, store))
                .unwrap()
        };
        run(&store, &policy);
        match events.try_recv().unwrap() {
            Event::Policy { kind: "RetryPolicy", key, target } => {
                assert_eq!(key.name, "rp1");
                assert_eq!(target.name, "my-route");
            }
            other => panic!("unexpected event {other:?}"),
        }
        // Same policy again: same state, no event (siblings would otherwise
        // re-trigger each other without end).
        run(&store, &policy);
        assert!(events.try_recv().is_err());
        // A sibling on the same target changes the conflict outcome: it publishes.
        let mut newer = make_policy("rp2", "default", "my-route", 1);
        newer.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        ));
        run(&store, &newer);
        assert!(matches!(events.try_recv().unwrap(), Event::Policy { key, .. } if key.name == "rp2"));
    }

    #[test]
    fn test_single_policy_accepted() {

        let store = ConfigStore::new();
        let policy = make_policy("rp1", "default", "my-route", 3);
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "rp1".to_string(),
        };
        assert!(store.retry_policies.get(&key).unwrap().accepted);
    }

    fn make_policy_with_retry_on(name: &str, ns: &str, target_name: &str, retries: u32, retry_on: Vec<String>) -> RetryPolicy {
        RetryPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: RetryPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: target_name.to_string(),
                    section_name: None,
                },
                retry: RetrySpec {
                    max_retries: retries,
                    retry_on,
                },
            },
            status: None,
        }
    }

    #[test]
    fn test_gateway_error_retry_on_accepted_with_connect_only_note() {
        let store = ConfigStore::new();
        let policy = make_policy_with_retry_on(
            "rp-ge",
            "default",
            "my-route",
            2,
            vec!["gateway-error".to_string()],
        );
        let conditions = reconcile_inner(&policy, &store).unwrap();
        let accepted = conditions.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted.status, "True");
        assert!(
            accepted.message.contains("connection failures only"),
            "status must disclose that gateway-error is connect-level: {}",
            accepted.message
        );
    }

    #[test]
    fn test_invalid_retry_on_rejected() {
        let store = ConfigStore::new();
        let policy = make_policy_with_retry_on("rp-bad", "default", "my-route", 3, vec!["5xx".to_string()]);
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "InvalidRetryCondition");
        assert!(conditions[0].message.contains("5xx"));

        // Verify stored as not-accepted
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "rp-bad".to_string(),
        };
        assert!(!store.retry_policies.get(&key).unwrap().accepted);
    }

    #[test]
    fn test_valid_retry_conditions_accepted() {
        let store = ConfigStore::new();
        let policy = make_policy_with_retry_on(
            "rp-ok", "default", "my-route", 3,
            vec!["connect-failure".to_string(), "gateway-error".to_string()],
        );
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[0].reason, "Accepted");
    }

    #[test]
    fn test_mixed_valid_invalid_retry_on_rejected() {
        let store = ConfigStore::new();
        let policy = make_policy_with_retry_on(
            "rp-mix", "default", "my-route", 3,
            vec!["connect-failure".to_string(), "5xx".to_string()],
        );
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "InvalidRetryCondition");
    }

    #[test]
    fn test_different_targets_no_conflict() {
        let store = ConfigStore::new();
        let p1 = make_policy("rp1", "default", "route-a", 3);
        let p2 = make_policy("rp2", "default", "route-b", 5);

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

        let mut older = make_policy("rp-old", "default", "my-route", 3);
        older.metadata.creation_timestamp = Some(older_ts);
        let mut newer = make_policy("rp-new", "default", "my-route", 5);
        newer.metadata.creation_timestamp = Some(newer_ts);

        let conds1 = reconcile_inner(&older, &store).unwrap();
        assert_eq!(conds1[0].status, "True");

        let conds2 = reconcile_inner(&newer, &store).unwrap();
        assert_eq!(conds2[0].type_, "Accepted");
        assert_eq!(conds2[0].status, "False");
        assert_eq!(conds2[0].reason, "Conflicted");

        let old_key = NamespacedName {
            namespace: "default".to_string(),
            name: "rp-old".to_string(),
        };
        let new_key = NamespacedName {
            namespace: "default".to_string(),
            name: "rp-new".to_string(),
        };
        assert!(store.retry_policies.get(&old_key).unwrap().accepted);
        assert!(!store.retry_policies.get(&new_key).unwrap().accepted);
    }
}
