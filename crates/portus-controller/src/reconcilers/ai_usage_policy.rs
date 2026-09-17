//! AIUsagePolicy reconciler: a token budget on an AIRoute. Validated here,
//! attached to the route's compiled config by the compiler, enforced on the
//! data plane with grants from the ledger.

use std::sync::Arc;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::ai_types::AIUsagePolicy;
use crate::status;
use crate::store::{AIUsagePolicyState, ConfigStore, NamespacedName, PolicyTargetKey};

/// Normalise the spec into the data plane's vocabulary, or say what is wrong.
pub fn normalise(policy: &AIUsagePolicy) -> Result<(String, String, bool), String> {
    let spec = &policy.spec;
    if spec.target_ref.kind != "AIRoute" {
        return Err(format!("targetRef.kind must be AIRoute, got {:?}", spec.target_ref.kind));
    }
    if spec.budget.tokens == 0 {
        return Err("budget.tokens must be at least 1".to_string());
    }
    let window = match spec.budget.window.to_ascii_lowercase().as_str() {
        "hourly" => "HOURLY",
        "daily" => "DAILY",
        "monthly" => "MONTHLY",
        other => return Err(format!("budget.window {other:?} is not Hourly, Daily or Monthly")),
    };
    let per = match spec.budget.per.as_deref().unwrap_or("Key").to_ascii_lowercase().as_str() {
        "key" => "KEY",
        "tenant" => "TENANT",
        "route" => "ROUTE",
        other => return Err(format!("budget.per {other:?} is not Key, Tenant or Route")),
    };
    let fail_open = match spec.on_ledger_unavailable.as_deref().unwrap_or("Open").to_ascii_lowercase().as_str() {
        "open" => true,
        "closed" => false,
        other => return Err(format!("onLedgerUnavailable {other:?} is not Open or Closed")),
    };
    Ok((window.to_string(), per.to_string(), fail_open))
}

pub fn reconcile_inner(policy: &AIUsagePolicy, store: &ConfigStore) -> Result<Vec<Condition>, ReconcileError> {
    let name = policy.metadata.name.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.name".into()))?;
    let namespace =
        policy.metadata.namespace.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.namespace".into()))?;
    let generation = policy.metadata.generation.unwrap_or(0);
    let my_key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };
    let target = PolicyTargetKey {
        group: policy.spec.target_ref.group.clone(),
        kind: policy.spec.target_ref.kind.clone(),
        namespace: namespace.to_string(),
        name: policy.spec.target_ref.name.clone(),
        section_name: policy.spec.target_ref.section_name.clone(),
    };

    let (accepted, reason, message) = match normalise(policy) {
        Ok((window, per, fail_open)) => {
            store.ai_usage_policies.insert(
                my_key.clone(),
                AIUsagePolicyState {
                    target: target.clone(),
                    tokens: policy.spec.budget.tokens,
                    window,
                    per,
                    fail_open,
                    generation,
                    creation_timestamp: policy.metadata.creation_timestamp.clone(),
                    accepted: true,
                },
            );
            resolve_conflicts(&my_key, &target, &store.ai_usage_policies);
            let won = store.ai_usage_policies.get(&my_key).map(|s| s.accepted).unwrap_or(false);
            if won {
                (true, "Accepted", "Policy accepted".to_string())
            } else {
                let msg = find_winner_key(&target, &my_key, &store.ai_usage_policies)
                    .map(|k| format!("Older AIUsagePolicy {k} takes precedence"))
                    .unwrap_or_else(|| "Conflicted with another policy".to_string());
                (false, "Conflicted", msg)
            }
        }
        Err(e) => {
            store.ai_usage_policies.remove(&my_key);
            (false, "Invalid", e)
        }
    };
    store.notify_change();

    let programmed = accepted && store.is_programmed();
    Ok(vec![
        status::build_condition("Accepted", accepted, reason, &message, generation),
        status::build_condition(
            "Programmed",
            programmed,
            if programmed { "Programmed" } else { "NotProgrammed" },
            if programmed { "Configuration programmed in data plane" } else { "Waiting for data plane to apply configuration" },
            generation,
        ),
    ])
}

pub async fn reconcile_ai_usage_policy(policy: Arc<AIUsagePolicy>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.ai_usage_policies,
        "AIUsagePolicy",
        &policy.metadata,
        || reconcile_inner(&policy, &ctx.store),
    )?;
    let name = policy.metadata.name.as_deref().unwrap_or_default();
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();
    let current_conditions: Vec<Condition> = policy.status.as_ref().map(|s| s.conditions.clone()).unwrap_or_default();
    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1alpha1",
        "kind": "AIUsagePolicy",
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
    let api: Api<AIUsagePolicy> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(&api, name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write AIUsagePolicy status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_types::{AIBudgetSpec, AIUsagePolicySpec};
    use crate::policy_types::PolicyTargetRef;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn policy(name: &str, window: &str, per: Option<&str>, unavailable: Option<&str>, tokens: u64) -> AIUsagePolicy {
        AIUsagePolicy {
            metadata: ObjectMeta { name: Some(name.into()), namespace: Some("llm".into()), generation: Some(1), ..Default::default() },
            spec: AIUsagePolicySpec {
                target_ref: PolicyTargetRef { group: "portus-gateway.dev".into(), kind: "AIRoute".into(), name: "claude".into(), section_name: None },
                budget: AIBudgetSpec { tokens, window: window.into(), per: per.map(str::to_string) },
                on_ledger_unavailable: unavailable.map(str::to_string),
            },
            status: None,
        }
    }

    #[test]
    fn specs_normalise_to_the_data_plane_vocabulary() {
        assert_eq!(normalise(&policy("a", "Daily", None, None, 10)), Ok(("DAILY".into(), "KEY".into(), true)));
        assert_eq!(normalise(&policy("a", "hourly", Some("Tenant"), Some("Closed"), 10)), Ok(("HOURLY".into(), "TENANT".into(), false)));
        assert!(normalise(&policy("a", "Weekly", None, None, 10)).is_err());
        assert!(normalise(&policy("a", "Daily", Some("User"), None, 10)).is_err());
        assert!(normalise(&policy("a", "Daily", None, Some("Maybe"), 10)).is_err());
        assert!(normalise(&policy("a", "Daily", None, None, 0)).is_err());
    }

    #[test]
    fn an_accepted_policy_is_stored_and_a_second_on_the_same_route_conflicts() {
        let store = ConfigStore::new();
        let mut first = policy("cap", "Monthly", None, None, 500);
        first.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::jiff::Timestamp::from_second(1000).unwrap()));
        let c = reconcile_inner(&first, &store).unwrap();
        assert_eq!((c[0].type_.as_str(), c[0].status.as_str()), ("Accepted", "True"));
        let state = store.ai_usage_policies.get(&NamespacedName { namespace: "llm".into(), name: "cap".into() }).unwrap().clone();
        assert_eq!((state.tokens, state.window.as_str(), state.per.as_str(), state.fail_open, state.accepted), (500, "MONTHLY", "KEY", true, true));

        let mut second = policy("cap2", "Daily", None, None, 900);
        second.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::jiff::Timestamp::from_second(2000).unwrap()));
        let c = reconcile_inner(&second, &store).unwrap();
        assert_eq!((c[0].status.as_str(), c[0].reason.as_str()), ("False", "Conflicted"), "{}", c[0].message);

        let c = reconcile_inner(&policy("bad", "Weekly", None, None, 1), &store).unwrap();
        assert_eq!(c[0].reason, "Invalid");
        assert!(store.ai_usage_policies.get(&NamespacedName { namespace: "llm".into(), name: "bad".into() }).is_none());
    }
}
