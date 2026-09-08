use crate::gateway_types::RouteParentStatus;
use crate::reconcilers::CONTROLLER_NAME;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Api, Patch, PatchParams};
use kube::Resource;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::future::Future;
use std::time::Duration;

/// Upper bound on any single write to the API server.
///
/// kube-client 4 no longer applies a read timeout by default, so a stalled
/// HTTP/2 stream would otherwise wedge the owning reconciler forever: seen live
/// on 2026-09-04 when a Gateway status patch never returned and the Gateway
/// stayed `Accepted=Unknown/Pending` for the rest of the conformance run.
pub const API_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Error surfaced when an API write exceeds its deadline.
#[derive(Debug, thiserror::Error)]
#[error("{what} timed out after {timeout:?}")]
pub struct ApiWriteTimeout {
    what: &'static str,
    timeout: Duration,
}

/// Run an API write with an explicit deadline, mapping expiry to
/// `kube::Error::Service` so callers keep their existing error handling.
pub async fn with_timeout<T, F>(what: &'static str, timeout: Duration, fut: F) -> Result<T, kube::Error>
where
    F: Future<Output = Result<T, kube::Error>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(kube::Error::Service(Box::new(ApiWriteTimeout { what, timeout }))),
    }
}

/// `with_timeout` bound to [`API_WRITE_TIMEOUT`]. Wrap every status patch,
/// lease write and annotation touch with this.
pub async fn with_write_timeout<T, F>(what: &'static str, fut: F) -> Result<T, kube::Error>
where
    F: Future<Output = Result<T, kube::Error>>,
{
    with_timeout(what, API_WRITE_TIMEOUT, fut).await
}

/// Build a Kubernetes status condition with the correct fields.
pub fn build_condition(
    type_: &str,
    status: bool,
    reason: &str,
    message: &str,
    generation: i64,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: if status { "True" } else { "False" }.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(generation),
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::now()),
    }
}

/// Compare two condition slices, ignoring lastTransitionTime.
/// Returns true if all semantic fields match (type, status, reason, message,
/// observedGeneration).
pub fn conditions_equal(a: &[Condition], b: &[Condition]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (ca, cb) in a.iter().zip(b.iter()) {
        if ca.type_ != cb.type_
            || ca.status != cb.status
            || ca.reason != cb.reason
            || ca.message != cb.message
            || ca.observed_generation != cb.observed_generation
        {
            return false;
        }
    }
    true
}

/// `status.parents` entries belong to whichever controller wrote them. Keep every
/// other controller's entries and append ours, so a route whose parentRefs span
/// two implementations does not have its status rewritten by each in turn (seen
/// live 2026-09-06: an HTTPRoute bound to an agentgateway Gateway was reconciled
/// ~190 times a second as the two controllers replaced each other's entry).
pub fn merge_route_parents(
    existing: &[RouteParentStatus],
    ours: Vec<serde_json::Value>,
) -> Vec<serde_json::Value> {
    existing
        .iter()
        .filter(|p| p.controller_name != CONTROLLER_NAME)
        .filter_map(|p| serde_json::to_value(p).ok())
        .chain(ours)
        .collect()
}

/// The conditions this controller previously wrote on a route: the
/// diff-before-write comparison must ignore other controllers' entries.
pub fn own_parent_conditions(existing: &[RouteParentStatus]) -> Vec<Condition> {
    existing
        .iter()
        .filter(|p| p.controller_name == CONTROLLER_NAME)
        .flat_map(|p| p.conditions.iter().cloned())
        .collect()
}

/// Patch the status subresource only if the desired conditions differ from
/// current conditions (diff-before-write to prevent reconciler feedback loops).
/// Uses server-side apply with field manager "portus-gateway".
pub async fn patch_status_if_changed<K>(
    api: &Api<K>,
    name: &str,
    desired_status: serde_json::Value,
    current_conditions: &[Condition],
    desired_conditions: &[Condition],
) -> Result<(), kube::Error>
where
    K: Resource + Serialize + DeserializeOwned + Clone + Debug,
{
    if conditions_equal(current_conditions, desired_conditions) {
        return Ok(());
    }
    let pp = PatchParams::apply("portus-gateway").force();
    with_write_timeout(
        "status patch",
        api.patch_status(name, &pp, &Patch::Apply(desired_status)),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_route_parents_keeps_other_controllers_entries_and_replaces_ours() {
        use crate::gateway_types::ParentReference;
        let theirs = RouteParentStatus {
            parent_ref: ParentReference { name: "agentgateway".into(), ..Default::default() },
            controller_name: "agentgateway.dev/agentgateway".into(),
            conditions: vec![build_condition("Accepted", true, "Accepted", "theirs", 1)],
        };
        let ours_old = RouteParentStatus {
            parent_ref: ParentReference { name: "portus".into(), ..Default::default() },
            controller_name: CONTROLLER_NAME.into(),
            conditions: vec![build_condition("Accepted", false, "Pending", "old", 1)],
        };
        let existing = vec![theirs.clone(), ours_old.clone()];
        let ours_new = serde_json::json!({"parentRef": {"name": "portus"}, "controllerName": CONTROLLER_NAME, "conditions": []});
        let merged = merge_route_parents(&existing, vec![ours_new.clone()]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0]["controllerName"], "agentgateway.dev/agentgateway", "foreign entry kept first");
        assert_eq!(merged[0]["conditions"][0]["message"], "theirs");
        assert_eq!(merged[1], ours_new, "our old entry replaced by the new one");

        // Diffing only looks at our own conditions, so a foreign entry never
        // makes the status look changed.
        let own = own_parent_conditions(&existing);
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].message, "old");
        assert!(own_parent_conditions(&[theirs]).is_empty());
    }

    #[test]
    fn test_build_condition_sets_all_fields() {
        let cond = build_condition("Accepted", true, "Accepted", "Gateway class accepted", 3);
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Accepted");
        assert_eq!(cond.message, "Gateway class accepted");
        assert_eq!(cond.observed_generation, Some(3));
    }

    #[test]
    fn test_build_condition_false_status() {
        let cond = build_condition("Programmed", false, "NotReady", "Waiting for data plane", 1);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotReady");
    }

    #[test]
    fn test_conditions_equal_matching() {
        let a = vec![
            build_condition("Accepted", true, "Accepted", "ok", 1),
            build_condition("Programmed", false, "Pending", "waiting", 1),
        ];
        // Build b separately so lastTransitionTime may differ
        let b = vec![
            build_condition("Accepted", true, "Accepted", "ok", 1),
            build_condition("Programmed", false, "Pending", "waiting", 1),
        ];
        assert!(conditions_equal(&a, &b));
    }

    #[test]
    fn test_conditions_equal_different_status() {
        let a = vec![build_condition("Accepted", true, "Accepted", "ok", 1)];
        let b = vec![build_condition("Accepted", false, "Invalid", "bad", 1)];
        assert!(!conditions_equal(&a, &b));
    }

    #[test]
    fn test_conditions_equal_different_generation() {
        let a = vec![build_condition("Accepted", true, "Accepted", "ok", 1)];
        let b = vec![build_condition("Accepted", true, "Accepted", "ok", 2)];
        assert!(!conditions_equal(&a, &b));
    }

    #[test]
    fn test_conditions_equal_different_lengths() {
        let a = vec![build_condition("Accepted", true, "Accepted", "ok", 1)];
        let b = vec![
            build_condition("Accepted", true, "Accepted", "ok", 1),
            build_condition("Programmed", false, "Pending", "waiting", 1),
        ];
        assert!(!conditions_equal(&a, &b));
    }

    #[tokio::test]
    async fn with_timeout_errors_on_stalled_request() {
        let stalled = std::future::pending::<Result<(), kube::Error>>();
        let err = with_timeout("test write", Duration::from_millis(10), stalled)
            .await
            .expect_err("a request that never completes must time out");
        assert!(matches!(err, kube::Error::Service(_)), "got {err:?}");
        assert!(err.to_string().contains("test write timed out after 10ms"), "got {err}");
    }

    #[tokio::test]
    async fn with_timeout_passes_through_completed_result() {
        let ok = with_timeout("ok", Duration::from_millis(10), async { Ok::<u8, kube::Error>(7) }).await;
        assert_eq!(ok.expect("completed future is returned as-is"), 7);
        let err = with_timeout("err", Duration::from_millis(10), async {
            Err::<u8, kube::Error>(kube::Error::LinesCodecMaxLineLengthExceeded)
        })
        .await;
        assert!(matches!(err, Err(kube::Error::LinesCodecMaxLineLengthExceeded)));
    }

    #[test]
    fn test_conditions_equal_empty() {
        let a: Vec<Condition> = vec![];
        let b: Vec<Condition> = vec![];
        assert!(conditions_equal(&a, &b));
    }
}
