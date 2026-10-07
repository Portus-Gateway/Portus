//! ExtAuthPolicy reconciler.
//!
//! Validates the spec, resolves conflicts (oldest-timestamp-wins) and writes
//! status. A cross-namespace `backendRef` needs a ReferenceGrant for
//! `Service`; without one the policy stays accepted and the route refuses
//! every request (500) rather than going unprotected, and `ResolvedRefs`
//! says why. The compiler re-checks the grant on every compile.

use std::sync::Arc;

use super::policy_common::{find_winner_key, is_header_name, resolve_conflicts, RESERVED_HEADERS};
use super::{is_reference_allowed_from, ReconcileContext, ReconcileError};
use crate::policy_types::{ExtAuthPolicy, ExtAuthPolicySpec};
use crate::status;
use crate::store::{ConfigStore, ExtAuthPolicyState, NamespacedName, PolicyTargetKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;

const DEFAULT_TIMEOUT_MS: u32 = 1000;
const MAX_TIMEOUT_MS: u32 = 60_000;

/// The policy as the store keeps it, or what is wrong with the spec.
pub fn validate(spec: &ExtAuthPolicySpec, namespace: &str, target: PolicyTargetKey, generation: i64, created: Option<Time>) -> Result<ExtAuthPolicyState, String> {
    let e = &spec.ext_auth;
    if e.backend_ref.name.is_empty() {
        return Err("extAuth.backendRef.name is required".to_string());
    }
    if e.backend_ref.port == 0 {
        return Err("extAuth.backendRef.port must be 1-65535".to_string());
    }
    let path = e.path.clone().unwrap_or_else(|| "/".to_string());
    if !path.starts_with('/') || path.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(format!("extAuth.path {path:?} must start with / and contain no spaces"));
    }
    let timeout_ms = e.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(format!("extAuth.timeoutMs must be 1-{MAX_TIMEOUT_MS}"));
    }
    let lower = |list: &[String], field: &str, reserved: bool| -> Result<Vec<String>, String> {
        list.iter()
            .map(|h| {
                let h = h.to_ascii_lowercase();
                if !is_header_name(&h) {
                    return Err(format!("extAuth.{field}: {h:?} is not a valid header name"));
                }
                if reserved && RESERVED_HEADERS.contains(&h.as_str()) {
                    return Err(format!("extAuth.{field}: the {h} header cannot be set from the service's answer"));
                }
                Ok(h)
            })
            .collect()
    };
    Ok(ExtAuthPolicyState {
        target,
        service_namespace: e.backend_ref.namespace.clone().unwrap_or_else(|| namespace.to_string()),
        service_name: e.backend_ref.name.clone(),
        port: e.backend_ref.port,
        path,
        timeout_ms,
        fail_open: e.fail_open,
        request_headers: lower(&e.request_headers, "requestHeaders", false)?,
        response_headers: lower(&e.response_headers, "responseHeaders", true)?,
        generation,
        creation_timestamp: created,
        accepted: true,
    })
}

/// Whether the policy may use its Service (same namespace, or granted).
pub fn reference_permitted(store: &ConfigStore, policy_namespace: &str, state: &ExtAuthPolicyState) -> bool {
    state.service_namespace == policy_namespace
        || is_reference_allowed_from(&store.reference_grants, "portus-gateway.dev", policy_namespace, "ExtAuthPolicy", &state.service_namespace, "Service", Some(&state.service_name))
}

fn programmed_condition(store: &ConfigStore, generation: i64) -> Condition {
    let programmed = store.is_programmed();
    status::build_condition(
        "Programmed",
        programmed,
        if programmed { "Programmed" } else { "NotProgrammed" },
        if programmed { "Configuration programmed in data plane" } else { "Waiting for data plane to apply configuration" },
        generation,
    )
}

/// Core reconciliation logic (pure store manipulation, no async I/O).
pub fn reconcile_inner(policy: &ExtAuthPolicy, store: &ConfigStore) -> Result<Vec<Condition>, ReconcileError> {
    let name = policy.metadata.name.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace =
        policy.metadata.namespace.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let generation = policy.metadata.generation.unwrap_or(0);
    let target_ref = &policy.spec.target_ref;
    let target = PolicyTargetKey {
        group: target_ref.group.clone(),
        kind: target_ref.kind.clone(),
        namespace: namespace.to_string(),
        name: target_ref.name.clone(),
        section_name: target_ref.section_name.clone(),
    };
    let my_key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };

    let state = match validate(&policy.spec, namespace, target.clone(), generation, policy.metadata.creation_timestamp.clone()) {
        Ok(s) => s,
        Err(message) => {
            let rejected = ExtAuthPolicyState {
                target,
                service_namespace: String::new(),
                service_name: String::new(),
                port: 0,
                path: String::new(),
                timeout_ms: 0,
                fail_open: false,
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                generation,
                creation_timestamp: policy.metadata.creation_timestamp.clone(),
                accepted: false,
            };
            store.ext_auth_policies.insert(my_key, rejected);
            store.notify_change();
            return Ok(vec![
                status::build_condition("Accepted", false, "Invalid", &message, generation),
                programmed_condition(store, generation),
            ]);
        }
    };
    let refs = if reference_permitted(store, namespace, &state) {
        status::build_condition("ResolvedRefs", true, "ResolvedRefs", "Authorization Service reference resolved", generation)
    } else {
        let message = format!(
            "Service {}/{} is in another namespace and no ReferenceGrant permits it; every request is refused",
            state.service_namespace, state.service_name
        );
        status::build_condition("ResolvedRefs", false, "RefNotPermitted", &message, generation)
    };
    store.ext_auth_policies.insert(my_key.clone(), state);
    resolve_conflicts(&my_key, &target, &store.ext_auth_policies);
    let accepted = store.ext_auth_policies.get(&my_key).is_some_and(|s| s.accepted);
    let accepted_condition = if accepted {
        status::build_condition("Accepted", true, "Accepted", "Policy accepted", generation)
    } else {
        let winner = find_winner_key(&target, &my_key, &store.ext_auth_policies)
            .map(|k| format!("Older ExtAuthPolicy {k} takes precedence"))
            .unwrap_or_else(|| "Conflicted with another policy".to_string());
        status::build_condition("Accepted", false, "Conflicted", &winner, generation)
    };
    store.notify_change();
    Ok(vec![accepted_condition, refs, programmed_condition(store, generation)])
}

/// Main reconcile function for ExtAuthPolicy resources.
pub async fn reconcile_ext_auth_policy(policy: Arc<ExtAuthPolicy>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.ext_auth_policies,
        "ExtAuthPolicy",
        &policy.metadata,
        || reconcile_inner(&policy, &ctx.store),
    )?;

    let name = policy.metadata.name.as_deref().unwrap_or_default();
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();
    let current_conditions: Vec<Condition> = policy.status.as_ref().map(|s| s.conditions.clone()).unwrap_or_default();
    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1beta1",
        "kind": "ExtAuthPolicy",
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
    let api: Api<ExtAuthPolicy> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(&api, name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write ExtAuthPolicy status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    // Siblings on the same target and data plane acks re-run this policy
    // through the store's events.
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_types::{ExtAuthSpec, PolicyTargetRef, ServiceBackendRef};
    use crate::store::{ReferenceGrantFrom, ReferenceGrantState, ReferenceGrantTo};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_policy(name: &str, ext_auth: ExtAuthSpec) -> ExtAuthPolicy {
        ExtAuthPolicy {
            metadata: ObjectMeta { name: Some(name.to_string()), namespace: Some("apps".to_string()), generation: Some(1), ..Default::default() },
            spec: ExtAuthPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: "web".to_string(),
                    section_name: None,
                },
                ext_auth,
            },
            status: None,
        }
    }

    fn spec(name: &str, namespace: Option<&str>) -> ExtAuthSpec {
        ExtAuthSpec {
            backend_ref: ServiceBackendRef { name: name.to_string(), namespace: namespace.map(str::to_string), port: 4180 },
            path: Some("/oauth2/auth".to_string()),
            response_headers: vec!["X-Auth-Request-User".to_string()],
            ..Default::default()
        }
    }

    fn condition<'a>(conditions: &'a [Condition], type_: &str) -> &'a Condition {
        conditions.iter().find(|c| c.type_ == type_).expect(type_)
    }

    #[test]
    fn a_valid_policy_is_accepted_with_defaults() {
        let store = ConfigStore::new();
        let conditions = reconcile_inner(&make_policy("p", ExtAuthSpec { path: None, ..spec("oauth2-proxy", None) }), &store).unwrap();
        assert_eq!(condition(&conditions, "Accepted").status, "True");
        assert_eq!(condition(&conditions, "ResolvedRefs").status, "True");
        let state = store.ext_auth_policies.iter().next().unwrap().clone();
        assert_eq!((state.service_namespace.as_str(), state.service_name.as_str(), state.port), ("apps", "oauth2-proxy", 4180));
        assert_eq!((state.path.as_str(), state.timeout_ms, state.fail_open), ("/", 1000, false));
        assert_eq!(state.response_headers, vec!["x-auth-request-user".to_string()]);
    }

    #[test]
    fn invalid_specs_are_not_accepted_and_say_why() {
        let cases: Vec<(ExtAuthSpec, &str)> = vec![
            (ExtAuthSpec { backend_ref: ServiceBackendRef { port: 0, ..spec("a", None).backend_ref }, ..spec("a", None) }, "port"),
            (ExtAuthSpec { backend_ref: ServiceBackendRef { name: String::new(), ..spec("a", None).backend_ref }, ..spec("a", None) }, "name is required"),
            (ExtAuthSpec { path: Some("check".into()), ..spec("a", None) }, "must start with /"),
            (ExtAuthSpec { path: Some("/a b".into()), ..spec("a", None) }, "must start with /"),
            (ExtAuthSpec { timeout_ms: Some(0), ..spec("a", None) }, "timeoutMs"),
            (ExtAuthSpec { timeout_ms: Some(120_000), ..spec("a", None) }, "timeoutMs"),
            (ExtAuthSpec { request_headers: vec!["bad header".into()], ..spec("a", None) }, "not a valid header name"),
            (ExtAuthSpec { response_headers: vec!["Host".into()], ..spec("a", None) }, "host header cannot be set"),
        ];
        for (ext_auth, why) in cases {
            let store = ConfigStore::new();
            let conditions = reconcile_inner(&make_policy("p", ext_auth), &store).unwrap();
            let accepted = condition(&conditions, "Accepted");
            assert_eq!((accepted.status.as_str(), accepted.reason.as_str()), ("False", "Invalid"), "{why}");
            assert!(accepted.message.contains(why), "{} should mention {why}", accepted.message);
        }
    }

    #[test]
    fn a_service_in_another_namespace_needs_a_reference_grant() {
        let store = ConfigStore::new();
        let conditions = reconcile_inner(&make_policy("p", spec("oauth2-proxy", Some("auth"))), &store).unwrap();
        assert_eq!(condition(&conditions, "Accepted").status, "True", "the route stays protected");
        let refs = condition(&conditions, "ResolvedRefs");
        assert_eq!((refs.status.as_str(), refs.reason.as_str()), ("False", "RefNotPermitted"));

        store.reference_grants.insert(
            NamespacedName { namespace: "auth".to_string(), name: "allow-apps".to_string() },
            ReferenceGrantState {
                namespace: "auth".to_string(),
                from: vec![ReferenceGrantFrom { group: "portus-gateway.dev".to_string(), kind: "ExtAuthPolicy".to_string(), namespace: "apps".to_string() }],
                to: vec![ReferenceGrantTo { group: String::new(), kind: "Service".to_string(), name: None }],
            },
        );
        let conditions = reconcile_inner(&make_policy("p", spec("oauth2-proxy", Some("auth"))), &store).unwrap();
        assert_eq!(condition(&conditions, "ResolvedRefs").status, "True");

        // A grant naming the Gateway API group is for routes, not this policy.
        store.reference_grants.alter(&NamespacedName { namespace: "auth".to_string(), name: "allow-apps".to_string() }, |_, mut g| {
            g.from[0].group = "gateway.networking.k8s.io".to_string();
            g
        });
        let conditions = reconcile_inner(&make_policy("p", spec("oauth2-proxy", Some("auth"))), &store).unwrap();
        assert_eq!(condition(&conditions, "ResolvedRefs").status, "False");
    }

    #[test]
    fn the_oldest_policy_on_a_target_wins() {
        let store = ConfigStore::new();
        let mut older = make_policy("older", spec("a", None));
        older.metadata.creation_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::from_second(1_000).unwrap()));
        let mut newer = make_policy("newer", spec("b", None));
        newer.metadata.creation_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::from_second(2_000).unwrap()));
        reconcile_inner(&older, &store).unwrap();
        let conditions = reconcile_inner(&newer, &store).unwrap();
        let accepted = condition(&conditions, "Accepted");
        assert_eq!((accepted.status.as_str(), accepted.reason.as_str()), ("False", "Conflicted"));
    }
}
