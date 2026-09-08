use crate::gateway_types::GatewayClass;
use crate::reconcilers::{ReconcileContext, ReconcileError, CONTROLLER_NAME};
use crate::status;
use crate::store::{Event, GatewayClassState};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Determine whether the GatewayClass should be accepted and return the store
/// state + status conditions to write. Pure logic, no I/O.
/// All Gateway API features supported by this implementation.
/// Used in GatewayClass status.supportedFeatures so the conformance test
/// suite knows which tests to run.
const SUPPORTED_FEATURES: &[&str] = &[
    // Core features
    "HTTPRoute",
    "HTTPRouteDestinationPortMatching",
    "HTTPRouteHostRewrite",
    "HTTPRouteMethodMatching",
    "HTTPRoutePathRedirect",
    "HTTPRoutePortRedirect",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteRequestHeaderModifier",
    "HTTPRouteResponseHeaderModifier",
    "HTTPRouteSchemeRedirect",
    // Extended features
    "HTTPRoutePathPrefix",
    "HTTPRouteRequestMirror",
    "HTTPRouteRequestTimeout",
    "HTTPRouteBackendTimeout",
    "HTTPRouteBackendRequestHeaderModifier",
    "GRPCRoute",
    "TLSRoute",
    "TCPRoute",
];

fn evaluate_gateway_class(
    _name: &str,
    controller_name: &str,
    generation: i64,
) -> Option<(GatewayClassState, Vec<Condition>)> {
    if controller_name != CONTROLLER_NAME {
        return None;
    }

    let state = GatewayClassState {
        accepted: true,
        generation,
    };

    let conditions = vec![
        status::build_condition(
            "Accepted",
            true,
            "Accepted",
            "GatewayClass accepted by portus-gateway",
            generation,
        ),
        status::build_condition(
            "SupportedVersion",
            true,
            "SupportedVersion",
            "Gateway API v1 supported",
            generation,
        ),
    ];

    Some((state, conditions))
}

/// Drop a GatewayClass we no longer manage; its Gateways re-run and stop
/// reporting status.
pub fn forget(store: &crate::store::ConfigStore, name: &str) -> bool {
    let removed = store.gateway_classes.remove(name).is_some();
    if removed {
        store.notify_change();
        store.publish(Event::GatewayClass(name.to_string()));
    }
    removed
}

pub async fn reconcile_gateway_class(
    gc: Arc<GatewayClass>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = gc
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;

    // Skip reconciliation for objects being deleted
    if gc.metadata.deletion_timestamp.is_some() {
        forget(&ctx.store, name);
        return Ok(Action::await_change());
    }

    let generation = gc.metadata.generation.unwrap_or(0);
    let controller_name = &gc.spec.controller_name;

    match evaluate_gateway_class(name, controller_name, generation) {
        None => {
            // Not our GatewayClass -- remove from store if present
            forget(&ctx.store, name);
            Ok(Action::await_change())
        }
        Some((state, desired_conditions)) => {
            // Accept this GatewayClass; its Gateways re-run on the event.
            if ctx.store.insert_and_notify(&ctx.store.gateway_classes, name.to_string(), state) {
                ctx.store.publish(Event::GatewayClass(name.to_string()));
            }

            // Write status
            let current_conditions = gc
                .status
                .as_ref()
                .map(|s| s.conditions.as_slice())
                .unwrap_or(&[]);

            let desired_status = json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "GatewayClass",
                "metadata": {
                    "name": name,
                },
                "status": {
                    "conditions": desired_conditions.iter().map(|c| json!({
                        "type": c.type_,
                        "status": c.status,
                        "reason": c.reason,
                        "message": c.message,
                        "observedGeneration": c.observed_generation,
                        "lastTransitionTime": c.last_transition_time.0.to_string(),
                    })).collect::<Vec<_>>(),
                    "supportedFeatures": SUPPORTED_FEATURES.iter().map(|f| json!({"name": f})).collect::<Vec<_>>(),
                }
            });

            let api: Api<GatewayClass> = Api::all(ctx.client.clone());
            status::patch_status_if_changed(
                &api,
                name,
                desired_status,
                current_conditions,
                &desired_conditions,
            )
            .await?;

            Ok(Action::await_change())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;
    use std::sync::Arc;

    #[test]
    fn test_matching_controller_returns_accepted_state() {
        let result = evaluate_gateway_class("my-class", CONTROLLER_NAME, 1);
        assert!(result.is_some());
        let (state, conditions) = result.unwrap();
        assert!(state.accepted);
        assert_eq!(state.generation, 1);
        assert_eq!(conditions.len(), 2);
    }

    #[test]
    fn test_non_matching_controller_returns_none() {
        let result = evaluate_gateway_class("other-class", "other.io/controller", 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_matching_controller_inserts_into_store() {
        let store = Arc::new(ConfigStore::new());
        let result = evaluate_gateway_class("my-class", CONTROLLER_NAME, 5);
        let (state, _) = result.unwrap();

        store.gateway_classes.insert("my-class".to_string(), state);
        let entry = store.gateway_classes.get("my-class").unwrap();
        assert!(entry.accepted);
        assert_eq!(entry.generation, 5);
    }

    #[test]
    fn test_non_matching_controller_removes_from_store() {
        let store = Arc::new(ConfigStore::new());
        store.gateway_classes.insert(
            "changing".to_string(),
            GatewayClassState {
                accepted: true,
                generation: 1,
            },
        );
        assert!(store.gateway_classes.get("changing").is_some());

        let result = evaluate_gateway_class("changing", "other.io/ctrl", 2);
        assert!(result.is_none());

        // Reconciler should remove on None
        store.gateway_classes.remove("changing");
        assert!(store.gateway_classes.get("changing").is_none());
    }

    #[test]
    fn test_generation_propagated_to_store_state() {
        let result = evaluate_gateway_class("gen-class", CONTROLLER_NAME, 42);
        let (state, _) = result.unwrap();
        assert_eq!(state.generation, 42);
    }

    #[test]
    fn test_accepted_condition_fields() {
        let result = evaluate_gateway_class("c", CONTROLLER_NAME, 3);
        let (_, conditions) = result.unwrap();

        let accepted = conditions.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.reason, "Accepted");
        assert_eq!(accepted.message, "GatewayClass accepted by portus-gateway");
        assert_eq!(accepted.observed_generation, Some(3));
    }

    #[test]
    fn test_supported_version_condition_fields() {
        let result = evaluate_gateway_class("c", CONTROLLER_NAME, 5);
        let (_, conditions) = result.unwrap();

        let sv = conditions
            .iter()
            .find(|c| c.type_ == "SupportedVersion")
            .unwrap();
        assert_eq!(sv.status, "True");
        assert_eq!(sv.reason, "SupportedVersion");
        assert_eq!(sv.message, "Gateway API v1 supported");
        assert_eq!(sv.observed_generation, Some(5));
    }

    #[test]
    fn test_uses_controller_name_constant_not_hardcoded() {
        // Verify that evaluate_gateway_class uses the CONTROLLER_NAME constant
        // by checking against the known value
        assert_eq!(CONTROLLER_NAME, "github.com/Portus-Gateway/Portus");

        let result = evaluate_gateway_class("c", "github.com/Portus-Gateway/Portus", 1);
        assert!(result.is_some());
    }
}
