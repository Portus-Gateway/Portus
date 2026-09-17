//! AIRoute reconciler: bind to Gateway listeners like an HTTPRoute, turn the
//! body-field matches into `portus-body-*` header matches the data plane's
//! scanner satisfies, and point each rule at its provider's synthetic
//! Service.

use std::sync::Arc;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;

use super::http_route::bind_to_parents;
use super::{ReconcileContext, ReconcileError};
use crate::ai_types::{AIRoute, AIRouteMatch, AIStringMatch};
use crate::status;
use crate::store::{
    AIRouteRuleState, AIRouteState, BackendRefState, ConfigStore, HTTPRouteMatchState, NamespacedName, RouteKind,
};

/// Header-match name the data plane resolves from the body's `model`.
pub const MODEL_HEADER: &str = "portus-body-model";
/// Header-match name the data plane resolves from the body's `stream`.
pub const STREAM_HEADER: &str = "portus-body-stream";

/// One AIRoute match as the HTTPRoute-shaped state the compiler consumes.
/// `Err` names the field that could not be converted.
pub fn convert_match(m: &AIRouteMatch) -> Result<HTTPRouteMatchState, String> {
    let path = m.path.as_ref().map(|p| {
        (
            p.value.clone().unwrap_or_else(|| "/".to_string()),
            p.match_type.clone().unwrap_or_else(|| "PathPrefix".to_string()),
        )
    });
    let mut headers: Vec<(String, String, String)> = m
        .headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone(), h.match_type.clone().unwrap_or_else(|| "Exact".to_string())))
        .collect();
    if let Some(model) = &m.model {
        let (value, match_type) = string_match(model)?;
        headers.push((MODEL_HEADER.to_string(), value, match_type));
    }
    if let Some(stream) = m.stream {
        headers.push((STREAM_HEADER.to_string(), stream.to_string(), "Exact".to_string()));
    }
    Ok(HTTPRouteMatchState { path, headers, method: None, query_params: Vec::new() })
}

/// `Exact` and `RegularExpression` map straight onto header match types;
/// `Prefix` becomes an anchored regex on the escaped value.
fn string_match(m: &AIStringMatch) -> Result<(String, String), String> {
    match m.match_type.as_deref().unwrap_or("Exact") {
        "Exact" => Ok((m.value.clone(), "Exact".to_string())),
        "RegularExpression" => {
            regex::Regex::new(&m.value).map_err(|e| format!("model regex {:?}: {e}", m.value))?;
            Ok((m.value.clone(), "RegularExpression".to_string()))
        }
        "Prefix" => Ok((format!("^{}", regex::escape(&m.value)), "RegularExpression".to_string())),
        other => Err(format!("model match type {other:?} is not Exact, Prefix or RegularExpression")),
    }
}

/// Build the route state and its status conditions without touching the API.
pub fn reconcile_inner(route: &AIRoute, store: &ConfigStore) -> Result<(AIRouteState, Vec<Condition>), ReconcileError> {
    let name = route.metadata.name.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.name".into()))?;
    let namespace =
        route.metadata.namespace.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.namespace".into()))?;
    let generation = route.metadata.generation.unwrap_or(0).max(1);

    let route_ns_labels = store.namespace_labels.get(namespace).map(|v| v.value().clone()).unwrap_or_default();
    let parent_refs = bind_to_parents(&route.spec.parent_refs, namespace, &route_ns_labels, &route.spec.hostnames, store);

    let mut rules = Vec::with_capacity(route.spec.rules.len());
    let mut problems: Vec<String> = Vec::new();
    for (i, rule) in route.spec.rules.iter().enumerate() {
        let mut matches = Vec::with_capacity(rule.matches.len());
        for m in &rule.matches {
            match convert_match(m) {
                Ok(state) => matches.push(state),
                Err(e) => problems.push(format!("rule {i}: {e}")),
            }
        }
        // One provider per rule: the upstream TLS name is a route property,
        // so two providers with different hosts cannot share a rule yet.
        let provider_name = match rule.provider_refs.as_slice() {
            [one] => Some(one.name.clone()),
            [] => {
                problems.push(format!("rule {i}: providerRefs is empty"));
                None
            }
            _ => {
                problems.push(format!("rule {i}: one providerRef per rule in this version"));
                None
            }
        };
        let provider = NamespacedName { namespace: namespace.to_string(), name: provider_name.clone().unwrap_or_default() };
        let backend_refs = match provider_name.as_deref().and_then(|_| store.ai_providers.get(&provider)) {
            Some(p) => vec![BackendRefState {
                namespace: namespace.to_string(),
                name: p.service_name(),
                port: p.port,
                weight: 1,
                filters: Vec::new(),
            }],
            None => {
                if let Some(pn) = &provider_name {
                    problems.push(format!("rule {i}: AIProvider {namespace}/{pn} not found or not accepted"));
                }
                Vec::new()
            }
        };
        rules.push(AIRouteRuleState { matches, backend_refs, provider });
    }

    let resolved = problems.is_empty();
    let accepted = parent_refs.iter().any(|p| p.accepted);
    let state = AIRouteState {
        namespace: namespace.to_string(),
        hostnames: route.spec.hostnames.clone(),
        parent_refs,
        rules,
        require_api_key: route.spec.require_api_key,
        generation,
    };

    let reject = state.parent_refs.iter().find_map(|p| p.reject_reason.clone());
    let mut conditions = vec![status::build_condition(
        "Accepted",
        accepted,
        if accepted { "Accepted" } else { reject.as_deref().unwrap_or("NoMatchingParent") },
        if accepted { "Route accepted by a parent listener" } else { "No parent listener accepts this route" },
        generation,
    )];
    let problem_text = problems.join("; ");
    conditions.push(status::build_condition(
        "ResolvedRefs",
        resolved,
        if resolved { "ResolvedRefs" } else { "BackendNotFound" },
        if resolved { "All providers resolved" } else { &problem_text },
        generation,
    ));
    let programmed = accepted && resolved && store.is_programmed();
    conditions.push(status::build_condition(
        "Programmed",
        programmed,
        if programmed { "Programmed" } else { "NotProgrammed" },
        if programmed { "Configuration programmed in data plane" } else { "Waiting for data plane to apply configuration" },
        generation,
    ));
    let _ = name;
    Ok((state, conditions))
}

pub async fn reconcile_ai_route(route: Arc<AIRoute>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    let name = route.metadata.name.as_deref().unwrap_or_default().to_string();
    let namespace = route.metadata.namespace.as_deref().unwrap_or_default().to_string();
    let key = NamespacedName { namespace: namespace.clone(), name: name.clone() };
    if route.metadata.deletion_timestamp.is_some() {
        super::remove_route(&ctx.store, &ctx.store.ai_routes, RouteKind::Ai, &key);
        return Ok(Action::await_change());
    }
    let (state, desired_conditions) = reconcile_inner(&route, &ctx.store)?;
    let resolved = desired_conditions.iter().any(|c| c.type_ == "ResolvedRefs" && c.status == "True");
    super::store_route(&ctx.store, &ctx.store.ai_routes, RouteKind::Ai, key, state);

    let current_conditions: Vec<Condition> = route.status.as_ref().map(|s| s.conditions.clone()).unwrap_or_default();
    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1alpha1",
        "kind": "AIRoute",
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
    let api: Api<AIRoute> = Api::namespaced(ctx.client.clone(), &namespace);
    if let Err(e) = status::patch_status_if_changed(&api, &name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write AIRoute status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    // Providers are not Services, so no store event announces one arriving;
    // an unresolved route polls until its provider shows up.
    Ok(if resolved { Action::await_change() } else { Action::requeue(std::time::Duration::from_secs(15)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_types::{AIProviderRef, AIRouteRule, AIRouteSpec};
    use crate::gateway_types::{HTTPPathMatchCRD, ParentReference};
    use crate::store::{AIProviderState, AllowedRoutesState, GatewayState, ListenerState};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn gateway(store: &ConfigStore) {
        store.gateways.insert(
            NamespacedName { namespace: "llm".into(), name: "gw".into() },
            GatewayState {
                name: "gw".into(),
                namespace: "llm".into(),
                listeners: vec![ListenerState {
                    name: "http".into(),
                    port: 80,
                    protocol: "HTTP".into(),
                    hostname: None,
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState { namespaces_from: "Same".into(), namespace_selector: None },
                    tls_cert_refs: Vec::new(),
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
    }

    fn provider(store: &ConfigStore, name: &str) {
        store.ai_providers.insert(
            NamespacedName { namespace: "llm".into(), name: name.into() },
            AIProviderState {
                namespace: "llm".into(),
                name: name.into(),
                kind: "anthropic".into(),
                tls: true,
                host: "api.anthropic.com".into(),
                port: 443,
                credential: None,
                generation: 1,
            },
        );
    }

    fn route(rules: Vec<AIRouteRule>) -> AIRoute {
        AIRoute {
            metadata: ObjectMeta {
                name: Some("claude".into()),
                namespace: Some("llm".into()),
                generation: Some(3),
                ..Default::default()
            },
            spec: AIRouteSpec {
                parent_refs: vec![ParentReference { name: "gw".into(), ..Default::default() }],
                hostnames: vec!["llm.example.com".into()],
                require_api_key: false,
                rules,
            },
            status: None,
        }
    }

    fn rule(model: Option<AIStringMatch>, stream: Option<bool>, providers: &[&str]) -> AIRouteRule {
        AIRouteRule {
            matches: vec![AIRouteMatch {
                path: Some(HTTPPathMatchCRD { match_type: Some("PathPrefix".into()), value: Some("/v1/messages".into()) }),
                model,
                stream,
                headers: Vec::new(),
            }],
            provider_refs: providers.iter().map(|p| AIProviderRef { name: p.to_string(), weight: None }).collect(),
        }
    }

    #[test]
    fn body_matches_become_portus_body_header_matches_on_the_provider_service() {
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let r = route(vec![
            rule(Some(AIStringMatch { match_type: Some("Prefix".into()), value: "claude-opus".into() }), Some(true), &["anthropic"]),
            rule(Some(AIStringMatch { match_type: None, value: "claude-haiku-4-5".into() }), None, &["anthropic"]),
        ]);
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert!(state.parent_refs[0].accepted);
        assert_eq!(conditions.iter().map(|c| (c.type_.as_str(), c.status.as_str())).collect::<Vec<_>>(), vec![("Accepted", "True"), ("ResolvedRefs", "True"), ("Programmed", "False")]);
        let first = &state.rules[0];
        assert_eq!(first.matches[0].path, Some(("/v1/messages".into(), "PathPrefix".into())));
        assert_eq!(
            first.matches[0].headers,
            vec![
                ("portus-body-model".into(), "^claude\\-opus".into(), "RegularExpression".into()),
                ("portus-body-stream".into(), "true".into(), "Exact".into()),
            ]
        );
        assert_eq!(first.backend_refs[0].name, "aiprovider/llm/anthropic");
        assert_eq!(first.backend_refs[0].port, 443);
        assert_eq!(state.rules[1].matches[0].headers, vec![("portus-body-model".into(), "claude-haiku-4-5".into(), "Exact".into())]);
    }

    #[test]
    fn unknown_providers_and_multiple_providers_fail_resolved_refs_but_keep_the_route() {
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let r = route(vec![rule(None, None, &["nope"]), rule(None, None, &["anthropic", "anthropic"]), rule(None, None, &["anthropic"])]);
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "BackendNotFound");
        assert!(conditions[1].message.contains("llm/nope not found"), "{}", conditions[1].message);
        assert!(conditions[1].message.contains("one providerRef per rule"), "{}", conditions[1].message);
        assert!(state.rules[0].backend_refs.is_empty());
        assert!(state.rules[1].backend_refs.is_empty());
        assert_eq!(state.rules[2].backend_refs.len(), 1, "the good rule still routes");
    }

    #[test]
    fn a_bad_model_regex_is_reported() {
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let r = route(vec![rule(Some(AIStringMatch { match_type: Some("RegularExpression".into()), value: "(".into() }), None, &["anthropic"])]);
        let (_, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "False");
        assert!(conditions[1].message.contains("model regex"), "{}", conditions[1].message);
    }
}
