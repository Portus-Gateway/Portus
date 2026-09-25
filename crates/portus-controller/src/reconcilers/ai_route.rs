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
    AIJwtState, AIOnBehalfOfState, AIRouteRuleState, AIRouteState, BackendRefState, ConfigStore, HTTPFilterState, HTTPRouteMatchState,
    NamespacedName, RouteKind,
};

/// Header-match name the data plane resolves from the body's `model`.
pub const MODEL_HEADER: &str = "portus-body-model";
/// Header-match name the data plane resolves from the body's `stream`.
pub const STREAM_HEADER: &str = "portus-body-stream";
/// Header-match name the data plane resolves from a JSON-RPC body's `method`.
pub const METHOD_HEADER: &str = "portus-body-method";
/// Header-match name the data plane resolves from `params.name` of a
/// JSON-RPC `tools/call`.
pub const TOOL_HEADER: &str = "portus-body-tool";

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
    // A request speaks one dialect: LLM fields and MCP fields never both apply.
    let llm = m.model.is_some() || m.stream.is_some();
    let mcp = m.method.is_some() || m.tool.is_some();
    if llm && mcp {
        return Err("a match cannot combine model/stream with method/tool".to_string());
    }
    if let Some(model) = &m.model {
        let (value, match_type) = string_match("model", model)?;
        headers.push((MODEL_HEADER.to_string(), value, match_type));
    }
    if let Some(stream) = m.stream {
        headers.push((STREAM_HEADER.to_string(), stream.to_string(), "Exact".to_string()));
    }
    if let Some(method) = &m.method {
        let (value, match_type) = string_match("method", method)?;
        headers.push((METHOD_HEADER.to_string(), value, match_type));
    }
    if let Some(tool) = &m.tool {
        let (value, match_type) = string_match("tool", tool)?;
        headers.push((TOOL_HEADER.to_string(), value, match_type));
    }
    Ok(HTTPRouteMatchState { path, headers, method: None, query_params: Vec::new() })
}

/// `Exact` and `RegularExpression` map straight onto header match types;
/// `Prefix` becomes an anchored regex on the escaped value.
fn string_match(field: &str, m: &AIStringMatch) -> Result<(String, String), String> {
    match m.match_type.as_deref().unwrap_or("Exact") {
        "Exact" => Ok((m.value.clone(), "Exact".to_string())),
        "RegularExpression" => {
            regex::Regex::new(&m.value).map_err(|e| format!("{field} regex {:?}: {e}", m.value))?;
            Ok((m.value.clone(), "RegularExpression".to_string()))
        }
        "Prefix" => Ok((format!("^{}", regex::escape(&m.value)), "RegularExpression".to_string())),
        other => Err(format!("{field} match type {other:?} is not Exact, Prefix or RegularExpression")),
    }
}

/// `auth.jwt` normalised: an `https://` (or `http://`) issuer without a
/// trailing slash, claim names defaulted to `groups` and `scope`.
pub fn jwt_state(spec: &crate::ai_types::AIJwtSpec) -> Result<AIJwtState, String> {
    let issuer = spec.issuer.trim().trim_end_matches('/');
    if !(issuer.starts_with("https://") || issuer.starts_with("http://")) || issuer.len() < 9 {
        return Err(format!("issuer {:?} must be an https:// URL", spec.issuer));
    }
    let claim = |v: &Option<String>, default: &str| -> Result<String, String> {
        let c = v.as_deref().map(str::trim).unwrap_or(default);
        if c.is_empty() || c.contains(|ch: char| ch.is_whitespace()) {
            return Err(format!("claim name {c:?} is invalid"));
        }
        Ok(c.to_string())
    };
    let scopes: Vec<String> = match &spec.scopes {
        Some(list) => list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        None => ["openid", "profile", "email", "groups"].iter().map(|s| s.to_string()).collect(),
    };
    if scopes.iter().any(|s| s.contains(|ch: char| ch.is_whitespace() || ch == '"')) {
        return Err("scopes must not contain whitespace or quotes".to_string());
    }
    let tools_by_group: Vec<(String, Vec<String>)> = spec
        .tools_by_group
        .iter()
        .flatten()
        .map(|(g, tools)| (g.trim().to_string(), tools.iter().map(|t| t.trim()).filter(|t| !t.is_empty()).map(str::to_string).collect::<Vec<_>>()))
        .collect();
    if tools_by_group.iter().any(|(g, _)| g.is_empty()) {
        return Err("toolsByGroup has an empty group name".to_string());
    }
    Ok(AIJwtState {
        issuer: issuer.to_string(),
        audience: spec.audience.as_deref().map(str::trim).filter(|a| !a.is_empty()).map(str::to_string),
        tenant_claim: claim(&spec.tenant_claim, "groups")?,
        tools_claim: claim(&spec.tools_claim, "scope")?,
        scopes: scopes.join(" "),
        groups_claim: claim(&spec.groups_claim, "groups")?,
        tools_by_group,
    })
}

/// `auth.onBehalfOf` normalised: a lower-case header name (default
/// `x-portus-on-behalf-of`) and at least one trusted key.
pub fn on_behalf_of_state(spec: &crate::ai_types::AIOnBehalfOfSpec) -> Result<AIOnBehalfOfState, String> {
    let header = spec.header.as_deref().map(str::trim).filter(|h| !h.is_empty()).unwrap_or("x-portus-on-behalf-of").to_ascii_lowercase();
    // RFC 7230 token characters; what the data plane's header map accepts.
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if header.is_empty() || !header.chars().all(token) {
        return Err(format!("header {header:?} is not a valid header name"));
    }
    let trusted_keys: Vec<String> = spec.trusted_keys.iter().map(|k| k.trim()).filter(|k| !k.is_empty()).map(str::to_string).collect();
    if trusted_keys.is_empty() {
        return Err("trustedKeys must name at least one key (name, tenant/name, tenant/* or label:key=value)".to_string());
    }
    for k in &trusted_keys {
        trusted_key_form(k)?;
    }
    Ok(AIOnBehalfOfState { header, trusted_keys })
}

/// One `trustedKeys` entry is `name`, `tenant/name`, `tenant/*` or
/// `label:key=value`. A bare `*` or `*/…` would trust every key and is
/// refused: an agent could then name any user.
fn trusted_key_form(k: &str) -> Result<(), String> {
    if let Some(label) = k.strip_prefix("label:") {
        return match label.split_once('=') {
            Some((key, _)) if !key.is_empty() => Ok(()),
            _ => Err(format!("trustedKeys entry {k:?} must be label:key=value")),
        };
    }
    let wildcard_all = k == "*" || k.starts_with("*/");
    let bad = match k.split_once('/') {
        Some((tenant, name)) => tenant.is_empty() || name.is_empty() || (name.contains('*') && name != "*") || name.contains('/'),
        None => k.contains('*'),
    };
    if wildcard_all || bad {
        return Err(format!("trustedKeys entry {k:?} must be name, tenant/name, tenant/* or label:key=value"));
    }
    Ok(())
}

/// A rule's `urlRewrite` as the HTTPRoute filter state the compiler consumes.
pub fn rewrite_filter(rw: &crate::ai_types::AIUrlRewrite) -> Result<HTTPFilterState, String> {
    let Some(pm) = rw.path.as_ref() else { return Err("urlRewrite.path is required".to_string()) };
    let (path, path_type) = match pm.modifier_type.as_deref().unwrap_or("") {
        "ReplaceFullPath" => (pm.replace_full_path.clone().ok_or("urlRewrite.path.replaceFullPath is required for ReplaceFullPath")?, "ReplaceFullPath"),
        "ReplacePrefixMatch" => (pm.replace_prefix_match.clone().ok_or("urlRewrite.path.replacePrefixMatch is required for ReplacePrefixMatch")?, "ReplacePrefixMatch"),
        other => return Err(format!("urlRewrite.path.type {other:?} is not ReplaceFullPath or ReplacePrefixMatch")),
    };
    if !path.starts_with('/') {
        return Err(format!("urlRewrite path {path:?} must start with /"));
    }
    Ok(HTTPFilterState::URLRewrite { hostname: None, path: Some(path), path_type: Some(path_type.to_string()) })
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
        let filters = match rule.url_rewrite.as_ref().map(rewrite_filter) {
            Some(Ok(f)) => vec![f],
            Some(Err(e)) => {
                problems.push(format!("rule {i}: {e}"));
                Vec::new()
            }
            None => Vec::new(),
        };
        rules.push(AIRouteRuleState { matches, backend_refs, provider, filters });
    }

    let jwt = match route.spec.auth.as_ref().and_then(|a| a.jwt.as_ref()) {
        Some(j) => match jwt_state(j) {
            Ok(state) => Some(state),
            Err(e) => {
                problems.push(format!("auth.jwt: {e}"));
                None
            }
        },
        None => None,
    };
    let on_behalf_of = match route.spec.auth.as_ref().and_then(|a| a.on_behalf_of.as_ref()) {
        Some(o) => match on_behalf_of_state(o) {
            Ok(state) => Some(state),
            Err(e) => {
                problems.push(format!("auth.onBehalfOf: {e}"));
                None
            }
        },
        None => None,
    };
    let resolved = problems.is_empty();
    let accepted = parent_refs.iter().any(|p| p.accepted);
    let state = AIRouteState {
        namespace: namespace.to_string(),
        hostnames: route.spec.hostnames.clone(),
        parent_refs,
        rules,
        require_api_key: route.spec.require_api_key,
        jwt,
        on_behalf_of,
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
                session_affinity: false,
                members: Vec::new(),
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
                auth: None,
                rules,
            },
            status: None,
        }
    }

    #[test]
    fn auth_jwt_is_normalised_onto_the_route_and_bad_issuers_are_reported() {
        use crate::ai_types::{AIJwtSpec, AIRouteAuth};
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let mut r = route(vec![rule(None, None, &["anthropic"])]);
        r.spec.require_api_key = true;
        r.spec.auth = Some(AIRouteAuth { jwt: Some(AIJwtSpec { issuer: "https://dex.example.com/".into(), audience: Some("portus".into()), tenant_claim: None, tools_claim: Some("tools".into()), scopes: None, groups_claim: None, tools_by_group: None }), on_behalf_of: None });
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "True", "{}", conditions[1].message);
        assert_eq!(state.jwt, Some(AIJwtState { issuer: "https://dex.example.com".into(), audience: Some("portus".into()), tenant_claim: "groups".into(), tools_claim: "tools".into(), scopes: "openid profile email groups".into(), groups_claim: "groups".into(), tools_by_group: Vec::new() }));
        // Group map: trimmed, sorted by group, empty tool names dropped.
        let mut map = std::collections::BTreeMap::new();
        map.insert("ops".to_string(), vec!["fleet_report".to_string(), " ".to_string()]);
        map.insert("eng".to_string(), vec!["github.*".to_string()]);
        r.spec.auth = Some(AIRouteAuth { jwt: Some(AIJwtSpec { issuer: "https://dex.example.com".into(), audience: None, tenant_claim: None, tools_claim: None, scopes: None, groups_claim: Some("roles".into()), tools_by_group: Some(map) }), on_behalf_of: None });
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "True", "{}", conditions[1].message);
        let j = state.jwt.unwrap();
        assert_eq!(j.groups_claim, "roles");
        assert_eq!(j.tools_by_group, vec![("eng".to_string(), vec!["github.*".to_string()]), ("ops".to_string(), vec!["fleet_report".to_string()])]);
        r.spec.auth = Some(AIRouteAuth { jwt: Some(AIJwtSpec { issuer: "https://dex.example.com".into(), audience: None, tenant_claim: None, tools_claim: None, scopes: Some(vec!["openid".into(), "email".into(), "federated:id".into()]), groups_claim: None, tools_by_group: None }), on_behalf_of: None });
        let (state, _) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(state.jwt.unwrap().scopes, "openid email federated:id");
        r.spec.auth = Some(AIRouteAuth { jwt: Some(AIJwtSpec { issuer: "dex.example.com".into(), audience: None, tenant_claim: None, tools_claim: None, scopes: None, groups_claim: None, tools_by_group: None }), on_behalf_of: None });
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "False");
        assert!(conditions[1].message.contains("auth.jwt"), "{}", conditions[1].message);
        assert!(state.jwt.is_none());
    }

    #[test]
    fn on_behalf_of_needs_trusted_keys_and_lands_lower_cased_on_the_route() {
        use crate::ai_types::{AIOnBehalfOfSpec, AIRouteAuth};
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let mut r = route(vec![rule(None, None, &["anthropic"])]);
        r.spec.require_api_key = true;
        r.spec.auth = Some(AIRouteAuth { jwt: None, on_behalf_of: Some(AIOnBehalfOfSpec { header: Some("X-Acting-User".into()), trusted_keys: vec!["team-a/hub".into(), " ".into(), "orchestrator".into()] }) });
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "True", "{}", conditions[1].message);
        assert_eq!(state.on_behalf_of, Some(AIOnBehalfOfState { header: "x-acting-user".into(), trusted_keys: vec!["team-a/hub".into(), "orchestrator".into()] }));
        r.spec.auth = Some(AIRouteAuth { jwt: None, on_behalf_of: Some(AIOnBehalfOfSpec { header: None, trusted_keys: vec!["hub".into()] }) });
        let (state, _) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(state.on_behalf_of.unwrap().header, "x-portus-on-behalf-of", "default header");
        r.spec.auth = Some(AIRouteAuth { jwt: None, on_behalf_of: Some(AIOnBehalfOfSpec { header: None, trusted_keys: vec![] }) });
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "False");
        assert!(conditions[1].message.contains("trustedKeys"), "{}", conditions[1].message);
        assert!(state.on_behalf_of.is_none(), "nobody is trusted by default");
        r.spec.auth = Some(AIRouteAuth { jwt: None, on_behalf_of: Some(AIOnBehalfOfSpec { header: Some("bad header".into()), trusted_keys: vec!["hub".into()] }) });
        let (_, conditions) = reconcile_inner(&r, &store).unwrap();
        assert!(conditions[1].message.contains("header"), "{}", conditions[1].message);
    }

    #[test]
    fn trusted_keys_take_tenant_wildcards_and_labels_but_never_everyone() {
        for ok in ["hub", "team-a/hub", "team-a/*", "label:role=hub", "label:owner="] {
            assert!(trusted_key_form(ok).is_ok(), "{ok}");
        }
        for bad in ["*", "*/*", "*/hub", "/hub", "team-a/", "team-a/h*", "h*", "label:role", "label:=x", "a/b/c"] {
            assert!(trusted_key_form(bad).is_err(), "{bad}");
        }
        let spec = crate::ai_types::AIOnBehalfOfSpec { header: None, trusted_keys: vec!["team-a/*".into(), "*".into()] };
        assert!(on_behalf_of_state(&spec).unwrap_err().contains("\"*\""), "one bad entry fails the lot");
    }

    #[test]
    fn a_rule_url_rewrite_becomes_the_http_route_filter_and_bad_ones_are_reported() {
        use crate::ai_types::AIUrlRewrite;
        use crate::gateway_types::HTTPPathModifierCRD;
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let mut good = rule(None, None, &["anthropic"]);
        good.url_rewrite = Some(AIUrlRewrite { path: Some(HTTPPathModifierCRD { modifier_type: Some("ReplaceFullPath".into()), replace_full_path: Some("/mcp".into()), replace_prefix_match: None }) });
        let mut prefix = rule(None, None, &["anthropic"]);
        prefix.url_rewrite = Some(AIUrlRewrite { path: Some(HTTPPathModifierCRD { modifier_type: Some("ReplacePrefixMatch".into()), replace_full_path: None, replace_prefix_match: Some("/".into()) }) });
        let (state, conditions) = reconcile_inner(&route(vec![good, prefix]), &store).unwrap();
        assert_eq!(conditions[1].status, "True", "{}", conditions[1].message);
        assert_eq!(state.rules[0].filters, vec![HTTPFilterState::URLRewrite { hostname: None, path: Some("/mcp".into()), path_type: Some("ReplaceFullPath".into()) }]);
        assert_eq!(state.rules[1].filters, vec![HTTPFilterState::URLRewrite { hostname: None, path: Some("/".into()), path_type: Some("ReplacePrefixMatch".into()) }]);
        let mut bad = rule(None, None, &["anthropic"]);
        bad.url_rewrite = Some(AIUrlRewrite { path: Some(HTTPPathModifierCRD { modifier_type: Some("ReplaceFullPath".into()), replace_full_path: Some("mcp".into()), replace_prefix_match: None }) });
        let mut missing = rule(None, None, &["anthropic"]);
        missing.url_rewrite = Some(AIUrlRewrite { path: Some(HTTPPathModifierCRD { modifier_type: Some("ReplacePrefixMatch".into()), replace_full_path: None, replace_prefix_match: None }) });
        let (state, conditions) = reconcile_inner(&route(vec![bad, missing]), &store).unwrap();
        assert_eq!(conditions[1].status, "False");
        assert!(conditions[1].message.contains("must start with /") && conditions[1].message.contains("replacePrefixMatch is required"), "{}", conditions[1].message);
        assert!(state.rules.iter().all(|r| r.filters.is_empty()));
    }

    fn rule(model: Option<AIStringMatch>, stream: Option<bool>, providers: &[&str]) -> AIRouteRule {
        AIRouteRule {
            matches: vec![AIRouteMatch {
                path: Some(HTTPPathMatchCRD { match_type: Some("PathPrefix".into()), value: Some("/v1/messages".into()) }),
                model,
                stream,
                method: None,
                tool: None,
                headers: Vec::new(),
            }],
            provider_refs: providers.iter().map(|p| AIProviderRef { name: p.to_string(), weight: None }).collect(),
            url_rewrite: None,
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
    fn mcp_method_and_tool_matches_become_body_header_matches_and_never_mix_with_model() {
        let store = ConfigStore::new();
        gateway(&store);
        provider(&store, "anthropic");
        let m = |method: Option<(&str, &str)>, tool: Option<(&str, &str)>, model: Option<&str>| AIRouteMatch {
            path: Some(HTTPPathMatchCRD { match_type: Some("PathPrefix".into()), value: Some("/mcp".into()) }),
            model: model.map(|v| AIStringMatch { match_type: None, value: v.into() }),
            stream: None,
            method: method.map(|(t, v)| AIStringMatch { match_type: Some(t.into()), value: v.into() }),
            tool: tool.map(|(t, v)| AIStringMatch { match_type: Some(t.into()), value: v.into() }),
            headers: Vec::new(),
        };
        let call = convert_match(&m(Some(("Exact", "tools/call")), Some(("Prefix", "github.")), None)).unwrap();
        assert_eq!(
            call.headers,
            vec![
                ("portus-body-method".into(), "tools/call".into(), "Exact".into()),
                ("portus-body-tool".into(), "^github\\.".into(), "RegularExpression".into()),
            ]
        );
        let list = convert_match(&m(Some(("Exact", "tools/list")), None, None)).unwrap();
        assert_eq!(list.headers, vec![("portus-body-method".into(), "tools/list".into(), "Exact".into())]);
        let mixed = convert_match(&m(Some(("Exact", "tools/call")), None, Some("claude-opus-5")));
        assert!(mixed.unwrap_err().contains("cannot combine"));
        let bad = convert_match(&m(None, Some(("RegularExpression", "(")), None));
        assert!(bad.unwrap_err().contains("tool regex"));

        // Through the reconciler the rule lands on the provider's Service like an LLM rule.
        let r = route(vec![AIRouteRule {
            matches: vec![m(Some(("Exact", "tools/call")), Some(("Exact", "github.search")), None)],
            provider_refs: vec![AIProviderRef { name: "anthropic".into(), weight: None }],
            url_rewrite: None,
        }]);
        let (state, conditions) = reconcile_inner(&r, &store).unwrap();
        assert_eq!(conditions[1].status, "True", "{}", conditions[1].message);
        assert_eq!(state.rules[0].backend_refs[0].name, "aiprovider/llm/anthropic");
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
