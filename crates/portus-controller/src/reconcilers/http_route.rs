//! HTTPRoute reconciler with Core + Extended matches and filters.
//!
//! Converts HTTPRoute resources into HTTPRouteState in ConfigStore.
//! Supports Core match types (path Prefix/Exact, headers Exact, method, query
//! params Exact), Extended match types (RegularExpression path/headers),
//! Core filter types (RequestHeaderModifier, ResponseHeaderModifier,
//! RequestRedirect, URLRewrite), and Extended filter types (RequestMirror).
//!
//! Also handles per-route timeouts (request + backendRequest) and weighted
//! backend refs.
//!
//! Uses shared `is_reference_allowed` from mod.rs for cross-namespace backend
//! ref checking. Does NOT re-define it locally.
//!
//! Uses CRD types from gateway_types.rs (kube-derived) for kube-rs Controller
//! compatibility.

use super::{hostname_matches, is_reference_allowed, ReconcileContext, ReconcileError, CONTROLLER_NAME};
use crate::gateway_types::{
    HTTPBackendRef, HTTPRoute, HTTPRouteFilterCRD, HTTPRouteMatchCRD, ParentReference,
};
use crate::status;
use crate::store::{
    BackendRefState, ConfigStore, HTTPFilterState, HTTPRouteMatchState, HTTPRouteRuleState,
    HTTPRouteState, NamespacedName, ParentKind, ParentRefState, RouteKind, RouteRetryState,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Reconciler functions
// ---------------------------------------------------------------------------

/// Validate parentRef bindings against Gateway listeners in the store.
///
/// For each parentRef, checks:
/// - Gateway exists in store
/// - sectionName matches a listener (if specified)
/// - Listener protocol accepts HTTPRoute (HTTP or HTTPS)
/// - Route namespace is allowed by listener's allowedRoutes
/// - Route hostnames are compatible with listener hostname
fn bind_to_parents(
    parent_refs: &[ParentReference],
    route_namespace: &str,
    route_ns_labels: &std::collections::BTreeMap<String, String>,
    route_hostnames: &[String],
    store: &ConfigStore,
) -> Vec<ParentRefState> {
    let mut results = Vec::new();

    for pref in parent_refs {
        let group = pref
            .group
            .as_deref()
            .unwrap_or("gateway.networking.k8s.io");
        let kind = pref.kind.as_deref().unwrap_or("Gateway");
        if group != "gateway.networking.k8s.io" {
            continue;
        }
        if kind != "Gateway" && kind != "ListenerSet" {
            continue;
        }

        let parent_kind = if kind == "ListenerSet" {
            ParentKind::ListenerSet
        } else {
            ParentKind::Gateway
        };

        let parent_namespace = pref.namespace.as_deref().unwrap_or(route_namespace);
        let parent_name = &pref.name;
        let parent_key = NamespacedName {
            namespace: parent_namespace.to_string(),
            name: parent_name.to_string(),
        };

        // For ListenerSet parents: resolve via store.listener_sets. The
        // ListenerSet must be accepted (its parent Gateway must exist and
        // allow attachment) for routes to bind.
        let (gw_namespace, gw_name, gw_listeners, gw_ns_for_allowedroutes, parent_accepted_reject) =
            if parent_kind == ParentKind::ListenerSet {
                let ls = match store.listener_sets.get(&parent_key) {
                    Some(ls) => ls.clone(),
                    None => {
                        results.push(ParentRefState {
                            parent_kind,
                            gateway_namespace: parent_namespace.to_string(),
                            gateway_name: parent_name.to_string(),
                            section_name: pref.section_name.clone(),
                            port: pref.port,
                            accepted: false,
                            resolved_refs: false,
                            reject_reason: Some("NoMatchingParent".to_string()),
                        });
                        continue;
                    }
                };
                if !ls.accepted {
                    results.push(ParentRefState {
                        parent_kind,
                        gateway_namespace: parent_namespace.to_string(),
                        gateway_name: parent_name.to_string(),
                        section_name: pref.section_name.clone(),
                        port: pref.port,
                        accepted: false,
                        resolved_refs: true,
                        reject_reason: ls.not_accepted_reason.clone().or_else(|| Some("NotAllowed".to_string())),
                    });
                    continue;
                }
                // The ListenerSet's parent Gateway is the namespace owner for
                // allowedRoutes checks. Look it up for its namespace (in case
                // ls.parent_gateway's namespace differs from route namespace).
                let gw_namespace = ls.parent_gateway.namespace.clone();
                (
                    ls.namespace.clone(),
                    ls.name.clone(),
                    ls.listeners.clone(),
                    gw_namespace,
                    None::<String>,
                )
            } else {
                let gw = match store.gateways.get(&parent_key) {
                    Some(gw) => gw.clone(),
                    None => {
                        results.push(ParentRefState {
                            parent_kind,
                            gateway_namespace: parent_namespace.to_string(),
                            gateway_name: parent_name.to_string(),
                            section_name: pref.section_name.clone(),
                            port: pref.port,
                            accepted: false,
                            resolved_refs: false,
                            reject_reason: Some("NoMatchingParent".to_string()),
                        });
                        continue;
                    }
                };
                (
                    gw.namespace.clone(),
                    gw.name.clone(),
                    gw.listeners.clone(),
                    gw.namespace.clone(),
                    None,
                )
            };
        let _ = parent_accepted_reject;

        // Build a Gateway-shaped view so existing matching logic below applies.
        let gw = crate::store::GatewayState {
            name: gw_name.clone(),
            namespace: gw_namespace.clone(),
            listeners: gw_listeners,
            generation: 0,
            allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        };
        let _ = gw_ns_for_allowedroutes;

        // Determine which listeners to check based on sectionName and port
        let listeners_to_check: Vec<_> = if let Some(ref section) = pref.section_name {
            match gw.listeners.iter().find(|l| l.name == *section) {
                Some(l) => vec![l],
                None => {
                    // sectionName does not match any listener — per Gateway API
                    // conformance, this is NoMatchingParent (not NotAllowedByListeners)
                    results.push(ParentRefState {
                        parent_kind,
                        gateway_namespace: parent_namespace.to_string(),
                        gateway_name: parent_name.to_string(),
                        section_name: pref.section_name.clone(),
                        port: pref.port,
                        accepted: false,
                        resolved_refs: true,
                        reject_reason: Some("NoMatchingParent".to_string()),
                    });
                    continue;
                }
            }
        } else {
            gw.listeners.iter().collect()
        };

        // If parentRef specifies a port, check that at least one listener
        // matches it. If no listener has the requested port, reject with
        // NoMatchingParent before doing protocol/hostname/namespace checks.
        if let Some(requested_port) = pref.port
            && !listeners_to_check.iter().any(|l| l.port == requested_port) {
                results.push(ParentRefState {
                    parent_kind,
                    gateway_namespace: parent_namespace.to_string(),
                    gateway_name: parent_name.to_string(),
                    section_name: pref.section_name.clone(),
                    port: pref.port,
                    accepted: false,
                    resolved_refs: true,
                    reject_reason: Some("NoMatchingParent".to_string()),
                });
                continue;
            }

        let mut accepted = false;
        let mut has_protocol_match = false;
        let mut has_hostname_match = false;
        for listener in &listeners_to_check {
            // Port filter: if parentRef specifies a port, skip non-matching listeners
            if let Some(requested_port) = pref.port
                && listener.port != requested_port {
                    continue;
                }

            // Protocol check: HTTPRoute binds to HTTP or HTTPS listeners only
            if listener.protocol != "HTTP" && listener.protocol != "HTTPS" {
                continue;
            }
            has_protocol_match = true;

            // Hostname compatibility
            if !hostnames_compatible(&listener.hostname, route_hostnames) {
                continue;
            }
            has_hostname_match = true;

            // AllowedRoutes namespace check
            if !namespace_allowed(
                &listener.allowed_routes,
                route_namespace,
                &gw.namespace,
                route_ns_labels,
            ) {
                continue;
            }

            accepted = true;
            break;
        }

        // Determine rejection reason for status
        let reject_reason = if !accepted {
            if has_protocol_match && !has_hostname_match {
                "NoMatchingListenerHostname"
            } else {
                "NotAllowedByListeners"
            }
        } else {
            ""
        };
        results.push(ParentRefState {
            parent_kind,
            gateway_namespace: parent_namespace.to_string(),
            gateway_name: parent_name.to_string(),
            section_name: pref.section_name.clone(),
            port: pref.port,
            accepted,
            resolved_refs: true, // updated per-rule later
            reject_reason: if accepted { None } else { Some(reject_reason.to_string()) },
        });
    }

    results
}

/// Check if route hostnames are compatible with a listener hostname.
pub(crate) fn hostnames_compatible(listener_hostname: &Option<String>, route_hostnames: &[String]) -> bool {
    let listener_host = match listener_hostname {
        Some(h) => h,
        None => return true, // no restriction on listener
    };

    if route_hostnames.is_empty() {
        return true; // route matches any listener
    }

    for rh in route_hostnames {
        if hostname_matches(listener_host, rh) {
            return true;
        }
    }

    false
}

/// Check if route namespace is allowed by listener's allowedRoutes policy.
///
/// `route_ns_labels` is the label map of the route's own namespace (needed for
/// `Selector` mode). Callers that don't know labels should pass an empty map —
/// this correctly rejects cross-namespace routes under `Selector` while leaving
/// `Same`/`All` unaffected.
pub(crate) fn namespace_allowed(
    allowed: &crate::store::AllowedRoutesState,
    route_namespace: &str,
    gateway_namespace: &str,
    route_ns_labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    match allowed.namespaces_from.as_str() {
        "Same" => route_namespace == gateway_namespace,
        "All" => true,
        "Selector" => match &allowed.namespace_selector {
            // No selector configured under Selector mode — reject (safe default).
            None => false,
            // Empty matchLabels = match all (K8s LabelSelector semantics).
            Some(labels) if labels.is_empty() => true,
            Some(labels) => labels
                .iter()
                .all(|(k, v)| route_ns_labels.get(k).is_some_and(|rv| rv == v)),
        },
        _ => false,
    }
}

/// Convert CRD-level matches to internal HTTPRouteMatchState.
///
/// Returns (matches, has_invalid_regex) where has_invalid_regex is true if any
/// RegularExpression pattern fails compilation.
fn convert_matches(spec_matches: &[HTTPRouteMatchCRD]) -> (Vec<HTTPRouteMatchState>, bool) {
    let mut results = Vec::new();
    let mut has_invalid_regex = false;

    for m in spec_matches {
        let path = m.path.as_ref().map(|p| {
            let match_type_str = p.match_type.as_deref().unwrap_or("PathPrefix");
            let match_type = match match_type_str {
                "PathPrefix" => "Prefix".to_string(),
                "Exact" => "Exact".to_string(),
                "RegularExpression" => "RegularExpression".to_string(),
                other => other.to_string(),
            };
            let path_value = p.value.clone().unwrap_or_else(|| "/".to_string());
            // Validate regex patterns
            if match_type == "RegularExpression"
                && regex::RegexBuilder::new(&path_value).size_limit(64 * 1024).build().is_err() {
                    log::warn!("invalid regex path pattern: {}", path_value);
                    has_invalid_regex = true;
                }
            (path_value, match_type)
        });

        let headers: Vec<(String, String, String)> = m
            .headers
            .iter()
            .map(|h| {
                let match_type = h.match_type.clone().unwrap_or_else(|| "Exact".to_string());
                // Validate regex patterns for headers
                if match_type == "RegularExpression"
                    && regex::RegexBuilder::new(&h.value).size_limit(64 * 1024).build().is_err() {
                        log::warn!(
                            "invalid regex header pattern for {}: {}",
                            h.name,
                            h.value
                        );
                        // We mark invalid but still include the header in state
                        // The reconciler will set resolved_refs = false
                    }
                (h.name.clone(), h.value.clone(), match_type)
            })
            .collect();

        // Check for invalid regex in headers (separate pass for flag)
        for h in &m.headers {
            let mt = h.match_type.as_deref().unwrap_or("Exact");
            if mt == "RegularExpression" && regex::RegexBuilder::new(&h.value).size_limit(64 * 1024).build().is_err() {
                has_invalid_regex = true;
            }
        }

        let method = m.method.clone();

        let query_params: Vec<(String, String, String)> = m
            .query_params
            .iter()
            .filter_map(|q| {
                let mt = q.match_type.as_deref().unwrap_or("Exact");
                match mt {
                    "Exact" | "RegularExpression" => {
                        if mt == "RegularExpression"
                            && regex::RegexBuilder::new(&q.value).size_limit(64 * 1024).build().is_err() {
                                log::warn!("invalid regex query param pattern for '{}': {}", q.name, q.value);
                                has_invalid_regex = true;
                                return None;
                            }
                        Some((q.name.clone(), q.value.clone(), mt.to_string()))
                    }
                    other => {
                        log::warn!(
                            "query param '{}' uses unsupported match type '{}', skipping",
                            q.name, other
                        );
                        None
                    }
                }
            })
            .collect();

        results.push(HTTPRouteMatchState {
            path,
            headers,
            method,
            query_params,
        });
    }

    // If no matches specified, add a default catch-all
    if results.is_empty() {
        results.push(HTTPRouteMatchState {
            path: Some(("/".to_string(), "Prefix".to_string())),
            headers: vec![],
            method: None,
            query_params: vec![],
        });
    }

    (results, has_invalid_regex)
}

/// Parse a Gateway API duration string into milliseconds.
///
/// Supports:
/// - "Xs" -> X * 1000 ms
/// - "Xms" -> X ms
/// - "Xm" -> X * 60000 ms
/// - "Xh" -> X * 3600000 ms
///
/// Returns None if the format is unrecognized or the numeric part is invalid.
fn parse_gateway_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        num.parse::<u64>().ok()
    } else if let Some(num) = s.strip_suffix('s') {
        num.parse::<u64>().ok().and_then(|n| n.checked_mul(1_000))
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().and_then(|n| n.checked_mul(60_000))
    } else if let Some(num) = s.strip_suffix('h') {
        num.parse::<u64>().ok().and_then(|n| n.checked_mul(3_600_000))
    } else {
        None
    }
}

/// Convert CRD-level filters to internal HTTPFilterState.
fn convert_filters(spec_filters: &[HTTPRouteFilterCRD], route_namespace: &str) -> Vec<HTTPFilterState> {
    let mut results = Vec::new();

    for f in spec_filters {
        match f {
            HTTPRouteFilterCRD::RequestHeaderModifier {
                request_header_modifier,
            } => {
                let add: Vec<(String, String)> = request_header_modifier
                    .add
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                let set: Vec<(String, String)> = request_header_modifier
                    .set
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                results.push(HTTPFilterState::RequestHeaderModifier {
                    add,
                    set,
                    remove: request_header_modifier.remove.clone(),
                });
            }
            HTTPRouteFilterCRD::ResponseHeaderModifier {
                response_header_modifier,
            } => {
                let add: Vec<(String, String)> = response_header_modifier
                    .add
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                let set: Vec<(String, String)> = response_header_modifier
                    .set
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                results.push(HTTPFilterState::ResponseHeaderModifier {
                    add,
                    set,
                    remove: response_header_modifier.remove.clone(),
                });
            }
            HTTPRouteFilterCRD::RequestRedirect { request_redirect } => {
                let (path, path_type) = if let Some(ref pm) = request_redirect.path {
                    let p = pm
                        .replace_full_path
                        .clone()
                        .or_else(|| pm.replace_prefix_match.clone());
                    let pt = pm.modifier_type.clone();
                    (p, pt)
                } else {
                    (None, None)
                };
                results.push(HTTPFilterState::RequestRedirect {
                    scheme: request_redirect.scheme.clone(),
                    hostname: request_redirect.hostname.clone(),
                    port: request_redirect.port,
                    path,
                    path_type,
                    status_code: request_redirect.status_code.unwrap_or(302),
                });
            }
            HTTPRouteFilterCRD::URLRewrite { url_rewrite } => {
                let (path, path_type) = if let Some(ref pm) = url_rewrite.path {
                    let p = pm
                        .replace_full_path
                        .clone()
                        .or_else(|| pm.replace_prefix_match.clone());
                    let pt = pm.modifier_type.clone();
                    (p, pt)
                } else {
                    (None, None)
                };
                results.push(HTTPFilterState::URLRewrite {
                    hostname: url_rewrite.hostname.clone(),
                    path,
                    path_type,
                });
            }
            HTTPRouteFilterCRD::RequestMirror { request_mirror } => {
                let br = &request_mirror.backend_ref;
                // fraction takes precedence over percent per Gateway API spec.
                // fraction: numerator/denominator → integer percentage.
                // percent: direct integer percentage.
                // Neither set: 0 means mirror all requests.
                let percent = if let Some(ref frac) = request_mirror.fraction {
                    let denom = frac.denominator.unwrap_or(100);
                    if denom > 0 {
                        ((frac.numerator as f64 / denom as f64) * 100.0).round() as u32
                    } else {
                        0
                    }
                } else {
                    request_mirror.percent.unwrap_or(0)
                };
                results.push(HTTPFilterState::RequestMirror {
                    backend_namespace: br
                        .namespace
                        .clone()
                        .unwrap_or_else(|| route_namespace.to_string()),
                    backend_name: br.name.clone(),
                    backend_port: br.port.unwrap_or(80),
                    percent,
                });
            }
            HTTPRouteFilterCRD::CORS { cors } => {
                results.push(HTTPFilterState::CORS {
                    allow_origins: cors.allow_origins.clone(),
                    allow_methods: cors.allow_methods.clone(),
                    allow_headers: cors.allow_headers.clone(),
                    expose_headers: cors.expose_headers.clone(),
                    allow_credentials: cors.allow_credentials.unwrap_or(false),
                    max_age: cors.max_age,
                });
            }
        }
    }

    results
}

/// Resolve backend refs for a single rule. Cross-namespace refs are checked
/// against ReferenceGrants via `super::is_reference_allowed`.
///
/// Returns (backends, resolved, reject_reason) where resolved is false if any
/// ref is invalid, and reject_reason is the most specific Gateway API reason.
fn resolve_backend_refs(
    backend_refs: &[HTTPBackendRef],
    route_namespace: &str,
    store: &ConfigStore,
) -> (Vec<BackendRefState>, bool, &'static str) {
    let mut backends = Vec::new();
    let mut all_resolved = true;
    let mut reason = "ResolvedRefs";

    for bref in backend_refs {
        // Validate group and kind: only core group ("" or unset) + Service kind supported
        let group = bref.group.as_deref().unwrap_or("");
        let kind = bref.kind.as_deref().unwrap_or("Service");
        if !group.is_empty() || kind != "Service" {
            all_resolved = false;
            reason = "InvalidKind";
            continue;
        }

        let ns = bref.namespace.as_deref().unwrap_or(route_namespace);
        let port = bref.port.unwrap_or(0);
        let weight = bref.weight.unwrap_or(1);

        // Cross-namespace reference check
        if ns != route_namespace
            && !is_reference_allowed(
                &store.reference_grants,
                route_namespace,
                "HTTPRoute",
                ns,
                "Service",
                Some(&bref.name),
            )
        {
            all_resolved = false;
            if reason == "ResolvedRefs" {
                reason = "RefNotPermitted";
            }
            continue;
        }

        // Check if the backend Service exists in the store.
        // A service is "found" if either:
        //   1. It has entries in service_port_map (Service reconciler has seen it), OR
        //   2. It has entries in endpoints (EndpointSlice reconciler has seen it)
        // This avoids false BackendNotFound for services that exist but have
        // no ready endpoints yet (e.g., headless services, services with
        // manually-managed EndpointSlices).
        let svc_exists = store.service_port_map.iter().any(|entry| {
            let key = entry.key();
            key.namespace == ns && key.name == bref.name
        }) || store.endpoints.iter().any(|entry| {
            let key = entry.key();
            key.namespace == ns && key.name == bref.name
        });
        if !svc_exists {
            all_resolved = false;
            if reason == "ResolvedRefs" {
                reason = "BackendNotFound";
            }
        }

        let backend_filters = convert_filters(&bref.filters, route_namespace);
        backends.push(BackendRefState {
            namespace: ns.to_string(),
            name: bref.name.clone(),
            port,
            weight,
            filters: backend_filters,
        });
    }

    (backends, all_resolved, reason)
}

/// Main HTTPRoute reconciler entry point.
///
/// Validates parentRef bindings, converts matches and filters, resolves backend
/// refs, writes HTTPRouteState into ConfigStore, and signals recompilation.
pub async fn reconcile_http_route(
    route: Arc<HTTPRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = route
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = route
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;

    // Skip reconciliation for objects being deleted
    if route.metadata.deletion_timestamp.is_some() {
        log::info!("HTTPRoute {}/{} is being deleted, cleaning up", namespace, name);
        let key = crate::store::NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        super::remove_route(&ctx.store, &ctx.store.http_routes, RouteKind::Http, &key);
        return Ok(Action::await_change());
    }

    let generation = route.metadata.generation.unwrap_or(0).max(1);

    let hostnames = route.spec.hostnames.clone();
    let store = &ctx.store;

    // Read route's namespace labels from the store cache (populated by the
    // Namespace reconciler). Empty when the Namespace reconciler hasn't seen
    // this namespace yet — Selector mode then rejects until the cache warms
    // up. Labels changes trigger change_notify which requeues this route.
    let route_ns_labels: std::collections::BTreeMap<String, String> = ctx
        .store
        .namespace_labels
        .get(namespace)
        .map(|v| v.value().clone())
        .unwrap_or_default();

    // Validate parentRef bindings
    let mut parent_refs =
        bind_to_parents(&route.spec.parent_refs, namespace, &route_ns_labels, &hostnames, store);

    // Process rules
    let mut rules = Vec::new();
    let mut all_rules_resolved = true;
    let mut resolved_reason = "ResolvedRefs";

    for rule_spec in &route.spec.rules {
        let (matches, has_invalid_regex) = convert_matches(&rule_spec.matches);
        let filters = convert_filters(&rule_spec.filters, namespace);
        let (backend_refs, rule_resolved, rule_reason) =
            resolve_backend_refs(&rule_spec.backend_refs, namespace, store);

        if !rule_resolved || has_invalid_regex {
            all_rules_resolved = false;
            if resolved_reason == "ResolvedRefs" {
                resolved_reason = rule_reason;
            }
        }

        // Parse timeouts from CRD
        let request_timeout_ms = rule_spec
            .timeouts
            .as_ref()
            .and_then(|t| t.request.as_deref())
            .and_then(parse_gateway_duration);
        let backend_request_timeout_ms = rule_spec
            .timeouts
            .as_ref()
            .and_then(|t| t.backend_request.as_deref())
            .and_then(parse_gateway_duration);

        // Rule-level retry: `attempts` defaults to one retry when only codes
        // are given (the spec leaves the default to the implementation).
        let retry = rule_spec.retry.as_ref().map(|r| RouteRetryState {
            codes: r.codes.clone(),
            attempts: r.attempts.unwrap_or(1),
        });

        rules.push(HTTPRouteRuleState {
            matches,
            filters,
            backend_refs,
            request_timeout_ms,
            backend_request_timeout_ms,
            retry,
        });
    }

    // Update resolved_refs on accepted parent refs based on backend resolution
    for pref in &mut parent_refs {
        if pref.accepted {
            pref.resolved_refs = all_rules_resolved;
        }
    }

    if !super::any_parent_known(store, &parent_refs) {
        let key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };
        if super::remove_route(store, &store.http_routes, RouteKind::Http, &key) {
            log::info!("HTTPRoute {}/{}: no parent of ours any more; dropped", namespace, name);
        }
        return Ok(Action::await_change());
    }

    // Build per-parentRef status entries before moving into store
    let mut parent_statuses = Vec::new();
    let mut desired_conditions: Vec<Condition> = Vec::new();

    for pref in parent_refs.iter().filter(|p| super::parent_known(store, p)) {
        let reject_reason = pref.reject_reason.as_deref().unwrap_or("NotAllowedByListeners");
        let accepted_cond = status::build_condition(
            "Accepted",
            pref.accepted,
            if pref.accepted { "Accepted" } else { reject_reason },
            if pref.accepted {
                "Route accepted by parent Gateway"
            } else if reject_reason == "NoMatchingListenerHostname" {
                "Route hostname does not match any listener hostname"
            } else {
                "Route not allowed by listener"
            },
            generation,
        );
        let resolved_cond = status::build_condition(
            "ResolvedRefs",
            pref.resolved_refs,
            if pref.resolved_refs { "ResolvedRefs" } else { resolved_reason },
            if pref.resolved_refs {
                "All backend references resolved"
            } else {
                match resolved_reason {
                    "InvalidKind" => "Backend ref has unsupported group or kind",
                    "RefNotPermitted" => "Cross-namespace backend ref not permitted by ReferenceGrant",
                    _ => "One or more backend references could not be resolved",
                }
            },
            generation,
        );

        let mut section_name_json = serde_json::Map::new();
        section_name_json.insert("group".to_string(), json!("gateway.networking.k8s.io"));
        let parent_kind_str = match pref.parent_kind {
            ParentKind::Gateway => "Gateway",
            ParentKind::ListenerSet => "ListenerSet",
        };
        section_name_json.insert("kind".to_string(), json!(parent_kind_str));
        section_name_json.insert("name".to_string(), json!(pref.gateway_name));
        section_name_json.insert("namespace".to_string(), json!(pref.gateway_namespace));
        if let Some(ref sn) = pref.section_name {
            section_name_json.insert("sectionName".to_string(), json!(sn));
        }
        if let Some(p) = pref.port {
            section_name_json.insert("port".to_string(), json!(p));
        }

        let conditions_json: Vec<serde_json::Value> = [&accepted_cond, &resolved_cond]
            .iter()
            .map(|c| json!({
                "type": c.type_,
                "status": c.status,
                "reason": c.reason,
                "message": c.message,
                "observedGeneration": c.observed_generation,
                "lastTransitionTime": c.last_transition_time.0.to_string(),
            }))
            .collect();

        parent_statuses.push(json!({
            "parentRef": section_name_json,
            "controllerName": CONTROLLER_NAME,
            "conditions": conditions_json,
        }));

        desired_conditions.push(accepted_cond);
        desired_conditions.push(resolved_cond);
    }

    let route_state = HTTPRouteState {
        namespace: namespace.to_string(),
        hostnames,
        parent_refs,
        rules,
        generation,
    };

    let accepted_count = route_state.parent_refs.iter().filter(|pr| pr.accepted).count();
    let total_parents = route_state.parent_refs.len();
    let rules_count = route_state.rules.len();
    log::info!(
        "HTTPRoute {}/{}: gen={}, parents={}/{} accepted, rules={}, resolved={}",
        namespace, name, generation, accepted_count, total_parents, rules_count, resolved_reason
    );

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    super::store_route(store, &store.http_routes, RouteKind::Http, key, route_state);

    // Write per-parentRef status conditions to Kubernetes, keeping other
    // controllers' entries.
    let existing_parents = route.status.as_ref().map(|s| s.parents.as_slice()).unwrap_or_default();
    let current_conditions = status::own_parent_conditions(existing_parents);

    let desired_status = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "status": {
            "parents": status::merge_route_parents(existing_parents, parent_statuses)
        }
    });

    let api: Api<HTTPRoute> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(
        &api,
        name,
        desired_status,
        &current_conditions,
        &desired_conditions,
    )
    .await
    {
        log::warn!("failed to write HTTPRoute status for {}/{}: {}; will retry on next reconcile", namespace, name, e);
    }

    // Everything this status was derived from re-triggers the route through
    // the store's events (parents, Services, ReferenceGrants, Namespace labels);
    // see `triggers::routes_for`.
    Ok(Action::await_change())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{
        HTTPBackendRef, HTTPHeaderCRD, HTTPHeaderFilterCRD, HTTPHeaderMatchCRD,
        HTTPPathMatchCRD, HTTPPathModifierCRD, HTTPQueryParamMatchCRD,
        HTTPRequestRedirectFilterCRD, HTTPRouteFilterCRD, HTTPRouteMatchCRD, HTTPRouteRule,
        HTTPURLRewriteFilterCRD, ParentReference,
    };
    use crate::store::{
        AllowedRoutesState, ConfigStore, GatewayState, ListenerState, ReferenceGrantFrom,
        ReferenceGrantState, ReferenceGrantTo, ServiceKey,
    };

    /// Create a dummy kube::Client for unit tests that don't make API calls.
    fn dummy_client() -> kube::Client {
        use kube::client::Body;
        let svc = tower::service_fn(|_req: http::Request<Body>| async {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::builder()
                    .status(500)
                    .body(Body::empty())
                    .unwrap(),
            )
        });
        kube::Client::new(svc, "default")
    }

    fn make_gateway(
        name: &str,
        namespace: &str,
        listeners: Vec<ListenerState>,
    ) -> (NamespacedName, GatewayState) {
        let key = NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        let state = GatewayState {
            name: name.to_string(),
            namespace: namespace.to_string(),
            listeners,
            generation: 1,
            allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        };
        (key, state)
    }

    fn make_listener(
        name: &str,
        port: u16,
        protocol: &str,
        hostname: Option<&str>,
        namespaces_from: &str,
    ) -> ListenerState {
        ListenerState {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: hostname.map(|s| s.to_string()),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: AllowedRoutesState {
                namespaces_from: namespaces_from.to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: None,
        }
    }

    fn make_parent_ref(
        name: &str,
        namespace: Option<&str>,
        section: Option<&str>,
    ) -> ParentReference {
        ParentReference {
            group: None,
            kind: None,
            name: name.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            section_name: section.map(|s| s.to_string()),
            port: None,
        }
    }

    fn make_parent_ref_with_port(
        name: &str,
        namespace: Option<&str>,
        section: Option<&str>,
        port: Option<u16>,
    ) -> ParentReference {
        ParentReference {
            group: None,
            kind: None,
            name: name.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            section_name: section.map(|s| s.to_string()),
            port,
        }
    }

    // --- bind_to_parents tests ---

    #[test]
    fn test_httproute_bind_accepted_when_valid() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("my-gw", None, None)];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(result[0].accepted);
        assert_eq!(result[0].gateway_name, "my-gw");
    }

    #[test]
    fn test_httproute_bind_rejected_namespace_not_allowed() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "my-gw",
            "infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("my-gw", Some("infra"), None)];
        let result = bind_to_parents(&refs, "app-ns", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "route from different namespace should be rejected with Same policy"
        );
    }

    #[test]
    fn test_httproute_bind_section_name_matches_listener() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![
                make_listener("http", 80, "HTTP", None, "Same"),
                make_listener("https", 443, "HTTPS", None, "Same"),
            ],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("my-gw", None, Some("https"))];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(result[0].accepted);
        assert_eq!(result[0].section_name, Some("https".to_string()));
    }

    #[test]
    fn test_httproute_bind_section_name_no_match() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("my-gw", None, Some("nonexistent"))];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "sectionName not matching any listener should reject"
        );
    }

    #[test]
    fn test_httproute_bind_gateway_not_found() {
        let store = ConfigStore::new();

        let refs = vec![make_parent_ref("missing-gw", None, None)];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(!result[0].accepted);
    }

    #[test]
    fn test_httproute_bind_allowed_routes_all() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "my-gw",
            "infra",
            vec![make_listener("http", 80, "HTTP", None, "All")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("my-gw", Some("infra"), None)];
        let result = bind_to_parents(&refs, "other-ns", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            result[0].accepted,
            "allowedRoutes All should accept any namespace"
        );
    }

    #[test]
    fn test_httproute_bind_protocol_rejects_tcp() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "tcp-gw",
            "default",
            vec![make_listener("tcp", 9000, "TCP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref("tcp-gw", None, None)];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "TCP listener should not accept HTTPRoute"
        );
    }

    // --- convert_matches tests ---

    #[test]
    fn test_httproute_convert_matches_path_prefix() {
        let matches = vec![HTTPRouteMatchCRD {
            path: Some(HTTPPathMatchCRD {
                match_type: Some("PathPrefix".to_string()),
                value: Some("/api".to_string()),
            }),
            headers: vec![],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(!has_invalid);
        assert_eq!(result.len(), 1);
        let (path_val, match_type) = result[0].path.as_ref().unwrap();
        assert_eq!(path_val, "/api");
        assert_eq!(match_type, "Prefix");
    }

    #[test]
    fn test_httproute_convert_matches_path_exact() {
        let matches = vec![HTTPRouteMatchCRD {
            path: Some(HTTPPathMatchCRD {
                match_type: Some("Exact".to_string()),
                value: Some("/api/v1/users".to_string()),
            }),
            headers: vec![],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(!has_invalid);
        assert_eq!(result.len(), 1);
        let (path_val, match_type) = result[0].path.as_ref().unwrap();
        assert_eq!(path_val, "/api/v1/users");
        assert_eq!(match_type, "Exact");
    }

    #[test]
    fn test_httproute_convert_matches_header_exact() {
        let matches = vec![HTTPRouteMatchCRD {
            path: None,
            headers: vec![HTTPHeaderMatchCRD {
                name: "X-Custom".to_string(),
                value: "test-value".to_string(),
                match_type: Some("Exact".to_string()),
            }],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(!has_invalid);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].headers.len(), 1);
        assert_eq!(result[0].headers[0].0, "X-Custom");
        assert_eq!(result[0].headers[0].1, "test-value");
    }

    #[test]
    fn test_httproute_convert_matches_method() {
        let matches = vec![HTTPRouteMatchCRD {
            path: None,
            headers: vec![],
            method: Some("POST".to_string()),
            query_params: vec![],
        }];

        let (result, _) = convert_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].method, Some("POST".to_string()));
    }

    #[test]
    fn test_httproute_convert_matches_query_params() {
        let matches = vec![HTTPRouteMatchCRD {
            path: None,
            headers: vec![],
            method: None,
            query_params: vec![HTTPQueryParamMatchCRD {
                name: "version".to_string(),
                value: "v2".to_string(),
                match_type: Some("Exact".to_string()),
            }],
        }];

        let (result, _) = convert_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].query_params.len(), 1);
        assert_eq!(result[0].query_params[0].0, "version");
        assert_eq!(result[0].query_params[0].1, "v2");
    }

    // --- convert_filters tests ---

    #[test]
    fn test_httproute_convert_filters_request_header_modifier() {
        let filters = vec![HTTPRouteFilterCRD::RequestHeaderModifier {
            request_header_modifier: HTTPHeaderFilterCRD {
                add: vec![HTTPHeaderCRD {
                    name: "X-Added".to_string(),
                    value: "true".to_string(),
                }],
                set: vec![HTTPHeaderCRD {
                    name: "X-Set".to_string(),
                    value: "value".to_string(),
                }],
                remove: vec!["X-Remove".to_string()],
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestHeaderModifier { add, set, remove } => {
                assert_eq!(add.len(), 1);
                assert_eq!(add[0].0, "X-Added");
                assert_eq!(set.len(), 1);
                assert_eq!(set[0].0, "X-Set");
                assert_eq!(remove.len(), 1);
                assert_eq!(remove[0], "X-Remove");
            }
            _ => panic!("expected RequestHeaderModifier"),
        }
    }

    #[test]
    fn test_httproute_convert_filters_response_header_modifier() {
        let filters = vec![HTTPRouteFilterCRD::ResponseHeaderModifier {
            response_header_modifier: HTTPHeaderFilterCRD {
                add: vec![HTTPHeaderCRD {
                    name: "X-Response".to_string(),
                    value: "added".to_string(),
                }],
                set: vec![],
                remove: vec![],
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::ResponseHeaderModifier { add, .. } => {
                assert_eq!(add.len(), 1);
                assert_eq!(add[0].0, "X-Response");
            }
            _ => panic!("expected ResponseHeaderModifier"),
        }
    }

    #[test]
    fn test_httproute_convert_filters_request_redirect() {
        let filters = vec![HTTPRouteFilterCRD::RequestRedirect {
            request_redirect: HTTPRequestRedirectFilterCRD {
                scheme: Some("https".to_string()),
                hostname: Some("example.com".to_string()),
                port: Some(443),
                path: Some(HTTPPathModifierCRD {
                    modifier_type: Some("ReplaceFullPath".to_string()),
                    replace_full_path: Some("/new-path".to_string()),
                    replace_prefix_match: None,
                }),
                status_code: Some(301),
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestRedirect {
                scheme,
                hostname,
                port,
                path,
                path_type,
                status_code,
            } => {
                assert_eq!(scheme.as_deref(), Some("https"));
                assert_eq!(hostname.as_deref(), Some("example.com"));
                assert_eq!(*port, Some(443));
                assert_eq!(path.as_deref(), Some("/new-path"));
                assert_eq!(path_type.as_deref(), Some("ReplaceFullPath"));
                assert_eq!(*status_code, 301);
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    fn test_httproute_convert_filters_url_rewrite() {
        let filters = vec![HTTPRouteFilterCRD::URLRewrite {
            url_rewrite: HTTPURLRewriteFilterCRD {
                hostname: Some("internal.example.com".to_string()),
                path: Some(HTTPPathModifierCRD {
                    modifier_type: Some("ReplacePrefixMatch".to_string()),
                    replace_full_path: None,
                    replace_prefix_match: Some("/v2".to_string()),
                }),
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::URLRewrite {
                hostname,
                path,
                path_type,
            } => {
                assert_eq!(hostname.as_deref(), Some("internal.example.com"));
                assert_eq!(path.as_deref(), Some("/v2"));
                assert_eq!(path_type.as_deref(), Some("ReplacePrefixMatch"));
            }
            _ => panic!("expected URLRewrite"),
        }
    }

    // --- resolve_backend_refs tests ---

    #[test]
    fn test_httproute_resolve_same_namespace() {
        let store = ConfigStore::new();
        // Populate endpoints so the existence check passes
        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "my-svc".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );
        let refs = vec![HTTPBackendRef {
            name: "my-svc".to_string(),
            namespace: None,
            port: Some(8080),
            weight: Some(1),
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, all_resolved, _reason) = resolve_backend_refs(&refs, "default", &store);
        assert!(all_resolved);
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].name, "my-svc");
        assert_eq!(backends[0].namespace, "default");
        assert_eq!(backends[0].port, 8080);
    }

    #[test]
    fn test_httproute_resolve_cross_namespace_no_grant() {
        let store = ConfigStore::new();
        let refs = vec![HTTPBackendRef {
            name: "backend-svc".to_string(),
            namespace: Some("backend-ns".to_string()),
            port: Some(8080),
            weight: Some(1),
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, all_resolved, _reason) = resolve_backend_refs(&refs, "app-ns", &store);
        assert!(
            !all_resolved,
            "cross-namespace ref without grant should not be resolved"
        );
        assert!(backends.is_empty());
    }

    #[test]
    fn test_httproute_resolve_cross_namespace_with_grant() {
        let store = ConfigStore::new();
        // Populate endpoints so the existence check passes
        store.endpoints.insert(
            ServiceKey { namespace: "backend-ns".to_string(), name: "backend-svc".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );
        let grant_key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-app".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "app-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None,
                }],
            },
        );

        let refs = vec![HTTPBackendRef {
            name: "backend-svc".to_string(),
            namespace: Some("backend-ns".to_string()),
            port: Some(8080),
            weight: Some(1),
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, all_resolved, _reason) = resolve_backend_refs(&refs, "app-ns", &store);
        assert!(all_resolved);
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].namespace, "backend-ns");
    }

    // --- Full reconcile tests ---

    #[tokio::test]
    async fn test_httproute_reconcile_stores_state() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);
        // Populate endpoints so resolved_refs check passes
        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "my-svc".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("my-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(3),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: None,
                    kind: None,
                    name: "my-gw".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec!["example.com".to_string()],
                rules: vec![HTTPRouteRule {
                    matches: vec![HTTPRouteMatchCRD {
                        path: Some(HTTPPathMatchCRD {
                            match_type: Some("PathPrefix".to_string()),
                            value: Some("/api".to_string()),
                        }),
                        headers: vec![HTTPHeaderMatchCRD {
                            name: "X-Version".to_string(),
                            value: "2".to_string(),
                            match_type: Some("Exact".to_string()),
                        }],
                        method: Some("GET".to_string()),
                        query_params: vec![HTTPQueryParamMatchCRD {
                            name: "format".to_string(),
                            value: "json".to_string(),
                            match_type: Some("Exact".to_string()),
                        }],
                    }],
                    filters: vec![HTTPRouteFilterCRD::RequestHeaderModifier {
                        request_header_modifier: HTTPHeaderFilterCRD {
                            add: vec![HTTPHeaderCRD {
                                name: "X-Added".to_string(),
                                value: "true".to_string(),
                            }],
                            set: vec![],
                            remove: vec![],
                        },
                    }],
                    backend_refs: vec![HTTPBackendRef {
                        name: "my-svc".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: Some(1),
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-route".to_string(),
        };
        let entry = store
            .http_routes
            .get(&route_key)
            .expect("route should be stored");
        assert_eq!(entry.generation, 3);
        assert_eq!(entry.hostnames, vec!["example.com".to_string()]);
        assert_eq!(entry.parent_refs.len(), 1);
        assert!(entry.parent_refs[0].accepted);
        assert!(entry.parent_refs[0].resolved_refs);
        assert_eq!(entry.rules.len(), 1);

        // Verify match conversion
        let rule = &entry.rules[0];
        assert_eq!(rule.matches.len(), 1);
        let m = &rule.matches[0];
        assert_eq!(m.path, Some(("/api".to_string(), "Prefix".to_string())));
        assert_eq!(m.headers, vec![("X-Version".to_string(), "2".to_string(), "Exact".to_string())]);
        assert_eq!(m.method, Some("GET".to_string()));
        assert_eq!(
            m.query_params,
            vec![("format".to_string(), "json".to_string(), "Exact".to_string())]
        );

        // Verify filter conversion
        assert_eq!(rule.filters.len(), 1);
        match &rule.filters[0] {
            HTTPFilterState::RequestHeaderModifier { add, .. } => {
                assert_eq!(add[0].0, "X-Added");
            }
            _ => panic!("expected RequestHeaderModifier"),
        }

        // Verify backend refs
        assert_eq!(rule.backend_refs.len(), 1);
        assert_eq!(rule.backend_refs[0].name, "my-svc");
        assert_eq!(rule.backend_refs[0].port, 8080);
    }

    #[tokio::test]
    async fn test_httproute_unresolvable_backend_sets_resolved_refs_false() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("bad-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: None,
                    kind: None,
                    name: "my-gw".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "cross-svc".to_string(),
                        namespace: Some("other-ns".to_string()),
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "bad-route".to_string(),
        };
        let entry = store
            .http_routes
            .get(&route_key)
            .expect("route should be stored");
        assert!(entry.parent_refs[0].accepted);
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "unresolvable cross-namespace backend should set resolved_refs false"
        );
    }

    #[test]
    fn test_httproute_hostname_exact_match() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(!hostname_matches("example.com", "other.com"));
    }

    #[test]
    fn test_httproute_hostname_wildcard_listener() {
        assert!(hostname_matches("*.example.com", "foo.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        // Multi-level subdomains match per Gateway API intersection semantics
        assert!(hostname_matches("*.example.com", "foo.bar.example.com"));
    }

    // --- Phase 8: RequestMirror filter tests ---

    #[test]
    fn test_httproute_convert_filter_request_mirror() {
        let filters = vec![HTTPRouteFilterCRD::RequestMirror {
            request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                backend_ref: HTTPBackendRef {
                    name: "mirror-svc".to_string(),
                    namespace: Some("mirror-ns".to_string()),
                    port: Some(9090),
                    weight: None,
                    group: None,
                    kind: None,
                    filters: vec![],
                },
                percent: None,
                fraction: None,
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestMirror {
                backend_namespace,
                backend_name,
                backend_port,
                percent,
            } => {
                assert_eq!(backend_namespace, "mirror-ns");
                assert_eq!(backend_name, "mirror-svc");
                assert_eq!(*backend_port, 9090);
                assert_eq!(*percent, 0); // no percent = mirror all
            }
            _ => panic!("expected RequestMirror"),
        }
    }

    #[test]
    fn test_httproute_convert_filter_request_mirror_defaults() {
        // Test defaults: namespace defaults to route namespace, port defaults to 80
        let filters = vec![HTTPRouteFilterCRD::RequestMirror {
            request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                backend_ref: HTTPBackendRef {
                    name: "mirror-svc".to_string(),
                    namespace: None,
                    port: None,
                    weight: None,
                    group: None,
                    kind: None,
                    filters: vec![],
                },
                percent: None,
                fraction: None,
            },
        }];

        let result = convert_filters(&filters, "my-namespace");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestMirror {
                backend_namespace,
                backend_name,
                backend_port,
                percent,
            } => {
                assert_eq!(backend_namespace, "my-namespace");
                assert_eq!(backend_name, "mirror-svc");
                assert_eq!(*backend_port, 80);
                assert_eq!(*percent, 0);
            }
            _ => panic!("expected RequestMirror"),
        }
    }

    #[test]
    fn test_httproute_convert_filter_request_mirror_with_percent() {
        let filters = vec![HTTPRouteFilterCRD::RequestMirror {
            request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                backend_ref: HTTPBackendRef {
                    name: "mirror-svc".to_string(),
                    namespace: None,
                    port: Some(8080),
                    weight: None,
                    group: None,
                    kind: None,
                    filters: vec![],
                },
                percent: Some(20),
                fraction: None,
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestMirror { percent, .. } => {
                assert_eq!(*percent, 20);
            }
            _ => panic!("expected RequestMirror"),
        }
    }

    #[test]
    fn test_httproute_convert_filter_request_mirror_with_fraction() {
        use crate::gateway_types::HTTPMirrorFraction;
        let filters = vec![HTTPRouteFilterCRD::RequestMirror {
            request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                backend_ref: HTTPBackendRef {
                    name: "mirror-svc".to_string(),
                    namespace: None,
                    port: Some(8080),
                    weight: None,
                    group: None,
                    kind: None,
                    filters: vec![],
                },
                percent: Some(99), // should be overridden by fraction
                fraction: Some(HTTPMirrorFraction {
                    numerator: 25,
                    denominator: Some(50),
                }),
            },
        }];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 1);
        match &result[0] {
            HTTPFilterState::RequestMirror { percent, .. } => {
                // fraction 25/50 = 50%
                assert_eq!(*percent, 50);
            }
            _ => panic!("expected RequestMirror"),
        }
    }

    #[test]
    fn test_httproute_convert_filter_multiple_mirrors() {
        let filters = vec![
            HTTPRouteFilterCRD::RequestMirror {
                request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                    backend_ref: HTTPBackendRef {
                        name: "mirror-v2".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    },
                    percent: None,
                    fraction: None,
                },
            },
            HTTPRouteFilterCRD::RequestMirror {
                request_mirror: crate::gateway_types::HTTPRequestMirrorFilterCRD {
                    backend_ref: HTTPBackendRef {
                        name: "mirror-v3".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    },
                    percent: None,
                    fraction: None,
                },
            },
        ];

        let result = convert_filters(&filters, "default");
        assert_eq!(result.len(), 2);
        let mut mirror_names: Vec<&str> = result
            .iter()
            .filter_map(|f| match f {
                HTTPFilterState::RequestMirror { backend_name, .. } => Some(backend_name.as_str()),
                _ => None,
            })
            .collect();
        mirror_names.sort();
        assert_eq!(mirror_names, vec!["mirror-v2", "mirror-v3"]);
    }

    // --- Phase 8: RegularExpression match tests ---

    #[test]
    fn test_httproute_convert_matches_regex_path() {
        let matches = vec![HTTPRouteMatchCRD {
            path: Some(HTTPPathMatchCRD {
                match_type: Some("RegularExpression".to_string()),
                value: Some("^/api/v[0-9]+".to_string()),
            }),
            headers: vec![],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(!has_invalid, "valid regex should not flag as invalid");
        assert_eq!(result.len(), 1);
        let (path_val, match_type) = result[0].path.as_ref().unwrap();
        assert_eq!(path_val, "^/api/v[0-9]+");
        assert_eq!(match_type, "RegularExpression");
    }

    #[test]
    fn test_httproute_convert_matches_regex_header() {
        let matches = vec![HTTPRouteMatchCRD {
            path: None,
            headers: vec![HTTPHeaderMatchCRD {
                name: "X-Version".to_string(),
                value: "v[0-9]+".to_string(),
                match_type: Some("RegularExpression".to_string()),
            }],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(!has_invalid, "valid regex header should not flag as invalid");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].headers.len(), 1);
        assert_eq!(result[0].headers[0].0, "X-Version");
        assert_eq!(result[0].headers[0].1, "v[0-9]+");
        assert_eq!(result[0].headers[0].2, "RegularExpression");
    }

    #[test]
    fn test_httproute_convert_matches_invalid_regex_sets_flag() {
        let matches = vec![HTTPRouteMatchCRD {
            path: Some(HTTPPathMatchCRD {
                match_type: Some("RegularExpression".to_string()),
                value: Some("[invalid(regex".to_string()),
            }),
            headers: vec![],
            method: None,
            query_params: vec![],
        }];

        let (result, has_invalid) = convert_matches(&matches);
        assert!(has_invalid, "invalid regex should flag as invalid");
        // The match is still produced (for diagnostic purposes), but the flag is set
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path.as_ref().unwrap().1, "RegularExpression");
    }

    #[test]
    fn test_httproute_convert_matches_invalid_regex_header_sets_flag() {
        let matches = vec![HTTPRouteMatchCRD {
            path: None,
            headers: vec![HTTPHeaderMatchCRD {
                name: "X-Bad".to_string(),
                value: "[invalid(regex".to_string(),
                match_type: Some("RegularExpression".to_string()),
            }],
            method: None,
            query_params: vec![],
        }];

        let (_result, has_invalid) = convert_matches(&matches);
        assert!(has_invalid, "invalid regex header should flag as invalid");
    }

    // --- Phase 8: Timeout tests ---

    #[test]
    fn test_parse_gateway_duration_seconds() {
        assert_eq!(parse_gateway_duration("10s"), Some(10_000));
        assert_eq!(parse_gateway_duration("1s"), Some(1_000));
        assert_eq!(parse_gateway_duration("0s"), Some(0));
    }

    #[test]
    fn test_parse_gateway_duration_milliseconds() {
        assert_eq!(parse_gateway_duration("500ms"), Some(500));
        assert_eq!(parse_gateway_duration("1ms"), Some(1));
    }

    #[test]
    fn test_parse_gateway_duration_minutes() {
        assert_eq!(parse_gateway_duration("1m"), Some(60_000));
        assert_eq!(parse_gateway_duration("5m"), Some(300_000));
    }

    #[test]
    fn test_parse_gateway_duration_hours() {
        assert_eq!(parse_gateway_duration("1h"), Some(3_600_000));
    }

    #[test]
    fn test_parse_gateway_duration_invalid() {
        assert_eq!(parse_gateway_duration("invalid"), None);
        assert_eq!(parse_gateway_duration(""), None);
        assert_eq!(parse_gateway_duration("10x"), None);
    }

    #[tokio::test]
    async fn test_httproute_reconcile_with_timeouts() {
        use kube::api::ObjectMeta;
        use crate::gateway_types::HTTPRouteTimeouts;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("timeout-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: None,
                    kind: None,
                    name: "my-gw".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "svc".to_string(),
                        namespace: None,
                        port: Some(80),
                        weight: Some(1),
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: Some(HTTPRouteTimeouts {
                        request: Some("10s".to_string()),
                        backend_request: Some("5s".to_string()),
                    }),
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "timeout-route".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        let rule = &entry.rules[0];
        assert_eq!(rule.request_timeout_ms, Some(10_000));
        assert_eq!(rule.backend_request_timeout_ms, Some(5_000));
        assert!(rule.retry.is_none());
    }

    #[tokio::test]
    async fn test_httproute_rule_retry_is_stored_with_default_attempts() {
        // httproute-retry.yaml: codes [500] attempts 3; codes [500,502,503,504] attempts 2.
        use kube::api::ObjectMeta;
        use crate::gateway_types::{HTTPPathMatchCRD, HTTPRouteMatchCRD, HTTPRouteRetry};

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway("same-namespace", "default", vec![make_listener("http", 80, "HTTP", None, "Same")]);
        store.gateways.insert(key, gw);
        let rule = |path: &str, retry: HTTPRouteRetry| HTTPRouteRule {
            matches: vec![HTTPRouteMatchCRD {
                path: Some(HTTPPathMatchCRD { match_type: Some("PathPrefix".into()), value: Some(path.into()) }),
                ..Default::default()
            }],
            backend_refs: vec![HTTPBackendRef { name: "infra-backend-v3".into(), port: Some(8080), ..Default::default() }],
            retry: Some(retry),
            ..Default::default()
        };
        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("retries".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference { name: "same-namespace".to_string(), ..Default::default() }],
                hostnames: vec![],
                rules: vec![
                    rule("/retry/code-500-attempts-3", HTTPRouteRetry { codes: vec![500], attempts: Some(3), backoff: None }),
                    rule("/retry/code-all-attempts-2", HTTPRouteRetry { codes: vec![500, 502, 503, 504], attempts: Some(2), backoff: None }),
                    rule("/retry/default-attempts", HTTPRouteRetry { codes: vec![503], attempts: None, backoff: Some("100ms".into()) }),
                ],
            },
            status: None,
        });
        let ctx = Arc::new(ReconcileContext { store: store.clone(), client: dummy_client() });
        reconcile_http_route(route, ctx).await.unwrap();

        let stored = store.http_routes.get(&NamespacedName { namespace: "default".into(), name: "retries".into() }).unwrap();
        assert_eq!(stored.rules[0].retry, Some(RouteRetryState { codes: vec![500], attempts: 3 }));
        assert_eq!(stored.rules[1].retry, Some(RouteRetryState { codes: vec![500, 502, 503, 504], attempts: 2 }));
        assert_eq!(stored.rules[2].retry, Some(RouteRetryState { codes: vec![503], attempts: 1 }), "attempts defaults to 1");
    }

    #[tokio::test]
    async fn test_httproute_reconcile_invalid_regex_sets_resolved_refs_false() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "my-gw",
            "default",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("regex-bad-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: None,
                    kind: None,
                    name: "my-gw".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![HTTPRouteMatchCRD {
                        path: Some(HTTPPathMatchCRD {
                            match_type: Some("RegularExpression".to_string()),
                            value: Some("[invalid(regex".to_string()),
                        }),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "svc".to_string(),
                        namespace: None,
                        port: Some(80),
                        weight: Some(1),
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "regex-bad-route".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "invalid regex should set resolved_refs = false"
        );
    }

    // =========================================================================
    // Conformance-mirror tests: Gateway API controller status behavior
    // =========================================================================
    //
    // Each test below mirrors a specific Gateway API conformance test for
    // HTTPRoute status/validation behavior. The expected conditions (type,
    // status, reason) are taken directly from the upstream Go test files.

    // --- 1. HTTPRouteInvalidBackendRefUnknownKind ---
    // Conformance: route with backendRef group=unknownkind.example.com, kind=NonExistent
    // Expected: Accepted=True, ResolvedRefs=False with reason=InvalidKind

    #[test]
    fn test_conformance_invalid_backend_ref_unknown_kind_resolve() {
        let store = ConfigStore::new();
        // Add endpoints so same-ns Service would resolve (but the ref has wrong kind)
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-infra".to_string(),
                name: "infra-backend-v1".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let refs = vec![HTTPBackendRef {
            name: "infra-backend-v1".to_string(),
            namespace: None,
            port: Some(8080),
            weight: None,
            group: Some("unknownkind.example.com".to_string()),
            kind: Some("NonExistent".to_string()),
            filters: vec![],
        }];

        let (_backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(!resolved, "unknown kind should not resolve");
        assert_eq!(reason, "InvalidKind", "reason must be InvalidKind per conformance");
    }

    #[tokio::test]
    async fn test_conformance_invalid_backend_ref_unknown_kind_full() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("invalid-backend-ref-unknown-kind".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "infra-backend-v1".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: Some("unknownkind.example.com".to_string()),
                        kind: Some("NonExistent".to_string()),
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "invalid-backend-ref-unknown-kind".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        // Conformance: Route must be Accepted
        assert!(
            entry.parent_refs[0].accepted,
            "route should be accepted by parent Gateway"
        );
        // Conformance: ResolvedRefs=False, Reason=InvalidKind
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "unknown kind backend should set resolved_refs = false"
        );
    }

    // --- 2. HTTPRouteInvalidNonExistentBackendRef ---
    // Conformance: route referencing Service "nonexistent" that doesn't exist
    // Expected: Accepted=True, ResolvedRefs=False, Reason=BackendNotFound

    #[test]
    fn test_conformance_invalid_nonexistent_backend_ref_resolve() {
        let store = ConfigStore::new();
        // Do NOT add any endpoints for "nonexistent"

        let refs = vec![HTTPBackendRef {
            name: "nonexistent".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(!resolved, "nonexistent service should not resolve");
        assert_eq!(
            reason, "BackendNotFound",
            "reason must be BackendNotFound per conformance"
        );
        // The backend is still added to the list (with no endpoints)
        assert_eq!(backends.len(), 1, "backend ref should still be in list");
        assert_eq!(backends[0].name, "nonexistent");
    }

    // --- HTTPRouteServiceTypes ---
    // Conformance: services exist (in service_port_map) but may not have
    // endpoints yet. ResolvedRefs should be True because the Service exists.

    #[test]
    fn test_service_exists_in_port_map_resolves_refs() {
        let store = ConfigStore::new();
        // Service exists in service_port_map (Service reconciler ran) but has
        // no endpoints yet (EndpointSlice reconciler hasn't run or slices are
        // pending manual patching, as in the ServiceTypes conformance test).
        store.service_port_map.insert(
            ServiceKey {
                namespace: "gateway-conformance-infra".to_string(),
                name: "manual-endpointslices".to_string(),
                port: 8080,
            },
            3000,
        );

        let refs = vec![HTTPBackendRef {
            name: "manual-endpointslices".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(
            resolved,
            "service in service_port_map should resolve even without endpoints"
        );
        assert_eq!(reason, "ResolvedRefs");
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].name, "manual-endpointslices");
    }

    #[test]
    fn test_headless_service_with_endpoints_resolves_refs() {
        let store = ConfigStore::new();
        // Headless service with endpoints (selector-based, auto-populated)
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-infra".to_string(),
                name: "headless".to_string(),
                port: 3000,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 3000,
            }],
        );

        let refs = vec![HTTPBackendRef {
            name: "headless".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(resolved, "headless service with endpoints should resolve");
        assert_eq!(reason, "ResolvedRefs");
        assert_eq!(backends.len(), 1);
    }

    #[tokio::test]
    async fn test_conformance_invalid_nonexistent_backend_ref_full() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("invalid-nonexistent-backend-ref".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "nonexistent".to_string(),
                        namespace: Some("gateway-conformance-infra".to_string()),
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "invalid-nonexistent-backend-ref".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        assert!(entry.parent_refs[0].accepted, "route should be accepted");
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "nonexistent backend should set resolved_refs = false"
        );
    }

    // --- 3. HTTPRouteInvalidCrossNamespaceBackendRef ---
    // Conformance: cross-namespace backend ref without ReferenceGrant
    // Expected: Accepted=True, ResolvedRefs=False, Reason=RefNotPermitted

    #[test]
    fn test_conformance_invalid_cross_namespace_backend_ref_resolve() {
        let store = ConfigStore::new();
        // No ReferenceGrant from gateway-conformance-infra -> gateway-conformance-web-backend

        let refs = vec![HTTPBackendRef {
            name: "web-backend".to_string(),
            namespace: Some("gateway-conformance-web-backend".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(!resolved, "cross-namespace without grant should not resolve");
        assert_eq!(
            reason, "RefNotPermitted",
            "reason must be RefNotPermitted per conformance"
        );
        assert!(
            backends.is_empty(),
            "cross-namespace ref without grant should be skipped"
        );
    }

    #[tokio::test]
    async fn test_conformance_invalid_cross_namespace_backend_ref_full() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("invalid-cross-namespace-backend-ref".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "web-backend".to_string(),
                        namespace: Some("gateway-conformance-web-backend".to_string()),
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "invalid-cross-namespace-backend-ref".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        assert!(entry.parent_refs[0].accepted, "route should be accepted");
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "cross-namespace without grant should set resolved_refs = false"
        );
    }

    // --- 4. HTTPRouteInvalidCrossNamespaceParentRef ---
    // Conformance: route in gateway-conformance-web-backend, Gateway in
    // gateway-conformance-infra with listener allowedRoutes.namespaces.from=Same
    // Expected: Accepted=False, Reason=NotAllowedByListeners, ResolvedRefs=True

    #[test]
    fn test_conformance_invalid_cross_namespace_parent_ref_bind() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        // Route is in a DIFFERENT namespace than the Gateway
        let refs = vec![ParentReference {
            group: None,
            kind: None,
            name: "same-namespace".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            section_name: None,
            port: None,
        }];
        let result = bind_to_parents(&refs, "gateway-conformance-web-backend", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "cross-namespace route should not be accepted when listener allows Same only"
        );
        assert_eq!(
            result[0].reject_reason.as_deref(),
            Some("NotAllowedByListeners"),
            "reason must be NotAllowedByListeners per conformance"
        );
        // ResolvedRefs should be true (parent binding is separate from backend resolution)
        assert!(
            result[0].resolved_refs,
            "resolved_refs should be true initially (updated per-rule later)"
        );
    }

    // --- 5. HTTPRouteInvalidParentRefNotMatchingSectionName ---
    // Conformance: sectionName="http1" doesn't match any listener
    // Expected: Accepted=False, Reason=NoMatchingParent
    //
    // NOTE: Our current code returns "NotAllowedByListeners" for sectionName
    // mismatch. The conformance test expects "NoMatchingParent". This test
    // validates the conformance-correct behavior.

    #[test]
    fn test_conformance_invalid_parentref_not_matching_section_name() {
        let store = ConfigStore::new();
        // Gateway with listener named "http" (not "http1")
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![ParentReference {
            group: None,
            kind: None,
            name: "same-namespace".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            section_name: Some("http1".to_string()), // doesn't match "http"
            port: None,
        }];
        let result = bind_to_parents(&refs, "gateway-conformance-infra", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "sectionName not matching any listener should not be accepted"
        );
        // Conformance expects NoMatchingParent for sectionName mismatch
        let reason = result[0].reject_reason.as_deref().unwrap_or("");
        assert_eq!(
            reason, "NoMatchingParent",
            "reason must be NoMatchingParent per conformance (got '{}')",
            reason
        );
    }

    // --- 6. HTTPRouteInvalidParentRefNotMatchingListenerPort ---
    // Conformance: parentRef with port=81, Gateway listener is port=80
    // Expected: Accepted=False, Reason=NoMatchingParent

    #[test]
    fn test_conformance_invalid_parentref_not_matching_listener_port() {
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        // parentRef specifies port=81, but listener is on port=80
        let refs = vec![make_parent_ref_with_port(
            "same-namespace",
            Some("gateway-conformance-infra"),
            None,
            Some(81),
        )];
        let result = bind_to_parents(&refs, "gateway-conformance-infra", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(!result[0].accepted, "port 81 should not match listener on port 80");
        let reason = result[0].reject_reason.as_deref().unwrap_or("");
        assert_eq!(
            reason, "NoMatchingParent",
            "reason must be NoMatchingParent per conformance (got '{}')",
            reason
        );
    }

    // --- 7. HTTPRouteDisallowedKind (regression coverage) ---
    // Conformance: Gateway with TLS listener only; HTTPRoute cannot bind
    // Expected: Accepted=False, Reason=NotAllowedByListeners, ResolvedRefs=True

    #[test]
    fn test_conformance_disallowed_kind_tls_listener() {
        let store = ConfigStore::new();
        // Gateway only has a TLS listener (protocol != HTTP/HTTPS)
        let (key, gw) = make_gateway(
            "tlsroutes-only",
            "gateway-conformance-infra",
            vec![make_listener("tls", 443, "TLS", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![ParentReference {
            group: None,
            kind: None,
            name: "tlsroutes-only".to_string(),
            namespace: Some("gateway-conformance-infra".to_string()),
            section_name: None,
            port: None,
        }];
        let result = bind_to_parents(&refs, "gateway-conformance-infra", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(!result[0].accepted, "HTTPRoute should not bind to TLS-only listener");
        assert_eq!(
            result[0].reject_reason.as_deref(),
            Some("NotAllowedByListeners"),
            "reason must be NotAllowedByListeners per conformance"
        );
        assert!(
            result[0].resolved_refs,
            "resolved_refs should be true for a disallowed kind (refs not evaluated)"
        );
    }

    #[tokio::test]
    async fn test_conformance_disallowed_kind_full() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "tlsroutes-only",
            "gateway-conformance-infra",
            vec![make_listener("tls", 443, "TLS", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("disallowed-kind".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: None,
                    kind: None,
                    name: "tlsroutes-only".to_string(),
                    namespace: Some("gateway-conformance-infra".to_string()),
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "infra-backend-v1".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "disallowed-kind".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");
        assert!(!entry.parent_refs[0].accepted, "should not be accepted");
        assert_eq!(
            entry.parent_refs[0].reject_reason.as_deref(),
            Some("NotAllowedByListeners"),
        );
    }

    // --- 8. HTTPRouteObservedGenerationBump (regression coverage) ---
    // Conformance: after updating a route, observedGeneration should match
    // the new generation.

    #[tokio::test]
    async fn test_conformance_observed_generation_bump() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-infra".to_string(),
                name: "infra-backend-v1".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        // First reconcile at generation 1
        let route_gen1 = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("observed-generation-bump".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "infra-backend-v1".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let _ = reconcile_http_route(route_gen1, ctx.clone()).await;

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "observed-generation-bump".to_string(),
        };
        {
            let entry = store.http_routes.get(&route_key).expect("route stored");
            assert_eq!(entry.generation, 1);
        }

        // Second reconcile at generation 2 (simulates spec update)
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-infra".to_string(),
                name: "infra-backend-v2".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.2".to_string(),
                port: 8080,
            }],
        );

        let route_gen2 = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("observed-generation-bump".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(2),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        name: "infra-backend-v2".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: None,
                        group: None,
                        kind: None,
                        filters: vec![],
                    }],
                    timeouts: None,
                    retry: None,
                }],
            },
            status: None,
        });

        let _ = reconcile_http_route(route_gen2, ctx).await;

        let entry = store.http_routes.get(&route_key).expect("route stored");
        assert_eq!(
            entry.generation, 2,
            "generation should be bumped to 2 after update"
        );
        assert!(entry.parent_refs[0].accepted, "route should still be accepted");
        assert!(
            entry.parent_refs[0].resolved_refs,
            "resolved refs should be true"
        );
    }

    // --- 9. HTTPRouteReferenceGrant ---
    // Conformance: cross-namespace backend WITH ReferenceGrant -> works.
    // After removing ReferenceGrant -> ResolvedRefs=False

    #[test]
    fn test_conformance_reference_grant_allows_cross_namespace() {
        let store = ConfigStore::new();
        // Add the ReferenceGrant
        let grant_key = NamespacedName {
            namespace: "gateway-conformance-web-backend".to_string(),
            name: "reference-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "gateway-conformance-web-backend".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "gateway-conformance-infra".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("web-backend".to_string()),
                }],
            },
        );
        // Add endpoints for the cross-namespace service
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-web-backend".to_string(),
                name: "web-backend".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let refs = vec![HTTPBackendRef {
            name: "web-backend".to_string(),
            namespace: Some("gateway-conformance-web-backend".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(resolved, "cross-namespace with grant should resolve");
        assert_eq!(reason, "ResolvedRefs");
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].namespace, "gateway-conformance-web-backend");
        assert_eq!(backends[0].name, "web-backend");
    }

    #[test]
    fn test_conformance_reference_grant_removed_fails() {
        let store = ConfigStore::new();
        // NO ReferenceGrant in store (simulates deletion)
        // Endpoints exist but grant is missing
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-web-backend".to_string(),
                name: "web-backend".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let refs = vec![HTTPBackendRef {
            name: "web-backend".to_string(),
            namespace: Some("gateway-conformance-web-backend".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (_backends, resolved, reason) =
            resolve_backend_refs(&refs, "gateway-conformance-infra", &store);
        assert!(
            !resolved,
            "after removing ReferenceGrant, cross-namespace should not resolve"
        );
        assert_eq!(
            reason, "RefNotPermitted",
            "reason should be RefNotPermitted without grant"
        );
    }

    #[tokio::test]
    async fn test_conformance_reference_grant_full_lifecycle() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        // Add ReferenceGrant and endpoints
        let grant_key = NamespacedName {
            namespace: "gateway-conformance-web-backend".to_string(),
            name: "reference-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key.clone(),
            ReferenceGrantState {
                namespace: "gateway-conformance-web-backend".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "gateway-conformance-infra".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("web-backend".to_string()),
                }],
            },
        );
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-web-backend".to_string(),
                name: "web-backend".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let make_route = || {
            Arc::new(HTTPRoute {
                metadata: ObjectMeta {
                    name: Some("reference-grant".to_string()),
                    namespace: Some("gateway-conformance-infra".to_string()),
                    generation: Some(1),
                    ..Default::default()
                },
                spec: crate::gateway_types::HTTPRouteSpec {
                    parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                    hostnames: vec![],
                    rules: vec![HTTPRouteRule {
                        matches: vec![],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            name: "web-backend".to_string(),
                            namespace: Some("gateway-conformance-web-backend".to_string()),
                            port: Some(8080),
                            weight: None,
                            group: None,
                            kind: None,
                            filters: vec![],
                        }],
                        timeouts: None,
                        retry: None,
                    }],
                },
                status: None,
            })
        };

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        // Phase 1: With ReferenceGrant present, everything should resolve
        let _ = reconcile_http_route(make_route(), ctx.clone()).await;

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "reference-grant".to_string(),
        };
        {
            let entry = store.http_routes.get(&route_key).expect("route stored");
            assert!(entry.parent_refs[0].accepted, "should be accepted");
            assert!(
                entry.parent_refs[0].resolved_refs,
                "with ReferenceGrant, resolved_refs should be true"
            );
        }

        // Phase 2: Remove the ReferenceGrant, re-reconcile
        store.reference_grants.remove(&grant_key);

        let _ = reconcile_http_route(make_route(), ctx).await;

        {
            let entry = store.http_routes.get(&route_key).expect("route stored");
            assert!(entry.parent_refs[0].accepted, "should still be accepted");
            assert!(
                !entry.parent_refs[0].resolved_refs,
                "after removing ReferenceGrant, resolved_refs should be false"
            );
        }
    }

    // --- 10. HTTPRoutePartiallyInvalidViaInvalidReferenceGrant ---
    // Conformance: ReferenceGrant allows "app-backend-v1" but NOT "app-backend-v2"
    // Route has two rules: one referencing v2 (not granted), one referencing v1 (granted)
    // Expected: Accepted=True, ResolvedRefs=False, Reason=RefNotPermitted

    #[test]
    fn test_conformance_partially_invalid_reference_grant_resolve() {
        let store = ConfigStore::new();

        // ReferenceGrant only allows app-backend-v1, NOT app-backend-v2
        let grant_key = NamespacedName {
            namespace: "gateway-conformance-app-backend".to_string(),
            name: "invalid-reference-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "gateway-conformance-app-backend".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "gateway-conformance-infra".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("app-backend-v1".to_string()),
                }],
            },
        );

        // Add endpoints for both services
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-app-backend".to_string(),
                name: "app-backend-v1".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-app-backend".to_string(),
                name: "app-backend-v2".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.2".to_string(),
                port: 8080,
            }],
        );

        // Rule 1: references app-backend-v2 (NOT granted)
        let refs_v2 = vec![HTTPBackendRef {
            name: "app-backend-v2".to_string(),
            namespace: Some("gateway-conformance-app-backend".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];
        let (_backends_v2, resolved_v2, reason_v2) =
            resolve_backend_refs(&refs_v2, "gateway-conformance-infra", &store);
        assert!(!resolved_v2, "app-backend-v2 should not resolve (no grant for it)");
        assert_eq!(reason_v2, "RefNotPermitted");

        // Rule 2: references app-backend-v1 (IS granted)
        let refs_v1 = vec![HTTPBackendRef {
            name: "app-backend-v1".to_string(),
            namespace: Some("gateway-conformance-app-backend".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];
        let (backends_v1, resolved_v1, reason_v1) =
            resolve_backend_refs(&refs_v1, "gateway-conformance-infra", &store);
        assert!(resolved_v1, "app-backend-v1 should resolve (grant exists)");
        assert_eq!(reason_v1, "ResolvedRefs");
        assert_eq!(backends_v1.len(), 1);
    }

    #[tokio::test]
    async fn test_conformance_partially_invalid_reference_grant_full() {
        use kube::api::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        // ReferenceGrant only allows app-backend-v1
        let grant_key = NamespacedName {
            namespace: "gateway-conformance-app-backend".to_string(),
            name: "invalid-reference-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "gateway-conformance-app-backend".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "gateway-conformance-infra".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("app-backend-v1".to_string()),
                }],
            },
        );

        // Endpoints for both
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-app-backend".to_string(),
                name: "app-backend-v1".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );
        store.endpoints.insert(
            ServiceKey {
                namespace: "gateway-conformance-app-backend".to_string(),
                name: "app-backend-v2".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.2".to_string(),
                port: 8080,
            }],
        );

        let route = Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some("invalid-reference-grant".to_string()),
                namespace: Some("gateway-conformance-infra".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::gateway_types::HTTPRouteSpec {
                parent_refs: vec![make_parent_ref("same-namespace", None, None)],
                hostnames: vec![],
                rules: vec![
                    // Rule 1: /v2 -> app-backend-v2 (NOT granted)
                    HTTPRouteRule {
                        matches: vec![HTTPRouteMatchCRD {
                            path: Some(HTTPPathMatchCRD {
                                match_type: Some("PathPrefix".to_string()),
                                value: Some("/v2".to_string()),
                            }),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            name: "app-backend-v2".to_string(),
                            namespace: Some("gateway-conformance-app-backend".to_string()),
                            port: Some(8080),
                            weight: None,
                            group: None,
                            kind: None,
                            filters: vec![],
                        }],
                        timeouts: None,
                        retry: None,
                    },
                    // Rule 2: / -> app-backend-v1 (IS granted)
                    HTTPRouteRule {
                        matches: vec![],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            name: "app-backend-v1".to_string(),
                            namespace: Some("gateway-conformance-app-backend".to_string()),
                            port: Some(8080),
                            weight: None,
                            group: None,
                            kind: None,
                            filters: vec![],
                        }],
                        timeouts: None,
                        retry: None,
                    },
                ],
            },
            status: None,
        });

        let ctx = Arc::new(ReconcileContext {
            store: store.clone(),
            client: dummy_client(),
        });

        let result = reconcile_http_route(route, ctx).await;
        assert!(result.is_ok());

        let route_key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "invalid-reference-grant".to_string(),
        };
        let entry = store.http_routes.get(&route_key).expect("route should be stored");

        // Route should be Accepted (parent binding is valid)
        assert!(entry.parent_refs[0].accepted, "route should be accepted");
        // ResolvedRefs should be False because rule 1 has an ungrant'd backend
        assert!(
            !entry.parent_refs[0].resolved_refs,
            "partially invalid route should have resolved_refs = false"
        );

        // Both rules should still be present in the state
        assert_eq!(entry.rules.len(), 2, "both rules should be stored");
    }

    // --- Additional edge case tests for completeness ---

    #[test]
    fn test_conformance_backend_ref_invalid_kind_skips_backend() {
        // Verify that backends with invalid kind are NOT added to the backends list
        let store = ConfigStore::new();
        let refs = vec![HTTPBackendRef {
            name: "some-backend".to_string(),
            namespace: None,
            port: Some(8080),
            weight: None,
            group: Some("custom.io".to_string()),
            kind: Some("CustomResource".to_string()),
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "default", &store);
        assert!(!resolved);
        assert_eq!(reason, "InvalidKind");
        assert!(
            backends.is_empty(),
            "invalid kind backend should be skipped (not added to list)"
        );
    }

    #[test]
    fn test_conformance_mixed_valid_invalid_backend_refs() {
        // One valid backend + one invalid kind backend
        let store = ConfigStore::new();
        store.endpoints.insert(
            ServiceKey {
                namespace: "default".to_string(),
                name: "valid-svc".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let refs = vec![
            HTTPBackendRef {
                name: "valid-svc".to_string(),
                namespace: None,
                port: Some(8080),
                weight: Some(1),
                group: None,
                kind: None,
                filters: vec![],
            },
            HTTPBackendRef {
                name: "invalid-backend".to_string(),
                namespace: None,
                port: Some(8080),
                weight: Some(1),
                group: Some("custom.io".to_string()),
                kind: Some("NotAService".to_string()),
                filters: vec![],
            },
        ];

        let (backends, resolved, reason) = resolve_backend_refs(&refs, "default", &store);
        assert!(!resolved, "having any invalid backend means not resolved");
        assert_eq!(reason, "InvalidKind");
        // Valid backend is still in the list
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].name, "valid-svc");
    }

    #[test]
    fn test_conformance_reference_grant_with_specific_name_rejects_other() {
        // Grant allows "app-backend-v1" specifically; "app-backend-v2" should fail
        let store = ConfigStore::new();
        let grant_key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "specific-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "route-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("allowed-svc".to_string()),
                }],
            },
        );

        // Try to reference a different service name
        let refs = vec![HTTPBackendRef {
            name: "disallowed-svc".to_string(),
            namespace: Some("backend-ns".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (_backends, resolved, reason) =
            resolve_backend_refs(&refs, "route-ns", &store);
        assert!(!resolved);
        assert_eq!(
            reason, "RefNotPermitted",
            "grant for specific name should reject other names"
        );
    }

    #[test]
    fn test_conformance_reference_grant_wildcard_name_allows_any() {
        // Grant with name=None allows any Service in the target namespace
        let store = ConfigStore::new();
        let grant_key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "wildcard-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "route-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None, // wildcard: any service name
                }],
            },
        );
        store.endpoints.insert(
            ServiceKey {
                namespace: "backend-ns".to_string(),
                name: "any-svc".to_string(),
                port: 8080,
            },
            vec![portus_types::BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8080,
            }],
        );

        let refs = vec![HTTPBackendRef {
            name: "any-svc".to_string(),
            namespace: Some("backend-ns".to_string()),
            port: Some(8080),
            weight: None,
            group: None,
            kind: None,
            filters: vec![],
        }];

        let (backends, resolved, reason) =
            resolve_backend_refs(&refs, "route-ns", &store);
        assert!(resolved, "wildcard grant should allow any service");
        assert_eq!(reason, "ResolvedRefs");
        assert_eq!(backends.len(), 1);
    }

    // --- Issue 1: InvalidParentRefNotMatchingListenerPort ---

    #[test]
    fn test_bind_to_parents_port_mismatch_rejected() {
        // Conformance: HTTPRouteInvalidParentRefNotMatchingListenerPort
        // parentRef specifies port=81 but Gateway listener is on port=80
        // Expected: Accepted=False, Reason=NoMatchingParent
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref_with_port(
            "same-namespace",
            Some("gateway-conformance-infra"),
            None,
            Some(81), // mismatched port
        )];
        let result = bind_to_parents(&refs, "gateway-conformance-infra", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            !result[0].accepted,
            "parentRef with port=81 should not match listener on port=80"
        );
        assert_eq!(
            result[0].reject_reason.as_deref(),
            Some("NoMatchingParent"),
            "reason must be NoMatchingParent when port doesn't match any listener"
        );
        assert_eq!(result[0].port, Some(81));
    }

    #[test]
    fn test_bind_to_parents_port_match_accepted() {
        // parentRef specifies port=80 which matches the listener
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "same-namespace",
            "gateway-conformance-infra",
            vec![make_listener("http", 80, "HTTP", None, "Same")],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref_with_port(
            "same-namespace",
            Some("gateway-conformance-infra"),
            None,
            Some(80), // matching port
        )];
        let result = bind_to_parents(&refs, "gateway-conformance-infra", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            result[0].accepted,
            "parentRef with port=80 should match listener on port=80"
        );
    }

    #[test]
    fn test_bind_to_parents_port_filters_to_specific_listener() {
        // Gateway has listeners on port 80 (HTTP) and 443 (HTTPS)
        // parentRef specifies port=443, should only bind to HTTPS listener
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "multi-port-gw",
            "default",
            vec![
                make_listener("http", 80, "HTTP", None, "Same"),
                make_listener("https", 443, "HTTPS", None, "Same"),
            ],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref_with_port(
            "multi-port-gw",
            None,
            None,
            Some(443),
        )];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(result[0].accepted);
        assert_eq!(result[0].port, Some(443));
    }

    #[test]
    fn test_bind_to_parents_no_port_matches_all_listeners() {
        // When no port is specified, route should match any compatible listener
        let store = ConfigStore::new();
        let (key, gw) = make_gateway(
            "multi-port-gw",
            "default",
            vec![
                make_listener("http", 80, "HTTP", None, "Same"),
                make_listener("tcp", 9000, "TCP", None, "Same"),
            ],
        );
        store.gateways.insert(key, gw);

        let refs = vec![make_parent_ref_with_port(
            "multi-port-gw",
            None,
            None,
            None, // no port filter
        )];
        let result = bind_to_parents(&refs, "default", &std::collections::BTreeMap::new(), &[], &store);

        assert_eq!(result.len(), 1);
        assert!(
            result[0].accepted,
            "should match the HTTP listener (protocol match)"
        );
    }
}
