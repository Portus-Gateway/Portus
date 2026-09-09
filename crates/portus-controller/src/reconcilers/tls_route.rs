//! TLSRoute reconciler with SNI-based TLS passthrough.
//!
//! Converts TLSRoute resources into TLSRouteState in ConfigStore.
//! Validates that parentRefs bind to TLS-protocol listeners.
//! Uses shared `is_reference_allowed` from mod.rs for cross-namespace backend
//! ref checking.

use super::{hostname_matches, is_reference_allowed, ReconcileContext, ReconcileError, CONTROLLER_NAME};
use crate::gateway_types::{TLSRoute, ParentReference};
use crate::reconcilers::http_route::namespace_allowed;
use crate::status;
use crate::store::{RouteKind, ParentKind, 
    BackendRefState, ConfigStore, NamespacedName, ParentRefState, TLSRouteState,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Reconciler functions
// ---------------------------------------------------------------------------

/// Validate parentRef bindings against Gateway listeners for TLS protocol.
///
/// For each parentRef, checks:
/// - Gateway exists in store
/// - sectionName matches a listener (if specified)
/// - Listener protocol is "TLS"
/// - Listener hostname is compatible with route hostnames
fn bind_to_parents_tls(
    parent_refs: &[ParentReference],
    route_namespace: &str,
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
        if group != "gateway.networking.k8s.io" || kind != "Gateway" {
            continue;
        }

        let gw_namespace = pref.namespace.as_deref().unwrap_or(route_namespace);
        let gw_name = &pref.name;
        let key = NamespacedName {
            namespace: gw_namespace.to_string(),
            name: gw_name.to_string(),
        };

        let gw = match store.gateways.get(&key) {
            Some(gw) => gw.clone(),
            None => {
                results.push(ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: gw_namespace.to_string(),
                    gateway_name: gw_name.to_string(),
                    section_name: pref.section_name.clone(),
                    port: pref.port,
                    accepted: false,
                    resolved_refs: false,
                    reject_reason: Some("NoMatchingParent".to_string()),
                });
                continue;
            }
        };

        // If sectionName is specified, check it matches a listener
        if let Some(ref section) = pref.section_name
            && !gw.listeners.iter().any(|l| l.name == *section) {
                results.push(ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: gw_namespace.to_string(),
                    gateway_name: gw_name.to_string(),
                    section_name: pref.section_name.clone(),
                    port: pref.port,
                    accepted: false,
                    resolved_refs: true,
                    reject_reason: Some("NoMatchingParent".to_string()),
                });
                continue;
            }

        let section_name = pref.section_name.as_deref();

        let mut accepted = false;
        let mut has_protocol_match = false;
        let mut has_hostname_match = false;

        for l in &gw.listeners {
            // If sectionName specified, must match
            if let Some(sn) = section_name
                && sn != l.name {
                    continue;
                }

            // TLSRoute only binds to TLS protocol listeners
            if l.protocol != "TLS" {
                continue;
            }
            has_protocol_match = true;

            // Hostname compatibility
            if let Some(ref lh) = l.hostname
                && !route_hostnames.is_empty()
                    && !route_hostnames.iter().any(|rh| hostname_matches(lh, rh))
                {
                    continue;
                }
            has_hostname_match = true;

            // AllowedRoutes namespace check. TLSRoute does not currently
            // evaluate Selector mode — pass empty labels (Same/All unaffected).
            let empty_labels = std::collections::BTreeMap::new();
            if !namespace_allowed(
                &l.allowed_routes,
                route_namespace,
                &gw.namespace,
                &empty_labels,
            ) {
                continue;
            }

            if l.accepted {
                accepted = true;
                break;
            }
        }

        let reject_reason = if accepted {
            None
        } else if has_protocol_match && !has_hostname_match {
            Some("NoMatchingListenerHostname".to_string())
        } else {
            Some("NotAllowedByListeners".to_string())
        };

        results.push(ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: gw_namespace.to_string(),
            gateway_name: gw_name.to_string(),
            section_name: pref.section_name.clone(),
            port: pref.port,
            accepted,
            resolved_refs: true,
            reject_reason,
        });
    }

    results
}

/// Check if a route hostname matches a listener hostname, handling wildcards.
/// Check if a listener hostname and route hostname can intersect (for attachment).
/// Gateway API spec: wildcards match any subdomain depth.
/// - `*.com` matches `abc.example.com` (multi-level)
/// - `*.example.com` matches `foo.example.com`
/// - `abc.example.com` matches `*.example.com`
///
/// Public wrapper for use in gateway reconciler attachedRoutes counting.
pub fn hostname_matches_pub(listener: &str, route: &str) -> bool {
    hostname_matches(listener, route)
}
// Local hostname_matches removed — now uses super::hostname_matches

/// Core reconciliation logic for TLSRoute.
/// Separated from async reconcile for testability.
pub fn reconcile_tls_route_inner(
    route: &TLSRoute,
    store: &ConfigStore,
) -> Result<(), ReconcileError> {
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
    let generation = route.metadata.generation.unwrap_or(0);

    // Bind to parent Gateways (TLS protocol only)
    let mut parent_refs =
        bind_to_parents_tls(&route.spec.parent_refs, namespace, &route.spec.hostnames, store);

    // Resolve backend refs from the first rule
    let mut backend_refs = Vec::new();
    let mut all_resolved = true;
    let mut resolved_reason = "ResolvedRefs";

    if let Some(rule) = route.spec.rules.first() {
        for bref in &rule.backend_refs {
            // Validate group and kind: only core group ("" or unset) + Service kind supported
            let group = bref.group.as_deref().unwrap_or("");
            let kind = bref.kind.as_deref().unwrap_or("Service");
            if !group.is_empty() || kind != "Service" {
                all_resolved = false;
                resolved_reason = "InvalidKind";
                continue;
            }

            let ns = bref.namespace.as_deref().unwrap_or(namespace);
            let port = bref.port.unwrap_or(0);
            let weight = bref.weight.unwrap_or(1);

            // Cross-namespace check
            if ns != namespace
                && !is_reference_allowed(
                    &store.reference_grants,
                    namespace,
                    "TLSRoute",
                    ns,
                    "Service",
                    Some(&bref.name),
                )
            {
                all_resolved = false;
                if resolved_reason == "ResolvedRefs" {
                    resolved_reason = "RefNotPermitted";
                }
                continue;
            }

            // Check if the backend Service exists in the store
            let svc_exists = store.service_port_map.iter().any(|entry| {
                let key = entry.key();
                key.namespace == ns && key.name == bref.name
            }) || store.endpoints.iter().any(|entry| {
                let key = entry.key();
                key.namespace == ns && key.name == bref.name
            });
            if !svc_exists {
                all_resolved = false;
                if resolved_reason == "ResolvedRefs" {
                    resolved_reason = "BackendNotFound";
                }
            }

            backend_refs.push(BackendRefState {
                namespace: ns.to_string(),
                name: bref.name.clone(),
                port,
                weight,
                filters: vec![],
            });
        }
    }

    // Update resolved_refs on accepted parent_refs
    for pref in &mut parent_refs {
        if pref.accepted {
            pref.resolved_refs = all_resolved;
        }
    }

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    if !super::any_parent_known(store, &parent_refs) {
        super::remove_route(store, &store.tls_routes, RouteKind::Tls, &key);
        return Ok(());
    }

    let state = TLSRouteState {
        namespace: namespace.to_string(),
        hostnames: route.spec.hostnames.clone(),
        parent_refs,
        backend_refs,
        generation,
        resolved_reason: resolved_reason.to_string(),
    };

    super::store_route(store, &store.tls_routes, RouteKind::Tls, key, state);

    Ok(())
}

/// Main reconcile function for TLSRoute resources.
pub async fn reconcile_tls_route(
    route: Arc<TLSRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = route.metadata.name.as_deref().unwrap_or_default();
    let namespace = route.metadata.namespace.as_deref().unwrap_or_default();

    // Skip reconciliation for objects being deleted
    if route.metadata.deletion_timestamp.is_some() {
        log::info!("TLSRoute {}/{} is being deleted, cleaning up", namespace, name);
        let key = NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        super::remove_route(&ctx.store, &ctx.store.tls_routes, RouteKind::Tls, &key);
        return Ok(Action::await_change());
    }

    reconcile_tls_route_inner(&route, &ctx.store)?;
    let generation = route.metadata.generation.unwrap_or(0).max(1);

    let route_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    if let Some(stored) = ctx.store.tls_routes.get(&route_key) {
        let resolved_reason = stored.resolved_reason.as_str();
        let mut parent_statuses = Vec::new();
        let mut desired_conditions: Vec<Condition> = Vec::new();

        for pref in stored.parent_refs.iter().filter(|p| super::parent_known(&ctx.store, p)) {
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

            let mut parent_ref_json = serde_json::Map::new();
            parent_ref_json.insert("group".to_string(), json!("gateway.networking.k8s.io"));
            parent_ref_json.insert("kind".to_string(), json!("Gateway"));
            parent_ref_json.insert("name".to_string(), json!(pref.gateway_name));
            parent_ref_json.insert("namespace".to_string(), json!(pref.gateway_namespace));
            if let Some(ref sn) = pref.section_name {
                parent_ref_json.insert("sectionName".to_string(), json!(sn));
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
                "parentRef": parent_ref_json,
                "controllerName": CONTROLLER_NAME,
                "conditions": conditions_json,
            }));

            desired_conditions.push(accepted_cond);
            desired_conditions.push(resolved_cond);
        }

        let existing_parents = route.status.as_ref().map(|s| s.parents.as_slice()).unwrap_or_default();
        let current_conditions = status::own_parent_conditions(existing_parents);

        let desired_status = json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "TLSRoute",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "status": {
                "parents": status::merge_route_parents(existing_parents, parent_statuses)
            }
        });

        let accepted_count = stored.parent_refs.iter().filter(|pr| pr.accepted).count();
        log::info!(
            "TLSRoute {}/{}: gen={}, parents={}/{} accepted, hostnames={:?}",
            namespace, name, generation, accepted_count, stored.parent_refs.len(), stored.hostnames
        );

        let api: Api<TLSRoute> = Api::namespaced(ctx.client.clone(), namespace);
        if let Err(e) = status::patch_status_if_changed(
            &api,
            name,
            desired_status,
            &current_conditions,
            &desired_conditions,
        )
        .await
        {
            log::warn!("failed to write TLSRoute status for {}/{}: {}; retrying", namespace, name, e);
            return Err(e.into());
        }
    }

    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{
        TLSBackendRef, TLSRouteRule, TLSRouteSpec, ParentReference,
    };
    use crate::store::{
        AllowedRoutesState, ConfigStore, GatewayState, ListenerState,
        ReferenceGrantFrom, ReferenceGrantState, ReferenceGrantTo, ServiceKey,
    };
    use portus_types::BackendEndpoint;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_listener(name: &str, protocol: &str, port: u16, hostname: Option<&str>, accepted: bool) -> ListenerState {
        ListenerState {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: hostname.map(|h| h.to_string()),
            accepted,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: AllowedRoutesState {
                namespaces_from: "All".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: None,
        }
    }

    fn make_gateway(name: &str, ns: &str, listeners: Vec<ListenerState>) -> GatewayState {
        GatewayState {
            name: name.to_string(),
            namespace: ns.to_string(),
            listeners,
            generation: 1,
            allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        }
    }

    fn make_tls_route(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        hostnames: Vec<String>,
        backend_refs: Vec<TLSBackendRef>,
    ) -> TLSRoute {
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs,
                hostnames,
                rules: vec![TLSRouteRule { backend_refs }],
            },
            status: None,
        }
    }

    // --- bind_to_parents_tls tests ---

    #[test]
    fn test_tls_route_accepted_with_tls_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(parents[0].accepted);
    }

    #[test]
    fn test_tls_route_rejected_with_http_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", 80, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
    }

    #[test]
    fn test_tls_route_stores_sni_hostnames() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["a.example.com".to_string(), "b.example.com".to_string()],
            vec![TLSBackendRef {
                name: "backend".to_string(),
                port: Some(443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).expect("route should be stored");
        assert_eq!(stored.hostnames, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn test_tls_route_backend_refs_resolved_with_grant() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        // Add grant for cross-namespace
        let grant_key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-tls".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "TLSRoute".to_string(),
                    namespace: "default".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None,
                }],
            },
        );

        // Add service so it's found in the store
        store.endpoints.insert(
            ServiceKey {
                namespace: "backend-ns".to_string(),
                name: "backend-svc".to_string(),
                port: 8443,
            },
            vec![BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 8443,
            }],
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![TLSBackendRef {
                name: "backend-svc".to_string(),
                namespace: Some("backend-ns".to_string()),
                port: Some(8443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).unwrap();
        assert_eq!(stored.backend_refs.len(), 1);
        assert_eq!(stored.backend_refs[0].namespace, "backend-ns");
        assert_eq!(stored.backend_refs[0].name, "backend-svc");
        assert_eq!(stored.backend_refs[0].port, 8443);
        assert!(stored.parent_refs[0].resolved_refs);
    }

    // --- reject_reason tests ---

    #[test]
    fn test_tls_route_reject_reason_no_matching_parent() {
        // Gateway doesn't exist → NoMatchingParent
        let store = ConfigStore::new();

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "nonexistent-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
        assert_eq!(
            parents[0].reject_reason.as_deref(),
            Some("NoMatchingParent"),
            "gateway not found should produce NoMatchingParent"
        );
    }

    #[test]
    fn test_tls_route_reject_reason_section_name_mismatch() {
        // sectionName doesn't match any listener → NoMatchingParent
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("nonexistent-listener".to_string()),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
        assert_eq!(
            parents[0].reject_reason.as_deref(),
            Some("NoMatchingParent"),
            "sectionName mismatch should produce NoMatchingParent"
        );
    }

    #[test]
    fn test_tls_route_reject_reason_protocol_mismatch() {
        // HTTP listener → NotAllowedByListeners
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", 80, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
        assert_eq!(
            parents[0].reject_reason.as_deref(),
            Some("NotAllowedByListeners"),
            "protocol mismatch should produce NotAllowedByListeners"
        );
    }

    #[test]
    fn test_tls_route_reject_reason_hostname_mismatch() {
        // Hostnames don't intersect → NoMatchingListenerHostname
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway(
                "my-gw",
                "default",
                vec![make_listener("tls", "TLS", 443, Some("other.example.com"), true)],
            ),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![],
        );

        let parents = bind_to_parents_tls(
            &route.spec.parent_refs,
            "default",
            &route.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
        assert_eq!(
            parents[0].reject_reason.as_deref(),
            Some("NoMatchingListenerHostname"),
            "hostname mismatch should produce NoMatchingListenerHostname"
        );
    }

    #[test]
    fn test_tls_route_less_specific_wildcard_listener_accepts_multi_level() {
        // Conformance: TLSRouteHostnameIntersection / less specific wildcard listener
        // Listener *.com should accept routes with abc.example.com and *.example.com
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "gw-wildcard-com".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway(
                "gw-wildcard-com",
                "default",
                vec![make_listener("tls", "TLS", 443, Some("*.com"), true)],
            ),
        );

        // Route with exact hostname abc.example.com → should be accepted
        let route_exact = make_tls_route(
            "route-exact",
            "default",
            vec![ParentReference {
                name: "gw-wildcard-com".to_string(),
                ..Default::default()
            }],
            vec!["abc.example.com".to_string()],
            vec![],
        );
        let parents = bind_to_parents_tls(
            &route_exact.spec.parent_refs,
            "default",
            &route_exact.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(
            parents[0].accepted,
            "*.com listener should accept route with abc.example.com (multi-level)"
        );

        // Route with wildcard *.example.com → should be accepted
        let route_wc = make_tls_route(
            "route-wc",
            "default",
            vec![ParentReference {
                name: "gw-wildcard-com".to_string(),
                ..Default::default()
            }],
            vec!["*.example.com".to_string()],
            vec![],
        );
        let parents = bind_to_parents_tls(
            &route_wc.spec.parent_refs,
            "default",
            &route_wc.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(
            parents[0].accepted,
            "*.com listener should accept route with *.example.com"
        );

        // Route with non-intersecting hostname → should be rejected
        let route_bad = make_tls_route(
            "route-bad",
            "default",
            vec![ParentReference {
                name: "gw-wildcard-com".to_string(),
                ..Default::default()
            }],
            vec!["abc.example.org".to_string()],
            vec![],
        );
        let parents = bind_to_parents_tls(
            &route_bad.spec.parent_refs,
            "default",
            &route_bad.spec.hostnames,
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(
            !parents[0].accepted,
            "*.com listener should reject route with abc.example.org"
        );
    }

    // --- backend ref validation tests ---

    #[test]
    fn test_tls_route_backend_ref_invalid_kind() {
        // Non-Service backendRef → InvalidKind (ResolvedRefs=False)
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![TLSBackendRef {
                name: "backend".to_string(),
                port: Some(443),
                group: Some("example.com".to_string()),
                kind: Some("NonExistent".to_string()),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).unwrap();
        assert!(!stored.parent_refs[0].resolved_refs, "should have unresolved refs");
    }

    #[test]
    fn test_tls_route_backend_ref_nonexistent_service() {
        // Service doesn't exist in store → BackendNotFound (ResolvedRefs=False)
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![TLSBackendRef {
                name: "nonexistent-svc".to_string(),
                port: Some(443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).unwrap();
        assert!(!stored.parent_refs[0].resolved_refs, "nonexistent service should be unresolved");
    }

    #[test]
    fn test_tls_route_backend_ref_cross_ns_no_grant() {
        // Cross-namespace ref without ReferenceGrant → RefNotPermitted (ResolvedRefs=False)
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec!["secure.example.com".to_string()],
            vec![TLSBackendRef {
                name: "backend-svc".to_string(),
                namespace: Some("other-ns".to_string()),
                port: Some(443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).unwrap();
        assert!(!stored.parent_refs[0].resolved_refs, "cross-ns without grant should be unresolved");
    }

    #[test]
    fn test_tls_route_cross_ns_no_grant_unresolved() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tls", "TLS", 443, None, true)]),
        );

        let route = make_tls_route(
            "tls-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec![],
            vec![TLSBackendRef {
                name: "backend-svc".to_string(),
                namespace: Some("other-ns".to_string()),
                port: Some(443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        let stored = store.tls_routes.get(&key).unwrap();
        assert!(!stored.parent_refs[0].resolved_refs);
        assert!(stored.backend_refs.is_empty());
    }

    // --- Conformance: TLSRouteMixedTerminationSameNamespace ---

    /// Verify a TLS route with hostname tls.example.com binds to the
    /// Terminate listener on a gateway with mixed TLS listeners.
    #[test]
    fn test_tls_route_binds_to_matching_terminate_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "gateway-tlsroute-mixed-termination".to_string(),
        };

        let mut terminate_listener = make_listener("tls-terminate", "TLS", 8883, Some("tls.example.com"), true);
        terminate_listener.tls_mode = Some("Terminate".to_string());
        terminate_listener.tls_cert_refs = vec![("default".to_string(), "tls-terminate-checks-certificate".to_string())];

        let mut passthrough_listener = make_listener("tls-passthrough", "TLS", 8883, Some("abc.example.com"), true);
        passthrough_listener.tls_mode = Some("Passthrough".to_string());

        store.gateways.insert(
            gw_key,
            make_gateway(
                "gateway-tlsroute-mixed-termination",
                "default",
                vec![terminate_listener, passthrough_listener],
            ),
        );

        // Add service endpoint so backend resolves
        store.endpoints.insert(
            ServiceKey {
                namespace: "default".to_string(),
                name: "tcp-backend".to_string(),
                port: 3000,
            },
            vec![BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 3000,
            }],
        );

        // TLSRoute with hostname tls.example.com, no sectionName
        let route = make_tls_route(
            "gateway-conformance-mixed-terminateroute",
            "default",
            vec![ParentReference {
                name: "gateway-tlsroute-mixed-termination".to_string(),
                ..Default::default()
            }],
            vec!["tls.example.com".to_string()],
            vec![TLSBackendRef {
                name: "tcp-backend".to_string(),
                port: Some(3000),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "gateway-conformance-mixed-terminateroute".to_string(),
        };
        let stored = store.tls_routes.get(&key).expect("route should be stored");
        assert_eq!(stored.parent_refs.len(), 1);
        assert!(
            stored.parent_refs[0].accepted,
            "terminate route should be accepted by gateway"
        );
        assert!(
            stored.parent_refs[0].resolved_refs,
            "terminate route backend refs should be resolved"
        );
        assert_eq!(stored.hostnames, vec!["tls.example.com"]);
        assert_eq!(stored.backend_refs.len(), 1);
        assert_eq!(stored.backend_refs[0].name, "tcp-backend");
        assert_eq!(stored.backend_refs[0].port, 3000);
    }

    /// Verify a TLS route with hostname abc.example.com binds to the
    /// Passthrough listener on a gateway with mixed TLS listeners.
    #[test]
    fn test_tls_route_binds_to_matching_passthrough_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "gateway-tlsroute-mixed-termination".to_string(),
        };

        let mut terminate_listener = make_listener("tls-terminate", "TLS", 8883, Some("tls.example.com"), true);
        terminate_listener.tls_mode = Some("Terminate".to_string());
        terminate_listener.tls_cert_refs = vec![("default".to_string(), "tls-terminate-checks-certificate".to_string())];

        let mut passthrough_listener = make_listener("tls-passthrough", "TLS", 8883, Some("abc.example.com"), true);
        passthrough_listener.tls_mode = Some("Passthrough".to_string());

        store.gateways.insert(
            gw_key,
            make_gateway(
                "gateway-tlsroute-mixed-termination",
                "default",
                vec![terminate_listener, passthrough_listener],
            ),
        );

        // Add service endpoint so backend resolves
        store.endpoints.insert(
            ServiceKey {
                namespace: "default".to_string(),
                name: "tcp-backend".to_string(),
                port: 8443,
            },
            vec![BackendEndpoint {
                address: "10.0.0.2".to_string(),
                port: 8443,
            }],
        );

        // TLSRoute with hostname abc.example.com, no sectionName
        let route = make_tls_route(
            "gateway-conformance-mixed-passthroughroute",
            "default",
            vec![ParentReference {
                name: "gateway-tlsroute-mixed-termination".to_string(),
                ..Default::default()
            }],
            vec!["abc.example.com".to_string()],
            vec![TLSBackendRef {
                name: "tcp-backend".to_string(),
                port: Some(8443),
                ..Default::default()
            }],
        );

        reconcile_tls_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "gateway-conformance-mixed-passthroughroute".to_string(),
        };
        let stored = store.tls_routes.get(&key).expect("route should be stored");
        assert_eq!(stored.parent_refs.len(), 1);
        assert!(
            stored.parent_refs[0].accepted,
            "passthrough route should be accepted by gateway"
        );
        assert!(
            stored.parent_refs[0].resolved_refs,
            "passthrough route backend refs should be resolved"
        );
        assert_eq!(stored.hostnames, vec!["abc.example.com"]);
        assert_eq!(stored.backend_refs.len(), 1);
        assert_eq!(stored.backend_refs[0].name, "tcp-backend");
        assert_eq!(stored.backend_refs[0].port, 8443);
    }
}
