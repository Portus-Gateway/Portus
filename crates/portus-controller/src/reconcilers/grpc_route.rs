//! GRPCRoute reconciler with service/method matching.
//!
//! Converts GRPCRoute resources into GRPCRouteState in ConfigStore.
//! Uses shared `is_reference_allowed` from mod.rs for cross-namespace checks.

use super::{is_reference_allowed, ReconcileContext, ReconcileError, CONTROLLER_NAME};
use crate::gateway_types::{GRPCRoute, GRPCRouteMatch, GRPCRouteRule};
use crate::status;
use crate::store::{RouteKind, ParentKind, 
    BackendRefState, ConfigStore, GRPCRouteMatchState, GRPCRouteRuleState, GRPCRouteState,
    NamespacedName, ParentRefState,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

// -- Core logic functions --

/// Convert GRPCRouteMatch specs into GRPCRouteMatchState for ConfigStore.
fn convert_grpc_matches(spec_matches: &[GRPCRouteMatch]) -> Vec<GRPCRouteMatchState> {
    spec_matches
        .iter()
        .map(|m| {
            let (service, method, match_type) = match &m.method {
                Some(mm) => {
                    let svc = mm.service.as_ref().filter(|s| !s.is_empty()).cloned();
                    let meth = mm.method.as_ref().filter(|s| !s.is_empty()).cloned();
                    let mt = mm
                        .match_type
                        .as_ref()
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .unwrap_or_else(|| "Exact".to_string());
                    (svc, meth, mt)
                }
                None => (None, None, "Exact".to_string()),
            };
            let headers: Vec<(String, String, String)> = m
                .headers
                .iter()
                .map(|h| {
                    let mt = h
                        .match_type
                        .as_deref()
                        .unwrap_or("Exact")
                        .to_string();
                    (h.name.clone(), h.value.clone(), mt)
                })
                .collect();
            GRPCRouteMatchState {
                service,
                method,
                match_type,
                headers,
            }
        })
        .collect()
}

/// Bind GRPCRoute to parent Gateway listeners. Accepted protocols: HTTP, HTTPS.
fn bind_grpc_to_parents(
    route: &GRPCRoute,
    route_namespace: &str,
    store: &ConfigStore,
) -> Vec<ParentRefState> {
    let mut results = Vec::new();
    for pref in &route.spec.parent_refs {
        // Validate group is gateway.networking.k8s.io or empty (default)
        let group = pref.group.as_deref().unwrap_or("gateway.networking.k8s.io");
        if group != "gateway.networking.k8s.io" && !group.is_empty() {
            continue;
        }

        // Only Gateway kind (or empty default)
        let kind = pref.kind.as_deref().unwrap_or("Gateway");
        if kind != "Gateway" {
            continue;
        }

        let gw_namespace = pref.namespace.as_deref().unwrap_or(route_namespace);
        let gw_name = &pref.name;
        let section_name = pref.section_name.as_deref();

        let gw_key = NamespacedName {
            namespace: gw_namespace.to_string(),
            name: gw_name.clone(),
        };

        // Look up gateway in store
        let accepted = match store.gateways.get(&gw_key) {
            Some(gw) => {
                // Find matching listeners (HTTP or HTTPS for gRPC over HTTP/2)
                gw.listeners.iter().any(|l| {
                    let proto_ok = l.protocol == "HTTP" || l.protocol == "HTTPS";
                    let section_ok = section_name.map(|sn| sn == l.name).unwrap_or(true);
                    proto_ok && section_ok && l.accepted
                })
            }
            None => false,
        };

        results.push(ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: gw_namespace.to_string(),
            gateway_name: gw_name.clone(),
            section_name: pref.section_name.clone(),
            port: pref.port,
            accepted,
            resolved_refs: true, // will be updated per backend resolution
            reject_reason: None,
        });
    }
    results
}

/// Resolve GRPCRoute backend refs using is_reference_allowed for cross-namespace.
/// Returns (backend_refs, all_resolved).
fn resolve_grpc_backend_refs(
    rule: &GRPCRouteRule,
    route_namespace: &str,
    store: &ConfigStore,
) -> (Vec<BackendRefState>, bool) {
    let mut refs = Vec::new();
    let mut all_resolved = true;

    for bref in &rule.backend_refs {
        let kind = bref.kind.as_deref().unwrap_or("Service");
        if kind != "Service" {
            all_resolved = false;
            continue;
        }

        let ns = bref.namespace.as_deref().unwrap_or(route_namespace);
        let port = bref.port.unwrap_or(0);
        let weight = bref.weight.unwrap_or(1);

        // Cross-namespace check
        if ns != route_namespace
            && !is_reference_allowed(
                &store.reference_grants,
                route_namespace,
                "GRPCRoute",
                ns,
                "Service",
                Some(&bref.name),
            )
        {
            all_resolved = false;
            continue;
        }

        refs.push(BackendRefState {
            namespace: ns.to_string(),
            name: bref.name.clone(),
            port,
            weight,
            filters: vec![],
        });
    }

    (refs, all_resolved)
}

/// Core reconciliation logic: builds GRPCRouteState from the route and inserts into store.
/// Separated from the async reconcile function so it can be unit-tested without a kube Client.
pub fn reconcile_grpc_route_inner(
    route: &GRPCRoute,
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

    // Bind to parent Gateways
    let mut parent_refs = bind_grpc_to_parents(route, namespace, store);

    // Process rules
    let mut rules = Vec::new();
    let mut all_refs_resolved = true;
    for rule in &route.spec.rules {
        let matches = convert_grpc_matches(&rule.matches);
        let (backend_refs, resolved) = resolve_grpc_backend_refs(rule, namespace, store);
        if !resolved {
            all_refs_resolved = false;
        }
        rules.push(GRPCRouteRuleState {
            matches,
            backend_refs,
        });
    }

    // Update resolved_refs on parent_refs based on backend resolution
    for pref in &mut parent_refs {
        pref.resolved_refs = all_refs_resolved;
    }

    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    if !super::any_parent_known(store, &parent_refs) {
        super::remove_route(store, &store.grpc_routes, RouteKind::Grpc, &key);
        return Ok(());
    }

    let state = GRPCRouteState {
        namespace: namespace.to_string(),
        hostnames: route.spec.hostnames.clone(),
        parent_refs,
        rules,
        generation,
    };

    super::store_route(store, &store.grpc_routes, RouteKind::Grpc, key, state);

    Ok(())
}

/// Main reconcile function for GRPCRoute resources.
pub async fn reconcile_grpc_route(
    route: Arc<GRPCRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = route.metadata.name.as_deref().unwrap_or_default();
    let namespace = route.metadata.namespace.as_deref().unwrap_or_default();

    // Skip reconciliation for objects being deleted
    if route.metadata.deletion_timestamp.is_some() {
        log::info!("GRPCRoute {}/{} is being deleted, cleaning up", namespace, name);
        let key = NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        super::remove_route(&ctx.store, &ctx.store.grpc_routes, RouteKind::Grpc, &key);
        return Ok(Action::await_change());
    }

    reconcile_grpc_route_inner(&route, &ctx.store)?;
    let generation = route.metadata.generation.unwrap_or(0).max(1);

    let route_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    if let Some(stored) = ctx.store.grpc_routes.get(&route_key) {
        let mut parent_statuses = Vec::new();
        let mut desired_conditions: Vec<Condition> = Vec::new();

        for pref in stored.parent_refs.iter().filter(|p| super::parent_known(&ctx.store, p)) {
            let accepted_cond = status::build_condition(
                "Accepted",
                pref.accepted,
                if pref.accepted { "Accepted" } else { "NotAllowedByListeners" },
                if pref.accepted {
                    "Route accepted by parent Gateway"
                } else {
                    "Route not allowed by listener"
                },
                generation,
            );
            let resolved_cond = status::build_condition(
                "ResolvedRefs",
                pref.resolved_refs,
                if pref.resolved_refs { "ResolvedRefs" } else { "BackendNotFound" },
                if pref.resolved_refs {
                    "All backend references resolved"
                } else {
                    "One or more backend references could not be resolved"
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
            "kind": "GRPCRoute",
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
            "GRPCRoute {}/{}: gen={}, parents={}/{} accepted, rules={}",
            namespace, name, generation, accepted_count, stored.parent_refs.len(), stored.rules.len()
        );

        let api: Api<GRPCRoute> = Api::namespaced(ctx.client.clone(), namespace);
        if let Err(e) = status::patch_status_if_changed(
            &api,
            name,
            desired_status,
            &current_conditions,
            &desired_conditions,
        )
        .await
        {
            log::warn!("failed to write GRPCRoute status for {}/{}: {}; will retry on next reconcile", namespace, name, e);
        }
    }

    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Event, ParentKind, RouteKind};
    use crate::gateway_types::{
        GRPCBackendRef, GRPCMethodMatch, GRPCRouteMatch as GRPCRouteMatchInput,
        GRPCRouteRule as GRPCRouteRuleInput, GRPCRouteSpec, ParentReference,
    };
    use crate::store::{
        AllowedRoutesState, ConfigStore, GatewayState, ListenerState, ReferenceGrantFrom,
        ReferenceGrantState, ReferenceGrantTo,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_store() -> Arc<ConfigStore> {
        Arc::new(ConfigStore::new())
    }

    fn make_listener(name: &str, protocol: &str, accepted: bool) -> ListenerState {
        ListenerState {
            name: name.to_string(),
            port: 80,
            protocol: protocol.to_string(),
            hostname: None,
            accepted,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: AllowedRoutesState {
                namespaces_from: "Same".to_string(),
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

    fn make_grpc_route(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        rules: Vec<GRPCRouteRuleInput>,
        hostnames: Vec<String>,
    ) -> GRPCRoute {
        GRPCRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GRPCRouteSpec {
                hostnames,
                parent_refs,
                rules,
            },
            status: None,
        }
    }

    // --- convert_grpc_matches tests ---

    #[test]
    fn test_service_and_method_exact_match() {
        let matches = vec![GRPCRouteMatchInput {
            method: Some(GRPCMethodMatch {
                match_type: Some("Exact".to_string()),
                service: Some("mypackage.MyService".to_string()),
                method: Some("DoThing".to_string()),
            }),
            ..Default::default()
        }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, Some("mypackage.MyService".to_string()));
        assert_eq!(result[0].method, Some("DoThing".to_string()));
        assert_eq!(result[0].match_type, "Exact");
    }

    #[test]
    fn test_service_only_no_method_matches_all_methods() {
        let matches = vec![GRPCRouteMatchInput {
            method: Some(GRPCMethodMatch {
                match_type: None,
                service: Some("mypackage.MyService".to_string()),
                method: None,
            }),
            ..Default::default()
        }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, Some("mypackage.MyService".to_string()));
        assert_eq!(result[0].method, None);
        assert_eq!(result[0].match_type, "Exact");
    }

    #[test]
    fn test_empty_service_and_method_matches_all_grpc_traffic() {
        let matches = vec![GRPCRouteMatchInput {
            method: Some(GRPCMethodMatch {
                match_type: None,
                service: Some("".to_string()),
                method: Some("".to_string()),
            }),
            ..Default::default()
        }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, None);
        assert_eq!(result[0].method, None);
        assert_eq!(result[0].match_type, "Exact");
    }

    #[test]
    fn test_no_method_field_at_all_matches_all() {
        let matches = vec![GRPCRouteMatchInput { method: None, ..Default::default() }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, None);
        assert_eq!(result[0].method, None);
        assert_eq!(result[0].match_type, "Exact");
    }

    // --- bind_grpc_to_parents tests ---

    #[test]
    fn a_route_with_no_parent_of_ours_is_not_stored_and_publishes_nothing() {
        let store = ConfigStore::new();
        let mut events = store.events.subscribe();
        store.take_dirty();
        let route = make_grpc_route(
            "orphan",
            "default",
            vec![ParentReference { name: "someone-elses".to_string(), ..Default::default() }],
            vec![],
            vec![],
        );
        reconcile_grpc_route_inner(&route, &store).unwrap();
        assert!(store.grpc_routes.is_empty(), "not ours to program");
        assert!(!store.take_dirty(), "and not worth a compile");
        assert!(events.try_recv().is_err());

        // The Gateway appears (its own event re-runs the route): now it is stored
        // and its parents are told.
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "someone-elses".into() },
            make_gateway("someone-elses", "default", vec![make_listener("http", "HTTP", true)]),
        );
        reconcile_grpc_route_inner(&route, &store).unwrap();
        assert_eq!(store.grpc_routes.len(), 1);
        assert!(store.take_dirty());
        match events.try_recv().unwrap() {
            Event::Route { kind: RouteKind::Grpc, key, parents, .. } => {
                assert_eq!(key.name, "orphan");
                assert_eq!(parents, vec![(ParentKind::Gateway, NamespacedName { namespace: "default".into(), name: "someone-elses".into() })]);
            }
            other => panic!("unexpected event {other:?}"),
        }

        // Reconciling the same route again changes nothing: no compile, no event,
        // so the Gateway it would trigger cannot trigger it back for ever.
        reconcile_grpc_route_inner(&route, &store).unwrap();
        assert!(!store.take_dirty());
        assert!(events.try_recv().is_err());

        // Deleting the Gateway (its event re-runs the route) drops the route and
        // names the parent that lost it.
        store.gateways.clear();
        reconcile_grpc_route_inner(&route, &store).unwrap();
        assert!(store.grpc_routes.is_empty());
        assert!(matches!(events.try_recv().unwrap(), Event::Route { parents, .. } if parents.len() == 1));
    }

    #[test]
    fn test_parent_ref_binds_to_http_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", true)]),
        );

        let route = make_grpc_route(
            "grpc-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec![],
            vec![],
        );

        let parents = bind_grpc_to_parents(&route, "default", &store);
        assert_eq!(parents.len(), 1);
        assert!(parents[0].accepted);
    }

    #[test]
    fn test_parent_ref_binds_to_https_listener() {
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
                vec![make_listener("https", "HTTPS", true)],
            ),
        );

        let route = make_grpc_route(
            "grpc-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec![],
            vec![],
        );

        let parents = bind_grpc_to_parents(&route, "default", &store);
        assert_eq!(parents.len(), 1);
        assert!(parents[0].accepted);
    }

    #[test]
    fn test_parent_ref_not_accepted_for_tcp_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", true)]),
        );

        let route = make_grpc_route(
            "grpc-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            vec![],
            vec![],
        );

        let parents = bind_grpc_to_parents(&route, "default", &store);
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
    }

    // --- resolve_grpc_backend_refs tests ---

    #[test]
    fn test_backend_refs_resolve_same_namespace() {
        let store = ConfigStore::new();
        let rule = GRPCRouteRuleInput {
            matches: vec![],
            backend_refs: vec![GRPCBackendRef {
                name: "backend-svc".to_string(),
                port: Some(8080),
                weight: Some(1),
                ..Default::default()
            }],
        };

        let (refs, resolved) = resolve_grpc_backend_refs(&rule, "default", &store);
        assert!(resolved);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].namespace, "default");
        assert_eq!(refs[0].name, "backend-svc");
        assert_eq!(refs[0].port, 8080);
    }

    #[test]
    fn test_cross_namespace_without_grant_fails() {
        let store = ConfigStore::new();
        let rule = GRPCRouteRuleInput {
            matches: vec![],
            backend_refs: vec![GRPCBackendRef {
                name: "backend-svc".to_string(),
                namespace: Some("other-ns".to_string()),
                port: Some(8080),
                weight: Some(1),
                ..Default::default()
            }],
        };

        let (refs, resolved) = resolve_grpc_backend_refs(&rule, "default", &store);
        assert!(!resolved);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_cross_namespace_with_grant_succeeds() {
        let store = ConfigStore::new();
        let grant_key = NamespacedName {
            namespace: "other-ns".to_string(),
            name: "allow-grpc".to_string(),
        };
        store.reference_grants.insert(
            grant_key,
            ReferenceGrantState {
                namespace: "other-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "GRPCRoute".to_string(),
                    namespace: "default".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None,
                }],
            },
        );

        let rule = GRPCRouteRuleInput {
            matches: vec![],
            backend_refs: vec![GRPCBackendRef {
                name: "backend-svc".to_string(),
                namespace: Some("other-ns".to_string()),
                port: Some(8080),
                weight: Some(1),
                ..Default::default()
            }],
        };

        let (refs, resolved) = resolve_grpc_backend_refs(&rule, "default", &store);
        assert!(resolved);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].namespace, "other-ns");
    }

    // --- Full reconcile_inner tests (pure store logic, no kube Client needed) ---

    #[test]
    fn test_reconcile_grpc_route_stores_state() {
        let store = make_store();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", true)]),
        );

        let route = GRPCRoute {
            metadata: ObjectMeta {
                name: Some("grpc-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(3),
                ..Default::default()
            },
            spec: GRPCRouteSpec {
                hostnames: vec!["grpc.example.com".to_string()],
                parent_refs: vec![ParentReference {
                    name: "my-gw".to_string(),
                    ..Default::default()
                }],
                rules: vec![GRPCRouteRuleInput {
                    matches: vec![GRPCRouteMatchInput {
                        method: Some(GRPCMethodMatch {
                            match_type: Some("Exact".to_string()),
                            service: Some("pkg.Svc".to_string()),
                            method: Some("Do".to_string()),
                        }),
                        ..Default::default()
                    }],
                    backend_refs: vec![GRPCBackendRef {
                        name: "backend".to_string(),
                        port: Some(9090),
                        weight: Some(1),
                        ..Default::default()
                    }],
                }],
            },
            status: None,
        };

        let result = reconcile_grpc_route_inner(&route, &store);
        assert!(result.is_ok());

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route".to_string(),
        };
        let entry = store.grpc_routes.get(&key).expect("route should be stored");
        assert_eq!(entry.generation, 3);
        assert_eq!(entry.hostnames, vec!["grpc.example.com".to_string()]);
        assert_eq!(entry.parent_refs.len(), 1);
        assert!(entry.parent_refs[0].accepted);
        assert!(entry.parent_refs[0].resolved_refs);
        assert_eq!(entry.rules.len(), 1);
        assert_eq!(entry.rules[0].matches.len(), 1);
        assert_eq!(
            entry.rules[0].matches[0].service,
            Some("pkg.Svc".to_string())
        );
        assert_eq!(entry.rules[0].matches[0].method, Some("Do".to_string()));
        assert_eq!(entry.rules[0].backend_refs.len(), 1);
        assert_eq!(entry.rules[0].backend_refs[0].name, "backend");
        assert_eq!(entry.rules[0].backend_refs[0].port, 9090);
    }

    #[test]
    fn test_reconcile_grpc_route_cross_ns_no_grant_unresolved() {
        let store = make_store();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", true)]),
        );

        let route = GRPCRoute {
            metadata: ObjectMeta {
                name: Some("grpc-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GRPCRouteSpec {
                hostnames: vec![],
                parent_refs: vec![ParentReference {
                    name: "my-gw".to_string(),
                    ..Default::default()
                }],
                rules: vec![GRPCRouteRuleInput {
                    matches: vec![],
                    backend_refs: vec![GRPCBackendRef {
                        name: "backend".to_string(),
                        namespace: Some("other-ns".to_string()),
                        port: Some(8080),
                        ..Default::default()
                    }],
                }],
            },
            status: None,
        };

        let result = reconcile_grpc_route_inner(&route, &store);
        assert!(result.is_ok());

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route".to_string(),
        };
        let entry = store.grpc_routes.get(&key).expect("route should be stored");
        // ResolvedRefs should be false because cross-namespace ref without grant
        assert!(!entry.parent_refs[0].resolved_refs);
    }

    // --- Header parsing tests ---

    #[test]
    fn test_convert_grpc_matches_parses_headers() {
        use crate::gateway_types::GRPCHeaderMatch;

        let matches = vec![GRPCRouteMatchInput {
            method: Some(GRPCMethodMatch {
                match_type: Some("Exact".to_string()),
                service: Some("pkg.Svc".to_string()),
                method: Some("Call".to_string()),
            }),
            headers: vec![
                GRPCHeaderMatch {
                    match_type: Some("Exact".to_string()),
                    name: "version".to_string(),
                    value: "one".to_string(),
                },
                GRPCHeaderMatch {
                    match_type: None, // defaults to Exact
                    name: "color".to_string(),
                    value: "blue".to_string(),
                },
            ],
        }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].headers.len(), 2);
        assert_eq!(result[0].headers[0], ("version".to_string(), "one".to_string(), "Exact".to_string()));
        assert_eq!(result[0].headers[1], ("color".to_string(), "blue".to_string(), "Exact".to_string()));
    }

    #[test]
    fn test_convert_grpc_matches_empty_headers() {
        let matches = vec![GRPCRouteMatchInput {
            method: Some(GRPCMethodMatch {
                match_type: Some("Exact".to_string()),
                service: Some("pkg.Svc".to_string()),
                method: None,
            }),
            ..Default::default()
        }];
        let result = convert_grpc_matches(&matches);
        assert_eq!(result.len(), 1);
        assert!(result[0].headers.is_empty());
    }

    #[test]
    fn test_reconcile_grpc_route_stores_headers() {
        use crate::gateway_types::GRPCHeaderMatch;

        let store = make_store();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", true)]),
        );

        let route = GRPCRoute {
            metadata: ObjectMeta {
                name: Some("grpc-hdr-route".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GRPCRouteSpec {
                hostnames: vec![],
                parent_refs: vec![ParentReference {
                    name: "my-gw".to_string(),
                    ..Default::default()
                }],
                rules: vec![GRPCRouteRuleInput {
                    matches: vec![GRPCRouteMatchInput {
                        method: Some(GRPCMethodMatch {
                            match_type: Some("Exact".to_string()),
                            service: Some("pkg.Svc".to_string()),
                            method: Some("Do".to_string()),
                        }),
                        headers: vec![
                            GRPCHeaderMatch {
                                match_type: Some("Exact".to_string()),
                                name: "x-version".to_string(),
                                value: "v1".to_string(),
                            },
                        ],
                    }],
                    backend_refs: vec![GRPCBackendRef {
                        name: "backend".to_string(),
                        port: Some(9090),
                        weight: Some(1),
                        ..Default::default()
                    }],
                }],
            },
            status: None,
        };

        let result = reconcile_grpc_route_inner(&route, &store);
        assert!(result.is_ok());

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-hdr-route".to_string(),
        };
        let entry = store.grpc_routes.get(&key).expect("route should be stored");
        assert_eq!(entry.rules[0].matches[0].headers.len(), 1);
        assert_eq!(
            entry.rules[0].matches[0].headers[0],
            ("x-version".to_string(), "v1".to_string(), "Exact".to_string())
        );
    }
}
