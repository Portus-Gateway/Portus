//! TCPRoute and UDPRoute reconciler.
//!
//! Both kinds have the same shape (parentRefs plus one rule of backendRefs)
//! and the same semantics, differing only in the listener protocol they bind
//! to, so one implementation serves both through the [`L4Route`] trait.
//! Converts a route into an [`L4RouteState`] in the ConfigStore. A parentRef
//! binds to every listener of the route's protocol on the Gateway that matches
//! its optional `sectionName` and `port` (neither set = all such listeners).
//! When several routes bind the same listener every route is still `Accepted`;
//! the compiler programs only the oldest one (Gateway API conflict resolution)
//! and the listener's `attachedRoutes` counts them all.
//! Uses shared `is_reference_allowed` from mod.rs for cross-namespace backend
//! ref checking and the Service/EndpointSlice caches for `BackendNotFound`.

use super::{is_reference_allowed, ReconcileContext, ReconcileError, CONTROLLER_NAME};
use crate::gateway_types::{L4RouteRule, ParentReference, RouteParentStatus, TCPRoute, UDPRoute};
use crate::reconcilers::http_route::namespace_allowed;
use crate::status;
use crate::store::{
    BackendRefState, RouteKind, ConfigStore, L4RouteState, NamespacedName, ParentKind, ParentRefState,
};
use dashmap::DashMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::Resource;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::fmt::Debug;
use std::sync::Arc;

/// What the shared reconcile needs from a TCPRoute or UDPRoute.
pub trait L4Route:
    Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope> + Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// Kind name used in status patches and ReferenceGrant `from` checks.
    const KIND: &'static str;
    /// Listener protocol this kind binds to.
    const PROTOCOL: &'static str;
    /// Event tag for this kind's store changes.
    const ROUTE_KIND: RouteKind;
    /// The store map holding this kind's state.
    fn routes(store: &ConfigStore) -> &DashMap<NamespacedName, L4RouteState>;
    fn parent_refs(&self) -> &[ParentReference];
    fn rules(&self) -> &[L4RouteRule];
    fn status_parents(&self) -> &[RouteParentStatus];
}

impl L4Route for TCPRoute {
    const KIND: &'static str = "TCPRoute";
    const PROTOCOL: &'static str = "TCP";
    const ROUTE_KIND: RouteKind = RouteKind::Tcp;
    fn routes(store: &ConfigStore) -> &DashMap<NamespacedName, L4RouteState> {
        &store.tcp_routes
    }
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn rules(&self) -> &[L4RouteRule] {
        &self.spec.rules
    }
    fn status_parents(&self) -> &[RouteParentStatus] {
        self.status.as_ref().map(|s| s.parents.as_slice()).unwrap_or_default()
    }
}

impl L4Route for UDPRoute {
    const KIND: &'static str = "UDPRoute";
    const PROTOCOL: &'static str = "UDP";
    const ROUTE_KIND: RouteKind = RouteKind::Udp;
    fn routes(store: &ConfigStore) -> &DashMap<NamespacedName, L4RouteState> {
        &store.udp_routes
    }
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn rules(&self) -> &[L4RouteRule] {
        &self.spec.rules
    }
    fn status_parents(&self) -> &[RouteParentStatus] {
        self.status.as_ref().map(|s| s.parents.as_slice()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Reconciler functions
// ---------------------------------------------------------------------------

/// Validate parentRef bindings against Gateway listeners of `protocol`.
fn bind_to_parents_l4(
    protocol: &str,
    parent_refs: &[ParentReference],
    route_namespace: &str,
    route_ns_labels: &std::collections::BTreeMap<String, String>,
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
                    reject_reason: None,
                });
                continue;
            }
        };

        let section_name = pref.section_name.as_deref();

        // Listeners the parentRef points at: sectionName and/or port narrow the
        // set; neither set means every listener on the Gateway.
        let candidates: Vec<_> = gw
            .listeners
            .iter()
            .filter(|l| section_name.is_none_or(|sn| sn == l.name))
            .filter(|l| pref.port.is_none_or(|p| p == l.port))
            .collect();

        let allowed = |l: &&crate::store::ListenerState| {
            l.protocol == protocol
                && namespace_allowed(&l.allowed_routes, route_namespace, &gw.namespace, route_ns_labels)
        };
        let (accepted, reject_reason) = if candidates.is_empty() {
            (false, Some("NoMatchingParent".to_string()))
        } else if !candidates.iter().any(|l| l.protocol == protocol) {
            // The referenced listener exists but speaks another protocol.
            (false, Some("NotAllowedByListeners".to_string()))
        } else if !candidates.iter().any(allowed) {
            (false, Some("NotAllowedByListeners".to_string()))
        } else if candidates.iter().any(|l| l.accepted && allowed(l)) {
            (true, None)
        } else {
            (false, Some("NoMatchingParent".to_string()))
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

/// Core reconciliation logic for a TCPRoute or UDPRoute.
/// Separated from async reconcile for testability.
pub fn reconcile_l4_route_inner<K: L4Route>(
    route: &K,
    store: &ConfigStore,
) -> Result<(), ReconcileError> {
    let meta = route.meta();
    let name = meta
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = meta
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let generation = meta.generation.unwrap_or(0);

    // Bind to parent Gateways (listeners of this kind's protocol only). Route
    // namespace labels come from the Namespace reconciler cache for
    // `namespaces.from: Selector`.
    let route_ns_labels = store
        .namespace_labels
        .get(namespace)
        .map(|v| v.value().clone())
        .unwrap_or_default();
    let mut parent_refs =
        bind_to_parents_l4(K::PROTOCOL, route.parent_refs(), namespace, &route_ns_labels, store);

    // Resolve backend refs from the first rule
    let mut backend_refs = Vec::new();
    let mut all_resolved = true;
    let mut resolved_refs_reason: Option<String> = None;

    if let Some(rule) = route.rules().first() {
        for bref in &rule.backend_refs {
            let ns = bref.namespace.as_deref().unwrap_or(namespace);
            let port = bref.port.unwrap_or(0);
            let weight = bref.weight.unwrap_or(1);

            // Cross-namespace check
            if ns != namespace
                && !is_reference_allowed(
                    &store.reference_grants,
                    namespace,
                    K::KIND,
                    ns,
                    "Service",
                    Some(&bref.name),
                )
            {
                all_resolved = false;
                resolved_refs_reason.get_or_insert_with(|| "RefNotPermitted".to_string());
                continue;
            }

            // The Service must exist: seen by the Service reconciler (ports) or
            // by the EndpointSlice reconciler (endpoints).
            let svc_exists = store.service_port_map.iter().any(|entry| {
                let key = entry.key();
                key.namespace == ns && key.name == bref.name
            }) || store.endpoints.iter().any(|entry| {
                let key = entry.key();
                key.namespace == ns && key.name == bref.name
            });
            if !svc_exists {
                all_resolved = false;
                resolved_refs_reason.get_or_insert_with(|| "BackendNotFound".to_string());
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

    // Update resolved_refs on parent_refs
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
        super::remove_route(store, K::routes(store), K::ROUTE_KIND, &key);
        return Ok(());
    }

    let state = L4RouteState {
        namespace: namespace.to_string(),
        parent_refs,
        backend_refs,
        generation,
        creation_timestamp: meta.creation_timestamp.clone(),
        resolved_refs_reason,
    };

    super::store_route(store, K::routes(store), K::ROUTE_KIND, key, state);

    Ok(())
}

/// Main reconcile function for TCPRoute and UDPRoute resources.
pub async fn reconcile_l4_route<K: L4Route>(
    route: Arc<K>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let meta = route.meta();
    let name = meta.name.as_deref().unwrap_or_default();
    let namespace = meta.namespace.as_deref().unwrap_or_default();
    let route_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };

    // Skip reconciliation for objects being deleted
    if meta.deletion_timestamp.is_some() {
        super::remove_route(&ctx.store, K::routes(&ctx.store), K::ROUTE_KIND, &route_key);
        return Ok(Action::await_change());
    }

    reconcile_l4_route_inner(route.as_ref(), &ctx.store)?;
    let generation = meta.generation.unwrap_or(0);

    if let Some(stored) = K::routes(&ctx.store).get(&route_key) {
        let mut parent_statuses = Vec::new();
        let mut desired_conditions: Vec<Condition> = Vec::new();

        for pref in stored.parent_refs.iter().filter(|p| super::parent_known(&ctx.store, p)) {
            let (accepted_reason, accepted_msg) = if pref.accepted {
                ("Accepted", "Route accepted by parent Gateway".to_string())
            } else {
                match pref.reject_reason.as_deref() {
                    Some("NotAllowedByListeners") => (
                        "NotAllowedByListeners",
                        format!(
                            "The referenced listener is not a {} listener or does not allow routes from this namespace",
                            K::PROTOCOL
                        ),
                    ),
                    _ => ("NoMatchingParent", "No listener on the parent Gateway matches this parentRef".to_string()),
                }
            };

            let accepted_cond = status::build_condition(
                "Accepted",
                pref.accepted,
                accepted_reason,
                &accepted_msg,
                generation,
            );
            let resolved_reason = if pref.resolved_refs {
                "ResolvedRefs"
            } else {
                stored.resolved_refs_reason.as_deref().unwrap_or("BackendNotFound")
            };
            let resolved_cond = status::build_condition(
                "ResolvedRefs",
                pref.resolved_refs,
                resolved_reason,
                match resolved_reason {
                    "ResolvedRefs" => "All backend references resolved",
                    "RefNotPermitted" => "A cross-namespace backend reference is not permitted by any ReferenceGrant",
                    _ => "One or more backend Services do not exist",
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
            if let Some(port) = pref.port {
                parent_ref_json.insert("port".to_string(), json!(port));
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

        let existing_parents = route.status_parents();
        let current_conditions = status::own_parent_conditions(existing_parents);

        let desired_status = json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": K::KIND,
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "status": {
                "parents": status::merge_route_parents(existing_parents, parent_statuses)
            }
        });

        let api: Api<K> = Api::namespaced(ctx.client.clone(), namespace);
        if let Err(e) = status::patch_status_if_changed(
            &api,
            name,
            desired_status,
            &current_conditions,
            &desired_conditions,
        )
        .await
        {
            log::warn!("failed to write {} status for {}/{}: {}; will retry on next reconcile", K::KIND, namespace, name, e);
        }
    }

    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{L4BackendRef, L4RouteRule, ParentReference, TCPRouteSpec, UDPRouteSpec};
    use crate::store::{AllowedRoutesState, ConfigStore, GatewayState, ListenerState};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_listener(name: &str, protocol: &str, port: u16, accepted: bool) -> ListenerState {
        ListenerState {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: None,
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

    fn meta(name: &str, namespace: &str) -> ObjectMeta {
        ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            generation: Some(1),
            ..Default::default()
        }
    }

    fn make_tcp_route(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<L4BackendRef>,
    ) -> TCPRoute {
        TCPRoute {
            metadata: meta(name, namespace),
            spec: TCPRouteSpec {
                parent_refs,
                rules: vec![L4RouteRule { backend_refs }],
            },
            status: None,
        }
    }

    fn make_udp_route(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<L4BackendRef>,
    ) -> UDPRoute {
        UDPRoute {
            metadata: meta(name, namespace),
            spec: UDPRouteSpec {
                parent_refs,
                rules: vec![L4RouteRule { backend_refs }],
            },
            status: None,
        }
    }

    fn bind_to_parents_tcp(
        parent_refs: &[ParentReference],
        route_namespace: &str,
        route_ns_labels: &std::collections::BTreeMap<String, String>,
        store: &ConfigStore,
    ) -> Vec<ParentRefState> {
        bind_to_parents_l4("TCP", parent_refs, route_namespace, route_ns_labels, store)
    }

    // --- bind_to_parents tests ---

    #[test]
    fn test_tcp_route_accepted_with_tcp_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", 5432, true)]),
        );

        let parents = bind_to_parents_tcp(
            &[ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("tcp".to_string()),
                ..Default::default()
            }],
            "default",
            &std::collections::BTreeMap::new(),
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(parents[0].accepted);
    }

    #[test]
    fn test_tcp_route_rejected_with_http_listener() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("http", "HTTP", 80, true)]),
        );

        let parents = bind_to_parents_tcp(
            &[ParentReference {
                name: "my-gw".to_string(),
                ..Default::default()
            }],
            "default",
            &std::collections::BTreeMap::new(),
            &store,
        );
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].accepted);
        assert_eq!(parents[0].reject_reason.as_deref(), Some("NotAllowedByListeners"));
    }

    #[test]
    fn test_tcp_route_binds_by_port_and_by_section_and_port() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "gw".into() },
            make_gateway("gw", "default", vec![
                make_listener("one", "TCP", 9300, true),
                make_listener("two", "TCP", 9301, true),
                make_listener("three", "TCP", 9302, true),
            ]),
        );
        let labels = std::collections::BTreeMap::new();
        // port only
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), port: Some(9300), ..Default::default() }], "default", &labels, &store);
        assert!(p[0].accepted && p[0].reject_reason.is_none(), "{:?}", p[0]);
        // section + port that agree
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), section_name: Some("three".into()), port: Some(9302), ..Default::default() }], "default", &labels, &store);
        assert!(p[0].accepted);
        // section + port that disagree → no listener matches both
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), section_name: Some("three".into()), port: Some(9300), ..Default::default() }], "default", &labels, &store);
        assert!(!p[0].accepted);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NoMatchingParent"));
        // unknown port
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), port: Some(1), ..Default::default() }], "default", &labels, &store);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NoMatchingParent"));
    }

    #[test]
    fn test_tcp_route_without_section_or_port_attaches_to_all_tcp_listeners() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "gw".into() },
            make_gateway("gw", "default", vec![
                make_listener("http", "HTTP", 80, true),
                make_listener("one", "TCP", 9310, true),
                make_listener("two", "TCP", 9311, true),
            ]),
        );
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), ..Default::default() }], "default", &std::collections::BTreeMap::new(), &store);
        assert!(p[0].accepted, "a bare parentRef attaches to every TCP listener");
    }

    #[test]
    fn test_tcp_route_section_name_pointing_at_http_listener_is_not_allowed() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "gw".into() },
            make_gateway("gw", "default", vec![make_listener("only-allow-http-routes", "HTTP", 5300, true)]),
        );
        let p = bind_to_parents_tcp(
            &[ParentReference { name: "gw".into(), section_name: Some("only-allow-http-routes".into()), ..Default::default() }],
            "default", &std::collections::BTreeMap::new(), &store,
        );
        assert!(!p[0].accepted);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NotAllowedByListeners"));
    }

    // --- UDPRoute binds UDP listeners with the same rules, and only those ---

    #[test]
    fn test_udp_route_binds_udp_listeners_not_tcp_or_tls() {
        // udproute-simple (UDP listener) and udproute-not-allowed-by-listeners
        // (TLS listener -> NotAllowedByListeners, zero attached routes).
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "gw".into() },
            make_gateway("gw", "default", vec![
                make_listener("coredns", "UDP", 5300, true),
                make_listener("tcp", "TCP", 5300, true),
                make_listener("tls", "TLS", 443, true),
            ]),
        );
        let labels = std::collections::BTreeMap::new();
        let p = bind_to_parents_l4("UDP", &[ParentReference { name: "gw".into(), section_name: Some("coredns".into()), ..Default::default() }], "default", &labels, &store);
        assert!(p[0].accepted);
        let p = bind_to_parents_l4("UDP", &[ParentReference { name: "gw".into(), section_name: Some("tls".into()), ..Default::default() }], "default", &labels, &store);
        assert!(!p[0].accepted);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NotAllowedByListeners"));
        let p = bind_to_parents_l4("UDP", &[ParentReference { name: "gw".into(), section_name: Some("tcp".into()), ..Default::default() }], "default", &labels, &store);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NotAllowedByListeners"), "a TCP listener is not a UDPRoute parent");
        // Bare parentRef: attaches because a UDP listener exists.
        let p = bind_to_parents_l4("UDP", &[ParentReference { name: "gw".into(), ..Default::default() }], "default", &labels, &store);
        assert!(p[0].accepted);
        // And a TCPRoute on the same Gateway binds the TCP listener, not the UDP one.
        let p = bind_to_parents_tcp(&[ParentReference { name: "gw".into(), section_name: Some("coredns".into()), ..Default::default() }], "default", &labels, &store);
        assert_eq!(p[0].reject_reason.as_deref(), Some("NotAllowedByListeners"));
    }

    #[test]
    fn test_udp_route_lands_in_udp_routes_with_its_backends() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "udp-gateway".into() },
            make_gateway("udp-gateway", "default", vec![make_listener("coredns", "UDP", 5300, true)]),
        );
        store.service_port_map.insert(
            crate::store::ServiceKey { namespace: "default".into(), name: "coredns".into(), port: 53 },
            53,
        );
        let route = make_udp_route(
            "udp-coredns",
            "default",
            vec![ParentReference { name: "udp-gateway".into(), section_name: Some("coredns".into()), ..Default::default() }],
            vec![L4BackendRef { name: "coredns".into(), port: Some(53), ..Default::default() }],
        );
        reconcile_l4_route_inner(&route, &store).unwrap();
        let key = NamespacedName { namespace: "default".into(), name: "udp-coredns".into() };
        let stored = store.udp_routes.get(&key).expect("stored under udp_routes");
        assert!(store.tcp_routes.get(&key).is_none(), "never under tcp_routes");
        assert!(stored.parent_refs[0].accepted);
        assert!(stored.parent_refs[0].resolved_refs);
        assert_eq!(stored.backend_refs[0].port, 53);
    }

    #[test]
    fn test_udp_route_cross_namespace_backend_needs_a_grant_naming_udproute() {
        // udproute-invalid-cross-namespace-backend-ref / udproute-reference-grant
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "gw".into() },
            make_gateway("gw", "default", vec![make_listener("udp", "UDP", 5300, true)]),
        );
        let route = make_udp_route(
            "cross",
            "default",
            vec![ParentReference { name: "gw".into(), ..Default::default() }],
            vec![L4BackendRef { name: "udp-echo".into(), namespace: Some("other".into()), port: Some(8080), ..Default::default() }],
        );
        reconcile_l4_route_inner(&route, &store).unwrap();
        let key = NamespacedName { namespace: "default".into(), name: "cross".into() };
        {
            // Scoped: a live DashMap guard would deadlock the re-reconcile below.
            let stored = store.udp_routes.get(&key).unwrap();
            assert!(stored.parent_refs[0].accepted);
            assert!(!stored.parent_refs[0].resolved_refs);
            assert_eq!(stored.resolved_refs_reason.as_deref(), Some("RefNotPermitted"));
        }

        // A ReferenceGrant from UDPRoute/default to Service in `other` fixes it.
        store.reference_grants.insert(
            NamespacedName { namespace: "other".into(), name: "allow".into() },
            crate::store::ReferenceGrantState {
                namespace: "other".into(),
                from: vec![crate::store::ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".into(),
                    kind: "UDPRoute".into(),
                    namespace: "default".into(),
                }],
                to: vec![crate::store::ReferenceGrantTo { group: String::new(), kind: "Service".into(), name: None }],
            },
        );
        store.service_port_map.insert(
            crate::store::ServiceKey { namespace: "other".into(), name: "udp-echo".into(), port: 8080 },
            8080,
        );
        reconcile_l4_route_inner(&route, &store).unwrap();
        let stored = store.udp_routes.get(&key).unwrap();
        assert!(stored.parent_refs[0].resolved_refs);
        assert!(stored.resolved_refs_reason.is_none());
        assert_eq!(stored.backend_refs.len(), 1);
    }

    // --- several routes on one listener: all Accepted, compiler picks the oldest ---

    #[test]
    fn test_two_tcp_routes_same_listener_are_both_accepted() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", 5432, true)]),
        );

        // First route binds successfully
        let route1 = make_tcp_route(
            "tcp-route-1",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("tcp".to_string()),
                ..Default::default()
            }],
            vec![L4BackendRef {
                name: "backend-1".to_string(),
                port: Some(5432),
                ..Default::default()
            }],
        );
        reconcile_l4_route_inner(&route1, &store).unwrap();

        // Verify first route accepted
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "tcp-route-1".to_string(),
        };
        assert!(store.tcp_routes.get(&key1).unwrap().parent_refs[0].accepted);

        let route2 = make_tcp_route(
            "tcp-route-2",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("tcp".to_string()),
                ..Default::default()
            }],
            vec![L4BackendRef {
                name: "backend-2".to_string(),
                port: Some(5432),
                ..Default::default()
            }],
        );
        reconcile_l4_route_inner(&route2, &store).unwrap();

        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "tcp-route-2".to_string(),
        };
        let stored2 = store.tcp_routes.get(&key2).unwrap();
        assert!(
            stored2.parent_refs[0].accepted,
            "both routes report Accepted=True; the listener-attachment conflict is resolved by the compiler (oldest wins)"
        );
    }

    // --- backend ref tests ---

    #[test]
    fn test_tcp_route_backend_refs_resolved() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", 5432, true)]),
        );

        store.service_port_map.insert(
            crate::store::ServiceKey { namespace: "default".into(), name: "pg-svc".into(), port: 5432 },
            5432,
        );
        let route = make_tcp_route(
            "tcp-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("tcp".to_string()),
                ..Default::default()
            }],
            vec![L4BackendRef {
                name: "pg-svc".to_string(),
                port: Some(5432),
                ..Default::default()
            }],
        );

        reconcile_l4_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tcp-route".to_string(),
        };
        let stored = store.tcp_routes.get(&key).unwrap();
        assert_eq!(stored.backend_refs.len(), 1);
        assert_eq!(stored.backend_refs[0].name, "pg-svc");
        assert_eq!(stored.backend_refs[0].port, 5432);
        assert!(stored.parent_refs[0].resolved_refs);
        assert!(stored.resolved_refs_reason.is_none());
    }

    #[test]
    fn test_tcp_route_nonexistent_backend_is_backend_not_found() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "my-gw".into() },
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", 9300, true)]),
        );
        let route = make_tcp_route(
            "tcp-route-invalid-backend-ref-nonexistent",
            "default",
            vec![ParentReference { name: "my-gw".into(), section_name: Some("tcp".into()), ..Default::default() }],
            vec![L4BackendRef { name: "nonexistent-service".into(), port: Some(8080), ..Default::default() }],
        );
        reconcile_l4_route_inner(&route, &store).unwrap();
        let stored = store
            .tcp_routes
            .get(&NamespacedName { namespace: "default".into(), name: "tcp-route-invalid-backend-ref-nonexistent".into() })
            .unwrap();
        assert!(stored.parent_refs[0].accepted, "route is still Accepted");
        assert!(!stored.parent_refs[0].resolved_refs);
        assert_eq!(stored.resolved_refs_reason.as_deref(), Some("BackendNotFound"));
        // The backend is still recorded so the compiler can emit the route (it
        // simply has no endpoints until the Service appears).
        assert_eq!(stored.backend_refs.len(), 1);
    }

    #[test]
    fn test_tcp_route_cross_ns_no_grant_unresolved() {
        let store = ConfigStore::new();
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            make_gateway("my-gw", "default", vec![make_listener("tcp", "TCP", 5432, true)]),
        );

        let route = make_tcp_route(
            "tcp-route",
            "default",
            vec![ParentReference {
                name: "my-gw".to_string(),
                section_name: Some("tcp".to_string()),
                ..Default::default()
            }],
            vec![L4BackendRef {
                name: "pg-svc".to_string(),
                namespace: Some("other-ns".to_string()),
                port: Some(5432),
                ..Default::default()
            }],
        );

        reconcile_l4_route_inner(&route, &store).unwrap();

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tcp-route".to_string(),
        };
        let stored = store.tcp_routes.get(&key).unwrap();
        assert!(!stored.parent_refs[0].resolved_refs);
        assert_eq!(stored.resolved_refs_reason.as_deref(), Some("RefNotPermitted"));
        assert!(stored.backend_refs.is_empty());
    }
}
