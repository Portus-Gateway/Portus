use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
pub mod api_key_auth_policy;
pub mod backend_tls_policy;
pub mod basic_auth_policy;
pub mod policy_common;
pub mod provisioner;
pub mod circuit_breaker_policy;
pub mod configmap;
pub mod connection_policy;
pub mod cors_policy;
pub mod endpointslice;
pub mod gateway;
pub mod gateway_class;
pub mod grpc_route;
pub mod health_check_policy;
pub mod http_route;
pub mod ip_allowlist_policy;
pub mod listener_set;
pub mod namespace;
pub mod rate_limit_policy;
pub mod reference_grant;
pub mod request_body_size_limit_policy;
pub mod retry_policy;
pub mod secret;
pub mod service;
pub mod l4_route;
pub mod timeout_policy;
pub mod tls_route;

use crate::store::{ConfigStore, NamespacedName, ReferenceGrantState};
use dashmap::DashMap;
use std::sync::Arc;

pub const CONTROLLER_NAME: &str = "github.com/Portus-Gateway/Portus";
pub const FIELD_MANAGER: &str = "portus-gateway";

/// True when the parent a route names is one of ours: a Gateway (or ListenerSet)
/// this controller has accepted into the store. Routes get a `status.parents`
/// entry only for those; a parent that belongs to another implementation, or
/// does not exist, is that implementation's to report on.
/// Store a route's state and, if it differs from what was held, publish the
/// [`Event::Route`] its parents, ListenerSets and policies react to. Returns
/// whether anything changed.
pub fn store_route<S>(
    store: &crate::store::ConfigStore,
    map: &dashmap::DashMap<crate::store::NamespacedName, S>,
    kind: crate::store::RouteKind,
    key: crate::store::NamespacedName,
    state: S,
) -> bool
where
    S: crate::store::RouteState + PartialEq,
{
    let previous: Option<(Vec<_>, Vec<_>)> = map.get(&key).map(|p| (p.parents(), p.backends()));
    let (mut parents, mut backends) = (state.parents(), state.backends());
    if !store.insert_and_notify(map, key.clone(), state) {
        return false;
    }
    // The old parents lose a route as much as the new ones gain one.
    if let Some((old_parents, old_backends)) = previous {
        parents.extend(old_parents);
        backends.extend(old_backends);
        parents.sort();
        parents.dedup();
        backends.sort();
        backends.dedup();
    }
    store.publish(crate::store::Event::Route { kind, key, parents, backends });
    true
}

/// Remove a route's state (deleted, or no longer bound to any parent we know)
/// and publish the event for the parents it had. Returns whether it was stored.
pub fn remove_route<S>(
    store: &crate::store::ConfigStore,
    map: &dashmap::DashMap<crate::store::NamespacedName, S>,
    kind: crate::store::RouteKind,
    key: &crate::store::NamespacedName,
) -> bool
where
    S: crate::store::RouteState,
{
    let Some((_, gone)) = store.remove_and_notify(map, key) else {
        return false;
    };
    store.publish(crate::store::Event::Route {
        kind,
        key: key.clone(),
        parents: gone.parents(),
        backends: gone.backends(),
    });
    true
}

/// True when at least one parentRef names a Gateway or ListenerSet this
/// controller manages. A route bound only to other implementations' (or not
/// yet existing) parents is not stored: it is not ours to program or report
/// on, and the parent's own event re-runs the route when it appears.
pub fn any_parent_known(store: &crate::store::ConfigStore, prefs: &[crate::store::ParentRefState]) -> bool {
    prefs.iter().any(|p| parent_known(store, p))
}

pub fn parent_known(store: &crate::store::ConfigStore, pref: &crate::store::ParentRefState) -> bool {
    let key = crate::store::NamespacedName {
        namespace: pref.gateway_namespace.clone(),
        name: pref.gateway_name.clone(),
    };
    match pref.parent_kind {
        crate::store::ParentKind::Gateway => store.gateways.contains_key(&key),
        crate::store::ParentKind::ListenerSet => store.listener_sets.contains_key(&key),
    }
}

#[cfg(test)]
mod parent_known_tests {
    use super::parent_known;
    use crate::store::{ConfigStore, GatewayState, NamespacedName, ParentKind, ParentRefState};

    #[test]
    fn store_route_names_the_parents_a_route_moved_between() {
        use crate::store::{Event, L4RouteState, RouteKind};
        let store = ConfigStore::new();
        let mut events = store.events.subscribe();
        let key = NamespacedName { namespace: "apps".into(), name: "r".into() };
        let state = |gw: &str| L4RouteState {
            namespace: "apps".into(),
            parent_refs: vec![pref(ParentKind::Gateway, "infra", gw)],
            backend_refs: vec![],
            generation: 1,
            creation_timestamp: None,
            resolved_refs_reason: None,
        };
        assert!(super::store_route(&store, &store.tcp_routes, RouteKind::Tcp, key.clone(), state("a")));
        assert!(matches!(events.try_recv().unwrap(), Event::Route { parents, .. } if parents == vec![(ParentKind::Gateway, NamespacedName { namespace: "infra".into(), name: "a".into() })]));
        assert!(!super::store_route(&store, &store.tcp_routes, RouteKind::Tcp, key.clone(), state("a")), "unchanged");
        assert!(events.try_recv().is_err());
        // Re-pointed at Gateway b: a loses a route, b gains one; both are named.
        assert!(super::store_route(&store, &store.tcp_routes, RouteKind::Tcp, key.clone(), state("b")));
        match events.try_recv().unwrap() {
            Event::Route { parents, .. } => {
                let names: Vec<&str> = parents.iter().map(|(_, k)| k.name.as_str()).collect();
                assert_eq!(names, vec!["a", "b"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(super::remove_route(&store, &store.tcp_routes, RouteKind::Tcp, &key));
        assert!(matches!(events.try_recv().unwrap(), Event::Route { parents, .. } if parents.len() == 1));
        assert!(!super::remove_route(&store, &store.tcp_routes, RouteKind::Tcp, &key));
    }

    fn pref(kind: ParentKind, ns: &str, name: &str) -> ParentRefState {
        ParentRefState {
            parent_kind: kind,
            gateway_namespace: ns.into(),
            gateway_name: name.into(),
            section_name: None,
            port: None,
            accepted: false,
            resolved_refs: false,
            reject_reason: None,
        }
    }

    #[test]
    fn only_parents_in_the_store_get_a_status_entry() {
        // bench/agentgateway: a Gateway of another implementation's class is
        // never in our store, so the route gets no entry from us.
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName { namespace: "bench".into(), name: "portus".into() },
            GatewayState {
                name: "portus".into(),
                namespace: "bench".into(),
                listeners: vec![],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
        assert!(parent_known(&store, &pref(ParentKind::Gateway, "bench", "portus")));
        assert!(!parent_known(&store, &pref(ParentKind::Gateway, "bench", "agentgateway")));
        assert!(!parent_known(&store, &pref(ParentKind::ListenerSet, "bench", "portus")), "kind matters");
    }
}

/// Per-listener status output: (listener name, conditions, supported route kinds as (group, kind)).
pub(crate) type PerListenerConditions = Vec<(String, Vec<Condition>, Vec<(String, String)>)>;

/// Check if a route hostname matches a listener hostname per Gateway API spec.
///
/// For route attachment purposes, wildcards match at any subdomain depth:
/// `*.com` matches `abc.example.com` (multi-level) per Gateway API intersection
/// semantics. All comparisons are case-insensitive per DNS spec.
pub fn hostname_matches(listener: &str, route: &str) -> bool {
    let l = listener.to_ascii_lowercase();
    let r = route.to_ascii_lowercase();
    if l == r {
        return true;
    }
    // Listener wildcard: *.example.com matches foo.example.com, a.b.example.com, etc.
    if let Some(l_suffix) = l.strip_prefix("*.") {
        if let Some(r_suffix) = r.strip_prefix("*.") {
            // Both wildcards: overlap if one suffix contains the other
            return l_suffix == r_suffix
                || r_suffix.ends_with(&format!(".{}", l_suffix))
                || l_suffix.ends_with(&format!(".{}", r_suffix));
        }
        // Wildcard listener, exact route: multi-level match allowed
        if let Some(prefix) = r.strip_suffix(l_suffix).and_then(|p| p.strip_suffix('.')) {
            return !prefix.is_empty();
        }
    }
    // Route wildcard, listener exact: multi-level match allowed
    if let Some(r_suffix) = r.strip_prefix("*.")
        && let Some(prefix) = l.strip_suffix(r_suffix).and_then(|p| p.strip_suffix('.')) {
            return !prefix.is_empty();
        }
    false
}

/// Compute the intersection of a listener hostname and a route hostname.
/// Returns None if they don't intersect, or the more specific hostname (lowercased).
///
/// Gateway API intersection semantics: a wildcard like `*.example.com` intersects
/// with ANY hostname under that domain, including multi-level subdomains like
/// `foo.bar.example.com`. This is different from DNS wildcard matching (single-level
/// only) — intersection determines which hostnames a route should be compiled for,
/// while DNS matching determines what the dataplane actually routes.
/// All comparisons are case-insensitive per DNS spec.
pub fn intersect_hostnames(listener: &str, route: &str) -> Option<String> {
    let l_wild = listener.starts_with("*.");
    let r_wild = route.starts_with("*.");
    let l_lower = listener.to_ascii_lowercase();
    let r_lower = route.to_ascii_lowercase();

    match (l_wild, r_wild) {
        (false, false) => {
            if l_lower == r_lower {
                Some(l_lower)
            } else {
                None
            }
        }
        (true, false) => {
            // Listener wildcard, route exact: route must be under listener domain
            // Multi-level allowed: *.example.com intersects foo.bar.example.com
            let suffix = &l_lower[1..]; // ".example.com"
            if r_lower.ends_with(suffix) && r_lower.len() > suffix.len() {
                Some(r_lower)
            } else {
                None
            }
        }
        (false, true) => {
            // Listener exact, route wildcard: listener must be under route domain
            let suffix = &r_lower[1..]; // ".example.com"
            if l_lower.ends_with(suffix) && l_lower.len() > suffix.len() {
                Some(l_lower)
            } else {
                None
            }
        }
        (true, true) => {
            // Both wildcards: the more specific (longer suffix) wins
            let l_suffix = &l_lower[1..];
            let r_suffix = &r_lower[1..];
            if l_suffix == r_suffix {
                Some(l_lower)
            } else if r_suffix.ends_with(l_suffix) {
                Some(r_lower)
            } else if l_suffix.ends_with(r_suffix) {
                Some(l_lower)
            } else {
                None
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    #[error("provisioning: {0}")]
    Provision(#[from] provisioner::ProvisionError),
    #[error("missing field: {0}")]
    MissingField(String),
}

pub struct ReconcileContext {
    pub store: Arc<ConfigStore>,
    pub client: kube::Client,
}

/// Check whether a cross-namespace reference is allowed by examining
/// ReferenceGrant resources in the target namespace.
///
/// Same-namespace references are always allowed. Cross-namespace references
/// require a ReferenceGrant in the target namespace that permits the
/// from_namespace + from_kind to access to_kind (and optionally to_name).
pub fn is_reference_allowed(
    grants: &DashMap<NamespacedName, ReferenceGrantState>,
    from_namespace: &str,
    from_kind: &str,
    to_namespace: &str,
    to_kind: &str,
    to_name: Option<&str>,
) -> bool {
    // Same namespace is always allowed
    if from_namespace == to_namespace {
        return true;
    }
    // Check grants in target namespace
    for entry in grants.iter() {
        let grant = entry.value();
        if grant.namespace != to_namespace {
            continue;
        }
        for from in &grant.from {
            // Gateway API spec: from.group must match the referencing resource's group
            if from.group != "gateway.networking.k8s.io" {
                continue;
            }
            if from.namespace == from_namespace && from.kind == from_kind {
                for to in &grant.to {
                    // Gateway API spec: to.group "" means core API group (Services)
                    if !to.group.is_empty() {
                        continue;
                    }
                    if to.kind == to_kind
                        && (to.name.is_none() || to.name.as_deref() == to_name) {
                            return true;
                        }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ReferenceGrantFrom, ReferenceGrantTo};

    #[test]
    fn test_same_namespace_returns_true_without_grants() {
        let grants = DashMap::new();
        assert!(is_reference_allowed(
            &grants,
            "default",
            "HTTPRoute",
            "default",
            "Service",
            Some("my-svc"),
        ));
    }

    #[test]
    fn test_cross_namespace_no_grants_returns_false() {
        let grants = DashMap::new();
        assert!(!is_reference_allowed(
            &grants,
            "app-ns",
            "HTTPRoute",
            "backend-ns",
            "Service",
            Some("my-svc"),
        ));
    }

    #[test]
    fn test_cross_namespace_with_matching_grant_returns_true() {
        let grants = DashMap::new();
        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-app".to_string(),
        };
        grants.insert(
            key,
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
                    name: None, // allow all services
                }],
            },
        );
        assert!(is_reference_allowed(
            &grants,
            "app-ns",
            "HTTPRoute",
            "backend-ns",
            "Service",
            Some("my-svc"),
        ));
    }

    #[test]
    fn test_cross_namespace_with_grant_for_wrong_kind_returns_false() {
        let grants = DashMap::new();
        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-grpc".to_string(),
        };
        grants.insert(
            key,
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "GRPCRoute".to_string(), // only GRPCRoute, not HTTPRoute
                    namespace: "app-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None,
                }],
            },
        );
        assert!(!is_reference_allowed(
            &grants,
            "app-ns",
            "HTTPRoute", // HTTPRoute, but grant is for GRPCRoute
            "backend-ns",
            "Service",
            Some("my-svc"),
        ));
    }

    #[test]
    fn test_cross_namespace_grant_with_specific_name_match() {
        let grants = DashMap::new();
        let key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "allow-specific".to_string(),
        };
        grants.insert(
            key,
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
                    name: Some("allowed-svc".to_string()),
                }],
            },
        );
        // Matching name
        assert!(is_reference_allowed(
            &grants,
            "app-ns",
            "HTTPRoute",
            "backend-ns",
            "Service",
            Some("allowed-svc"),
        ));
        // Non-matching name
        assert!(!is_reference_allowed(
            &grants,
            "app-ns",
            "HTTPRoute",
            "backend-ns",
            "Service",
            Some("other-svc"),
        ));
    }

    #[test]
    fn test_controller_name_constant() {
        assert_eq!(CONTROLLER_NAME, "github.com/Portus-Gateway/Portus");
    }

    #[test]
    fn test_field_manager_constant() {
        assert_eq!(FIELD_MANAGER, "portus-gateway");
    }
}
