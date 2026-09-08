//! Dependency triggers: which objects re-reconcile when the store changes.
//!
//! A reconciler derives an object's status from other objects' state in the
//! [`ConfigStore`] (a route from its parent Gateway, a Gateway from the routes
//! attached to it, a policy from its siblings on the same target). The
//! reconciler that owns that other state publishes an [`Event`] right after
//! writing it, and the functions here turn the event into the list of objects
//! whose reconcile must run. Because the event follows the write, the dependent
//! reconcile always reads the new state; because publishers emit only on an
//! actual change, two controllers cannot keep re-triggering each other. This is
//! what replaced the timed requeues.
//!
//! The mapping functions are pure (event + the controller's reflector contents
//! → object refs) so they are unit-tested here; [`on_events`] adapts one of
//! them to the stream `Controller::reconcile_on` wants.

use std::sync::Arc;

use futures::{Stream, StreamExt};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::Resource;
use tokio::sync::broadcast;

use crate::gateway_types::{
    BackendTLSPolicy, GRPCRoute, Gateway, HTTPRoute, ListenerSet, ParentReference, TCPRoute, TLSRoute, UDPRoute,
};
use crate::policy_types::PolicyTargetRef;
use crate::store::{ConfigStore, Event, NamespacedName, ParentKind, PolicyTargetKey};

/// Subscribe a controller to the store's events. `map` names the objects an
/// event affects (given the controller's own reflector, so no API calls); a
/// subscriber that lagged behind the bus re-reconciles everything it owns.
pub fn on_events<K, F>(
    store: &ConfigStore,
    reader: Store<K>,
    map: F,
) -> impl Stream<Item = ObjectRef<K>> + Send + 'static
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
    F: Fn(&Event, &Store<K>) -> Vec<ObjectRef<K>> + Send + Sync + 'static,
{
    let rx = store.events.subscribe();
    futures::stream::unfold((rx, reader, map), |(mut rx, reader, map)| async move {
        loop {
            let refs = match rx.recv().await {
                Ok(event) => map(&event, &reader),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!(
                        "{}: {n} store events missed; re-reconciling every object",
                        std::any::type_name::<K>().rsplit("::").next().unwrap_or("controller")
                    );
                    reader.state().iter().map(|o| ObjectRef::from_obj(o.as_ref())).collect()
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            };
            if !refs.is_empty() {
                return Some((futures::stream::iter(refs), (rx, reader, map)));
            }
        }
    })
    .flatten()
}

fn key_of<K: Resource<DynamicType = ()>>(obj: &K) -> NamespacedName {
    NamespacedName {
        namespace: obj.meta().namespace.clone().unwrap_or_default(),
        name: obj.meta().name.clone().unwrap_or_default(),
    }
}

/// The parent a `parentRef` names, in store terms.
pub fn parent_key(pr: &ParentReference, route_namespace: &str) -> (ParentKind, NamespacedName) {
    let kind = if pr.kind.as_deref() == Some("ListenerSet") { ParentKind::ListenerSet } else { ParentKind::Gateway };
    (
        kind,
        NamespacedName {
            namespace: pr.namespace.clone().unwrap_or_else(|| route_namespace.to_string()),
            name: pr.name.clone(),
        },
    )
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// What every route kind exposes for trigger mapping.
pub trait RouteRefs: Resource<DynamicType = ()> + Clone + Send + Sync + 'static {
    fn parent_refs(&self) -> &[ParentReference];
    /// Services the rules reference; a ref without a namespace is in the route's.
    fn backend_services(&self) -> Vec<NamespacedName>;

    fn parents(&self) -> Vec<(ParentKind, NamespacedName)> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.parent_refs().iter().map(|pr| parent_key(pr, &ns)).collect()
    }
}

fn service_key(namespace: Option<&str>, name: &str, route_namespace: &str) -> NamespacedName {
    NamespacedName {
        namespace: namespace.unwrap_or(route_namespace).to_string(),
        name: name.to_string(),
    }
}

impl RouteRefs for HTTPRoute {
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn backend_services(&self) -> Vec<NamespacedName> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.spec
            .rules
            .iter()
            .flat_map(|r| r.backend_refs.iter())
            .map(|b| service_key(b.namespace.as_deref(), &b.name, &ns))
            .collect()
    }
}

impl RouteRefs for GRPCRoute {
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn backend_services(&self) -> Vec<NamespacedName> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.spec
            .rules
            .iter()
            .flat_map(|r| r.backend_refs.iter())
            .map(|b| service_key(b.namespace.as_deref(), &b.name, &ns))
            .collect()
    }
}

impl RouteRefs for TLSRoute {
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn backend_services(&self) -> Vec<NamespacedName> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.spec
            .rules
            .iter()
            .flat_map(|r| r.backend_refs.iter())
            .map(|b| service_key(b.namespace.as_deref(), &b.name, &ns))
            .collect()
    }
}

impl RouteRefs for TCPRoute {
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn backend_services(&self) -> Vec<NamespacedName> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.spec
            .rules
            .iter()
            .flat_map(|r| r.backend_refs.iter())
            .map(|b| service_key(b.namespace.as_deref(), &b.name, &ns))
            .collect()
    }
}

impl RouteRefs for UDPRoute {
    fn parent_refs(&self) -> &[ParentReference] {
        &self.spec.parent_refs
    }
    fn backend_services(&self) -> Vec<NamespacedName> {
        let ns = self.meta().namespace.clone().unwrap_or_default();
        self.spec
            .rules
            .iter()
            .flat_map(|r| r.backend_refs.iter())
            .map(|b| service_key(b.namespace.as_deref(), &b.name, &ns))
            .collect()
    }
}

/// Routes whose status depends on the changed object: their parents (binding
/// and `parent_known`), the Services their rules name (`BackendNotFound`), the
/// ReferenceGrants in a namespace they reach into (`RefNotPermitted`) and their
/// own Namespace's labels (`allowedRoutes` selectors).
pub fn routes_for<K: RouteRefs>(event: &Event, routes: &[Arc<K>]) -> Vec<ObjectRef<K>> {
    let affected = |route: &K| -> bool {
        let ns = route.meta().namespace.clone().unwrap_or_default();
        match event {
            Event::Gateway(gw) => route.parents().iter().any(|(k, p)| *k == ParentKind::Gateway && p == gw),
            Event::ListenerSet { key, .. } => {
                route.parents().iter().any(|(k, p)| *k == ParentKind::ListenerSet && p == key)
            }
            Event::Service(svc) => route.backend_services().contains(svc),
            Event::ReferenceGrant { namespace } => {
                route.backend_services().iter().any(|s| s.namespace != ns && s.namespace == *namespace)
            }
            Event::Namespace(name) => ns == *name,
            Event::GatewayClass(_) | Event::Route { .. } | Event::Policy { .. } | Event::Programmed(_) => false,
        }
    };
    routes.iter().filter(|r| affected(r)).map(|r| ObjectRef::from_obj(r.as_ref())).collect()
}

// ---------------------------------------------------------------------------
// Gateways and ListenerSets
// ---------------------------------------------------------------------------

fn gateway_references_namespace(gw: &Gateway, namespace: &str) -> bool {
    let in_ns = |n: &Option<String>| n.as_deref() == Some(namespace);
    let listener_refs = gw
        .spec
        .listeners
        .iter()
        .flat_map(|l| l.tls.iter())
        .flat_map(|t| t.certificate_refs.iter())
        .any(|r| in_ns(&r.namespace));
    let tls = gw.spec.tls.as_ref();
    let backend_ref = tls
        .and_then(|t| t.backend.as_ref())
        .and_then(|b| b.client_certificate_ref.as_ref())
        .is_some_and(|r| in_ns(&r.namespace));
    let frontend_refs = tls
        .and_then(|t| t.frontend.as_ref())
        .into_iter()
        .flat_map(|f| std::iter::once(&f.default).chain(f.per_port.iter().map(|p| &p.tls)))
        .flat_map(|c| c.validation.iter())
        .flat_map(|v| v.ca_certificate_refs.iter())
        .any(|r| in_ns(&r.namespace));
    listener_refs || backend_ref || frontend_refs
}

fn gateway_uses_selectors(gw: &Gateway) -> bool {
    let listeners = gw.spec.listeners.iter().any(|l| {
        l.allowed_routes
            .as_ref()
            .and_then(|a| a.namespaces.as_ref())
            .and_then(|n| n.from.as_deref())
            == Some("Selector")
    });
    let listener_sets = gw
        .spec
        .allowed_listeners
        .as_ref()
        .and_then(|a| a.namespaces.as_ref())
        .and_then(|n| n.from.as_deref())
        == Some("Selector");
    listeners || listener_sets
}

/// Gateways whose status depends on the changed object: their class, the
/// routes and ListenerSets attached to them (`attachedRoutes`, ports), a data
/// plane ack (`Programmed`), ReferenceGrants in a namespace their TLS refs
/// reach into, and Namespace labels when a listener selects by label.
/// ListenerSet parents in a route event are resolved through `store`.
pub fn gateways_for(event: &Event, gateways: &[Arc<Gateway>], store: &ConfigStore) -> Vec<ObjectRef<Gateway>> {
    let by_key = |keys: Vec<NamespacedName>| -> Vec<ObjectRef<Gateway>> {
        keys.into_iter().map(|k| ObjectRef::<Gateway>::new(&k.name).within(&k.namespace)).collect()
    };
    match event {
        Event::GatewayClass(class) => gateways
            .iter()
            .filter(|gw| gw.spec.gateway_class_name == *class)
            .map(|gw| ObjectRef::from_obj(gw.as_ref()))
            .collect(),
        Event::Programmed(gw) => by_key(vec![gw.clone()]),
        Event::ListenerSet { parent, .. } => by_key(vec![parent.clone()]),
        Event::Route { parents, .. } => {
            let mut keys: Vec<NamespacedName> = parents
                .iter()
                .filter_map(|(kind, key)| match kind {
                    ParentKind::Gateway => Some(key.clone()),
                    ParentKind::ListenerSet => store.listener_sets.get(key).map(|ls| ls.parent_gateway.clone()),
                })
                .collect();
            keys.sort();
            keys.dedup();
            by_key(keys)
        }
        Event::ReferenceGrant { namespace } => gateways
            .iter()
            .filter(|gw| gateway_references_namespace(gw, namespace))
            .map(|gw| ObjectRef::from_obj(gw.as_ref()))
            .collect(),
        Event::Namespace(_) => gateways
            .iter()
            .filter(|gw| gateway_uses_selectors(gw))
            .map(|gw| ObjectRef::from_obj(gw.as_ref()))
            .collect(),
        Event::Gateway(_) | Event::Service(_) | Event::Policy { .. } => Vec::new(),
    }
}

fn listener_set_parent(ls: &ListenerSet) -> NamespacedName {
    NamespacedName {
        namespace: ls
            .spec
            .parent_ref
            .namespace
            .clone()
            .or_else(|| ls.meta().namespace.clone())
            .unwrap_or_default(),
        name: ls.spec.parent_ref.name.clone(),
    }
}

/// ListenerSets whose status depends on the changed object: their parent
/// Gateway (acceptance, `Programmed`), siblings on the same parent (listener
/// precedence), routes attached to them and Namespace labels (selectors).
pub fn listener_sets_for(event: &Event, sets: &[Arc<ListenerSet>]) -> Vec<ObjectRef<ListenerSet>> {
    let affected = |ls: &ListenerSet| -> bool {
        match event {
            Event::Gateway(gw) | Event::Programmed(gw) => listener_set_parent(ls) == *gw,
            Event::ListenerSet { key, parent } => listener_set_parent(ls) == *parent && key_of(ls) != *key,
            Event::Route { parents, .. } => {
                let me = key_of(ls);
                parents.iter().any(|(k, p)| *k == ParentKind::ListenerSet && *p == me)
            }
            Event::Namespace(_) => true,
            Event::GatewayClass(_) | Event::ReferenceGrant { .. } | Event::Service(_) | Event::Policy { .. } => false,
        }
    };
    sets.iter().filter(|ls| affected(ls)).map(|ls| ObjectRef::from_obj(ls.as_ref())).collect()
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/// What a policy with a single `targetRef` exposes for trigger mapping.
pub trait PolicyRefs: Resource<DynamicType = ()> + Clone + Send + Sync + 'static {
    const KIND: &'static str;
    fn target_ref(&self) -> &PolicyTargetRef;

    fn target(&self) -> PolicyTargetKey {
        let t = self.target_ref();
        PolicyTargetKey {
            group: t.group.clone(),
            kind: t.kind.clone(),
            namespace: self.meta().namespace.clone().unwrap_or_default(),
            name: t.name.clone(),
            section_name: t.section_name.clone(),
        }
    }
}

macro_rules! policy_refs {
    ($($ty:ident),* $(,)?) => {$(
        impl PolicyRefs for crate::policy_types::$ty {
            const KIND: &'static str = stringify!($ty);
            fn target_ref(&self) -> &PolicyTargetRef {
                &self.spec.target_ref
            }
        }
    )*};
}
policy_refs!(
    RateLimitPolicy,
    CircuitBreakerPolicy,
    ConnectionPolicy,
    BasicAuthPolicy,
    APIKeyAuthPolicy,
    RetryPolicy,
    IPAllowlistPolicy,
    RequestBodySizeLimitPolicy,
    HealthCheckPolicy,
    CORSPolicy,
    TimeoutPolicy,
);

/// Policies whose status depends on the changed object: every policy when a
/// data plane acks (`Programmed` is the aggregate), and the siblings of a
/// policy of the same kind on the same target (oldest wins; the others report
/// `Conflicted`). The publishing policy itself is excluded so a reconcile can
/// never re-trigger itself.
pub fn policies_for<K: PolicyRefs>(event: &Event, policies: &[Arc<K>]) -> Vec<ObjectRef<K>> {
    let affected = |p: &K| -> bool {
        match event {
            Event::Programmed(_) => true,
            Event::Policy { kind, key, target } => *kind == K::KIND && key_of(p) != *key && p.target() == *target,
            _ => false,
        }
    };
    policies.iter().filter(|p| affected(p)).map(|p| ObjectRef::from_obj(p.as_ref())).collect()
}

/// BackendTLSPolicy targets Services and reports ancestors from the routes that
/// use them, so it also follows route changes naming one of its targets.
pub fn backend_tls_policies_for(event: &Event, policies: &[Arc<BackendTLSPolicy>]) -> Vec<ObjectRef<BackendTLSPolicy>> {
    let targets = |p: &BackendTLSPolicy| -> Vec<NamespacedName> {
        let ns = p.meta().namespace.clone().unwrap_or_default();
        p.spec
            .target_refs
            .iter()
            .map(|t| NamespacedName { namespace: ns.clone(), name: t.name.clone() })
            .collect()
    };
    let affected = |p: &BackendTLSPolicy| -> bool {
        match event {
            Event::Programmed(_) => true,
            Event::Policy { kind, key, target } => {
                *kind == "BackendTLSPolicy"
                    && key_of(p) != *key
                    && targets(p).iter().any(|t| t.namespace == target.namespace && t.name == target.name)
            }
            Event::Route { backends, .. } => targets(p).iter().any(|t| backends.contains(t)),
            _ => false,
        }
    };
    policies.iter().filter(|p| affected(p)).map(|p| ObjectRef::from_obj(p.as_ref())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{
        GatewayBackendTLS, GatewaySpec, GatewayTLS, GatewayTLSConfig, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec,
        Listener, ListenerSetSpec, ParentGatewayReference, SecretObjectReference,
    };
    use crate::policy_types::{RetryPolicy, RetryPolicySpec, RetrySpec};
    use crate::store::{ListenerSetState, RouteKind};
    use kube::api::ObjectMeta;

    fn nn(ns: &str, name: &str) -> NamespacedName {
        NamespacedName { namespace: ns.into(), name: name.into() }
    }

    fn meta(ns: &str, name: &str) -> ObjectMeta {
        ObjectMeta { namespace: Some(ns.into()), name: Some(name.into()), ..Default::default() }
    }

    fn route(ns: &str, name: &str, parents: Vec<ParentReference>, backends: Vec<HTTPBackendRef>) -> Arc<HTTPRoute> {
        Arc::new(HTTPRoute {
            metadata: meta(ns, name),
            spec: HTTPRouteSpec {
                parent_refs: parents,
                rules: vec![HTTPRouteRule { backend_refs: backends, ..Default::default() }],
                ..Default::default()
            },
            status: None,
        })
    }

    fn parent(name: &str, ns: Option<&str>, kind: Option<&str>) -> ParentReference {
        ParentReference {
            name: name.into(),
            namespace: ns.map(String::from),
            kind: kind.map(String::from),
            ..Default::default()
        }
    }

    fn backend(name: &str, ns: Option<&str>) -> HTTPBackendRef {
        HTTPBackendRef { name: name.into(), namespace: ns.map(String::from), ..Default::default() }
    }

    fn names<K: Resource<DynamicType = ()>>(refs: Vec<ObjectRef<K>>) -> Vec<String> {
        let mut v: Vec<String> = refs.into_iter().map(|r| format!("{}/{}", r.namespace.unwrap_or_default(), r.name)).collect();
        v.sort();
        v
    }

    #[test]
    fn parent_key_defaults_to_gateway_in_the_route_namespace() {
        assert_eq!(parent_key(&parent("gw", None, None), "apps"), (ParentKind::Gateway, nn("apps", "gw")));
        assert_eq!(
            parent_key(&parent("ls", Some("infra"), Some("ListenerSet")), "apps"),
            (ParentKind::ListenerSet, nn("infra", "ls"))
        );
    }

    #[test]
    fn routes_follow_their_parents_only() {
        let routes = vec![
            route("apps", "a", vec![parent("gw", Some("infra"), None)], vec![]),
            route("apps", "b", vec![parent("other", Some("infra"), None)], vec![]),
            route("apps", "c", vec![parent("ls", Some("infra"), Some("ListenerSet"))], vec![]),
            route("infra", "d", vec![parent("gw", None, None)], vec![]),
        ];
        assert_eq!(names(routes_for(&Event::Gateway(nn("infra", "gw")), &routes)), vec!["apps/a", "infra/d"]);
        assert_eq!(
            names(routes_for(&Event::ListenerSet { key: nn("infra", "ls"), parent: nn("infra", "gw") }, &routes)),
            vec!["apps/c"]
        );
        // A route naming a ListenerSet does not follow a Gateway of the same name.
        assert!(routes_for(&Event::Gateway(nn("infra", "ls")), &routes).is_empty());
    }

    #[test]
    fn routes_follow_backend_services_grants_and_their_namespace() {
        let routes = vec![
            route("apps", "same-ns", vec![], vec![backend("svc", None)]),
            route("apps", "cross-ns", vec![], vec![backend("svc", Some("backends"))]),
            route("other", "unrelated", vec![], vec![backend("svc", None)]),
        ];
        assert_eq!(names(routes_for(&Event::Service(nn("apps", "svc")), &routes)), vec!["apps/same-ns"]);
        assert_eq!(names(routes_for(&Event::Service(nn("backends", "svc")), &routes)), vec!["apps/cross-ns"]);
        // Only a route reaching *into* the grant's namespace cares about it.
        assert_eq!(
            names(routes_for(&Event::ReferenceGrant { namespace: "backends".into() }, &routes)),
            vec!["apps/cross-ns"]
        );
        assert!(routes_for(&Event::ReferenceGrant { namespace: "apps".into() }, &routes).is_empty());
        assert_eq!(names(routes_for(&Event::Namespace("other".into()), &routes)), vec!["other/unrelated"]);
        // Events routes never depend on.
        assert!(routes_for(&Event::Programmed(nn("infra", "gw")), &routes).is_empty());
        assert!(routes_for(&Event::GatewayClass("portus".into()), &routes).is_empty());
    }

    fn gateway(ns: &str, name: &str, class: &str) -> Gateway {
        Gateway {
            metadata: meta(ns, name),
            spec: GatewaySpec { gateway_class_name: class.into(), ..Default::default() },
            status: None,
        }
    }

    #[test]
    fn gateways_follow_class_acks_listener_sets_and_routes() {
        let store = ConfigStore::new();
        store.listener_sets.insert(
            nn("infra", "ls"),
            ListenerSetState {
                name: "ls".into(),
                namespace: "infra".into(),
                parent_gateway: nn("infra", "gw"),
                listeners: vec![],
                accepted: true,
                generation: 1,
                not_accepted_reason: None,
                creation_timestamp: 0,
            },
        );
        let gws = vec![Arc::new(gateway("infra", "gw", "portus")), Arc::new(gateway("infra", "foreign", "other"))];
        assert_eq!(names(gateways_for(&Event::GatewayClass("portus".into()), &gws, &store)), vec!["infra/gw"]);
        assert_eq!(names(gateways_for(&Event::Programmed(nn("infra", "gw")), &gws, &store)), vec!["infra/gw"]);
        assert_eq!(
            names(gateways_for(&Event::ListenerSet { key: nn("infra", "ls"), parent: nn("infra", "gw") }, &gws, &store)),
            vec!["infra/gw"]
        );
        // Route parents: Gateways directly, ListenerSets through their parent; deduplicated.
        let ev = Event::Route {
            kind: RouteKind::Http,
            key: nn("apps", "r"),
            parents: vec![(ParentKind::Gateway, nn("infra", "gw")), (ParentKind::ListenerSet, nn("infra", "ls"))],
            backends: vec![],
        };
        assert_eq!(names(gateways_for(&ev, &gws, &store)), vec!["infra/gw"]);
        // A Gateway's own state change is its own reconcile, not a trigger.
        assert!(gateways_for(&Event::Gateway(nn("infra", "gw")), &gws, &store).is_empty());
    }

    #[test]
    fn gateways_follow_grants_in_namespaces_their_tls_refs_reach() {
        let mut gw = gateway("infra", "gw", "portus");
        gw.spec.listeners = vec![Listener {
            name: "https".into(),
            port: 443,
            protocol: "HTTPS".into(),
            tls: Some(GatewayTLSConfig {
                mode: None,
                certificate_refs: vec![SecretObjectReference {
                    group: None,
                    kind: None,
                    name: "cert".into(),
                    namespace: Some("certs".into()),
                }],
            }),
            ..Default::default()
        }];
        let mut mtls = gateway("infra", "mtls", "portus");
        mtls.spec.tls = Some(GatewayTLS {
            backend: Some(GatewayBackendTLS {
                client_certificate_ref: Some(SecretObjectReference {
                    group: None,
                    kind: None,
                    name: "client".into(),
                    namespace: Some("clients".into()),
                }),
            }),
            frontend: None,
        });
        let plain = gateway("infra", "plain", "portus");
        let gws = vec![Arc::new(gw), Arc::new(mtls), Arc::new(plain)];
        let store = ConfigStore::new();
        assert_eq!(
            names(gateways_for(&Event::ReferenceGrant { namespace: "certs".into() }, &gws, &store)),
            vec!["infra/gw"]
        );
        assert_eq!(
            names(gateways_for(&Event::ReferenceGrant { namespace: "clients".into() }, &gws, &store)),
            vec!["infra/mtls"]
        );
        assert!(gateways_for(&Event::ReferenceGrant { namespace: "infra".into() }, &gws, &store).is_empty());
    }

    #[test]
    fn gateways_follow_namespace_labels_only_when_they_select_by_label() {
        use crate::gateway_types::{AllowedRoutes, RouteNamespaces};
        let mut selecting = gateway("infra", "sel", "portus");
        selecting.spec.listeners = vec![Listener {
            name: "http".into(),
            port: 80,
            protocol: "HTTP".into(),
            allowed_routes: Some(AllowedRoutes {
                namespaces: Some(RouteNamespaces { from: Some("Selector".into()), selector: None }),
                kinds: vec![],
            }),
            ..Default::default()
        }];
        let gws = vec![Arc::new(selecting), Arc::new(gateway("infra", "plain", "portus"))];
        let store = ConfigStore::new();
        assert_eq!(names(gateways_for(&Event::Namespace("apps".into()), &gws, &store)), vec!["infra/sel"]);
    }

    fn listener_set(ns: &str, name: &str, parent_ns: Option<&str>, parent: &str) -> Arc<ListenerSet> {
        Arc::new(ListenerSet {
            metadata: meta(ns, name),
            spec: ListenerSetSpec {
                parent_ref: ParentGatewayReference {
                    group: None,
                    kind: None,
                    name: parent.into(),
                    namespace: parent_ns.map(String::from),
                },
                ..Default::default()
            },
            status: None,
        })
    }

    #[test]
    fn listener_sets_follow_parent_siblings_and_routes() {
        let sets = vec![
            listener_set("infra", "a", None, "gw"),
            listener_set("apps", "b", Some("infra"), "gw"),
            listener_set("infra", "c", None, "other"),
        ];
        assert_eq!(names(listener_sets_for(&Event::Gateway(nn("infra", "gw")), &sets)), vec!["apps/b", "infra/a"]);
        assert_eq!(names(listener_sets_for(&Event::Programmed(nn("infra", "gw")), &sets)), vec!["apps/b", "infra/a"]);
        // A sibling's change re-evaluates the others on the same parent, never the publisher.
        assert_eq!(
            names(listener_sets_for(&Event::ListenerSet { key: nn("infra", "a"), parent: nn("infra", "gw") }, &sets)),
            vec!["apps/b"]
        );
        let ev = Event::Route {
            kind: RouteKind::Http,
            key: nn("apps", "r"),
            parents: vec![(ParentKind::ListenerSet, nn("apps", "b")), (ParentKind::Gateway, nn("infra", "a"))],
            backends: vec![],
        };
        assert_eq!(names(listener_sets_for(&ev, &sets)), vec!["apps/b"]);
    }

    fn retry_policy(ns: &str, name: &str, target: &str) -> Arc<RetryPolicy> {
        Arc::new(RetryPolicy {
            metadata: meta(ns, name),
            spec: RetryPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".into(),
                    kind: "HTTPRoute".into(),
                    name: target.into(),
                    section_name: None,
                },
                retry: RetrySpec::default(),
            },
            status: None,
        })
    }

    #[test]
    fn policies_follow_acks_and_same_kind_siblings_on_the_target() {
        let policies = vec![
            retry_policy("apps", "older", "route"),
            retry_policy("apps", "newer", "route"),
            retry_policy("apps", "elsewhere", "other-route"),
        ];
        assert_eq!(names(policies_for(&Event::Programmed(nn("infra", "gw")), &policies)).len(), 3);
        let target = policies[0].target();
        let ev = Event::Policy { kind: "RetryPolicy", key: nn("apps", "older"), target: target.clone() };
        assert_eq!(names(policies_for(&ev, &policies)), vec!["apps/newer"]);
        // Another kind on the same target is a different conflict set.
        let ev = Event::Policy { kind: "TimeoutPolicy", key: nn("apps", "x"), target };
        assert!(policies_for(&ev, &policies).is_empty());
        assert!(policies_for(&Event::Gateway(nn("infra", "gw")), &policies).is_empty());
    }

    #[test]
    fn backend_tls_policies_follow_routes_that_use_their_target() {
        use crate::gateway_types::{BackendTLSPolicySpec, BackendTLSPolicyTargetRef, BackendTLSPolicyValidation};
        let policy = Arc::new(BackendTLSPolicy {
            metadata: meta("apps", "tls"),
            spec: BackendTLSPolicySpec {
                target_refs: vec![BackendTLSPolicyTargetRef {
                    group: String::new(),
                    kind: "Service".into(),
                    name: "svc".into(),
                    section_name: None,
                }],
                validation: BackendTLSPolicyValidation::default(),
            },
            status: None,
        });
        let policies = vec![policy];
        let uses = Event::Route {
            kind: RouteKind::Http,
            key: nn("apps", "r"),
            parents: vec![],
            backends: vec![nn("apps", "svc")],
        };
        assert_eq!(names(backend_tls_policies_for(&uses, &policies)), vec!["apps/tls"]);
        let other = Event::Route {
            kind: RouteKind::Http,
            key: nn("apps", "r"),
            parents: vec![],
            backends: vec![nn("other", "svc")],
        };
        assert!(backend_tls_policies_for(&other, &policies).is_empty());
    }

    #[tokio::test]
    async fn on_events_maps_events_and_skips_empty_results() {
        use kube::runtime::reflector::store;
        let store_ = Arc::new(ConfigStore::new());
        let (reader, _writer) = store::store::<HTTPRoute>();
        let stream = on_events(&store_, reader, |event, _| match event {
            Event::Gateway(gw) => vec![ObjectRef::<HTTPRoute>::new("r").within(&gw.namespace)],
            _ => Vec::new(),
        });
        let mut stream = Box::pin(stream);
        store_.publish(Event::Namespace("ignored".into()));
        store_.publish(Event::Gateway(nn("infra", "gw")));
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("an event must arrive")
            .expect("stream open");
        assert_eq!(got.name, "r");
        assert_eq!(got.namespace.as_deref(), Some("infra"));
    }
}
