use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log;
use tokio::sync::watch;

use portus_types::*;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use crate::store::{
    ConfigStore, GatewayState, HTTPFilterState, HTTPRouteRuleState, HTTPRouteState,
    NamespacedName, ParentRefState, PolicyTargetKey, ServiceKey, L4RouteState, TLSRouteState,
};

/// Compile all ConfigStore state into a CompiledConfig proto message.
///
/// Reads all DashMaps (gateways, http_routes, grpc_routes, endpoints)
/// and produces a CompiledConfig with routes, backends, and listeners.
/// Tracks the source of each compiled RouteConfig for policy matching.
struct RouteSource {
    kind: String,
    namespace: String,
    name: String,
    /// (gateway_namespace, gateway_name, section_name) per parent ref
    gateway_refs: Vec<(String, String, Option<String>)>,
}

/// The Gateway a parentRef ultimately belongs to: the Gateway itself, or the
/// parent Gateway of a ListenerSet.
fn owner_gateway(
    parent_kind: &crate::store::ParentKind,
    parent_ns: &str,
    parent_name: &str,
    ls_map: &HashMap<NamespacedName, crate::store::ListenerSetState>,
) -> (String, String) {
    match parent_kind {
        crate::store::ParentKind::Gateway => (parent_ns.to_string(), parent_name.to_string()),
        crate::store::ParentKind::ListenerSet => ls_map
            .get(&NamespacedName {
                namespace: parent_ns.to_string(),
                name: parent_name.to_string(),
            })
            .map(|ls| (ls.parent_gateway.namespace.clone(), ls.parent_gateway.name.clone()))
            .unwrap_or_else(|| (parent_ns.to_string(), parent_name.to_string())),
    }
}

/// The slice of a compiled config that one Gateway's dedicated data plane
/// needs: its listeners, the routes bound to them, the backends those routes
/// reference, and the TLS passthrough hostnames of its own TLS listeners.
/// `version` is carried over; `fingerprint` is recomputed for the slice so it
/// only changes when this Gateway's content changes.
pub fn scope_config(config: &CompiledConfig, namespace: &str, name: &str) -> CompiledConfig {
    let owned = |ns: &str, n: &str| ns == namespace && n == name;
    let routes: Vec<RouteConfig> = config
        .routes
        .iter()
        .filter(|r| owned(&r.gateway_namespace, &r.gateway_name))
        .cloned()
        .collect();
    let listeners: Vec<Listener> = config
        .listeners
        .iter()
        .filter(|l| owned(&l.gateway_namespace, &l.gateway_name))
        .cloned()
        .collect();
    let tls_passthrough_routes: Vec<TlsPassthroughRoute> = config
        .tls_passthrough_routes
        .iter()
        .filter(|t| owned(&t.gateway_namespace, &t.gateway_name))
        .cloned()
        .collect();
    let tcp_proxy_routes: Vec<L4ProxyRoute> = config
        .tcp_proxy_routes
        .iter()
        .filter(|t| owned(&t.gateway_namespace, &t.gateway_name))
        .cloned()
        .collect();
    let udp_proxy_routes: Vec<L4ProxyRoute> = config
        .udp_proxy_routes
        .iter()
        .filter(|t| owned(&t.gateway_namespace, &t.gateway_name))
        .cloned()
        .collect();

    let mut wanted: std::collections::HashSet<(&str, u32)> = std::collections::HashSet::new();
    for r in &routes {
        if !r.service_name.is_empty() {
            wanted.insert((r.service_name.as_str(), r.port));
        }
        for w in &r.weighted_backends {
            wanted.insert((w.service_name.as_str(), w.port));
        }
        for m in &r.mirror_backends {
            wanted.insert((m.service_name.as_str(), m.port));
        }
    }
    for t in &tls_passthrough_routes {
        if !t.backend_service.is_empty() {
            wanted.insert((t.backend_service.as_str(), t.backend_port));
        }
    }
    for t in tcp_proxy_routes.iter().chain(&udp_proxy_routes) {
        if !t.backend_service.is_empty() {
            wanted.insert((t.backend_service.as_str(), t.backend_port));
        }
        for w in &t.backends {
            wanted.insert((w.service_name.as_str(), w.port));
        }
    }
    let backends: Vec<BackendGroup> = config
        .backends
        .iter()
        .filter(|b| wanted.contains(&(b.service_name.as_str(), b.port)))
        .cloned()
        .collect();

    let tls_passthrough_listener_hostnames: Vec<String> = listeners
        .iter()
        .filter(|l| l.protocol == "TLS" && !l.hostname.is_empty())
        .map(|l| l.hostname.clone())
        .collect();
    let gateway_backend_tls: Vec<GatewayBackendTls> = config
        .gateway_backend_tls
        .iter()
        .filter(|g| owned(&g.gateway_namespace, &g.gateway_name))
        .cloned()
        .collect();

    let mut scoped = CompiledConfig {
        schema_version: config.schema_version.clone(),
        version: config.version,
        fingerprint: 0,
        routes,
        backends,
        listeners,
        tls_passthrough_routes,
        tcp_proxy_routes,
        udp_proxy_routes,
        tls_passthrough_listener_hostnames,
        gateway_backend_tls,
    };
    scoped.fingerprint = config_fingerprint(&scoped);
    scoped
}

/// The compiled frontend client validation for an HTTPS listener on `port` of
/// Gateway `gw_ns/gw_name`: the Gateway's per-port override or its default,
/// with every referenced ConfigMap's `ca.crt` inlined. `None` when the Gateway
/// configures no validation for that port (or the block is invalid, in which
/// case the listener was not accepted and is not compiled either).
fn client_validation_for_listener(
    store: &ConfigStore,
    gw_ns: &str,
    gw_name: &str,
    port: u16,
) -> Option<ClientValidation> {
    let key = NamespacedName { namespace: gw_ns.to_string(), name: gw_name.to_string() };
    let tls = store.gateway_tls.get(&key)?;
    let refs = match tls.frontend_validation_for_port(port)? {
        crate::store::ClientValidationOutcome::Valid(v) => v,
        crate::store::ClientValidationOutcome::Invalid { .. } => return None,
    };
    let ca_cert_pems: Vec<String> = refs
        .ca_config_maps
        .iter()
        .filter_map(|cm_key| {
            store
                .config_maps
                .get(cm_key)
                .and_then(|cm| cm.data.get("ca.crt").cloned())
                .filter(|pem| !pem.trim().is_empty())
        })
        .collect();
    if ca_cert_pems.is_empty() {
        return None;
    }
    Some(ClientValidation { ca_cert_pems, mode: refs.mode.clone() })
}

/// Backend client certificates (`spec.tls.backend.clientCertificateRef`), one
/// per Gateway whose referenced Secret is present with `tls.crt`/`tls.key`.
fn compile_gateway_backend_tls(store: &ConfigStore) -> Vec<GatewayBackendTls> {
    let mut out: Vec<GatewayBackendTls> = store
        .gateway_tls
        .iter()
        .filter_map(|entry| {
            let secret_key = entry.value().backend_client_cert_ref.as_ref()?;
            let secret = store.secrets.get(secret_key)?;
            let cert_pem = secret.data.get("tls.crt")?.clone();
            let key_pem = secret.data.get("tls.key")?.clone();
            Some(GatewayBackendTls {
                gateway_namespace: entry.key().namespace.clone(),
                gateway_name: entry.key().name.clone(),
                cert_pem,
                key_pem,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        (&a.gateway_namespace, &a.gateway_name).cmp(&(&b.gateway_namespace, &b.gateway_name))
    });
    out
}

pub fn compile_config(store: &ConfigStore) -> CompiledConfig {
    let version: u64 = 0; // Version is set by compilation_loop after fingerprinting
    let mut routes = Vec::new();
    let mut listeners = Vec::new();
    let mut backend_keys = std::collections::HashSet::new();
    let mut route_sources: Vec<RouteSource> = Vec::new();
    let mut backend_ns_index: HashMap<(String, u16), String> = HashMap::new();

    // Snapshot DashMaps into owned collections at the start of compilation.
    // This bounds shard lock hold time to O(n) copies instead of holding
    // read locks across the entire compilation duration.
    let gateways: Vec<(NamespacedName, GatewayState)> = store.gateways.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let gw_map: HashMap<NamespacedName, GatewayState> = gateways.iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Snapshot ListenerSets so the HTTP/gRPC compile paths can resolve
    // parentRefs with kind=ListenerSet alongside Gateway parents.
    let listener_sets: Vec<(NamespacedName, crate::store::ListenerSetState)> = store
        .listener_sets
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let ls_map: HashMap<NamespacedName, crate::store::ListenerSetState> = listener_sets
        .iter()
        .cloned()
        .collect();
    let http_routes: Vec<(NamespacedName, HTTPRouteState)> = store.http_routes.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let grpc_routes: Vec<(NamespacedName, _)> = store.grpc_routes.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let tls_routes: Vec<(NamespacedName, TLSRouteState)> = store.tls_routes.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let tcp_routes: Vec<(NamespacedName, L4RouteState)> = store.tcp_routes.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let udp_routes: Vec<(NamespacedName, L4RouteState)> = store.udp_routes.iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();

    // Compile Listeners from gateways AND attached ListenerSets. Both feed
    // into the dataplane's listener registry so that ports bound by
    // ListenerSet-contributed listeners are opened.
    // Every emitted listener is attributed to its owning Gateway (ListenerSet
    // listeners to their parent Gateway) so per-Gateway data planes can be
    // given exactly their slice of the config.
    let gateway_listener_iter = gateways.iter().flat_map(|(k, gw)| {
        let owner = (k.namespace.clone(), k.name.clone());
        gw.listeners.iter().map(move |l| (owner.clone(), l.clone()))
    });
    let listener_set_listener_iter = listener_sets.iter().filter_map(|(_k, ls)| {
        if ls.accepted {
            let owner = (ls.parent_gateway.namespace.clone(), ls.parent_gateway.name.clone());
            Some((owner, ls.listeners.clone()))
        } else {
            None
        }
    }).flat_map(|(owner, listeners)| {
        listeners.into_iter().map(move |l| (owner.clone(), l))
    });
    for ((gw_ns, gw_name), listener) in gateway_listener_iter.chain(listener_set_listener_iter) {
        {
            let listener = &listener;
            if listener.accepted {
                // For HTTPS/TLS Terminate listeners, resolve cert data from Secrets
                let tls_cert_ref = if matches!(listener.protocol.as_str(), "HTTPS" | "TLS")
                    && !listener.tls_cert_refs.is_empty()
                {
                    // Use the first certificate reference (primary cert)
                    let (ref ns, ref name) = listener.tls_cert_refs[0];
                    let secret_key = NamespacedName {
                        namespace: ns.clone(),
                        name: name.clone(),
                    };
                    store.secrets.get(&secret_key).and_then(|secret| {
                        let cert_pem = secret.data.get("tls.crt")?;
                        let key_pem = secret.data.get("tls.key")?;
                        Some(TlsCertRef {
                            cert_pem: cert_pem.clone(),
                            key_pem: key_pem.clone(),
                        })
                    })
                } else {
                    None
                };

                // Frontend client certificate validation (Gateway spec.tls.frontend)
                // for HTTPS listeners: per-port override, else the default. CA PEMs
                // are inlined from the referenced ConfigMaps' `ca.crt` keys.
                let client_validation = if listener.protocol == "HTTPS" {
                    client_validation_for_listener(store, &gw_ns, &gw_name, listener.port)
                } else {
                    None
                };

                listeners.push(Listener {
                    name: listener.name.clone(),
                    port: listener.port as u32,
                    protocol: listener.protocol.clone(),
                    hostname: listener.hostname.clone().unwrap_or_default(),
                    tls_cert_ref,
                    gateway_namespace: gw_ns.clone(),
                    gateway_name: gw_name.clone(),
                    client_validation,
                });
            }
        }
    }

    // Compile Routes from HTTP routes.
    //
    // We iterate per (accepted parent_ref, matching listener) so each compiled
    // RouteConfig is tagged with the exact listener_hostname it belongs to.
    // This is required for GatewayHTTPListenerIsolation: the dataplane scopes
    // route lookup to the single most-specific listener claiming the request
    // host, so a route's listener must be authoritatively known at compile time.
    //
    // NOTE: Routes with unresolved backend refs (resolved_refs=false) are still
    // compiled. The invalid backends are simply omitted from the BackendGroup
    // by resolve_backend_refs, so the data plane returns HTTP 500 naturally
    // when no endpoints exist.
    for (route_key, hr) in &http_routes {
        // Collect gateway refs for Gateway-targeted policy matching. Computed
        // once per HTTPRoute (invariant across listeners).
        let gateway_refs: Vec<(String, String, Option<String>)> = hr
            .parent_refs
            .iter()
            .map(|pr| (pr.gateway_namespace.clone(), pr.gateway_name.clone(), pr.section_name.clone()))
            .collect();

        // Track backend keys and cross-namespace namespace mapping ONCE per
        // HTTPRoute, regardless of how many listeners it binds to. Otherwise
        // we would insert the same keys repeatedly.
        for rule in &hr.rules {
            for backend_ref in &rule.backend_refs {
                let is_cross_ns = backend_ref.namespace != hr.namespace;
                let grant_ok = !is_cross_ns
                    || crate::reconcilers::is_reference_allowed(
                        &store.reference_grants,
                        &hr.namespace,
                        "HTTPRoute",
                        &backend_ref.namespace,
                        "Service",
                        Some(&backend_ref.name),
                    );
                if grant_ok {
                    backend_keys.insert(ServiceKey {
                        namespace: backend_ref.namespace.clone(),
                        name: backend_ref.name.clone(),
                        port: backend_ref.port,
                    });
                }
                backend_ns_index.insert(
                    (backend_ref.name.clone(), backend_ref.port),
                    backend_ref.namespace.clone(),
                );
            }
        }

        // Walk every (accepted parent_ref, matching HTTP/HTTPS listener) pair
        // and emit routes tagged with that listener's hostname. Both Gateway
        // and ListenerSet parents contribute listeners; resolution depends on
        // parent_kind.
        for parent_ref in hr.parent_refs.iter().filter(|pr| pr.accepted) {
            let parent_key = NamespacedName {
                namespace: parent_ref.gateway_namespace.clone(),
                name: parent_ref.gateway_name.clone(),
            };
            let parent_listeners: Vec<crate::store::ListenerState> = match parent_ref.parent_kind {
                crate::store::ParentKind::Gateway => match gw_map.get(&parent_key) {
                    Some(gw) => gw.listeners.clone(),
                    None => continue,
                },
                crate::store::ParentKind::ListenerSet => match ls_map.get(&parent_key) {
                    Some(ls) if ls.accepted => ls.listeners.clone(),
                    _ => continue,
                },
            };

            for listener in &parent_listeners {
                if !listener.accepted {
                    continue;
                }
                if !matches!(listener.protocol.as_str(), "HTTP" | "HTTPS") {
                    continue;
                }
                if let Some(ref sn) = parent_ref.section_name
                    && listener.name != *sn {
                        continue;
                    }
                if let Some(p) = parent_ref.port
                    && listener.port != p {
                        continue;
                    }

                // Per-listener namespace filter. A route bound to the parent
                // may only compile onto listeners whose allowedRoutes permit
                // the route's namespace. Without this, a Same/Selector
                // listener would serve cross-namespace routes that the route
                // reconciler accepted against a sibling All/Selector listener.
                // For a ListenerSet parent, `namespaces.from: Same` means the
                // ListenerSet's own namespace, not its Gateway's (matches the
                // route and ListenerSet reconcilers).
                let gateway_ns = match parent_ref.parent_kind {
                    crate::store::ParentKind::Gateway => parent_ref.gateway_namespace.as_str(),
                    crate::store::ParentKind::ListenerSet => ls_map
                        .get(&parent_key)
                        .map(|ls| ls.namespace.as_str())
                        .unwrap_or(parent_ref.gateway_namespace.as_str()),
                };
                let route_ns_labels = store
                    .namespace_labels
                    .get(&hr.namespace)
                    .map(|v| v.value().clone())
                    .unwrap_or_default();
                if !crate::reconcilers::http_route::namespace_allowed(
                    &listener.allowed_routes,
                    &hr.namespace,
                    gateway_ns,
                    &route_ns_labels,
                ) {
                    continue;
                }

                let listener_hostname_str =
                    listener.hostname.clone().unwrap_or_default();
                let listener_port = listener.port;
                let listener_name = parent_ref
                    .section_name
                    .clone()
                    .unwrap_or_else(|| listener.name.clone());
                let (owner_ns, owner_name) = owner_gateway(
                    &parent_ref.parent_kind,
                    &parent_ref.gateway_namespace,
                    &parent_ref.gateway_name,
                    &ls_map,
                );

                // Effective hosts for THIS listener only (intersect route
                // hostnames with listener hostname, or default to listener
                // hostname when the route has no hostnames, or "*" when both
                // are unrestricted).
                let effective_hosts =
                    compute_effective_hostnames_inner(
                        std::slice::from_ref(&listener.hostname),
                        &hr.hostnames,
                    );
                if effective_hosts.is_empty() {
                    continue;
                }

                for rule in &hr.rules {
                    let placeholder = effective_hosts
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("*");
                    let mut base_configs = compile_http_rule(
                        rule,
                        placeholder,
                        &listener_name,
                        listener_port,
                        &listener_hostname_str,
                    );
                    for rc in base_configs.iter_mut() {
                        rc.gateway_namespace = owner_ns.clone();
                        rc.gateway_name = owner_name.clone();
                    }

                    // Mirror backends may not have been declared as top-level
                    // backendRefs; track them too so their endpoints are
                    // resolved.
                    for rc in &base_configs {
                        for mb in &rc.mirror_backends {
                            backend_keys.insert(ServiceKey {
                                namespace: hr.namespace.clone(),
                                name: mb.service_name.clone(),
                                port: u16::try_from(mb.port).unwrap_or(0),
                            });
                        }
                    }

                    for host in &effective_hosts {
                        for rc in &base_configs {
                            let mut route = rc.clone();
                            route.host = host.clone();
                            log::debug!(
                                "compiled route host={} service={} listener_port={} listener_name={} listener_hostname={}",
                                host, route.service_name, listener_port, listener_name, listener_hostname_str
                            );

                            // Cross-namespace grant revocation check
                            if !route.service_name.is_empty() {
                                let backend_ns = rule
                                    .backend_refs
                                    .iter()
                                    .find(|b| {
                                        b.name == route.service_name
                                            && b.port as u32 == route.port
                                    })
                                    .map(|b| b.namespace.as_str())
                                    .unwrap_or(&hr.namespace);
                                if backend_ns != hr.namespace
                                    && !crate::reconcilers::is_reference_allowed(
                                        &store.reference_grants,
                                        &hr.namespace,
                                        "HTTPRoute",
                                        backend_ns,
                                        "Service",
                                        Some(&route.service_name),
                                    )
                                {
                                    route.service_name = String::new();
                                    route.port = 0;
                                }
                            }
                            route_sources.push(RouteSource {
                                kind: "HTTPRoute".to_string(),
                                namespace: route_key.namespace.clone(),
                                name: route_key.name.clone(),
                                gateway_refs: gateway_refs.clone(),
                            });
                            routes.push(route);
                        }
                    }
                }
            }
        }
    }

    // Compile Routes from gRPC routes. Same per-(parent_ref, listener) model
    // as HTTP so each compiled RouteConfig carries its listener's hostname.
    for (route_key, gr) in &grpc_routes {
        // Collect gateway refs once per GRPCRoute
        let gateway_refs: Vec<(String, String, Option<String>)> = gr
            .parent_refs
            .iter()
            .map(|pr| (pr.gateway_namespace.clone(), pr.gateway_name.clone(), pr.section_name.clone()))
            .collect();

        // Track backend keys ONCE per GRPCRoute
        for rule in &gr.rules {
            for backend_ref in &rule.backend_refs {
                let is_cross_ns = backend_ref.namespace != gr.namespace;
                let grant_ok = !is_cross_ns
                    || crate::reconcilers::is_reference_allowed(
                        &store.reference_grants,
                        &gr.namespace,
                        "GRPCRoute",
                        &backend_ref.namespace,
                        "Service",
                        Some(&backend_ref.name),
                    );
                if grant_ok {
                    backend_keys.insert(ServiceKey {
                        namespace: backend_ref.namespace.clone(),
                        name: backend_ref.name.clone(),
                        port: backend_ref.port,
                    });
                }
            }
        }

        for parent_ref in gr.parent_refs.iter().filter(|pr| pr.accepted) {
            let parent_key = NamespacedName {
                namespace: parent_ref.gateway_namespace.clone(),
                name: parent_ref.gateway_name.clone(),
            };
            let parent_listeners: Vec<crate::store::ListenerState> = match parent_ref.parent_kind {
                crate::store::ParentKind::Gateway => match gw_map.get(&parent_key) {
                    Some(gw) => gw.listeners.clone(),
                    None => continue,
                },
                crate::store::ParentKind::ListenerSet => match ls_map.get(&parent_key) {
                    Some(ls) if ls.accepted => ls.listeners.clone(),
                    _ => continue,
                },
            };

            for listener in &parent_listeners {
                if !listener.accepted {
                    continue;
                }
                if !matches!(listener.protocol.as_str(), "HTTP" | "HTTPS") {
                    continue;
                }
                if let Some(ref sn) = parent_ref.section_name
                    && listener.name != *sn {
                        continue;
                    }
                if let Some(p) = parent_ref.port
                    && listener.port != p {
                        continue;
                    }

                // Per-listener namespace filter (same as HTTPRoute path).
                // For a ListenerSet parent, `namespaces.from: Same` means the
                // ListenerSet's own namespace, not its Gateway's (matches the
                // route and ListenerSet reconcilers).
                let gateway_ns = match parent_ref.parent_kind {
                    crate::store::ParentKind::Gateway => parent_ref.gateway_namespace.as_str(),
                    crate::store::ParentKind::ListenerSet => ls_map
                        .get(&parent_key)
                        .map(|ls| ls.namespace.as_str())
                        .unwrap_or(parent_ref.gateway_namespace.as_str()),
                };
                let route_ns_labels = store
                    .namespace_labels
                    .get(&gr.namespace)
                    .map(|v| v.value().clone())
                    .unwrap_or_default();
                if !crate::reconcilers::http_route::namespace_allowed(
                    &listener.allowed_routes,
                    &gr.namespace,
                    gateway_ns,
                    &route_ns_labels,
                ) {
                    continue;
                }

                let listener_hostname: String =
                    listener.hostname.clone().unwrap_or_default();
                let listener_port: u16 = listener.port;
                let listener_name = parent_ref
                    .section_name
                    .clone()
                    .unwrap_or_else(|| listener.name.clone());
                let (owner_ns, owner_name) = owner_gateway(
                    &parent_ref.parent_kind,
                    &parent_ref.gateway_namespace,
                    &parent_ref.gateway_name,
                    &ls_map,
                );

                let effective_hosts = compute_effective_hostnames_inner(
                    std::slice::from_ref(&listener.hostname),
                    &gr.hostnames,
                );
                if effective_hosts.is_empty() {
                    continue;
                }

                for rule in &gr.rules {
                    // Build weighted backends list (same logic as HTTP)
                    let weighted_backends: Vec<WeightedBackend> = if rule.backend_refs.len() > 1
                        || rule.backend_refs.iter().any(|b| b.weight != 1)
                    {
                        rule.backend_refs
                            .iter()
                            .map(|b| WeightedBackend {
                                service_name: b.name.clone(),
                                port: b.port as u32,
                                weight: b.weight,
                                request_headers: None,
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                    // Gateway API OR semantics: each match entry produces its own RouteConfig.
                    // If there are no match entries, produce one RouteConfig with no match criteria.
                    let match_entries: Vec<_> = if rule.matches.is_empty() {
                        vec![None]
                    } else {
                        rule.matches.iter().map(Some).collect()
                    };

                    for match_entry in &match_entries {
                        let grpc_match = match_entry.map(|m| GrpcRouteMatch {
                            service: m.service.clone().unwrap_or_default(),
                            method: m.method.clone().unwrap_or_default(),
                            match_type: m.match_type.clone(),
                        });

                        let paths = if let Some(ref gm) = grpc_match {
                            let path = if !gm.service.is_empty() && !gm.method.is_empty() {
                                format!("/{}/{}", gm.service, gm.method)
                            } else if !gm.service.is_empty() {
                                format!("/{}", gm.service)
                            } else {
                                "/".to_string()
                            };
                            vec![PathRule {
                                path,
                                match_type: "Prefix".to_string(),
                            }]
                        } else {
                            vec![]
                        };

                        let header_matches: Vec<HeaderMatch> = match_entry
                            .map(|m| {
                                m.headers
                                    .iter()
                                    .map(|(name, value, match_type)| HeaderMatch {
                                        name: name.clone(),
                                        value: value.clone(),
                                        match_type: match_type.clone(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        for host in &effective_hosts {
                    if !weighted_backends.is_empty() {
                        // Multiple weighted backends: single RouteConfig with weighted_backends
                        let primary = &rule.backend_refs[0];
                        routes.push(RouteConfig {
                            host: host.clone(),
                            paths: paths.clone(),
                            service_name: primary.name.clone(),
                            port: primary.port as u32,
                            protocol: "GRPC".to_string(),
                            grpc_match: grpc_match.clone(),
                            header_matches: header_matches.clone(),
                            listener_name: listener_name.clone(),
                            listener_port: listener_port as u32,
                            listener_hostname: listener_hostname.clone(),
                            gateway_namespace: owner_ns.clone(),
                            gateway_name: owner_name.clone(),
                            weighted_backends: weighted_backends.clone(),
                            ..Default::default()
                        });
                        route_sources.push(RouteSource {
                            kind: "GRPCRoute".to_string(),
                            namespace: route_key.namespace.clone(),
                            name: route_key.name.clone(),
                            gateway_refs: gateway_refs.clone(),
                        });
                    } else if rule.backend_refs.is_empty() {
                        // No backends — emit route for matching only
                        routes.push(RouteConfig {
                            host: host.clone(),
                            paths: paths.clone(),
                            service_name: String::new(),
                            port: 0,
                            protocol: "GRPC".to_string(),
                            grpc_match: grpc_match.clone(),
                            header_matches: header_matches.clone(),
                            listener_name: listener_name.clone(),
                            listener_port: listener_port as u32,
                            listener_hostname: listener_hostname.clone(),
                            gateway_namespace: owner_ns.clone(),
                            gateway_name: owner_name.clone(),
                            ..Default::default()
                        });
                        route_sources.push(RouteSource {
                            kind: "GRPCRoute".to_string(),
                            namespace: route_key.namespace.clone(),
                            name: route_key.name.clone(),
                            gateway_refs: gateway_refs.clone(),
                        });
                    } else {
                        // Single backend
                        let backend_ref = &rule.backend_refs[0];
                        // Check if cross-namespace grant was revoked
                        let (svc_name, svc_port) =
                            if backend_ref.namespace != gr.namespace
                                && !crate::reconcilers::is_reference_allowed(
                                    &store.reference_grants,
                                    &gr.namespace,
                                    "GRPCRoute",
                                    &backend_ref.namespace,
                                    "Service",
                                    Some(&backend_ref.name),
                                )
                            {
                                (String::new(), 0u32)
                            } else {
                                (backend_ref.name.clone(), backend_ref.port as u32)
                            };
                        routes.push(RouteConfig {
                            host: host.clone(),
                            paths: paths.clone(),
                            service_name: svc_name,
                            port: svc_port,
                            protocol: "GRPC".to_string(),
                            grpc_match: grpc_match.clone(),
                            header_matches: header_matches.clone(),
                            listener_name: listener_name.clone(),
                            listener_port: listener_port as u32,
                            listener_hostname: listener_hostname.clone(),
                            gateway_namespace: owner_ns.clone(),
                            gateway_name: owner_name.clone(),
                            ..Default::default()
                        });
                        route_sources.push(RouteSource {
                            kind: "GRPCRoute".to_string(),
                            namespace: route_key.namespace.clone(),
                            name: route_key.name.clone(),
                            gateway_refs: gateway_refs.clone(),
                        });
                    }
                        }
                    }
                }
            }
        }
    }

    // Apply policies to compiled routes
    apply_policies(store, &mut routes, &route_sources);

    // Override backend protocol based on Service appProtocol.
    // This handles kubernetes.io/h2c and kubernetes.io/ws from backendRefs.
    for route in &mut routes {
        if route.service_name.is_empty() || route.protocol == "GRPC" {
            continue;
        }
        let backend_ns = backend_ns_index
            .get(&(route.service_name.clone(), u16::try_from(route.port).unwrap_or(0)))
            .cloned();
        if let Some(ns) = backend_ns {
            let key = ServiceKey {
                namespace: ns,
                name: route.service_name.clone(),
                port: u16::try_from(route.port).unwrap_or(0),
            };
            if let Some(app_proto) = store.service_app_protocols.get(&key) {
                match app_proto.as_str() {
                    "kubernetes.io/h2c" => route.protocol = "H2C".to_string(),
                    "kubernetes.io/ws" => route.protocol = "WS".to_string(),
                    "HTTPS" => {
                        // Service declares HTTPS appProtocol — enable upstream TLS
                        // so the proxy attempts TLS even without BackendTLSPolicy.
                        // With verify_cert=true and no custom CA (system CAs only),
                        // the handshake fails → 502. With a valid BackendTLSPolicy,
                        // the dataplane uses the policy's custom CA certs instead.
                        route.upstream_tls = Some(UpstreamTlsConfig {
                            enabled: true,
                            verify_cert: true,
                            sni: route.service_name.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Compile TLS passthrough routes.
    // The compiler re-evaluates parent ref binding directly from the gateway store,
    // NOT from the reconciler's `accepted` flag. This eliminates race conditions
    // where the TLSRoute reconciler runs before its Gateway is in the store.
    let mut tls_passthrough_routes = Vec::new();
    for (_key, tr) in &tls_routes {

        // Try each parent ref — find the first one whose gateway+listener exists in the store
        let resolved = tr.parent_refs.iter().find_map(|pr| {
            let gw_key = NamespacedName {
                namespace: pr.gateway_namespace.clone(),
                name: pr.gateway_name.clone(),
            };
            let gw = gw_map.get(&gw_key)?;

            let listener = if let Some(ref sn) = pr.section_name {
                gw.listeners.iter().find(|l| l.name == *sn && l.protocol == "TLS" && l.accepted)
            } else {
                // No sectionName: find the TLS listener whose hostname best matches
                let tls_listeners: Vec<_> = gw.listeners.iter()
                    .filter(|l| l.protocol == "TLS" && l.accepted)
                    .collect();
                if tls_listeners.len() <= 1 {
                    tls_listeners.into_iter().next()
                } else {
                    tls_listeners.into_iter().find(|l| {
                        if let Some(ref lh) = l.hostname {
                            tr.hostnames.iter().any(|rh| {
                                crate::reconcilers::tls_route::hostname_matches_pub(lh, rh)
                            })
                        } else {
                            true // empty hostname matches all
                        }
                    })
                }
            };

            listener.map(|l| (pr, l.clone()))
        });

        let (parent_ref, listener) = match resolved {
            Some((pr, l)) => (pr, l),
            None => continue, // No matching gateway+listener found in store
        };

        let listener_name = parent_ref.section_name.clone().unwrap_or_default();
        let listener_hostname = listener.hostname.clone().unwrap_or_default();
        let listener_port = listener.port as u32;
        let tls_mode = listener.tls_mode.clone()
            .unwrap_or_else(|| "Passthrough".to_string());

        // For Terminate mode, resolve cert data from the listener's certificateRef Secret
        let (cert_pem, key_pem) = if tls_mode == "Terminate" {
            listener.tls_cert_refs.first()
                .and_then(|(ns, name)| {
                    let secret_key = NamespacedName {
                        namespace: ns.clone(),
                        name: name.clone(),
                    };
                    store.secrets.get(&secret_key).and_then(|secret| {
                        let cert = secret.data.get("tls.crt")?.clone();
                        let key = secret.data.get("tls.key")?.clone();
                        Some((cert, key))
                    })
                })
                .unwrap_or_default()
        } else {
            (String::new(), String::new())
        };

        // Compute effective hostnames by intersecting route hostnames with listener hostnames
        let effective_hostnames = compute_effective_hostnames_tls(tr, &gw_map);

        if let Some(backend) = tr.backend_refs.first() {
            backend_keys.insert(ServiceKey {
                namespace: backend.namespace.clone(),
                name: backend.name.clone(),
                port: backend.port,
            });

            tls_passthrough_routes.push(TlsPassthroughRoute {
                sni_hostnames: effective_hostnames,
                backend_service: backend.name.clone(),
                backend_port: backend.port as u32,
                listener_name: listener_name.clone(),
                listener_hostname: listener_hostname.clone(),
                tls_mode: tls_mode.clone(),
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                listener_port,
                gateway_namespace: parent_ref.gateway_namespace.clone(),
                gateway_name: parent_ref.gateway_name.clone(),
            });
        } else if !effective_hostnames.is_empty() {
            // No backend but route has effective hostnames — register SNI so the
            // mux rejects instead of forwarding to Pingora HTTPS
            tls_passthrough_routes.push(TlsPassthroughRoute {
                sni_hostnames: effective_hostnames,
                backend_service: String::new(),
                backend_port: 0,
                listener_name: listener_name.clone(),
                listener_hostname: listener_hostname.clone(),
                tls_mode: tls_mode.clone(),
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                listener_port,
                gateway_namespace: parent_ref.gateway_namespace.clone(),
                gateway_name: parent_ref.gateway_name.clone(),
            });
        }
    }

    let tcp_proxy_routes = compile_l4_routes("TCP", &tcp_routes, &gw_map, &mut backend_keys);
    let udp_proxy_routes = compile_l4_routes("UDP", &udp_routes, &gw_map, &mut backend_keys);

    // Compile BackendGroups from endpoints.
    // Service ports (from HTTPRoute backendRefs) may differ from target ports
    // (from EndpointSlice). Use service_port_map to translate.
    let mut backends = Vec::new();
    for key in &backend_keys {
        // Translate service port → target port for endpoint lookup
        let target_port = store
            .service_port_map
            .get(key)
            .map(|v| *v)
            .unwrap_or(key.port);
        let endpoint_key = ServiceKey {
            namespace: key.namespace.clone(),
            name: key.name.clone(),
            port: target_port,
        };
        let endpoints = store
            .endpoints
            .get(&endpoint_key)
            .map(|v| {
                v.value()
                    .iter()
                    .map(|ep| BackendEndpoint {
                        address: ep.address.clone(),
                        port: ep.port,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Look up HealthCheckPolicy targeting this Service
        let health_check = store.health_check_policies.iter().find_map(|entry| {
            let policy = entry.value();
            if policy.accepted
                && policy.target.kind == "Service"
                && policy.target.namespace == key.namespace
                && policy.target.name == key.name
            {
                Some(HealthCheckConfig {
                    path: policy.path.clone(),
                    interval_secs: policy.interval_secs,
                    timeout_secs: policy.timeout_secs,
                    healthy_threshold: policy.healthy_threshold,
                    unhealthy_threshold: policy.unhealthy_threshold,
                })
            } else {
                None
            }
        });

        // Look up BackendTLSPolicy targeting this Service.
        // Supports sectionName (targets a specific port name) and service-wide (no sectionName).
        // sectionName match takes precedence; within each scope, oldest policy wins (GEP-713).
        let port_name = store
            .service_port_names
            .get(key)
            .map(|v| v.value().clone());
        let backend_tls = {
            let mut section_match: Option<&crate::store::BackendTLSPolicyState> = None;
            let mut service_wide: Option<&crate::store::BackendTLSPolicyState> = None;
            // We need to hold refs across iteration, so snapshot first
            let btls_snapshot: Vec<_> = store.backend_tls_policies.iter()
                .map(|e| e.value().clone())
                .collect();
            for policy in &btls_snapshot {
                if !policy.accepted
                    || policy.target.kind != "Service"
                    || policy.target.namespace != key.namespace
                    || policy.target.name != key.name
                {
                    continue;
                }
                if let Some(ref section) = policy.target.section_name {
                    // sectionName must match this port's name
                    if port_name.as_deref() == Some(section.as_str()) {
                        section_match = Some(pick_oldest(section_match, Some(policy)).unwrap());
                    }
                } else {
                    // Service-wide policy (no sectionName)
                    service_wide = Some(pick_oldest(service_wide, Some(policy)).unwrap());
                }
            }
            // sectionName match takes precedence over service-wide
            let winner = section_match.or(service_wide);
            winner.map(|p| BackendTlsConfig {
                ca_cert_pem: p.ca_cert_pem.clone(),
                hostname: p.hostname.clone(),
                subject_alt_names: p.subject_alt_names.iter().map(|san| SubjectAltName {
                    r#type: san.san_type.clone(),
                    value: san.value.clone(),
                }).collect(),
            })
        };

        backends.push(BackendGroup {
            service_name: key.name.clone(),
            port: key.port as u32,
            endpoints,
            health_check,
            backend_tls,
        });
    }

    // Collect all TLS Passthrough listener hostnames for SNI rejection.
    // If the SNI matches a listener hostname but no passthrough route exists,
    // the connection should be rejected (not forwarded to Pingora for HTTPS termination).
    let mut tls_passthrough_listener_hostnames = Vec::new();
    for (_key, gw) in &gateways {
        for listener in &gw.listeners {
            if listener.accepted && listener.protocol == "TLS"
                && let Some(ref hostname) = listener.hostname {
                    tls_passthrough_listener_hostnames.push(hostname.clone());
                }
        }
    }

    CompiledConfig {
        schema_version: "1.0.0".to_string(),
        version,
        routes,
        backends,
        listeners,
        tls_passthrough_routes,
        tcp_proxy_routes,
        udp_proxy_routes,
        tls_passthrough_listener_hostnames,
        gateway_backend_tls: compile_gateway_backend_tls(store),
        ..Default::default()
    }
}

/// TCPRoutes (`protocol` "TCP") or UDPRoutes ("UDP") into L4 proxy routes: one
/// entry per (accepted parentRef × matching listener of that protocol). A
/// parentRef with neither sectionName nor port attaches to every such listener
/// on the Gateway. When several routes bind the same listener only the oldest
/// (creationTimestamp, then name) is programmed — the Gateway API conflict
/// rule — but every backend of every route is still resolved so the winner
/// switches cleanly if the older route disappears.
fn compile_l4_routes(
    protocol: &str,
    routes: &[(NamespacedName, L4RouteState)],
    gw_map: &HashMap<NamespacedName, GatewayState>,
    backend_keys: &mut std::collections::HashSet<ServiceKey>,
) -> Vec<L4ProxyRoute> {
    struct Candidate<'a> {
        listener_key: (String, String, String),
        listener_port: u32,
        created: Option<Time>,
        route_name: String,
        route: &'a L4RouteState,
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    for (key, tr) in routes {
        for backend in &tr.backend_refs {
            backend_keys.insert(ServiceKey {
                namespace: backend.namespace.clone(),
                name: backend.name.clone(),
                port: backend.port,
            });
        }
        for pr in tr.parent_refs.iter().filter(|pr| pr.accepted) {
            let gw_key = NamespacedName {
                namespace: pr.gateway_namespace.clone(),
                name: pr.gateway_name.clone(),
            };
            let Some(gw) = gw_map.get(&gw_key) else { continue };
            for l in gw.listeners.iter().filter(|l| {
                l.protocol == protocol
                    && l.accepted
                    && pr.section_name.as_deref().is_none_or(|sn| sn == l.name)
                    && pr.port.is_none_or(|p| p == l.port)
            }) {
                candidates.push(Candidate {
                    listener_key: (gw.namespace.clone(), gw.name.clone(), l.name.clone()),
                    listener_port: l.port as u32,
                    created: tr.creation_timestamp.clone(),
                    route_name: key.name.clone(),
                    route: tr,
                });
            }
        }
    }
    // Oldest first; routes without a timestamp sort last.
    candidates.sort_by(|a, b| {
        a.listener_key
            .cmp(&b.listener_key)
            .then_with(|| match (&a.created, &b.created) {
                (Some(x), Some(y)) => x.0.cmp(&y.0),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.route_name.cmp(&b.route_name))
    });
    candidates.dedup_by(|later, earlier| later.listener_key == earlier.listener_key);
    candidates
        .into_iter()
        .filter(|c| !c.route.backend_refs.is_empty())
        .map(|c| {
            let first = &c.route.backend_refs[0];
            L4ProxyRoute {
                backend_service: first.name.clone(),
                backend_port: first.port as u32,
                listener_name: c.listener_key.2.clone(),
                listener_port: c.listener_port,
                backends: c
                    .route
                    .backend_refs
                    .iter()
                    .map(|b| WeightedBackend {
                        service_name: b.name.clone(),
                        port: b.port as u32,
                        weight: b.weight,
                        request_headers: None,
                    })
                    .collect(),
                gateway_namespace: c.listener_key.0.clone(),
                gateway_name: c.listener_key.1.clone(),
            }
        })
        .collect()
}

/// Compute effective hostnames for an HTTPRoute by intersecting route hostnames
/// with the hostnames of each bound listener. This enforces listener hostname
/// isolation per the Gateway API spec.
///
/// Rules:
/// - Listener `*.example.com` + route `foo.example.com` → `foo.example.com`
/// - Listener `*.example.com` + route `*.sub.example.com` → `*.sub.example.com`
/// - Listener `foo.example.com` + route `*.example.com` → `foo.example.com`
/// - Listener unset + route hostname → route hostname
/// - Listener hostname + route unset → listener hostname
/// - Both unset → `*`
///
/// Shared helper: collect listener hostnames from parent refs, filtered by protocol.
fn collect_listener_hostnames(
    parent_refs: &[ParentRefState],
    gw_map: &HashMap<NamespacedName, GatewayState>,
    protocol_filter: &[&str],
) -> Vec<Option<String>> {
    let mut listener_hostnames: Vec<Option<String>> = Vec::new();
    for pref in parent_refs {
        if !pref.accepted {
            continue;
        }
        let gw_key = NamespacedName {
            namespace: pref.gateway_namespace.clone(),
            name: pref.gateway_name.clone(),
        };
        if let Some(gw) = gw_map.get(&gw_key) {
            for listener in &gw.listeners {
                if !listener.accepted {
                    continue;
                }
                if let Some(ref sn) = pref.section_name
                    && listener.name != *sn {
                        continue;
                    }
                if let Some(requested_port) = pref.port
                    && listener.port != requested_port {
                        continue;
                    }
                if !protocol_filter.iter().any(|p| listener.protocol == *p) {
                    continue;
                }
                listener_hostnames.push(listener.hostname.clone());
            }
        }
    }
    listener_hostnames
}

/// Shared helper: compute effective hostnames by intersecting route hostnames
/// with listener hostnames. Uses case-insensitive, single-level wildcard
/// semantics per Gateway API spec.
fn compute_effective_hostnames_inner(
    listener_hostnames: &[Option<String>],
    route_hostnames: &[String],
) -> Vec<String> {
    use crate::reconcilers::intersect_hostnames;

    if listener_hostnames.is_empty() {
        return Vec::new();
    }

    // Ordered: this list is part of the compiled RouteConfig, and the config
    // fingerprint must not change when nothing did. A HashSet here made every
    // compile of a multi-hostname route look new, and the Programmed flip that
    // followed each "new" config re-ran the compile for ever.
    let mut effective = std::collections::BTreeSet::new();

    for listener_hostname in listener_hostnames {
        match listener_hostname {
            None => {
                if route_hostnames.is_empty() {
                    effective.insert("*".to_string());
                } else {
                    for rh in route_hostnames {
                        effective.insert(rh.to_ascii_lowercase());
                    }
                }
            }
            Some(lh) => {
                if route_hostnames.is_empty() {
                    effective.insert(lh.to_ascii_lowercase());
                } else {
                    for rh in route_hostnames {
                        if let Some(result) = intersect_hostnames(lh, rh) {
                            effective.insert(result);
                        }
                    }
                }
            }
        }
    }

    effective.into_iter().collect()
}

/// Effective hostnames for an HTTPRoute across all its accepted HTTP/HTTPS
/// parents. The compile path now works per (parent, listener) pair; this
/// aggregate form remains for the hostname-intersection unit tests.
#[cfg(test)]
fn compute_effective_hostnames(hr: &HTTPRouteState, gw_map: &HashMap<NamespacedName, GatewayState>) -> Vec<String> {
    let listener_hostnames = collect_listener_hostnames(
        &hr.parent_refs, gw_map, &["HTTP", "HTTPS"],
    );
    compute_effective_hostnames_inner(&listener_hostnames, &hr.hostnames)
}

fn compute_effective_hostnames_tls(tr: &TLSRouteState, gw_map: &HashMap<NamespacedName, GatewayState>) -> Vec<String> {
    let listener_hostnames = collect_listener_hostnames(
        &tr.parent_refs, gw_map, &["TLS"],
    );
    compute_effective_hostnames_inner(&listener_hostnames, &tr.hostnames)
}

/// Pick the oldest of two BackendTLSPolicy candidates by creation_timestamp.
/// If timestamps are equal or missing, the current winner is kept.
fn pick_oldest<'a>(
    current: Option<&'a crate::store::BackendTLSPolicyState>,
    candidate: Option<&'a crate::store::BackendTLSPolicyState>,
) -> Option<&'a crate::store::BackendTLSPolicyState> {
    match (current, candidate) {
        (None, c) => c,
        (c, None) => c,
        (Some(a), Some(b)) => {
            let a_ts = a.creation_timestamp.as_ref().map(|t| &t.0);
            let b_ts = b.creation_timestamp.as_ref().map(|t| &t.0);
            match (a_ts, b_ts) {
                (Some(at), Some(bt)) if bt < at => Some(b),
                _ => Some(a), // a is older or equal — keep a
            }
        }
    }
}

/// Find the first policy (by index) that matches a route source.
/// Uses pre-built index for O(1) direct-target lookup, then falls back to
/// linear scan for gateway-targeted policies only.
fn find_matching_policy<T>(
    policies: &[T],
    route_index: &HashMap<(String, String, String), Vec<usize>>,
    gateway_policies: &[usize],
    source: &RouteSource,
    get_target: impl Fn(&T) -> &PolicyTargetKey,
) -> Option<usize> {
    // O(1) direct route match
    let key = (source.kind.clone(), source.namespace.clone(), source.name.clone());
    if let Some(indices) = route_index.get(&key)
        && let Some(&idx) = indices.first() {
            return Some(idx);
        }
    // Linear scan only over gateway-targeted policies (typically few)
    for &idx in gateway_policies {
        let target = get_target(&policies[idx]);
        for (gw_ns, gw_name, section) in &source.gateway_refs {
            if target.namespace == *gw_ns && target.name == *gw_name {
                if let Some(ref policy_section) = target.section_name {
                    if section.as_deref() == Some(policy_section.as_str()) {
                        return Some(idx);
                    }
                } else {
                    return Some(idx);
                }
            }
        }
    }
    None
}

/// (kind, namespace, name) of a policy's route target.
type RouteTargetKey = (String, String, String);
/// Route-targeted policies indexed by target, plus indices of Gateway-targeted ones.
type PolicyIndex = (HashMap<RouteTargetKey, Vec<usize>>, Vec<usize>);

/// Build index for a policy vec: (kind, ns, name) → indices for route-targeted,
/// plus a vec of indices for gateway-targeted policies.
fn index_policies<T>(
    policies: &[T],
    get_target: impl Fn(&T) -> &PolicyTargetKey,
) -> PolicyIndex {
    let mut route_index: HashMap<RouteTargetKey, Vec<usize>> = HashMap::new();
    let mut gateway_indices = Vec::new();
    for (i, policy) in policies.iter().enumerate() {
        let target = get_target(policy);
        if target.kind == "Gateway" {
            gateway_indices.push(i);
        } else {
            route_index
                .entry((target.kind.clone(), target.namespace.clone(), target.name.clone()))
                .or_default()
                .push(i);
        }
    }
    (route_index, gateway_indices)
}

/// Apply all accepted policies from the store to compiled routes.
/// Each route is matched against policy targets by kind+namespace+name or Gateway binding.
///
/// Policies are collected from DashMaps into Vecs once up front so that shard locks
/// are held only during the initial collect, not for the entire route loop.
/// Pre-built indexes provide O(1) direct-target lookups; only gateway-targeted
/// policies require a linear scan (typically few policies target Gateways).
fn apply_policies(
    store: &ConfigStore,
    routes: &mut [RouteConfig],
    route_sources: &[RouteSource],
) {
    // Collect accepted policies from DashMaps into Vecs (one scan each).
    // This avoids holding DashMap shard locks during the per-route iteration.
    let rate_limits: Vec<_> = store.rate_limit_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let circuit_breakers: Vec<_> = store.circuit_breaker_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let connections: Vec<_> = store.connection_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let basic_auths: Vec<_> = store.basic_auth_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let api_key_auths: Vec<_> = store.api_key_auth_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let retries: Vec<_> = store.retry_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let ip_allowlists: Vec<_> = store.ip_allowlist_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let body_size_limits: Vec<_> = store.request_body_size_limit_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let cors_policies: Vec<_> = store.cors_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();
    let timeouts: Vec<_> = store.timeout_policies.iter()
        .filter(|e| e.value().accepted)
        .map(|e| e.value().clone())
        .collect();

    // Build O(1) indexes for each policy type — avoids O(routes×policies) scan.
    let (rl_ri, rl_gi) = index_policies(&rate_limits, |p| &p.target);
    let (cb_ri, cb_gi) = index_policies(&circuit_breakers, |p| &p.target);
    let (cn_ri, cn_gi) = index_policies(&connections, |p| &p.target);
    let (ba_ri, ba_gi) = index_policies(&basic_auths, |p| &p.target);
    let (ak_ri, ak_gi) = index_policies(&api_key_auths, |p| &p.target);
    let (rt_ri, rt_gi) = index_policies(&retries, |p| &p.target);
    let (ip_ri, ip_gi) = index_policies(&ip_allowlists, |p| &p.target);
    let (bs_ri, bs_gi) = index_policies(&body_size_limits, |p| &p.target);
    let (co_ri, co_gi) = index_policies(&cors_policies, |p| &p.target);
    let (to_ri, to_gi) = index_policies(&timeouts, |p| &p.target);

    for (i, route) in routes.iter_mut().enumerate() {
        let source = &route_sources[i];

        // Rate limit policies
        if let Some(idx) = find_matching_policy(&rate_limits, &rl_ri, &rl_gi, source, |p| &p.target) {
            let policy = &rate_limits[idx];
            route.rate_limit = Some(RateLimitConfig {
                requests_per_second: policy.requests_per_second,
                per_client: policy.per_client,
            });
        }

        // Circuit breaker policies
        if let Some(idx) = find_matching_policy(&circuit_breakers, &cb_ri, &cb_gi, source, |p| &p.target) {
            let policy = &circuit_breakers[idx];
            route.circuit_breaker = Some(CircuitBreakerConfig {
                failure_threshold: policy.failure_threshold,
                success_threshold: policy.success_threshold,
                timeout_secs: policy.timeout_secs,
            });
        }

        // Connection policies
        if let Some(idx) = find_matching_policy(&connections, &cn_ri, &cn_gi, source, |p| &p.target) {
            route.max_connections = Some(connections[idx].max_connections);
        }

        // BasicAuth policies -- resolve Secret for credentials
        if let Some(idx) = find_matching_policy(&basic_auths, &ba_ri, &ba_gi, source, |p| &p.target) {
            let policy = &basic_auths[idx];
            let secret_key = NamespacedName {
                namespace: policy.secret_namespace.clone(),
                name: policy.secret_name.clone(),
            };
            if let Some(secret) = store.secrets.get(&secret_key) {
                route.auth = Some(AuthConfig {
                    auth_type: Some(auth_config::AuthType::BasicAuth(BasicAuthConfig {
                        credentials: secret.data.clone(),
                        realm: policy.realm.clone(),
                    })),
                });
            } else {
                route.auth = Some(AuthConfig {
                    auth_type: Some(auth_config::AuthType::BasicAuth(BasicAuthConfig {
                        credentials: HashMap::new(),
                        realm: policy.realm.clone(),
                    })),
                });
            }
        }

        // APIKeyAuth policies -- resolve Secret for valid keys
        if route.auth.is_none()
            && let Some(idx) = find_matching_policy(&api_key_auths, &ak_ri, &ak_gi, source, |p| &p.target) {
                let policy = &api_key_auths[idx];
                let secret_key = NamespacedName {
                    namespace: policy.secret_namespace.clone(),
                    name: policy.secret_name.clone(),
                };
                if let Some(secret) = store.secrets.get(&secret_key) {
                    route.auth = Some(AuthConfig {
                        auth_type: Some(auth_config::AuthType::ApiKey(ApiKeyAuthConfig {
                            valid_keys: secret.data.values().cloned().collect(),
                            header_name: policy.header_name.clone(),
                        })),
                    });
                } else {
                    route.auth = Some(AuthConfig {
                        auth_type: Some(auth_config::AuthType::ApiKey(ApiKeyAuthConfig {
                            valid_keys: vec![],
                            header_name: policy.header_name.clone(),
                        })),
                    });
                }
            }

        // RetryPolicy: the rule's own `retry` (HTTPRouteRetry) wins over a policy.
        if route.max_retries == 0
            && route.retry_codes.is_empty()
            && let Some(idx) = find_matching_policy(&retries, &rt_ri, &rt_gi, source, |p| &p.target)
        {
            route.max_retries = retries[idx].max_retries;
            route.retry_on = retries[idx].retry_on.clone();
        }

        // IPAllowlistPolicy
        if let Some(idx) = find_matching_policy(&ip_allowlists, &ip_ri, &ip_gi, source, |p| &p.target) {
            route.ip_allowlist = Some(IpAllowlistConfig {
                allow_cidrs: ip_allowlists[idx].allow_cidrs.clone(),
                deny_cidrs: ip_allowlists[idx].deny_cidrs.clone(),
                trusted_proxy_cidrs: ip_allowlists[idx].trusted_proxy_cidrs.clone(),
            });
        }

        // RequestBodySizeLimitPolicy
        if let Some(idx) = find_matching_policy(&body_size_limits, &bs_ri, &bs_gi, source, |p| &p.target) {
            route.max_request_body_bytes = body_size_limits[idx].max_bytes;
        }

        // CORSPolicy -- overrides route-level CORS if no filter-based CORS
        if route.cors.is_none()
            && let Some(idx) = find_matching_policy(&cors_policies, &co_ri, &co_gi, source, |p| &p.target) {
                let policy = &cors_policies[idx];
                route.cors = Some(CorsConfig {
                    allow_origins: policy.allow_origins.clone(),
                    allow_methods: policy.allow_methods.clone(),
                    allow_headers: policy.allow_headers.clone(),
                    expose_headers: policy.expose_headers.clone(),
                    allow_credentials: policy.allow_credentials,
                    max_age: policy.max_age,
                });
            }

        // TimeoutPolicy -- overrides route-level timeouts
        if let Some(idx) = find_matching_policy(&timeouts, &to_ri, &to_gi, source, |p| &p.target) {
            let policy = &timeouts[idx];
            if policy.request_timeout_ms > 0 {
                route.request_timeout_ms = policy.request_timeout_ms;
            }
            if policy.backend_request_timeout_ms > 0 {
                route.backend_request_timeout_ms = policy.backend_request_timeout_ms;
            }
            if policy.connect_timeout_ms > 0 {
                if let Some(ref mut t) = route.timeouts {
                    t.connect_timeout_ms = policy.connect_timeout_ms;
                } else {
                    route.timeouts = Some(TimeoutConfig {
                        connect_timeout_ms: policy.connect_timeout_ms,
                        read_timeout_ms: 0,
                        write_timeout_ms: 0,
                    });
                }
            }
        }
    }
}

/// Compile a single HTTPRoute rule into RouteConfig entries.
///
/// Convert a RequestHeaderModifier filter state into a HeaderMutation proto.
fn filters_to_request_header_mutation(filters: &[HTTPFilterState]) -> Option<HeaderMutation> {
    for filter in filters {
        if let HTTPFilterState::RequestHeaderModifier { add, set, remove } = filter {
            return Some(HeaderMutation {
                add: add.iter().cloned().collect(),
                set: set.iter().cloned().collect(),
                remove: remove.clone(),
            });
        }
    }
    None
}

/// Gateway API spec: multiple match entries within a rule's `matches` array
/// are OR'd — each match entry produces its own RouteConfig(s). Multiple
/// fields within a single match entry (path + headers + method + query params)
/// are AND'd within that RouteConfig.
#[allow(deprecated)] // mirror_backend (field 21) is still populated for older dataplanes
fn compile_http_rule(
    rule: &HTTPRouteRuleState,
    default_host: &str,
    listener_name: &str,
    listener_port: u16,
    listener_hostname: &str,
) -> Vec<RouteConfig> {
    let mut result = Vec::new();

    // Process filters (shared across all match entries)
    let mut request_headers: Option<HeaderMutation> = None;
    let mut response_headers: Option<HeaderMutation> = None;
    let mut redirect: Option<RedirectFilter> = None;
    let mut url_rewrite: Option<UrlRewriteFilter> = None;
    let mut mirror_backends: Vec<MirrorBackend> = Vec::new();
    let mut cors: Option<CorsConfig> = None;

    for filter in &rule.filters {
        match filter {
            HTTPFilterState::RequestHeaderModifier { add, set, remove } => {
                let mut add_map = std::collections::HashMap::new();
                for (k, v) in add.iter() {
                    add_map.insert(k.clone(), v.clone());
                }
                let mut set_map = std::collections::HashMap::new();
                for (k, v) in set.iter() {
                    set_map.insert(k.clone(), v.clone());
                }
                request_headers = Some(HeaderMutation {
                    add: add_map,
                    set: set_map,
                    remove: remove.clone(),
                });
            }
            HTTPFilterState::ResponseHeaderModifier { add, set, remove } => {
                let mut add_map = std::collections::HashMap::new();
                for (k, v) in add.iter() {
                    add_map.insert(k.clone(), v.clone());
                }
                let mut set_map = std::collections::HashMap::new();
                for (k, v) in set.iter() {
                    set_map.insert(k.clone(), v.clone());
                }
                response_headers = Some(HeaderMutation {
                    add: add_map,
                    set: set_map,
                    remove: remove.clone(),
                });
            }
            HTTPFilterState::RequestRedirect {
                scheme,
                hostname,
                port,
                path,
                path_type,
                status_code,
            } => {
                redirect = Some(RedirectFilter {
                    scheme: scheme.clone().unwrap_or_default(),
                    hostname: hostname.clone().unwrap_or_default(),
                    port: port.unwrap_or(0) as u32,
                    path: path.clone().unwrap_or_default(),
                    path_type: path_type.clone().unwrap_or_default(),
                    status_code: *status_code as u32,
                });
            }
            HTTPFilterState::URLRewrite {
                hostname,
                path,
                path_type,
            } => {
                url_rewrite = Some(UrlRewriteFilter {
                    hostname: hostname.clone().unwrap_or_default(),
                    path: path.clone().unwrap_or_default(),
                    path_type: path_type.clone().unwrap_or_default(),
                });
            }
            HTTPFilterState::RequestMirror {
                backend_namespace: _,
                backend_name,
                backend_port,
                percent,
            } => {
                mirror_backends.push(MirrorBackend {
                    service_name: backend_name.clone(),
                    port: *backend_port as u32,
                    percent: *percent,
                });
            }
            HTTPFilterState::CORS {
                allow_origins,
                allow_methods,
                allow_headers,
                expose_headers,
                allow_credentials,
                max_age,
            } => {
                cors = Some(CorsConfig {
                    allow_origins: allow_origins.clone(),
                    allow_methods: allow_methods.clone(),
                    allow_headers: allow_headers.clone(),
                    expose_headers: expose_headers.clone(),
                    allow_credentials: *allow_credentials,
                    max_age: max_age.unwrap_or(0),
                });
            }
        }
    }

    // Build weighted backends list (triggered by multiple backends, non-default weights,
    // or any per-backend filters)
    let has_backend_filters = rule.backend_refs.iter().any(|b| !b.filters.is_empty());
    let weighted_backends: Vec<WeightedBackend> = if rule.backend_refs.len() > 1
        || rule.backend_refs.iter().any(|b| b.weight != 1)
        || has_backend_filters
    {
        rule.backend_refs
            .iter()
            .map(|b| WeightedBackend {
                service_name: b.name.clone(),
                port: b.port as u32,
                weight: b.weight,
                request_headers: filters_to_request_header_mutation(&b.filters),
            })
            .collect()
    } else {
        vec![]
    };

    // Timeouts from rule state
    let request_timeout_ms = rule.request_timeout_ms.unwrap_or(0);
    let backend_request_timeout_ms = rule.backend_request_timeout_ms.unwrap_or(0);
    // Rule-level retry (`HTTPRouteRetry`): attempts bound the retries, codes
    // say which upstream statuses trigger one. A RetryPolicy on the route is
    // applied later only when the rule has no retry of its own.
    let (max_retries, retry_codes): (u32, Vec<u32>) = rule
        .retry
        .as_ref()
        .map(|r| (r.attempts, r.codes.iter().map(|c| u32::from(*c)).collect()))
        .unwrap_or_default();

    // Gateway API OR semantics: each match entry produces its own RouteConfig(s).
    // If there are no match entries, produce one RouteConfig with no match criteria.
    let match_entries: Vec<_> = if rule.matches.is_empty() {
        // No matches: single entry with no criteria
        vec![None]
    } else {
        rule.matches.iter().map(Some).collect()
    };

    for match_entry in &match_entries {
        // Extract per-match-entry fields
        let paths: Vec<PathRule> = match_entry
            .and_then(|m| {
                m.path.as_ref().map(|(path, match_type)| PathRule {
                    path: path.clone(),
                    match_type: match_type.clone(),
                })
            })
            .into_iter()
            .collect();

        let header_matches: Vec<HeaderMatch> = match_entry
            .map(|m| {
                m.headers
                    .iter()
                    .map(|(name, value, match_type)| HeaderMatch {
                        name: name.clone(),
                        value: value.clone(),
                        match_type: match_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let method_match = match_entry
            .and_then(|m| m.method.clone())
            .unwrap_or_default();

        let query_param_matches: Vec<QueryParamMatch> = match_entry
            .map(|m| {
                m.query_params
                    .iter()
                    .map(|(name, value, match_type)| QueryParamMatch {
                        name: name.clone(),
                        value: value.clone(),
                        match_type: match_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // When there are multiple weighted backends, emit a single RouteConfig
        // using the first backend as primary. The data plane uses weighted_backends
        // for traffic splitting.
        if !weighted_backends.is_empty() {
            let primary = &rule.backend_refs[0];
            result.push(RouteConfig {
                host: default_host.to_string(),
                paths: paths.clone(),
                service_name: primary.name.clone(),
                port: primary.port as u32,
                protocol: "HTTP".to_string(),
                header_matches: header_matches.clone(),
                method_match: method_match.clone(),
                query_param_matches: query_param_matches.clone(),
                request_headers: request_headers.clone(),
                response_headers: response_headers.clone(),
                redirect: redirect.clone(),
                url_rewrite: url_rewrite.clone(),
                listener_name: listener_name.to_string(),
                listener_port: listener_port as u32,
                listener_hostname: listener_hostname.to_string(),
                mirror_backend: mirror_backends.first().cloned(),
                mirror_backends: mirror_backends.clone(),
                weighted_backends: weighted_backends.clone(),
                request_timeout_ms,
                backend_request_timeout_ms,
                max_retries,
                retry_codes: retry_codes.clone(),
                cors: cors.clone(),
                ..Default::default()
            });
        } else if rule.backend_refs.is_empty() {
            // Redirect-only (or filter-only) rules have no backends.
            // Emit a single RouteConfig with empty service_name so the
            // data plane can still match the route and execute the filter.
            result.push(RouteConfig {
                host: default_host.to_string(),
                paths: paths.clone(),
                service_name: String::new(),
                port: 0,
                protocol: "HTTP".to_string(),
                header_matches: header_matches.clone(),
                method_match: method_match.clone(),
                query_param_matches: query_param_matches.clone(),
                request_headers: request_headers.clone(),
                response_headers: response_headers.clone(),
                redirect: redirect.clone(),
                url_rewrite: url_rewrite.clone(),
                listener_name: listener_name.to_string(),
                listener_port: listener_port as u32,
                listener_hostname: listener_hostname.to_string(),
                mirror_backend: mirror_backends.first().cloned(),
                mirror_backends: mirror_backends.clone(),
                weighted_backends: vec![],
                request_timeout_ms,
                backend_request_timeout_ms,
                max_retries,
                retry_codes: retry_codes.clone(),
                cors: cors.clone(),
                ..Default::default()
            });
        } else {
            for backend_ref in &rule.backend_refs {
                result.push(RouteConfig {
                    host: default_host.to_string(),
                    paths: paths.clone(),
                    service_name: backend_ref.name.clone(),
                    port: backend_ref.port as u32,
                    protocol: "HTTP".to_string(),
                    header_matches: header_matches.clone(),
                    method_match: method_match.clone(),
                    query_param_matches: query_param_matches.clone(),
                    request_headers: request_headers.clone(),
                    response_headers: response_headers.clone(),
                    redirect: redirect.clone(),
                    url_rewrite: url_rewrite.clone(),
                    listener_name: listener_name.to_string(),
                    listener_port: listener_port as u32,
                    listener_hostname: listener_hostname.to_string(),
                    mirror_backend: mirror_backends.first().cloned(),
                    mirror_backends: mirror_backends.clone(),
                    weighted_backends: vec![],
                    request_timeout_ms,
                    backend_request_timeout_ms,
                    max_retries,
                    retry_codes: retry_codes.clone(),
                    cors: cors.clone(),
                    ..Default::default()
                });
            }
        }
    }

    result
}

/// Compute an order-independent fingerprint for a CompiledConfig.
/// Uses wrapping-add of per-element proto-encoded hashes so DashMap iteration
/// order doesn't matter. This replaces the clone+sort+compare pattern —
/// zero clones, O(n) hashing during compilation.
pub(crate) fn config_fingerprint(config: &CompiledConfig) -> u64 {
    use prost::Message;
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    fn hash_bytes(bytes: &[u8]) -> u64 {
        let mut h = DefaultHasher::new();
        bytes.hash(&mut h);
        h.finish()
    }

    fn hash_msg<M: Message>(msg: &M) -> u64 {
        hash_bytes(&msg.encode_to_vec())
    }

    // Order-independent: wrapping add of individual hashes.
    // Same set of elements in any order → same fingerprint.
    let mut fp: u64 = 0;
    for r in &config.routes { fp = fp.wrapping_add(hash_msg(r)); }
    for b in &config.backends { fp = fp.wrapping_add(hash_msg(b)); }
    for l in &config.listeners { fp = fp.wrapping_add(hash_msg(l)); }
    for t in &config.tls_passthrough_routes { fp = fp.wrapping_add(hash_msg(t)); }
    for t in &config.tcp_proxy_routes { fp = fp.wrapping_add(hash_msg(t)); }
    for t in &config.udp_proxy_routes { fp = fp.wrapping_add(hash_msg(t)); }
    for h in &config.tls_passthrough_listener_hostnames {
        fp = fp.wrapping_add(hash_bytes(h.as_bytes()));
    }
    for g in &config.gateway_backend_tls { fp = fp.wrapping_add(hash_msg(g)); }
    fp
}

/// Writes landing within this window after the first one compile together.
pub const COMPILE_DEBOUNCE: Duration = Duration::from_millis(100);

/// Compilation loop: wakes on `change_notify`, coalesces writes that land
/// within a short debounce window, compiles once. `Notify::notify_one` stores
/// a permit when no waiter is parked, so a notification sent between two
/// iterations is never lost; there is no timer. Panics inside compile_config
/// are caught and logged — the loop never dies silently.
pub async fn compilation_loop(store: Arc<ConfigStore>, tx: watch::Sender<CompiledConfig>) {
    let mut version: u64 = 0;
    let mut last_fingerprint: u64 = 0;
    let mut iterations: u64 = 0;
    loop {
        store.change_notify.notified().await;
        tokio::time::sleep(COMPILE_DEBOUNCE).await;
        // Clear the dirty flag *before* compiling so writes that race with this
        // compilation are picked up by the next wake.
        if !store.take_dirty() {
            continue;
        }
        iterations += 1;

        // Catch panics in compile_config so the loop never dies silently
        let config = {
            let store_ref = &store;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                compile_config(store_ref)
            })) {
                Ok(config) => config,
                Err(e) => {
                    let msg = if let Some(s) = e.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    log::error!(
                        "PANIC in compile_config (iteration {}): {} — loop continues with last good config",
                        iterations, msg
                    );
                    continue;
                }
            }
        };

        // Order-independent fingerprint for change detection. No clone needed —
        // wrapping-add of per-element hashes is immune to DashMap iteration order.
        let fp = config_fingerprint(&config);

        // Refresh per-Gateway slice fingerprints on every compile, not only
        // when the global config changed. A Gateway that contributes nothing to
        // the compiled config (all listeners invalid, or its content identical
        // to what a departing Gateway contributed) would otherwise never get an
        // entry here, and `is_programmed_for` would report it unprogrammed for
        // ever. Waking the Programmed trigger lets its reconciler pick the new
        // value up immediately rather than on its next timed requeue.
        {
            let live: Vec<NamespacedName> = store.gateways.iter().map(|e| e.key().clone()).collect();
            let departed: Vec<NamespacedName> = store
                .compiled_gateway_fingerprints
                .iter()
                .map(|e| e.key().clone())
                .filter(|k| !live.contains(k))
                .collect();
            for key in departed {
                store.compiled_gateway_fingerprints.remove(&key);
                store.notify_programmed(&key);
            }
            for key in live {
                let slice_fp = scope_config(&config, &key.namespace, &key.name).fingerprint;
                if store.compiled_gateway_fingerprints.insert(key.clone(), slice_fp) != Some(slice_fp) {
                    store.notify_programmed(&key);
                }
            }
        }

        if fp == last_fingerprint && version > 0 {
            continue;
        }

        version += 1;
        last_fingerprint = fp;
        let route_count = config.routes.len();
        let backend_count = config.backends.len();
        let tls_passthrough_count = config.tls_passthrough_routes.len();
        let listener_count = config.listeners.len();
        log::info!(
            "compiled config v{}: {} routes, {} backends, {} listeners, {} tls_passthrough",
            version, route_count, backend_count, listener_count, tls_passthrough_count,
        );
        // Publish version and fingerprint BEFORE sending so that when a data
        // plane applies this config and reports back, is_programmed() already
        // compares against it.
        store
            .compiled_version
            .store(version, std::sync::atomic::Ordering::Release);
        store
            .compiled_fingerprint
            .store(fp, std::sync::atomic::Ordering::Release);
        let mut broadcast = config;
        broadcast.version = version;
        broadcast.fingerprint = fp;
        let _ = tx.send(broadcast);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcilers::intersect_hostnames;
    use crate::store::*;

    fn empty_store() -> ConfigStore {
        ConfigStore::new()
    }

    /// Build a gateway map from the store (for compute_effective_hostnames tests)
    fn gw_map_from_store(store: &ConfigStore) -> HashMap<NamespacedName, GatewayState> {
        store.gateways.iter().map(|e| (e.key().clone(), e.value().clone())).collect()
    }

    /// Add a default gateway with an accepted HTTP listener (no hostname restriction)
    /// and return the ParentRefState to use in HTTPRoutes.
    fn setup_default_gateway(store: &ConfigStore) -> ParentRefState {
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "test-gw".to_string(),
        };
        store.gateways.insert(
            key,
            GatewayState {
                name: "test-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "http".to_string(),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    hostname: None, // no hostname restriction
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
        ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: "default".to_string(),
            gateway_name: "test-gw".to_string(),
            section_name: None,
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        }
    }

    #[test]
    fn test_compile_empty_store() {
        let store = empty_store();
        let config = compile_config(&store);
        assert_eq!(config.schema_version, "1.0.0");
        assert_eq!(config.version, 0); // version is set by compilation_loop, not compile_config
        assert!(config.routes.is_empty());
        assert!(config.backends.is_empty());
        assert!(config.listeners.is_empty());
    }

    #[test]
    fn test_compile_one_http_route() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/v1".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.host, "api.example.com");
        assert_eq!(route.paths.len(), 1);
        assert_eq!(route.paths[0].path, "/v1");
        assert_eq!(route.paths[0].match_type, "Prefix");
        assert_eq!(route.service_name, "backend-svc");
        assert_eq!(route.port, 8080);
        assert_eq!(route.protocol, "HTTP");
    }

    #[test]
    fn test_compile_http_route_with_header_matches() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "header-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![("X-Version".to_string(), "v2".to_string(), "Exact".to_string())],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "v2-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.header_matches.len(), 1);
        assert_eq!(route.header_matches[0].name, "X-Version");
        assert_eq!(route.header_matches[0].value, "v2");
        assert_eq!(route.header_matches[0].match_type, "Exact");
    }

    #[test]
    fn test_compile_http_route_with_redirect() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "redirect-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["old.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: Some("https".to_string()),
                        hostname: Some("new.example.com".to_string()),
                        port: Some(443),
                        path: None,
                        path_type: None,
                        status_code: 301,
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "placeholder".to_string(),
                        port: 80,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.scheme, "https");
        assert_eq!(redir.hostname, "new.example.com");
        assert_eq!(redir.port, 443);
        assert_eq!(redir.status_code, 301);
    }

    #[test]
    fn test_compile_http_route_with_url_rewrite() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "rewrite-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/old".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::URLRewrite {
                        hostname: Some("internal.svc".to_string()),
                        path: Some("/new".to_string()),
                        path_type: Some("ReplaceFullPath".to_string()),
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        let rewrite = route.url_rewrite.as_ref().unwrap();
        assert_eq!(rewrite.hostname, "internal.svc");
        assert_eq!(rewrite.path, "/new");
        assert_eq!(rewrite.path_type, "ReplaceFullPath");
    }

    #[test]
    fn test_compile_http_route_with_request_header_modifier() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "header-mod-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestHeaderModifier {
                        add: vec![("X-Added".to_string(), "yes".to_string())],
                        set: vec![("X-Set".to_string(), "val".to_string())],
                        remove: vec!["X-Remove".to_string()],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        let req_headers = route.request_headers.as_ref().unwrap();
        assert!(req_headers.add.contains_key("X-Added"));
        assert!(req_headers.set.contains_key("X-Set"));
        assert!(req_headers.remove.contains(&"X-Remove".to_string()));
    }

    #[test]
    fn test_compile_grpc_route() {
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["grpc.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some("mypackage.MyService".to_string()),
                        method: Some("DoThing".to_string()),
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-backend".to_string(),
                        port: 50051,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.protocol, "GRPC");
        assert_eq!(route.host, "grpc.example.com");
        assert_eq!(route.service_name, "grpc-backend");
        assert_eq!(route.port, 50051);
        let gm = route.grpc_match.as_ref().unwrap();
        assert_eq!(gm.service, "mypackage.MyService");
        assert_eq!(gm.method, "DoThing");
        assert_eq!(gm.match_type, "Exact");
        // Path derived from gRPC service/method
        assert_eq!(route.paths[0].path, "/mypackage.MyService/DoThing");
    }

    #[test]
    fn test_compile_listeners_from_gateways() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            key,
            GatewayState {
                name: "my-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "http".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("example.com".to_string()),
                        accepted: true,
                        conflicted: false,
                        resolved_refs: true,
                        allowed_routes: AllowedRoutesState {
                            namespaces_from: "Same".to_string(),
                            namespace_selector: None,
                        },
                        tls_cert_refs: vec![],
                        tls_mode: None,
                    },
                    ListenerState {
                        name: "https".to_string(),
                        port: 443,
                        protocol: "HTTPS".to_string(),
                        hostname: None,
                        accepted: false, // not accepted - should be excluded
                        conflicted: false,
                        resolved_refs: true,
                        allowed_routes: AllowedRoutesState {
                            namespaces_from: "Same".to_string(),
                            namespace_selector: None,
                        },
                        tls_cert_refs: vec![],
                        tls_mode: None,
                    },
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].name, "http");
        assert_eq!(config.listeners[0].port, 80);
        assert_eq!(config.listeners[0].protocol, "HTTP");
        assert_eq!(config.listeners[0].hostname, "example.com");
    }

    #[test]
    fn test_compile_backend_groups_from_endpoints() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "ep-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "my-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // Add endpoints for the backend
        let svc_key = ServiceKey {
            namespace: "default".to_string(),
            name: "my-svc".to_string(),
            port: 8080,
        };
        store.endpoints.insert(
            svc_key,
            vec![
                BackendEndpoint {
                    address: "10.0.0.1".to_string(),
                    port: 8080,
                },
                BackendEndpoint {
                    address: "10.0.0.2".to_string(),
                    port: 8080,
                },
            ],
        );

        let config = compile_config(&store);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].service_name, "my-svc");
        assert_eq!(config.backends[0].port, 8080);
        assert_eq!(config.backends[0].endpoints.len(), 2);
    }

    // --- Phase 8: Mirror backend tests ---

    #[test]
    #[allow(deprecated)]
    fn test_compile_http_route_with_mirror_backend() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "mirror-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestMirror {
                        backend_namespace: "default".to_string(),
                        backend_name: "mirror-svc".to_string(),
                        backend_port: 9090,
                        percent: 0,
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "primary-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        // Backward compat: mirror_backend (singular) is populated from first mirror
        let mb = route.mirror_backend.as_ref().expect("should have mirror_backend");
        assert_eq!(mb.service_name, "mirror-svc");
        assert_eq!(mb.port, 9090);
        // New field: mirror_backends (plural) contains all mirrors
        assert_eq!(route.mirror_backends.len(), 1);
        assert_eq!(route.mirror_backends[0].service_name, "mirror-svc");
        assert_eq!(route.mirror_backends[0].port, 9090);
        assert_eq!(route.mirror_backends[0].percent, 0);
    }

    #[test]
    fn test_compile_http_route_with_multiple_mirrors() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "multi-mirror-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/multi-mirror".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![
                        HTTPFilterState::RequestMirror {
                            backend_namespace: "default".to_string(),
                            backend_name: "mirror-svc-v2".to_string(),
                            backend_port: 8080,
                            percent: 0,
                        },
                        HTTPFilterState::RequestMirror {
                            backend_namespace: "default".to_string(),
                            backend_name: "mirror-svc-v3".to_string(),
                            backend_port: 8080,
                            percent: 0,
                        },
                    ],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "primary-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.mirror_backends.len(), 2);
        assert_eq!(route.mirror_backends[0].service_name, "mirror-svc-v2");
        assert_eq!(route.mirror_backends[1].service_name, "mirror-svc-v3");
    }

    #[test]
    fn test_compile_http_route_with_percentage_mirror() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "pct-mirror-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/percent-mirror".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestMirror {
                        backend_namespace: "default".to_string(),
                        backend_name: "mirror-svc".to_string(),
                        backend_port: 8080,
                        percent: 20,
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "primary-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.mirror_backends.len(), 1);
        assert_eq!(route.mirror_backends[0].service_name, "mirror-svc");
        assert_eq!(route.mirror_backends[0].percent, 20);
    }

    // --- Phase 8: Weighted backends tests ---

    #[test]
    fn test_compile_http_route_with_weighted_backends() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "weighted-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![
                        BackendRefState {
                            namespace: "default".to_string(),
                            name: "svc-a".to_string(),
                            port: 8080,
                            weight: 80,
                            filters: vec![],
                        },
                        BackendRefState {
                            namespace: "default".to_string(),
                            name: "svc-b".to_string(),
                            port: 8080,
                            weight: 20,
                            filters: vec![],
                        },
                    ],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        // Multiple weighted backends should produce a single RouteConfig
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.service_name, "svc-a"); // primary backend
        assert_eq!(route.weighted_backends.len(), 2);
        assert_eq!(route.weighted_backends[0].service_name, "svc-a");
        assert_eq!(route.weighted_backends[0].weight, 80);
        assert_eq!(route.weighted_backends[1].service_name, "svc-b");
        assert_eq!(route.weighted_backends[1].weight, 20);
    }

    // --- Phase 8: Timeout tests ---

    #[test]
    fn test_compile_http_route_with_request_timeout() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "timeout-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: Some(5000),
                    backend_request_timeout_ms: Some(3000),
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.request_timeout_ms, 5000);
        assert_eq!(route.backend_request_timeout_ms, 3000);
    }

    // --- Phase 8: RegularExpression header match tests ---

    #[test]
    fn test_compile_http_route_with_regex_header_match() {
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "regex-header-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![(
                            "X-Version".to_string(),
                            "v[0-9]+".to_string(),
                            "RegularExpression".to_string(),
                        )],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.header_matches.len(), 1);
        assert_eq!(route.header_matches[0].name, "X-Version");
        assert_eq!(route.header_matches[0].value, "v[0-9]+");
        assert_eq!(route.header_matches[0].match_type, "RegularExpression");
    }

    // --- Phase 8: TLS passthrough route tests ---

    /// Helper: add a TLS Passthrough gateway with a single listener
    fn setup_tls_gateway(store: &ConfigStore, ns: &str, name: &str, listener_name: &str, hostname: Option<&str>) {
        setup_gateway_with_listeners(store, ns, name, vec![ListenerState {
            name: listener_name.to_string(),
            port: 443,
            protocol: "TLS".to_string(),
            hostname: hostname.map(|s| s.to_string()),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: Some("Passthrough".to_string()),
        }]);
    }

    #[test]
    fn test_compile_tls_passthrough_route() {
        let store = empty_store();
        setup_tls_gateway(&store, "default", "my-gw", "tls-listener", None);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        store.tls_routes.insert(
            key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["secure.example.com".to_string(), "api.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "my-gw".to_string(),
                    section_name: Some("tls-listener".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tls-backend".to_string(),
                    port: 8443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        let tls = &config.tls_passthrough_routes[0];
        let mut hostnames = tls.sni_hostnames.clone();
        hostnames.sort();
        assert_eq!(hostnames, vec!["api.example.com", "secure.example.com"]);
        assert_eq!(tls.backend_service, "tls-backend");
        assert_eq!(tls.backend_port, 8443);
        assert_eq!(tls.listener_name, "tls-listener");
        // Backend should be in backend groups
        assert!(config.backends.iter().any(|b| b.service_name == "tls-backend" && b.port == 8443));
    }

    #[test]
    fn test_compile_tls_passthrough_route_no_backends_still_registers_sni() {
        // When a TLSRoute is accepted but has no valid backends (e.g., InvalidKind,
        // BackendNotFound), the SNI hostnames should still be registered in the
        // passthrough map so the SNI mux rejects the connection instead of
        // forwarding to Pingora HTTPS (which would complete a TLS handshake).
        let store = empty_store();
        setup_tls_gateway(&store, "default", "my-gw", "tls-listener", None);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-no-backend".to_string(),
        };
        store.tls_routes.insert(
            key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: false,
                    reject_reason: None,
                }],
                backend_refs: vec![], // No valid backends
                generation: 1,
                resolved_reason: "InvalidKind".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(
            config.tls_passthrough_routes.len(),
            1,
            "accepted route with no backends should still register SNI"
        );
        let tls = &config.tls_passthrough_routes[0];
        assert_eq!(tls.sni_hostnames, vec!["example.com"]);
        assert!(tls.backend_service.is_empty(), "backend_service should be empty");
        assert_eq!(tls.backend_port, 0);
    }

    #[test]
    fn test_compile_tls_passthrough_route_not_accepted_not_registered() {
        // When a TLSRoute is NOT accepted, it should NOT register SNI hostnames.
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-rejected".to_string(),
        };
        store.tls_routes.insert(
            key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["rejected.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: false,
                    resolved_refs: false,
                    reject_reason: Some("NotAllowedByListeners".to_string()),
                }],
                backend_refs: vec![],
                generation: 1,
                resolved_reason: "BackendNotFound".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(
            config.tls_passthrough_routes.len(),
            0,
            "rejected route should NOT register SNI"
        );
    }

    #[test]
    fn test_compile_tcp_proxy_route() {
        let store = empty_store();

        // Need a gateway for listener port lookup
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "my-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "tcp-db".to_string(),
                    port: 5432,
                    protocol: "TCP".to_string(),
                    hostname: None,
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "All".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tcp-route".to_string(),
        };
        store.tcp_routes.insert(
            key,
            L4RouteState {
                namespace: "default".to_string(),
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "my-gw".to_string(),
                    section_name: Some("tcp-db".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "postgres-svc".to_string(),
                    port: 5432,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                creation_timestamp: None,
                resolved_refs_reason: None,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tcp_proxy_routes.len(), 1);
        let tcp = &config.tcp_proxy_routes[0];
        assert_eq!(tcp.backend_service, "postgres-svc");
        assert_eq!(tcp.backend_port, 5432);
        assert_eq!(tcp.listener_name, "tcp-db");
        assert_eq!(tcp.listener_port, 5432);
        assert_eq!(tcp.backends.len(), 1);
        assert_eq!(tcp.backends[0].weight, 1);
        // Backend should be in backend groups
        assert!(config.backends.iter().any(|b| b.service_name == "postgres-svc" && b.port == 5432));
    }

    /// Helper for the TCP conformance-shaped tests below.
    fn tcp_gateway(store: &ConfigStore, name: &str, listeners: &[(&str, u16)]) {
        l4_gateway(store, name, "TCP", listeners);
    }

    /// A Gateway whose listeners all speak `protocol` ("TCP" or "UDP").
    fn l4_gateway(store: &ConfigStore, name: &str, protocol: &str, listeners: &[(&str, u16)]) {
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: name.into() },
            GatewayState {
                name: name.into(),
                namespace: "default".into(),
                listeners: listeners
                    .iter()
                    .map(|(ln, port)| ListenerState {
                        name: (*ln).into(),
                        port: *port,
                        protocol: protocol.into(),
                        hostname: None,
                        accepted: true,
                        conflicted: false,
                        resolved_refs: true,
                        allowed_routes: AllowedRoutesState { namespaces_from: "Same".into(), namespace_selector: None },
                        tls_cert_refs: vec![],
                        tls_mode: None,
                    })
                    .collect(),
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
    }

    fn tcp_route(
        store: &ConfigStore,
        name: &str,
        gw: &str,
        section: Option<&str>,
        port: Option<u16>,
        backends: &[(&str, u16, u32)],
        created_secs: Option<i64>,
    ) {
        l4_route(&store.tcp_routes, name, gw, section, port, backends, created_secs);
    }

    fn l4_route(
        routes: &dashmap::DashMap<NamespacedName, L4RouteState>,
        name: &str,
        gw: &str,
        section: Option<&str>,
        port: Option<u16>,
        backends: &[(&str, u16, u32)],
        created_secs: Option<i64>,
    ) {
        routes.insert(
            NamespacedName { namespace: "default".into(), name: name.into() },
            L4RouteState {
                namespace: "default".into(),
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".into(),
                    gateway_name: gw.into(),
                    section_name: section.map(Into::into),
                    port,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: backends
                    .iter()
                    .map(|(svc, p, w)| BackendRefState {
                        namespace: "default".into(),
                        name: (*svc).into(),
                        port: *p,
                        weight: *w,
                        filters: vec![],
                    })
                    .collect(),
                generation: 1,
                creation_timestamp: created_secs.map(|s| {
                    Time(k8s_openapi::jiff::Timestamp::from_second(s).expect("valid timestamp"))
                }),
                resolved_refs_reason: None,
            },
        );
    }

    #[test]
    fn test_compile_tcp_weighted_backends_all_emitted() {
        // tcproute-weighted-routing: 70 / 30 / 0
        let store = empty_store();
        tcp_gateway(&store, "tcp-weighted-gateway", &[("tcp", 9300)]);
        tcp_route(&store, "tcp-weighted-route", "tcp-weighted-gateway", Some("tcp"), None,
            &[("tcp-backend-v1", 3000, 70), ("tcp-backend-v2", 3000, 30), ("tcp-backend-v3", 3000, 0)], Some(1));
        let config = compile_config(&store);
        assert_eq!(config.tcp_proxy_routes.len(), 1);
        let r = &config.tcp_proxy_routes[0];
        assert_eq!(r.listener_port, 9300);
        let weights: Vec<(String, u32)> = r.backends.iter().map(|b| (b.service_name.clone(), b.weight)).collect();
        assert_eq!(weights, vec![("tcp-backend-v1".into(), 70), ("tcp-backend-v2".into(), 30), ("tcp-backend-v3".into(), 0)]);
        for svc in ["tcp-backend-v1", "tcp-backend-v2", "tcp-backend-v3"] {
            assert!(config.backends.iter().any(|b| b.service_name == svc && b.port == 3000), "{svc} backend group missing");
        }
    }

    #[test]
    fn test_compile_tcp_parentref_by_port_section_and_both() {
        // tcproute-parentref-port-and-section-name
        let store = empty_store();
        tcp_gateway(&store, "gw", &[("one", 9300), ("two", 9301), ("three", 9302)]);
        tcp_route(&store, "by-port", "gw", None, Some(9300), &[("tcp-echo-one", 3000, 1)], Some(1));
        tcp_route(&store, "by-section", "gw", Some("two"), None, &[("tcp-echo-two", 3000, 1)], Some(2));
        tcp_route(&store, "by-both", "gw", Some("three"), Some(9302), &[("tcp-echo-three", 3000, 1)], Some(3));
        let config = compile_config(&store);
        let mut got: Vec<(u32, String, String)> = config.tcp_proxy_routes.iter()
            .map(|r| (r.listener_port, r.listener_name.clone(), r.backend_service.clone())).collect();
        got.sort();
        assert_eq!(got, vec![
            (9300, "one".into(), "tcp-echo-one".into()),
            (9301, "two".into(), "tcp-echo-two".into()),
            (9302, "three".into(), "tcp-echo-three".into()),
        ]);
    }

    #[test]
    fn test_compile_tcp_bare_parentref_attaches_to_every_tcp_listener() {
        // tcproute-parentref-attach-all: four TCP listeners, one route, no section/port
        let store = empty_store();
        tcp_gateway(&store, "gw", &[("one", 9310), ("two", 9311), ("three", 9312), ("four", 9313)]);
        tcp_route(&store, "attach-all", "gw", None, None, &[("tcp-echo-attach-all", 3000, 1)], Some(1));
        let config = compile_config(&store);
        let mut ports: Vec<u32> = config.tcp_proxy_routes.iter().map(|r| r.listener_port).collect();
        ports.sort();
        assert_eq!(ports, vec![9310, 9311, 9312, 9313]);
        assert!(config.tcp_proxy_routes.iter().all(|r| r.backend_service == "tcp-echo-attach-all"));
    }

    #[test]
    fn test_compile_tcp_conflict_oldest_route_wins() {
        // tcproute-multiple-routes-attachment: both Accepted, only the oldest programmed
        let store = empty_store();
        tcp_gateway(&store, "gw", &[("tcp", 9310)]);
        tcp_route(&store, "tcproute-attach-newer", "gw", Some("tcp"), None, &[("tcp-attach-backend-2", 3000, 1)], Some(200));
        tcp_route(&store, "tcproute-attach-older", "gw", Some("tcp"), None, &[("tcp-attach-backend-1", 3000, 1)], Some(100));
        let config = compile_config(&store);
        assert_eq!(config.tcp_proxy_routes.len(), 1, "one programmed route per listener");
        assert_eq!(config.tcp_proxy_routes[0].backend_service, "tcp-attach-backend-1");
        // Both backends are still resolved into backend groups.
        assert!(config.backends.iter().any(|b| b.service_name == "tcp-attach-backend-2"));
    }

    #[test]
    fn test_compile_tcp_conflict_tie_breaks_by_name_and_missing_timestamp_loses() {
        let store = empty_store();
        tcp_gateway(&store, "gw", &[("tcp", 9310)]);
        tcp_route(&store, "b-route", "gw", Some("tcp"), None, &[("svc-b", 3000, 1)], Some(100));
        tcp_route(&store, "a-route", "gw", Some("tcp"), None, &[("svc-a", 3000, 1)], Some(100));
        tcp_route(&store, "no-ts", "gw", Some("tcp"), None, &[("svc-none", 3000, 1)], None);
        let config = compile_config(&store);
        assert_eq!(config.tcp_proxy_routes.len(), 1);
        assert_eq!(config.tcp_proxy_routes[0].backend_service, "svc-a");
    }

    #[test]
    fn test_compile_empty_tls_tcp_routes() {
        let store = empty_store();
        let config = compile_config(&store);
        assert!(config.tls_passthrough_routes.is_empty());
        assert!(config.tcp_proxy_routes.is_empty());
        assert!(config.udp_proxy_routes.is_empty());
    }

    // --- UDPRoute: the same L4 compile keyed on UDP listeners ---

    #[test]
    fn test_compile_udp_route_targets_udp_listeners_only() {
        // udproute-simple: listener coredns/UDP/5300 -> coredns:53. A TCP
        // listener on the same Gateway is never a UDPRoute parent, and a
        // TCPRoute never binds a UDP listener.
        let store = empty_store();
        store.gateways.insert(
            NamespacedName { namespace: "default".into(), name: "udp-gateway".into() },
            GatewayState {
                name: "udp-gateway".into(),
                namespace: "default".into(),
                listeners: vec![
                    ListenerState {
                        name: "coredns".into(), port: 5300, protocol: "UDP".into(), hostname: None,
                        accepted: true, conflicted: false, resolved_refs: true,
                        allowed_routes: AllowedRoutesState { namespaces_from: "Same".into(), namespace_selector: None },
                        tls_cert_refs: vec![], tls_mode: None,
                    },
                    ListenerState {
                        name: "tcp".into(), port: 5300, protocol: "TCP".into(), hostname: None,
                        accepted: true, conflicted: false, resolved_refs: true,
                        allowed_routes: AllowedRoutesState { namespaces_from: "Same".into(), namespace_selector: None },
                        tls_cert_refs: vec![], tls_mode: None,
                    },
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
        l4_route(&store.udp_routes, "udp-coredns", "udp-gateway", None, None, &[("coredns", 53, 1)], Some(1));
        l4_route(&store.tcp_routes, "tcp-echo", "udp-gateway", None, None, &[("tcp-echo", 3000, 1)], Some(1));
        let config = compile_config(&store);

        assert_eq!(config.udp_proxy_routes.len(), 1);
        let udp = &config.udp_proxy_routes[0];
        assert_eq!((udp.listener_name.as_str(), udp.listener_port), ("coredns", 5300));
        assert_eq!((udp.backend_service.as_str(), udp.backend_port), ("coredns", 53));
        assert_eq!((udp.gateway_namespace.as_str(), udp.gateway_name.as_str()), ("default", "udp-gateway"));
        assert_eq!(config.tcp_proxy_routes.len(), 1);
        assert_eq!(config.tcp_proxy_routes[0].listener_name, "tcp");
        assert!(config.backends.iter().any(|b| b.service_name == "coredns" && b.port == 53), "UDP backends get backend groups");
    }

    #[test]
    fn test_compile_udp_weighted_and_conflict_rules_match_tcp() {
        // udproute-weighted-routing (70/30/0) and udproute-multiple-routes-attachment (oldest wins).
        let store = empty_store();
        l4_gateway(&store, "udp-weighted-gateway", "UDP", &[("udp", 5300)]);
        l4_route(&store.udp_routes, "newer", "udp-weighted-gateway", Some("udp"), None, &[("udp-attach-backend-2", 8080, 1)], Some(200));
        l4_route(&store.udp_routes, "older", "udp-weighted-gateway", Some("udp"), None,
            &[("udp-backend-v1", 8080, 70), ("udp-backend-v2", 8080, 30), ("udp-backend-v3", 8080, 0)], Some(100));
        let config = compile_config(&store);
        assert_eq!(config.udp_proxy_routes.len(), 1, "one programmed route per UDP listener");
        let weights: Vec<(String, u32)> = config.udp_proxy_routes[0].backends.iter().map(|b| (b.service_name.clone(), b.weight)).collect();
        assert_eq!(weights, vec![("udp-backend-v1".into(), 70), ("udp-backend-v2".into(), 30), ("udp-backend-v3".into(), 0)]);
        assert!(config.backends.iter().any(|b| b.service_name == "udp-attach-backend-2"), "the loser's backend stays resolved");
    }

    #[test]
    fn test_compile_udp_bare_parentref_and_port_section_binding() {
        // udproute-parentref-attach-all-listeners + udproute-parentref-port-and-section-name
        let store = empty_store();
        l4_gateway(&store, "gw", "UDP", &[("udp-1", 5310), ("udp-2", 5311), ("udp-3", 5312)]);
        l4_route(&store.udp_routes, "attach-all", "gw", None, None, &[("udp-echo-attach-all", 8080, 1)], Some(1));
        let config = compile_config(&store);
        let mut ports: Vec<u32> = config.udp_proxy_routes.iter().map(|r| r.listener_port).collect();
        ports.sort();
        assert_eq!(ports, vec![5310, 5311, 5312]);

        let store = empty_store();
        l4_gateway(&store, "gw", "UDP", &[("by-port", 5300), ("by-section", 5301), ("by-section-and-port", 5302)]);
        l4_route(&store.udp_routes, "by-port", "gw", None, Some(5300), &[("udp-echo-by-port", 8080, 1)], Some(1));
        l4_route(&store.udp_routes, "by-section", "gw", Some("by-section"), None, &[("udp-echo-by-section", 8080, 1)], Some(1));
        l4_route(&store.udp_routes, "both", "gw", Some("by-section-and-port"), Some(5302), &[("udp-echo-both", 8080, 1)], Some(1));
        let config = compile_config(&store);
        let mut got: Vec<(u32, String)> = config.udp_proxy_routes.iter().map(|r| (r.listener_port, r.backend_service.clone())).collect();
        got.sort();
        assert_eq!(got, vec![(5300, "udp-echo-by-port".into()), (5301, "udp-echo-by-section".into()), (5302, "udp-echo-both".into())]);
    }

    #[test]
    fn test_scope_and_fingerprint_include_udp_routes() {
        let store = empty_store();
        l4_gateway(&store, "a", "UDP", &[("udp", 5300)]);
        l4_gateway(&store, "b", "UDP", &[("udp", 5301)]);
        l4_route(&store.udp_routes, "ra", "a", None, None, &[("svc-a", 53, 1)], Some(1));
        l4_route(&store.udp_routes, "rb", "b", None, None, &[("svc-b", 53, 1)], Some(1));
        let config = compile_config(&store);
        let a = scope_config(&config, "default", "a");
        assert_eq!(a.udp_proxy_routes.len(), 1);
        assert_eq!(a.udp_proxy_routes[0].backend_service, "svc-a");
        assert!(a.backends.iter().any(|b| b.service_name == "svc-a"));
        assert!(!a.backends.iter().any(|b| b.service_name == "svc-b"), "only the scoped Gateway's UDP backends");
        let b = scope_config(&config, "default", "b");
        assert_ne!(a.fingerprint, b.fingerprint);

        let mut without = config.clone();
        without.udp_proxy_routes.clear();
        assert_ne!(config_fingerprint(&config), config_fingerprint(&without), "UDP routes are part of the fingerprint");
    }

    #[test]
    fn test_compile_tls_tcp_backends_in_backend_keys() {
        let store = empty_store();
        setup_tls_gateway(&store, "default", "gw", "tls", None);

        // Add TLS route with endpoint data
        let tls_key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        store.tls_routes.insert(
            tls_key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["tls.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "gw".to_string(),
                    section_name: Some("tls".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tls-svc".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // Add endpoints for the TLS backend
        let svc_key = ServiceKey {
            namespace: "default".to_string(),
            name: "tls-svc".to_string(),
            port: 443,
        };
        store.endpoints.insert(
            svc_key,
            vec![BackendEndpoint {
                address: "10.0.0.1".to_string(),
                port: 443,
            }],
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        // Backend should have endpoints compiled
        let backend = config.backends.iter().find(|b| b.service_name == "tls-svc").unwrap();
        assert_eq!(backend.endpoints.len(), 1);
        assert_eq!(backend.endpoints[0].address, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_compilation_loop_debounce_and_broadcast() {
        let store = Arc::new(ConfigStore::new());
        let (tx, mut rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());

        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            compilation_loop(store_clone, tx).await;
        });

        // Signal a change
        store.notify_change();

        // Should receive compiled config after ~100ms debounce
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timeout waiting for compiled config")
            .expect("watch closed");
        let config = rx.borrow_and_update().clone();

        assert_eq!(config.version, 1);
        assert_eq!(config.schema_version, "1.0.0");
        assert_eq!(
            store
                .compiled_version
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_compilation_loop_route_deletion_pushes_update() {
        // Verify the full lifecycle: add route → compile → delete route → compile
        // The dataplane must receive a config with 0 routes after deletion.
        let store = Arc::new(ConfigStore::new());
        let (tx, mut rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());

        // Set up a gateway so routes compile
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "test-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "test-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "http".to_string(),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    hostname: None,
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            compilation_loop(store_clone, tx).await;
        });

        // Step 1: Add an HTTPRoute
        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "test-route".to_string(),
        };
        store.http_routes.insert(
            route_key.clone(),
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["test.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "test-gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/test".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );
        store.notify_change();

        // Should receive config with 1 route
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timeout waiting for config after add")
            .expect("watch closed");
        let config = rx.borrow_and_update().clone();
        assert_eq!(config.routes.len(), 1, "should have 1 route after add");
        assert_eq!(config.version, 1);

        // Step 2: Delete the HTTPRoute (simulating what reconciler does on deletion)
        store.http_routes.remove(&route_key);
        store.notify_change();

        // Should receive config with 0 routes
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timeout waiting for config after delete")
            .expect("watch closed");
        let config2 = rx.borrow_and_update().clone();
        assert_eq!(config2.routes.len(), 0, "should have 0 routes after deletion");
        assert!(config2.version > 1, "version should increment");

        handle.abort();
    }

    #[tokio::test]
    async fn test_compilation_loop_unchanged_config_not_broadcast() {
        // Verify that notify_change without actual store changes doesn't
        // send a new config (prevents unnecessary dataplane churn).
        let store = Arc::new(ConfigStore::new());
        let (tx, mut rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());

        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            compilation_loop(store_clone, tx).await;
        });

        // First notify: empty store → version 1
        store.notify_change();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timeout")
            .expect("watch closed");
        let config = rx.borrow_and_update().clone();
        assert_eq!(config.version, 1);

        // Second notify: store hasn't changed → should NOT send
        store.notify_change();
        let result = tokio::time::timeout(Duration::from_millis(300), rx.changed()).await;
        assert!(result.is_err(), "should NOT receive update when config unchanged");

        handle.abort();
    }

    // --- OR match semantics tests (Gateway API conformance) ---

    #[test]
    fn test_compile_or_match_produces_multiple_routes() {
        // Gateway API spec: multiple match entries within a rule are OR'd.
        // A rule with 2 match entries (different headers, no paths) should
        // produce 2 RouteConfigs per backend.
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "or-match-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![
                        HTTPRouteMatchState {
                            path: None,
                            headers: vec![("color".to_string(), "blue".to_string(), "Exact".to_string())],
                            method: None,
                            query_params: vec![],
                        },
                        HTTPRouteMatchState {
                            path: None,
                            headers: vec![("color".to_string(), "green".to_string(), "Exact".to_string())],
                            method: None,
                            query_params: vec![],
                        },
                    ],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        // Should produce 2 routes (one per match entry), not 1 flattened route
        assert_eq!(config.routes.len(), 2, "expected 2 routes for OR match semantics");
        // First route: color=blue
        let r0 = &config.routes[0];
        assert_eq!(r0.header_matches.len(), 1);
        assert_eq!(r0.header_matches[0].name, "color");
        assert_eq!(r0.header_matches[0].value, "blue");
        // Second route: color=green
        let r1 = &config.routes[1];
        assert_eq!(r1.header_matches.len(), 1);
        assert_eq!(r1.header_matches[0].name, "color");
        assert_eq!(r1.header_matches[0].value, "green");
        // Both should point to same backend
        assert_eq!(r0.service_name, "backend-svc");
        assert_eq!(r1.service_name, "backend-svc");
    }

    #[test]
    fn test_compile_and_match_within_single_entry() {
        // Multiple headers within a single match entry are AND'd.
        // Should produce 1 RouteConfig with both headers.
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "and-match-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: None,
                        headers: vec![
                            ("color".to_string(), "blue".to_string(), "Exact".to_string()),
                            ("animal".to_string(), "cat".to_string(), "Exact".to_string()),
                        ],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1, "single match entry -> 1 route");
        let route = &config.routes[0];
        assert_eq!(route.header_matches.len(), 2, "both headers should be in the same route");
        let names: Vec<&str> = route.header_matches.iter().map(|h| h.name.as_str()).collect();
        assert!(names.contains(&"color"));
        assert!(names.contains(&"animal"));
    }

    #[test]
    fn test_compile_match_with_path_and_headers() {
        // A match entry with both path AND header should produce 1 RouteConfig with both.
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "path-header-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/api".to_string(), "Prefix".to_string())),
                        headers: vec![("version".to_string(), "v2".to_string(), "Exact".to_string())],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.paths.len(), 1);
        assert_eq!(route.paths[0].path, "/api");
        assert_eq!(route.header_matches.len(), 1);
        assert_eq!(route.header_matches[0].name, "version");
    }

    #[test]
    fn test_compile_multiple_matches_different_paths() {
        // 2 match entries with different paths -> 2 RouteConfigs with different paths
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "multi-path-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![
                        HTTPRouteMatchState {
                            path: Some(("/foo".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                        HTTPRouteMatchState {
                            path: Some(("/bar".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                    ],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 2, "2 match entries -> 2 routes");
        let paths: Vec<&str> = config.routes.iter().flat_map(|r| r.paths.iter().map(|p| p.path.as_str())).collect();
        assert!(paths.contains(&"/foo"));
        assert!(paths.contains(&"/bar"));
        // Each route should have exactly 1 path
        assert_eq!(config.routes[0].paths.len(), 1);
        assert_eq!(config.routes[1].paths.len(), 1);
    }

    #[test]
    fn test_compile_or_match_with_methods() {
        // 2 match entries with different methods -> 2 RouteConfigs
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "method-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![
                        HTTPRouteMatchState {
                            path: Some(("/api".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: Some("GET".to_string()),
                            query_params: vec![],
                        },
                        HTTPRouteMatchState {
                            path: Some(("/api".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: Some("POST".to_string()),
                            query_params: vec![],
                        },
                    ],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 2, "2 match entries with different methods -> 2 routes");
        let methods: Vec<&str> = config.routes.iter().map(|r| r.method_match.as_str()).collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
    }

    // -----------------------------------------------------------------------
    // intersect_hostnames unit tests (Issue 3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_intersect_hostnames_wildcard_with_multi_level_subdomain() {
        // *.bar.com + multiple.prefixes.bar.com → MATCH (intersection allows multi-level)
        // Gateway API intersection semantics: a wildcard intersects with any hostname
        // under that domain, including multi-level subdomains.
        let result = intersect_hostnames("*.bar.com", "multiple.prefixes.bar.com");
        assert_eq!(
            result,
            Some("multiple.prefixes.bar.com".to_string()),
            "wildcard *.bar.com should intersect with multi-level multiple.prefixes.bar.com"
        );
    }

    #[test]
    fn test_intersect_hostnames_wildcard_with_apex_no_match() {
        // *.bar.com + bar.com → should NOT match (apex doesn't match wildcard)
        let result = intersect_hostnames("*.bar.com", "bar.com");
        assert_eq!(
            result, None,
            "wildcard *.bar.com should NOT match apex bar.com"
        );
    }

    #[test]
    fn test_intersect_hostnames_exact_match() {
        // bar.com + bar.com → exact match
        let result = intersect_hostnames("bar.com", "bar.com");
        assert_eq!(result, Some("bar.com".to_string()));
    }

    #[test]
    fn test_intersect_hostnames_exact_mismatch() {
        // foo.com + bar.com → no match
        let result = intersect_hostnames("foo.com", "bar.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_intersect_hostnames_both_wildcards_same_domain() {
        // *.bar.com + *.bar.com → match
        let result = intersect_hostnames("*.bar.com", "*.bar.com");
        assert_eq!(result, Some("*.bar.com".to_string()));
    }

    #[test]
    fn test_intersect_hostnames_both_wildcards_more_specific() {
        // *.bar.com + *.sub.bar.com → *.sub.bar.com (more specific)
        let result = intersect_hostnames("*.bar.com", "*.sub.bar.com");
        assert_eq!(
            result,
            Some("*.sub.bar.com".to_string()),
            "more specific wildcard should win"
        );
    }

    #[test]
    fn test_intersect_hostnames_both_wildcards_reversed() {
        // *.sub.bar.com + *.bar.com → *.sub.bar.com (listener is more specific)
        let result = intersect_hostnames("*.sub.bar.com", "*.bar.com");
        assert_eq!(
            result,
            Some("*.sub.bar.com".to_string()),
            "more specific wildcard should win regardless of order"
        );
    }

    #[test]
    fn test_intersect_hostnames_wildcard_listener_exact_route() {
        // *.bar.com + foo.bar.com → foo.bar.com (route is more specific)
        let result = intersect_hostnames("*.bar.com", "foo.bar.com");
        assert_eq!(result, Some("foo.bar.com".to_string()));
    }

    #[test]
    fn test_intersect_hostnames_exact_listener_wildcard_route() {
        // foo.bar.com + *.bar.com → foo.bar.com (listener is more specific)
        let result = intersect_hostnames("foo.bar.com", "*.bar.com");
        assert_eq!(result, Some("foo.bar.com".to_string()));
    }

    #[test]
    fn test_intersect_hostnames_case_insensitive_exact() {
        // Bar.Com + bar.com → match (case insensitive, result is lowercase)
        let result = intersect_hostnames("Bar.Com", "bar.com");
        assert_eq!(result, Some("bar.com".to_string()));
    }

    #[test]
    fn test_intersect_hostnames_disjoint_wildcards() {
        // *.foo.com + *.bar.com → no match (different domains)
        let result = intersect_hostnames("*.foo.com", "*.bar.com");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // Redirect-only rules (no backendRefs) — Gateway API conformance
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_redirect_only_rule_no_backend() {
        // A rule with a redirect filter and NO backendRefs should still produce a RouteConfig.
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "redirect-only".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/hostname-redirect".to_string(), "Exact".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: None,
                        hostname: Some("example.org".to_string()),
                        port: None,
                        path: None,
                        path_type: None,
                        status_code: 302,
                    }],
                    backend_refs: vec![], // NO backends — redirect only
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1, "redirect-only rule must produce a RouteConfig");
        let route = &config.routes[0];
        let redir = route.redirect.as_ref().expect("route must have redirect filter");
        assert_eq!(redir.hostname, "example.org");
        assert_eq!(redir.status_code, 302);
        assert!(route.service_name.is_empty(), "redirect route should have empty service_name");
    }

    #[test]
    fn test_compile_redirect_with_path_replacement() {
        // A redirect-only rule with ReplacePrefixMatch path replacement
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "redirect-path".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/original-prefix".to_string(), "PathPrefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: None,
                        hostname: None,
                        port: None,
                        path: Some("/replacement-prefix".to_string()),
                        path_type: Some("ReplacePrefixMatch".to_string()),
                        status_code: 302,
                    }],
                    backend_refs: vec![], // NO backends
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1, "redirect-only rule with path must produce a RouteConfig");
        let route = &config.routes[0];
        let redir = route.redirect.as_ref().expect("route must have redirect filter");
        assert_eq!(redir.path, "/replacement-prefix");
        assert_eq!(redir.path_type, "ReplacePrefixMatch");
        assert_eq!(redir.status_code, 302);
    }

    #[test]
    fn test_compile_redirect_multiple_matches_no_backend() {
        // Multiple match entries in a redirect-only rule should each produce a RouteConfig
        let store = empty_store();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "multi-redirect".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["example.com".to_string()],
                parent_refs: vec![setup_default_gateway(&store)],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![
                        HTTPRouteMatchState {
                            path: Some(("/a".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                        HTTPRouteMatchState {
                            path: Some(("/b".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                    ],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: Some("https".to_string()),
                        hostname: None,
                        port: None,
                        path: None,
                        path_type: None,
                        status_code: 301,
                    }],
                    backend_refs: vec![],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 2, "each match entry must produce its own RouteConfig");
        for route in &config.routes {
            let redir = route.redirect.as_ref().expect("must have redirect");
            assert_eq!(redir.scheme, "https");
            assert_eq!(redir.status_code, 301);
        }
    }

    // -----------------------------------------------------------------------
    // HTTPRouteHostnameIntersection conformance tests
    // (mirrors sigs.k8s.io/gateway-api/conformance/tests/httproute-hostname-intersection)
    // -----------------------------------------------------------------------

    /// Helper: create a gateway with the given listeners and insert into store.
    fn setup_gateway_with_listeners(
        store: &ConfigStore,
        ns: &str,
        name: &str,
        listeners: Vec<ListenerState>,
    ) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        store.gateways.insert(
            key,
            GatewayState {
                name: name.to_string(),
                namespace: ns.to_string(),
                listeners,
                generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );
    }

    fn make_listener(name: &str, hostname: Option<&str>) -> ListenerState {
        ListenerState {
            name: name.to_string(),
            port: 80,
            protocol: "HTTP".to_string(),
            hostname: hostname.map(|s| s.to_string()),
            accepted: true,
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

    fn make_listener_on_port(name: &str, hostname: Option<&str>, port: u16) -> ListenerState {
        ListenerState {
            port,
            ..make_listener(name, hostname)
        }
    }

    fn make_parent_ref(ns: &str, gw_name: &str, section: Option<&str>) -> ParentRefState {
        ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: ns.to_string(),
            gateway_name: gw_name.to_string(),
            section_name: section.map(|s| s.to_string()),
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        }
    }

    fn make_parent_ref_with_port(
        ns: &str,
        gw_name: &str,
        section: Option<&str>,
        port: u16,
    ) -> ParentRefState {
        ParentRefState {
            port: Some(port),
            ..make_parent_ref(ns, gw_name, section)
        }
    }

    fn make_http_route(
        ns: &str,
        hostnames: Vec<&str>,
        parent_refs: Vec<ParentRefState>,
        path: &str,
        backend: &str,
    ) -> HTTPRouteState {
        HTTPRouteState {
            namespace: ns.to_string(),
            hostnames: hostnames.into_iter().map(|s| s.to_string()).collect(),
            parent_refs,
            rules: vec![HTTPRouteRuleState {
                matches: vec![HTTPRouteMatchState {
                    path: Some((path.to_string(), "Prefix".to_string())),
                    headers: vec![],
                    method: None,
                    query_params: vec![],
                }],
                filters: vec![],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: backend.to_string(),
                    port: 8080,
                    weight: 1,
                    filters: vec![],
                }],
                request_timeout_ms: None,
                backend_request_timeout_ms: None,
                retry: None,
            }],
            generation: 1,
        }
    }

    #[test]
    fn compile_is_deterministic_for_multi_hostname_routes() {
        // The fingerprint is how "nothing changed" is decided all the way to the
        // data plane. Effective hostnames used to come out of a HashSet, so a
        // route with several hostnames produced a different fingerprint on every
        // compile; each "new" config flipped Programmed, the Gateway reconcile
        // woke the compiler again, and the controller spun at 30 reconciles/s.
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        for i in 0..4 {
            store.http_routes.insert(
                NamespacedName { namespace: "default".into(), name: format!("r{i}") },
                make_http_route(
                    "default",
                    vec!["a.example.com", "b.example.com", "c.example.com", "d.example.com"],
                    vec![parent.clone()],
                    &format!("/p{i}"),
                    "svc",
                ),
            );
        }
        store.endpoints.insert(
            ServiceKey { namespace: "default".into(), name: "svc".into(), port: 8080 },
            vec![
                BackendEndpoint { address: "10.0.0.1".into(), port: 8080 },
                BackendEndpoint { address: "10.0.0.2".into(), port: 8080 },
            ],
        );
        let first = config_fingerprint(&compile_config(&store));
        for _ in 0..50 {
            assert_eq!(config_fingerprint(&compile_config(&store)), first, "same store, same fingerprint");
        }
    }

    // --- Unit tests for compute_effective_hostnames ---

    #[test]
    fn test_hostname_intersection_specific_route_matches_specific_listener() {
        // Route hostnames ["non.matching.com", "*.nonmatchingwildcard.io", "very.specific.com"]
        // Listener hostname: "very.specific.com"
        // Expected effective: ["very.specific.com"]
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw",
            vec![make_listener("listener-1", Some("very.specific.com"))],
        );

        let hr = make_http_route(
            "default",
            vec!["non.matching.com", "*.nonmatchingwildcard.io", "very.specific.com"],
            vec![make_parent_ref("default", "gw", None)],
            "/s1",
            "backend-v1",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert_eq!(effective.len(), 1);
        assert!(effective.contains(&"very.specific.com".to_string()));
    }

    #[test]
    fn test_hostname_intersection_specific_routes_match_wildcard_listener() {
        // Route hostnames: ["non.matching.com", "wildcard.io", "foo.wildcard.io", "bar.wildcard.io", "foo.bar.wildcard.io"]
        // Listener hostname: "*.wildcard.io"
        // Expected: foo.wildcard.io, bar.wildcard.io, foo.bar.wildcard.io (multi-level allowed in intersection)
        // NOT wildcard.io (apex) or non.matching.com
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw",
            vec![make_listener("listener-2", Some("*.wildcard.io"))],
        );

        let hr = make_http_route(
            "default",
            vec!["non.matching.com", "wildcard.io", "foo.wildcard.io", "bar.wildcard.io", "foo.bar.wildcard.io"],
            vec![make_parent_ref("default", "gw", None)],
            "/s2",
            "backend-v2",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert_eq!(effective.len(), 3, "expected 3 matching hosts (multi-level allowed in intersection), got: {:?}", effective);
        assert!(effective.contains(&"foo.wildcard.io".to_string()));
        assert!(effective.contains(&"bar.wildcard.io".to_string()));
        assert!(effective.contains(&"foo.bar.wildcard.io".to_string()));
        // Must NOT contain apex or non-matching
        assert!(!effective.contains(&"wildcard.io".to_string()));
        assert!(!effective.contains(&"non.matching.com".to_string()));
    }

    #[test]
    fn test_hostname_intersection_wildcard_route_matches_specific_listener() {
        // Route hostnames: ["non.matching.com", "*.specific.com"]
        // Listener hostname: "very.specific.com"
        // Expected: ["very.specific.com"] (wildcard intersected with exact → exact)
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw",
            vec![make_listener("listener-1", Some("very.specific.com"))],
        );

        let hr = make_http_route(
            "default",
            vec!["non.matching.com", "*.specific.com"],
            vec![make_parent_ref("default", "gw", None)],
            "/s3",
            "backend-v3",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert_eq!(effective.len(), 1, "expected 1 matching host, got: {:?}", effective);
        assert!(effective.contains(&"very.specific.com".to_string()));
        // *.specific.com ∩ very.specific.com = very.specific.com ONLY
        // foo.specific.com must NOT be in the output
    }

    #[test]
    fn test_hostname_intersection_wildcard_route_matches_wildcard_listener() {
        // Route hostnames: ["*.anotherwildcard.io"]
        // Listener hostname: "*.anotherwildcard.io"
        // Expected: ["*.anotherwildcard.io"]
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw",
            vec![make_listener("listener-3", Some("*.anotherwildcard.io"))],
        );

        let hr = make_http_route(
            "default",
            vec!["*.anotherwildcard.io"],
            vec![make_parent_ref("default", "gw", None)],
            "/s4",
            "backend-v1",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert_eq!(effective.len(), 1, "expected 1 matching host, got: {:?}", effective);
        assert!(effective.contains(&"*.anotherwildcard.io".to_string()));
    }

    #[test]
    fn test_hostname_intersection_no_intersection() {
        // Route hostnames: ["specific.but.wrong.com", "wildcard.io"]
        // Gateway listeners: "very.specific.com", "*.wildcard.io", "*.anotherwildcard.io"
        // Expected: empty (no intersection)
        // "wildcard.io" does NOT match "*.wildcard.io" (apex doesn't match wildcard)
        // "specific.but.wrong.com" doesn't match any listener
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw",
            vec![
                make_listener("listener-1", Some("very.specific.com")),
                make_listener("listener-2", Some("*.wildcard.io")),
                make_listener("listener-3", Some("*.anotherwildcard.io")),
            ],
        );

        let hr = make_http_route(
            "default",
            vec!["specific.but.wrong.com", "wildcard.io"],
            vec![make_parent_ref("default", "gw", None)],
            "/s5",
            "backend-v2",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert!(effective.is_empty(), "expected no intersection, got: {:?}", effective);
    }

    #[test]
    fn test_hostname_intersection_no_hostname_listener_uses_route_hostnames() {
        // Listener has no hostname restriction.
        // Route hostnames: ["first.com", "sub.first.com", "second.com", "sub.second.com"]
        // Expected: all route hostnames
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "gw-all",
            vec![make_listener("listener-1", None)],
        );

        let hr = make_http_route(
            "default",
            vec!["first.com", "sub.first.com", "second.com", "sub.second.com"],
            vec![make_parent_ref("default", "gw-all", None)],
            "/",
            "backend-v2",
        );

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));
        assert_eq!(effective.len(), 4, "expected all 4 route hostnames, got: {:?}", effective);
        assert!(effective.contains(&"first.com".to_string()));
        assert!(effective.contains(&"sub.first.com".to_string()));
        assert!(effective.contains(&"second.com".to_string()));
        assert!(effective.contains(&"sub.second.com".to_string()));
    }

    // --- Full end-to-end compile_config test for hostname intersection ---

    #[test]
    fn test_compile_hostname_intersection_full_scenario() {
        // Mirrors the full httproute-hostname-intersection.yaml conformance test.
        // Sets up gateways and routes exactly as in the YAML and verifies the
        // compiled output has the correct host assignments.
        let store = empty_store();
        let ns = "gateway-conformance-infra";

        // Gateway: httproute-hostname-intersection with 3 listeners
        setup_gateway_with_listeners(
            &store,
            ns,
            "httproute-hostname-intersection",
            vec![
                make_listener("listener-1", Some("very.specific.com")),
                make_listener("listener-2", Some("*.wildcard.io")),
                make_listener("listener-3", Some("*.anotherwildcard.io")),
            ],
        );

        // Gateway: httproute-hostname-intersection-all with 1 listener (no hostname)
        setup_gateway_with_listeners(
            &store,
            ns,
            "httproute-hostname-intersection-all",
            vec![make_listener("listener-1", None)],
        );

        // Route 1: specific-host-matches-listener-specific-host
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "specific-host-matches-listener-specific-host".to_string() },
            make_http_route(
                ns,
                vec!["non.matching.com", "*.nonmatchingwildcard.io", "very.specific.com"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection", None)],
                "/s1",
                "infra-backend-v1",
            ),
        );

        // Route 2: specific-host-matches-listener-wildcard-host
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "specific-host-matches-listener-wildcard-host".to_string() },
            make_http_route(
                ns,
                vec!["non.matching.com", "wildcard.io", "foo.wildcard.io", "bar.wildcard.io", "foo.bar.wildcard.io"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection", None)],
                "/s2",
                "infra-backend-v2",
            ),
        );

        // Route 3: wildcard-host-matches-listener-specific-host
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "wildcard-host-matches-listener-specific-host".to_string() },
            make_http_route(
                ns,
                vec!["non.matching.com", "*.specific.com"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection", None)],
                "/s3",
                "infra-backend-v3",
            ),
        );

        // Route 4: wildcard-host-matches-listener-wildcard-host
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "wildcard-host-matches-listener-wildcard-host".to_string() },
            make_http_route(
                ns,
                vec!["*.anotherwildcard.io"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection", None)],
                "/s4",
                "infra-backend-v1",
            ),
        );

        // Route 5: no-intersecting-hosts (should produce NO routes)
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "no-intersecting-hosts".to_string() },
            make_http_route(
                ns,
                vec!["specific.but.wrong.com", "wildcard.io"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection", None)],
                "/s5",
                "infra-backend-v2",
            ),
        );

        // Route 6: httproute-hostname-intersection-all (no-hostname listener)
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "httproute-hostname-intersection-all".to_string() },
            make_http_route(
                ns,
                vec!["first.com", "sub.first.com", "second.com", "sub.second.com"],
                vec![make_parent_ref(ns, "httproute-hostname-intersection-all", None)],
                "/",
                "infra-backend-v2",
            ),
        );

        let config = compile_config(&store);

        // Collect routes by (host, path) → service_name for easy assertion
        let route_map: std::collections::HashMap<(String, String), String> = config
            .routes
            .iter()
            .map(|r| ((r.host.clone(), r.paths[0].path.clone()), r.service_name.clone()))
            .collect();

        // Route 1: very.specific.com/s1 → infra-backend-v1
        assert_eq!(
            route_map.get(&("very.specific.com".to_string(), "/s1".to_string())),
            Some(&"infra-backend-v1".to_string()),
            "very.specific.com/s1 should route to infra-backend-v1"
        );

        // Route 2: foo.wildcard.io/s2, bar.wildcard.io/s2, foo.bar.wildcard.io/s2 → infra-backend-v2
        // (intersection allows multi-level: *.wildcard.io intersects foo.bar.wildcard.io)
        assert_eq!(
            route_map.get(&("foo.wildcard.io".to_string(), "/s2".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );
        assert_eq!(
            route_map.get(&("bar.wildcard.io".to_string(), "/s2".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );
        assert_eq!(
            route_map.get(&("foo.bar.wildcard.io".to_string(), "/s2".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );

        // Route 2 MUST NOT have apex or non-matching
        assert!(
            !route_map.contains_key(&("non.matching.com".to_string(), "/s2".to_string())),
            "non.matching.com/s2 must not exist"
        );
        assert!(
            !route_map.contains_key(&("wildcard.io".to_string(), "/s2".to_string())),
            "wildcard.io/s2 must not exist (apex doesn't match *.wildcard.io)"
        );

        // Route 3: very.specific.com/s3 → infra-backend-v3
        // (wildcard *.specific.com ∩ exact very.specific.com = very.specific.com)
        assert_eq!(
            route_map.get(&("very.specific.com".to_string(), "/s3".to_string())),
            Some(&"infra-backend-v3".to_string()),
        );
        // foo.specific.com/s3 must NOT exist
        assert!(
            !route_map.contains_key(&("foo.specific.com".to_string(), "/s3".to_string())),
            "foo.specific.com/s3 must not exist"
        );

        // Route 4: *.anotherwildcard.io/s4 → infra-backend-v1
        assert_eq!(
            route_map.get(&("*.anotherwildcard.io".to_string(), "/s4".to_string())),
            Some(&"infra-backend-v1".to_string()),
        );

        // Route 5: no routes should exist for /s5
        assert!(
            !route_map.contains_key(&("specific.but.wrong.com".to_string(), "/s5".to_string())),
            "no-intersecting-hosts route must not produce any compiled routes"
        );
        assert!(
            !route_map.contains_key(&("wildcard.io".to_string(), "/s5".to_string())),
            "wildcard.io/s5 must not exist"
        );

        // Route 6 (no-hostname listener): all route hostnames should be present
        assert_eq!(
            route_map.get(&("first.com".to_string(), "/".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );
        assert_eq!(
            route_map.get(&("sub.first.com".to_string(), "/".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );
        assert_eq!(
            route_map.get(&("second.com".to_string(), "/".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );
        assert_eq!(
            route_map.get(&("sub.second.com".to_string(), "/".to_string())),
            Some(&"infra-backend-v2".to_string()),
        );

        // "third.com" must NOT have a route (not in route hostnames)
        assert!(
            !route_map.contains_key(&("third.com".to_string(), "/".to_string())),
            "third.com must not match — not in route hostnames even with no-hostname listener"
        );

        // non.matching.com/s1 must NOT exist (not in intersection)
        assert!(
            !route_map.contains_key(&("non.matching.com".to_string(), "/s1".to_string())),
            "non.matching.com/s1 must not exist"
        );

        // anotherwildcard.io/s4 apex must NOT be routable
        // (the compiled route uses *.anotherwildcard.io, NOT the apex)
        assert!(
            !route_map.contains_key(&("anotherwildcard.io".to_string(), "/s4".to_string())),
            "anotherwildcard.io/s4 must not exist (apex doesn't match wildcard)"
        );
    }

    // --- Unit tests for intersect_hostnames helper ---

    #[test]
    fn test_intersect_hostnames_both_exact_match() {
        assert_eq!(
            intersect_hostnames("very.specific.com", "very.specific.com"),
            Some("very.specific.com".to_string()),
        );
    }

    #[test]
    fn test_intersect_hostnames_both_exact_no_match() {
        assert_eq!(
            intersect_hostnames("very.specific.com", "non.matching.com"),
            None,
        );
    }

    #[test]
    fn test_intersect_hostnames_listener_wildcard_route_exact_match() {
        assert_eq!(
            intersect_hostnames("*.wildcard.io", "foo.wildcard.io"),
            Some("foo.wildcard.io".to_string()),
        );
    }

    #[test]
    fn test_intersect_hostnames_listener_wildcard_route_exact_multi_level() {
        // Gateway API intersection allows multi-level: *.wildcard.io intersects foo.bar.wildcard.io
        assert_eq!(
            intersect_hostnames("*.wildcard.io", "foo.bar.wildcard.io"),
            Some("foo.bar.wildcard.io".to_string()),
        );
    }

    #[test]
    fn test_intersect_hostnames_listener_wildcard_route_apex_no_match() {
        // Apex domain "wildcard.io" does NOT match "*.wildcard.io"
        assert_eq!(
            intersect_hostnames("*.wildcard.io", "wildcard.io"),
            None,
        );
    }

    #[test]
    fn test_intersect_hostnames_listener_exact_route_wildcard_match() {
        // *.specific.com ∩ very.specific.com = very.specific.com
        assert_eq!(
            intersect_hostnames("very.specific.com", "*.specific.com"),
            Some("very.specific.com".to_string()),
        );
    }

    #[test]
    fn test_intersect_hostnames_listener_exact_route_wildcard_no_match() {
        assert_eq!(
            intersect_hostnames("very.specific.com", "*.nonmatchingwildcard.io"),
            None,
        );
    }

    #[test]
    fn test_intersect_hostnames_both_wildcard_same_domain() {
        assert_eq!(
            intersect_hostnames("*.anotherwildcard.io", "*.anotherwildcard.io"),
            Some("*.anotherwildcard.io".to_string()),
        );
    }

    #[test]
    fn test_intersect_hostnames_both_wildcard_different_domains() {
        assert_eq!(
            intersect_hostnames("*.wildcard.io", "*.anotherwildcard.io"),
            None,
        );
    }

    #[test]
    fn test_intersect_hostnames_both_wildcard_more_specific() {
        // *.example.com ∩ *.sub.example.com = *.sub.example.com (more specific)
        assert_eq!(
            intersect_hostnames("*.example.com", "*.sub.example.com"),
            Some("*.sub.example.com".to_string()),
        );
        assert_eq!(
            intersect_hostnames("*.sub.example.com", "*.example.com"),
            Some("*.sub.example.com".to_string()),
        );
    }

    // --- Issue 3: Routes with unresolved refs should not be compiled ---

    #[test]
    fn test_compile_includes_routes_with_unresolved_refs() {
        // Conformance: HTTPRouteInvalidReferenceGrant
        // A route with accepted=true but resolved_refs=false should still compile.
        // The invalid backends are omitted from the BackendGroup (empty backend_refs),
        // so the data plane returns HTTP 500 naturally. The status shows ResolvedRefs=False.
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        // Route with unresolved refs (RefNotPermitted)
        let mut unresolved_parent = parent.clone();
        unresolved_parent.resolved_refs = false;

        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "ref-not-permitted".to_string() },
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![unresolved_parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![], // empty because cross-ns ref was rejected
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // Route should still be compiled (with empty service_name / no backend)
        assert_eq!(
            config.routes.len(),
            1,
            "routes with unresolved refs should still be compiled, got {} routes",
            config.routes.len()
        );
        // The route has no backend — data plane will return 500
        assert!(
            config.routes[0].service_name.is_empty(),
            "route with unresolved refs should have empty service_name"
        );
    }

    #[test]
    fn test_compile_includes_routes_with_resolved_refs() {
        // Control test: routes with resolved refs should still compile normally
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "good-route".to_string() },
            make_http_route("default", vec![], vec![parent], "/", "my-svc"),
        );
        // Populate endpoint so backend lookup succeeds
        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "my-svc".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        let config = compile_config(&store);

        assert!(
            !config.routes.is_empty(),
            "routes with resolved refs should be compiled"
        );
    }

    // --- ReferenceGrant revocation at compile time ---

    #[test]
    fn test_compile_cross_ns_backend_with_grant_has_service_name() {
        // Cross-namespace backend WITH a valid ReferenceGrant should compile
        // with the backend's service_name intact.
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        // Add a ReferenceGrant in the backend's namespace
        store.reference_grants.insert(
            NamespacedName { namespace: "backend-ns".to_string(), name: "allow-it".to_string() },
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: None,
                }],
            },
        );

        // Add endpoints in the backend namespace
        store.endpoints.insert(
            ServiceKey { namespace: "backend-ns".to_string(), name: "cross-svc".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "cross-ns-route".to_string() },
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![], method: None, query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "backend-ns".to_string(),
                        name: "cross-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].service_name, "cross-svc", "grant exists → service_name intact");
        assert_eq!(config.backends.len(), 1, "backend should be compiled");
        assert!(!config.backends[0].endpoints.is_empty(), "backend should have endpoints");
    }

    #[test]
    fn test_compile_cross_ns_backend_without_grant_clears_service_name() {
        // Cross-namespace backend WITHOUT a ReferenceGrant should compile
        // but with service_name cleared → dataplane returns 500.
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        // NO ReferenceGrant — cross-namespace ref is not permitted

        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "no-grant-route".to_string() },
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![], method: None, query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "other-ns".to_string(),
                        name: "forbidden-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1, "route should still compile");
        assert!(config.routes[0].service_name.is_empty(), "service_name must be cleared when grant missing");
        assert_eq!(config.routes[0].port, 0, "port must be cleared when grant missing");
    }

    #[test]
    fn test_compile_grant_revocation_clears_backend() {
        // Simulates the HTTPRouteReferenceGrant conformance test:
        // 1. Compile with grant → backend has service_name
        // 2. Remove grant from store → recompile → service_name cleared
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        let grant_key = NamespacedName {
            namespace: "backend-ns".to_string(),
            name: "temp-grant".to_string(),
        };
        store.reference_grants.insert(
            grant_key.clone(),
            ReferenceGrantState {
                namespace: "backend-ns".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Service".to_string(),
                    name: Some("web-backend".to_string()),
                }],
            },
        );
        store.endpoints.insert(
            ServiceKey { namespace: "backend-ns".to_string(), name: "web-backend".to_string(), port: 8080 },
            vec![portus_types::BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "ref-grant-route".to_string() },
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![], method: None, query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "backend-ns".to_string(),
                        name: "web-backend".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // Step 1: compile with grant → backend present
        let config1 = compile_config(&store);
        assert_eq!(config1.routes[0].service_name, "web-backend", "with grant: backend intact");
        assert!(!config1.backends.is_empty(), "with grant: backend compiled");

        // Step 2: revoke grant → recompile → backend cleared
        store.reference_grants.remove(&grant_key);
        let config2 = compile_config(&store);
        assert!(config2.routes[0].service_name.is_empty(), "after revocation: service_name cleared");
        assert_eq!(config2.routes[0].port, 0, "after revocation: port cleared");
    }

    // --- HTTPS listener TLS cert compilation tests ---

    #[test]
    fn test_compile_https_listener_includes_tls_cert() {
        // When a gateway has an HTTPS listener with tls_cert_refs pointing to a Secret
        // in the store, the compiled Listener should have tls_cert_ref populated with
        // the actual cert/key PEM from the Secret.
        let store = empty_store();

        // Insert a TLS secret with cert and key data
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "my-tls-secret".to_string(),
            },
            SecretState {
                data: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("tls.crt".to_string(), "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n".to_string());
                    m.insert("tls.key".to_string(), "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n".to_string());
                    m
                },
            },
        );

        // Create a gateway with an HTTPS listener referencing the secret
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "https-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "https-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "https".to_string(),
                    port: 443,
                    protocol: "HTTPS".to_string(),
                    hostname: Some("example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![("default".to_string(), "my-tls-secret".to_string())],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let config = compile_config(&store);

        assert_eq!(config.listeners.len(), 1, "should have one HTTPS listener");
        let listener = &config.listeners[0];
        assert_eq!(listener.name, "https");
        assert_eq!(listener.protocol, "HTTPS");

        let tls_ref = listener.tls_cert_ref.as_ref().expect("tls_cert_ref should be populated");
        assert!(tls_ref.cert_pem.contains("FAKECERT"), "cert_pem should contain the certificate");
        assert!(tls_ref.key_pem.contains("FAKEKEY"), "key_pem should contain the private key");
    }

    #[test]
    fn test_compile_https_listener_without_secret_has_no_tls_cert() {
        // When the referenced secret is missing from the store, tls_cert_ref should be None.
        let store = empty_store();

        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "https-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "https-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "https".to_string(),
                    port: 443,
                    protocol: "HTTPS".to_string(),
                    hostname: None,
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    // Reference to a secret that doesn't exist in the store
                    tls_cert_refs: vec![("default".to_string(), "missing-secret".to_string())],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let config = compile_config(&store);

        assert_eq!(config.listeners.len(), 1);
        assert!(
            config.listeners[0].tls_cert_ref.is_none(),
            "tls_cert_ref should be None when secret is missing"
        );
    }

    #[test]
    fn test_compile_http_listener_has_no_tls_cert() {
        // HTTP listeners should never have tls_cert_ref regardless of tls_cert_refs field.
        let store = empty_store();
        setup_default_gateway(&store);

        let config = compile_config(&store);

        for listener in &config.listeners {
            if listener.protocol == "HTTP" {
                assert!(
                    listener.tls_cert_ref.is_none(),
                    "HTTP listener should not have tls_cert_ref"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Listener port matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_listener_port_matching_separate_routes() {
        // 3 routes on ports 80/8080/8090 with same hostname foo.com.
        // Each compiled RouteConfig must have correct listener_port and host.
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "port-gw",
            vec![
                make_listener_on_port("listener-1", Some("foo.com"), 80),
                make_listener_on_port("listener-2", Some("foo.com"), 8080),
                make_listener_on_port("listener-3", Some("foo.com"), 8090),
            ],
        );

        // Route 1: port 80 → v1
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-port-80".to_string(),
        };
        store.http_routes.insert(
            key1,
            make_http_route(
                "default",
                vec!["foo.com"],
                vec![make_parent_ref_with_port(
                    "default",
                    "port-gw",
                    Some("listener-1"),
                    80,
                )],
                "/",
                "infra-backend-v1",
            ),
        );

        // Route 2: port 8080 → v2
        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-port-8080".to_string(),
        };
        store.http_routes.insert(
            key2,
            make_http_route(
                "default",
                vec!["foo.com"],
                vec![make_parent_ref_with_port(
                    "default",
                    "port-gw",
                    Some("listener-2"),
                    8080,
                )],
                "/",
                "infra-backend-v2",
            ),
        );

        // Route 3: port 8090 → v3
        let key3 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-port-8090".to_string(),
        };
        store.http_routes.insert(
            key3,
            make_http_route(
                "default",
                vec!["foo.com"],
                vec![make_parent_ref_with_port(
                    "default",
                    "port-gw",
                    Some("listener-3"),
                    8090,
                )],
                "/",
                "infra-backend-v3",
            ),
        );

        let config = compile_config(&store);

        // Should have 3 routes, each with foo.com and different listener_port
        assert!(
            config.routes.len() >= 3,
            "expected at least 3 routes, got {}",
            config.routes.len()
        );

        let v1_routes: Vec<_> = config
            .routes
            .iter()
            .filter(|r| r.service_name == "infra-backend-v1")
            .collect();
        let v2_routes: Vec<_> = config
            .routes
            .iter()
            .filter(|r| r.service_name == "infra-backend-v2")
            .collect();
        let v3_routes: Vec<_> = config
            .routes
            .iter()
            .filter(|r| r.service_name == "infra-backend-v3")
            .collect();

        assert!(!v1_routes.is_empty(), "v1 route missing");
        assert!(!v2_routes.is_empty(), "v2 route missing");
        assert!(!v3_routes.is_empty(), "v3 route missing");

        assert_eq!(v1_routes[0].host, "foo.com");
        assert_eq!(v1_routes[0].listener_port, 80);

        assert_eq!(v2_routes[0].host, "foo.com");
        assert_eq!(v2_routes[0].listener_port, 8080);

        assert_eq!(v3_routes[0].host, "foo.com");
        assert_eq!(v3_routes[0].listener_port, 8090);
    }

    #[test]
    fn test_compute_effective_hostnames_filters_by_port() {
        // Gateway with 5 listeners on different ports/hostnames.
        // Route with parentRef port=8080 should only get hostnames from port-8080 listeners.
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "multi-gw",
            vec![
                make_listener_on_port("listener-1", Some("foo.com"), 80),
                make_listener_on_port("listener-2", Some("bar.com"), 80),
                make_listener_on_port("listener-3", Some("foo.com"), 8080),
                make_listener_on_port("listener-4", Some("bar.com"), 8080),
                make_listener_on_port("listener-5", Some("baz.com"), 8090),
            ],
        );

        // Route bound to port 8080 only
        let hr = HTTPRouteState {
            namespace: "default".to_string(),
            hostnames: vec![], // no hostname restriction on route
            parent_refs: vec![ParentRefState {
                parent_kind: ParentKind::Gateway,
                gateway_namespace: "default".to_string(),
                gateway_name: "multi-gw".to_string(),
                section_name: None,
                port: Some(8080),
                accepted: true,
                resolved_refs: true,
                reject_reason: None,
            }],
            rules: vec![],
            generation: 1,
        };

        let effective = compute_effective_hostnames(&hr, &gw_map_from_store(&store));

        // Should only include foo.com and bar.com (from port 8080 listeners)
        assert_eq!(effective.len(), 2, "expected 2 hostnames, got {:?}", effective);
        assert!(effective.contains(&"foo.com".to_string()));
        assert!(effective.contains(&"bar.com".to_string()));
        // Should NOT include baz.com (port 8090)
        assert!(!effective.contains(&"baz.com".to_string()));
    }

    #[test]
    fn test_scope_config_gives_each_gateway_its_own_root_route() {
        // HTTPRouteMultipleGateways: two Gateways with an HTTP listener on :80
        // and a dedicated `/` route each. Shared, both compile into one config
        // and conflict; per-Gateway slices must each carry exactly their own
        // route and only the backends it references.
        let store = empty_store();
        setup_gateway_with_listeners(&store, "infra", "same-namespace", vec![make_listener("http", None)]);
        setup_gateway_with_listeners(&store, "infra", "all-namespaces", vec![make_listener("http", None)]);
        store.http_routes.insert(
            NamespacedName { namespace: "infra".into(), name: "same-dedicated".into() },
            make_http_route("infra", vec![], vec![make_parent_ref("infra", "same-namespace", None)], "/", "infra-backend-v2"),
        );
        store.http_routes.insert(
            NamespacedName { namespace: "infra".into(), name: "all-dedicated".into() },
            make_http_route("infra", vec![], vec![make_parent_ref("infra", "all-namespaces", None)], "/", "infra-backend-v3"),
        );
        store.http_routes.insert(
            NamespacedName { namespace: "infra".into(), name: "shared".into() },
            make_http_route(
                "infra",
                vec![],
                vec![
                    make_parent_ref("infra", "same-namespace", None),
                    make_parent_ref("infra", "all-namespaces", None),
                ],
                "/shared",
                "infra-backend-v1",
            ),
        );

        let config = compile_config(&store);
        // Every emitted item is attributed to a Gateway.
        assert!(config.routes.iter().all(|r| !r.gateway_name.is_empty()));
        assert!(config.listeners.iter().all(|l| !l.gateway_name.is_empty()));
        assert_eq!(config.routes.len(), 4, "2 dedicated + shared on 2 parents");

        let same = scope_config(&config, "infra", "same-namespace");
        let all = scope_config(&config, "infra", "all-namespaces");

        let root = |c: &CompiledConfig| -> Vec<String> {
            c.routes
                .iter()
                .filter(|r| r.paths.iter().any(|p| p.path == "/"))
                .map(|r| r.service_name.clone())
                .collect()
        };
        assert_eq!(root(&same), vec!["infra-backend-v2".to_string()]);
        assert_eq!(root(&all), vec!["infra-backend-v3".to_string()]);
        assert_eq!(same.listeners.len(), 1);
        assert_eq!(all.listeners.len(), 1);
        assert!(same.routes.iter().any(|r| r.service_name == "infra-backend-v1"), "shared route present");
        assert!(all.routes.iter().any(|r| r.service_name == "infra-backend-v1"));

        // Backends are pruned to what each slice references.
        let backend_names = |c: &CompiledConfig| -> std::collections::BTreeSet<String> {
            c.backends.iter().map(|b| b.service_name.clone()).collect()
        };
        assert!(!backend_names(&same).contains("infra-backend-v3"));
        assert!(!backend_names(&all).contains("infra-backend-v2"));

        // Slice fingerprints are their own and differ from each other and the
        // global one; a Gateway nobody owns scopes to nothing.
        assert_ne!(same.fingerprint, 0);
        assert_ne!(same.fingerprint, all.fingerprint);
        assert_ne!(same.fingerprint, config_fingerprint(&config));
        let none = scope_config(&config, "infra", "missing");
        assert!(none.routes.is_empty() && none.listeners.is_empty() && none.backends.is_empty());

        // Recompiling identical content yields identical slice fingerprints.
        let again = compile_config(&store);
        assert_eq!(scope_config(&again, "infra", "same-namespace").fingerprint, same.fingerprint);
    }

    #[test]
    fn test_compile_listener_port_matching_no_cross_contamination() {
        // Route bound to port 8090 with sectionName=listener-4 should only get
        // foo.com, NOT bar.com (which is on a different listener at same port).
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "cross-gw",
            vec![
                make_listener_on_port("listener-3", Some("bar.com"), 8080),
                make_listener_on_port("listener-4", Some("foo.com"), 8090),
                make_listener_on_port("listener-5", Some("bar.com"), 8090),
            ],
        );

        // Route bound specifically to listener-4 on port 8090
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "route-listener-4".to_string(),
        };
        store.http_routes.insert(
            key,
            make_http_route(
                "default",
                vec!["foo.com"],
                vec![make_parent_ref_with_port(
                    "default",
                    "cross-gw",
                    Some("listener-4"),
                    8090,
                )],
                "/",
                "infra-backend-v3",
            ),
        );

        let config = compile_config(&store);

        let v3_routes: Vec<_> = config
            .routes
            .iter()
            .filter(|r| r.service_name == "infra-backend-v3")
            .collect();

        assert_eq!(v3_routes.len(), 1, "expected exactly 1 route for v3");
        assert_eq!(v3_routes[0].host, "foo.com");
        assert_eq!(v3_routes[0].listener_port, 8090);

        // No route should have bar.com with v3 backend
        let bar_v3: Vec<_> = config
            .routes
            .iter()
            .filter(|r| r.service_name == "infra-backend-v3" && r.host == "bar.com")
            .collect();
        assert!(bar_v3.is_empty(), "v3 should not have bar.com route");
    }

    // -----------------------------------------------------------------------
    // GRPC route compiler tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_grpc_route_listener_port() {
        // GRPC route with sectionName should resolve the correct listener_port
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "grpc-gw",
            vec![make_listener_on_port("grpc-listener", None, 8080)],
        );
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "grpc-gw".to_string(),
                    section_name: Some("grpc-listener".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some("pkg.Svc".to_string()),
                        method: Some("Call".to_string()),
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-backend".to_string(),
                        port: 50051,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].listener_port, 8080);
        assert_eq!(config.routes[0].listener_name, "grpc-listener");
    }

    #[test]
    fn test_compile_grpc_route_header_matching() {
        // GRPC route with headers produces RouteConfig with header_matches
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-headers".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some("pkg.Svc".to_string()),
                        method: None,
                        match_type: "Exact".to_string(),
                        headers: vec![
                            ("version".to_string(), "one".to_string(), "Exact".to_string()),
                        ],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-backend-v1".to_string(),
                        port: 50051,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].header_matches.len(), 1);
        assert_eq!(config.routes[0].header_matches[0].name, "version");
        assert_eq!(config.routes[0].header_matches[0].value, "one");
        assert_eq!(config.routes[0].header_matches[0].match_type, "Exact");
    }

    #[test]
    fn test_compile_grpc_route_or_semantics() {
        // GRPC rule with 2 match entries produces 2 RouteConfigs (OR semantics)
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-or".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![
                        GRPCRouteMatchState {
                            service: Some("pkg.Svc".to_string()),
                            method: Some("Echo".to_string()),
                            match_type: "Exact".to_string(),
                            headers: vec![],
                        },
                        GRPCRouteMatchState {
                            service: Some("pkg.Svc".to_string()),
                            method: Some("EchoTwo".to_string()),
                            match_type: "Exact".to_string(),
                            headers: vec![],
                        },
                    ],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-backend".to_string(),
                        port: 50051,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 2, "2 match entries should produce 2 routes");
        // Both routes should point to the same backend
        assert!(config.routes.iter().all(|r| r.service_name == "grpc-backend"));
        // Paths should be different
        let paths: Vec<String> = config.routes.iter().map(|r| r.paths[0].path.clone()).collect();
        assert!(paths.contains(&"/pkg.Svc/Echo".to_string()));
        assert!(paths.contains(&"/pkg.Svc/EchoTwo".to_string()));
    }

    #[test]
    fn test_compile_grpc_route_weighted_backends() {
        // GRPC rule with 3 backends produces 1 RouteConfig with weighted_backends
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-weighted".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some("pkg.Svc".to_string()),
                        method: None,
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![
                        BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-v1".to_string(),
                            port: 50051,
                            weight: 70,
                            filters: vec![],
                        },
                        BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-v2".to_string(),
                            port: 50051,
                            weight: 30,
                            filters: vec![],
                        },
                        BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-v3".to_string(),
                            port: 50051,
                            weight: 0,
                            filters: vec![],
                        },
                    ],
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);
        // Should produce 1 route with weighted_backends (not 3 separate routes)
        assert_eq!(config.routes.len(), 1, "weighted backends should produce 1 route");
        let route = &config.routes[0];
        assert_eq!(route.service_name, "grpc-v1"); // primary backend
        assert_eq!(route.weighted_backends.len(), 3);
        assert_eq!(route.weighted_backends[0].service_name, "grpc-v1");
        assert_eq!(route.weighted_backends[0].weight, 70);
        assert_eq!(route.weighted_backends[1].service_name, "grpc-v2");
        assert_eq!(route.weighted_backends[1].weight, 30);
        assert_eq!(route.weighted_backends[2].service_name, "grpc-v3");
        assert_eq!(route.weighted_backends[2].weight, 0);
    }

    #[test]
    fn test_compile_tls_effective_hostnames() {
        // Route hostname `*.com` on listener hostname `*.example.com`
        // → effective hostname should be `*.example.com` (more specific wildcard wins)
        let store = empty_store();

        // Set up gateway with TLS Passthrough listener with hostname `*.example.com`
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "tls-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "tls-pass".to_string(),
                    port: 443,
                    protocol: "TLS".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // TLS route with wildcard hostname `*.com` attached to that listener
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        store.tls_routes.insert(
            key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["*.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "tls-gw".to_string(),
                    section_name: Some("tls-pass".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tls-backend".to_string(),
                    port: 8443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        let tls = &config.tls_passthrough_routes[0];
        // The effective hostname should be the intersection: *.example.com (more specific)
        assert_eq!(
            tls.sni_hostnames,
            vec!["*.example.com"],
            "expected effective hostname *.example.com from intersection of *.com and *.example.com"
        );
    }

    #[test]
    fn test_compile_tls_effective_hostname_exact_intersection() {
        // Route hostname `abc.example.com` on listener hostname `*.example.com`
        // → effective hostname should be `abc.example.com`
        let store = empty_store();

        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "tls-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "tls-pass".to_string(),
                    port: 443,
                    protocol: "TLS".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: None,
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "tls-route".to_string(),
        };
        store.tls_routes.insert(
            key,
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "tls-gw".to_string(),
                    section_name: Some("tls-pass".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tls-backend".to_string(),
                    port: 8443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        let tls = &config.tls_passthrough_routes[0];
        assert_eq!(
            tls.sni_hostnames,
            vec!["abc.example.com"],
            "expected effective hostname abc.example.com from intersection of *.example.com and abc.example.com"
        );
    }

    // --- TLS Terminate mode tests ---

    #[test]
    fn test_compile_tls_terminate_route_with_cert() {
        // When a TLSRoute is bound to a Terminate-mode listener with a cert,
        // the compiled route should include tls_mode="Terminate", cert_pem,
        // key_pem, and listener_port.
        let store = empty_store();

        // Add a Secret for the cert
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-secret".to_string(),
            },
            crate::store::SecretState {
                data: std::collections::HashMap::from([
                    ("tls.crt".to_string(), "CERT-PEM-DATA".to_string()),
                    ("tls.key".to_string(), "KEY-PEM-DATA".to_string()),
                ]),
            },
        );

        // Add a gateway with a TLS Terminate listener on port 8443
        store.gateways.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-gw".to_string(),
            },
            GatewayState {
                name: "tls-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "tls-terminate".to_string(),
                    port: 8443,
                    protocol: "TLS".to_string(),
                    hostname: Some("terminate.example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![("default".to_string(), "tls-secret".to_string())],
                    tls_mode: Some("Terminate".to_string()),
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Add a TLSRoute bound to the Terminate listener
        store.tls_routes.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-terminate-route".to_string(),
            },
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["terminate.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "tls-gw".to_string(),
                    section_name: Some("tls-terminate".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "backend-svc".to_string(),
                    port: 9443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        let tls = &config.tls_passthrough_routes[0];
        assert_eq!(tls.tls_mode, "Terminate");
        assert_eq!(tls.cert_pem, "CERT-PEM-DATA");
        assert_eq!(tls.key_pem, "KEY-PEM-DATA");
        assert_eq!(tls.listener_port, 8443);
        assert_eq!(tls.backend_service, "backend-svc");
        assert_eq!(tls.backend_port, 9443);
        assert_eq!(tls.sni_hostnames, vec!["terminate.example.com"]);
    }

    #[test]
    fn test_compile_tls_passthrough_route_has_passthrough_mode() {
        // Passthrough routes should have tls_mode="Passthrough" and no cert data.
        let store = empty_store();
        store.gateways.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-gw".to_string(),
            },
            GatewayState {
                name: "tls-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
                    name: "tls-passthrough".to_string(),
                    port: 443,
                    protocol: "TLS".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: Some("Passthrough".to_string()),
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        store.tls_routes.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-pt-route".to_string(),
            },
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["app.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "tls-gw".to_string(),
                    section_name: Some("tls-passthrough".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "pt-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.tls_passthrough_routes.len(), 1);
        let tls = &config.tls_passthrough_routes[0];
        assert_eq!(tls.tls_mode, "Passthrough");
        assert!(tls.cert_pem.is_empty());
        assert!(tls.key_pem.is_empty());
        assert_eq!(tls.listener_port, 443);
    }

    /// Conformance: TLSRouteMixedTerminationSameNamespace
    /// Gateway with 2 TLS listeners (Terminate + Passthrough) on port 8883.
    /// 2 TLS routes with no sectionName, binding by hostname.
    /// Verifies compiled config produces 2 TlsPassthroughRoute entries with
    /// correct tls_mode, cert data, listener_port, and effective hostnames.
    #[test]
    fn test_compile_tls_mixed_termination_routes() {
        let store = empty_store();

        // Add a Secret for the Terminate listener's cert
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-terminate-checks-certificate".to_string(),
            },
            crate::store::SecretState {
                data: std::collections::HashMap::from([
                    ("tls.crt".to_string(), "TERMINATE-CERT-PEM".to_string()),
                    ("tls.key".to_string(), "TERMINATE-KEY-PEM".to_string()),
                ]),
            },
        );

        // Gateway with 2 TLS listeners on port 8883
        store.gateways.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "gateway-tlsroute-mixed-termination".to_string(),
            },
            GatewayState {
                name: "gateway-tlsroute-mixed-termination".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "tls-terminate".to_string(),
                        port: 8883,
                        protocol: "TLS".to_string(),
                        hostname: Some("tls.example.com".to_string()),
                        accepted: true,
                        conflicted: false,
                        resolved_refs: true,
                        allowed_routes: AllowedRoutesState {
                            namespaces_from: "Same".to_string(),
                            namespace_selector: None,
                        },
                        tls_cert_refs: vec![("default".to_string(), "tls-terminate-checks-certificate".to_string())],
                        tls_mode: Some("Terminate".to_string()),
                    },
                    ListenerState {
                        name: "tls-passthrough".to_string(),
                        port: 8883,
                        protocol: "TLS".to_string(),
                        hostname: Some("abc.example.com".to_string()),
                        accepted: true,
                        conflicted: false,
                        resolved_refs: true,
                        allowed_routes: AllowedRoutesState {
                            namespaces_from: "Same".to_string(),
                            namespace_selector: None,
                        },
                        tls_cert_refs: vec![],
                        tls_mode: Some("Passthrough".to_string()),
                    },
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // TLSRoute for Terminate: tls.example.com → tcp-backend:3000
        // No sectionName — binds by hostname match
        store.tls_routes.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "gateway-conformance-mixed-terminateroute".to_string(),
            },
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["tls.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "gateway-tlsroute-mixed-termination".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tcp-backend".to_string(),
                    port: 3000,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLSRoute for Passthrough: abc.example.com → tcp-backend:8443
        // No sectionName — binds by hostname match
        store.tls_routes.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "gateway-conformance-mixed-passthroughroute".to_string(),
            },
            TLSRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "gateway-tlsroute-mixed-termination".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: "default".to_string(),
                    name: "tcp-backend".to_string(),
                    port: 8443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        let config = compile_config(&store);

        // Should produce exactly 2 TLS passthrough route entries
        assert_eq!(
            config.tls_passthrough_routes.len(),
            2,
            "expected 2 TLS routes, got {}",
            config.tls_passthrough_routes.len()
        );

        // Find the Terminate route (tls.example.com)
        let terminate_route = config
            .tls_passthrough_routes
            .iter()
            .find(|r| r.sni_hostnames.contains(&"tls.example.com".to_string()));
        assert!(
            terminate_route.is_some(),
            "should have a route with sni_hostname tls.example.com"
        );
        let terminate_route = terminate_route.unwrap();
        assert_eq!(terminate_route.tls_mode, "Terminate");
        assert_eq!(terminate_route.cert_pem, "TERMINATE-CERT-PEM");
        assert_eq!(terminate_route.key_pem, "TERMINATE-KEY-PEM");
        assert_eq!(terminate_route.listener_port, 8883);
        assert_eq!(terminate_route.backend_service, "tcp-backend");
        assert_eq!(terminate_route.backend_port, 3000);
        assert_eq!(
            terminate_route.listener_hostname, "tls.example.com",
            "terminate route should have listener_hostname=tls.example.com"
        );

        // Find the Passthrough route (abc.example.com)
        let passthrough_route = config
            .tls_passthrough_routes
            .iter()
            .find(|r| r.sni_hostnames.contains(&"abc.example.com".to_string()));
        assert!(
            passthrough_route.is_some(),
            "should have a route with sni_hostname abc.example.com"
        );
        let passthrough_route = passthrough_route.unwrap();
        assert_eq!(passthrough_route.tls_mode, "Passthrough");
        assert!(
            passthrough_route.cert_pem.is_empty(),
            "passthrough route should have no cert_pem"
        );
        assert!(
            passthrough_route.key_pem.is_empty(),
            "passthrough route should have no key_pem"
        );
        assert_eq!(passthrough_route.listener_port, 8883);
        assert_eq!(passthrough_route.backend_service, "tcp-backend");
        assert_eq!(passthrough_route.backend_port, 8443);
        assert_eq!(
            passthrough_route.listener_hostname, "abc.example.com",
            "passthrough route should have listener_hostname=abc.example.com"
        );
    }

    /// Reproduce the TLSRouteHostnameIntersection conformance test scenario.
    /// 4 gateways on port 443, 7 TLS routes — verifies compilation produces
    /// all passthrough routes with correct effective hostnames.
    #[test]
    fn test_compile_tls_hostname_intersection_conformance() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";

        // Helper to make a TLS Passthrough listener on port 443
        fn make_tls_listener(name: &str, hostname: Option<&str>) -> ListenerState {
            ListenerState {
                name: name.to_string(),
                port: 443,
                protocol: "TLS".to_string(),
                hostname: hostname.map(|s| s.to_string()),
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: vec![],
                tls_mode: Some("Passthrough".to_string()),
            }
        }

        // Gateway 1: exact hostname "abc.example.com"
        setup_gateway_with_listeners(
            &store, ns, "gw-tlsroute-exact-hostname-x-1",
            vec![make_tls_listener("listener-exact-hostname", Some("abc.example.com"))],
        );
        // Gateway 2: wildcard "*.example.com"
        setup_gateway_with_listeners(
            &store, ns, "gw-tlsroute-more-specific-wc-hostname-x-2",
            vec![make_tls_listener("listener-more-specific-wc-hostname", Some("*.example.com"))],
        );
        // Gateway 3: wildcard "*.com"
        setup_gateway_with_listeners(
            &store, ns, "gw-tlsroute-less-specific-wc-hostname-x-3",
            vec![make_tls_listener("listener-less-specific-wc-hostname", Some("*.com"))],
        );
        // Gateway 4: no hostname (matches all)
        setup_gateway_with_listeners(
            &store, ns, "gw-tlsroute-empty-hostname-x-4",
            vec![make_tls_listener("listener-empty-hostname", None)],
        );

        // TLS Route 1: *.example.com → gw1 (exact "abc.example.com")
        // Intersection: abc.example.com (exact wins over wildcard)
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-more-specific-wc-hostname-x-1".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["*.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-exact-hostname-x-1".to_string(),
                    section_name: Some("listener-exact-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 2: abc.example.com → gw2 (wildcard "*.example.com")
        // Intersection: abc.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-exact-hostname-x-2".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-more-specific-wc-hostname-x-2".to_string(),
                    section_name: Some("listener-more-specific-wc-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 3: *.com → gw2 (wildcard "*.example.com")
        // Intersection: *.example.com (more specific wildcard)
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-less-specific-wc-hostname-x-2".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["*.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-more-specific-wc-hostname-x-2".to_string(),
                    section_name: Some("listener-more-specific-wc-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend-2".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 4: abc.example.com → gw3 (wildcard "*.com")
        // Intersection: abc.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-exact-hostname-x-3".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-less-specific-wc-hostname-x-3".to_string(),
                    section_name: Some("listener-less-specific-wc-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 5: *.example.com → gw3 (wildcard "*.com")
        // Intersection: *.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-more-specific-wc-hostname-x-3".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["*.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-less-specific-wc-hostname-x-3".to_string(),
                    section_name: Some("listener-less-specific-wc-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend-2".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 6: abc.example.com → gw4 (no hostname)
        // Intersection: abc.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-exact-hostname-x-4".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-empty-hostname-x-4".to_string(),
                    section_name: Some("listener-empty-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // TLS Route 7: *.com → gw4 (no hostname)
        // Intersection: *.com (route hostname preserved)
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tlsroute-less-specific-wc-hostname-x-4".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["*.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "gw-tlsroute-empty-hostname-x-4".to_string(),
                    section_name: Some("listener-empty-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend-2".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // Add endpoints for both backends
        store.endpoints.insert(
            ServiceKey { namespace: ns.to_string(), name: "tls-backend".to_string(), port: 443 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 443 }],
        );
        store.endpoints.insert(
            ServiceKey { namespace: ns.to_string(), name: "tls-backend-2".to_string(), port: 443 },
            vec![BackendEndpoint { address: "10.0.0.2".to_string(), port: 443 }],
        );

        let config = compile_config(&store);

        // Should produce 7 TLS passthrough routes
        assert_eq!(
            config.tls_passthrough_routes.len(), 7,
            "expected 7 TLS passthrough routes, got {}. Routes: {:?}",
            config.tls_passthrough_routes.len(),
            config.tls_passthrough_routes.iter().map(|r| (&r.sni_hostnames, &r.listener_name)).collect::<Vec<_>>()
        );

        // Verify key intersection results by checking effective hostnames
        // Route 1: *.example.com on exact "abc.example.com" → intersection = abc.example.com
        let r1 = config.tls_passthrough_routes.iter()
            .find(|r| r.listener_name == "listener-exact-hostname" && r.backend_service == "tls-backend")
            .expect("route 1 should exist");
        assert!(
            r1.sni_hostnames.contains(&"abc.example.com".to_string()),
            "route 1 should intersect to abc.example.com, got {:?}", r1.sni_hostnames
        );

        // All routes should be Passthrough mode on port 443
        for r in &config.tls_passthrough_routes {
            assert_eq!(r.tls_mode, "Passthrough", "all routes should be Passthrough");
            assert_eq!(r.listener_port, 443, "all routes should be on port 443");
        }
    }

    /// Verify the full compilation loop pipeline delivers TLS passthrough routes
    /// through the watch channel. This tests the exact path that was failing in
    /// production: store update → notify_change → compilation_loop → watch → receiver.
    #[tokio::test]
    async fn test_compilation_loop_tls_passthrough_through_watch() {
        let store = Arc::new(ConfigStore::new());
        let (tx, mut rx) = watch::channel::<CompiledConfig>(CompiledConfig::default());

        // Clone tx like main.rs does (compilation loop gets the clone, gRPC server gets the original)
        let comp_tx = tx.clone();
        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            compilation_loop(store_clone, comp_tx).await;
        });

        // Simulate what reconcilers do: add gateway + TLS route + endpoints
        let ns = "default";
        store.gateways.insert(
            NamespacedName { namespace: ns.to_string(), name: "tls-gw".to_string() },
            GatewayState {
                name: "tls-gw".to_string(),
                namespace: ns.to_string(),
                listeners: vec![ListenerState {
                    name: "tls-listener".to_string(),
                    port: 443,
                    protocol: "TLS".to_string(),
                    hostname: Some("secure.example.com".to_string()),
                    accepted: true,
                    conflicted: false,
                    resolved_refs: true,
                    allowed_routes: AllowedRoutesState {
                        namespaces_from: "Same".to_string(),
                        namespace_selector: None,
                    },
                    tls_cert_refs: vec![],
                    tls_mode: Some("Passthrough".to_string()),
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
        store.tls_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "tls-route".to_string() },
            TLSRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["secure.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "tls-gw".to_string(),
                    section_name: Some("tls-listener".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![BackendRefState {
                    namespace: ns.to_string(),
                    name: "tls-backend".to_string(),
                    port: 443,
                    weight: 1,
                    filters: vec![],
                }],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );
        store.endpoints.insert(
            ServiceKey { namespace: ns.to_string(), name: "tls-backend".to_string(), port: 443 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 443 }],
        );

        // Trigger compilation
        store.notify_change();

        // Wait for compiled config through watch channel
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timeout waiting for compiled config")
            .expect("watch closed");
        let config = rx.borrow_and_update().clone();

        assert_eq!(config.version, 1);
        assert_eq!(
            config.tls_passthrough_routes.len(), 1,
            "should have 1 TLS passthrough route, got {}", config.tls_passthrough_routes.len()
        );
        let tls = &config.tls_passthrough_routes[0];
        assert_eq!(tls.sni_hostnames, vec!["secure.example.com"]);
        assert_eq!(tls.backend_service, "tls-backend");
        assert_eq!(tls.tls_mode, "Passthrough");
        assert_eq!(tls.listener_port, 443);

        // Now verify that the ORIGINAL tx (held by gRPC server) also reflects the update
        // by subscribing a new receiver from it
        let mut rx2 = tx.subscribe();
        let latest = rx2.borrow_and_update().clone();
        assert_eq!(latest.version, 1, "original tx should also have the latest config");
        assert_eq!(latest.tls_passthrough_routes.len(), 1);

        handle.abort();
    }

    /// Reproduce HTTPRouteHTTPSListener conformance test:
    /// Gateway with multiple HTTPS listeners (port 443), one with hostname restriction.
    /// HTTPRoute with no hostname attaches to hostname-specific listener via sectionName.
    /// The route should inherit the listener's hostname and compile with listener_port=443.
    #[test]
    fn test_compile_httproute_https_listener_hostname_inheritance() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";

        // Gateway: same-namespace-with-https-listener
        // 2 HTTPS listeners on port 443
        setup_gateway_with_listeners(&store, ns, "same-namespace-with-https-listener", vec![
            ListenerState {
                name: "https".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: None, // matches all
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: vec![],
                tls_mode: Some("Terminate".to_string()),
            },
            ListenerState {
                name: "https-with-hostname".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: Some("second-example.org".to_string()),
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: vec![],
                tls_mode: Some("Terminate".to_string()),
            },
        ]);

        // HTTPRoute 1: hostname "example.org" on "https" listener
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "httproute-https-test".to_string() },
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["example.org".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "same-namespace-with-https-listener".to_string(),
                    section_name: Some("https".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: ns.to_string(),
                        name: "infra-backend-v1".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // HTTPRoute 2: NO hostname, attaches to "https-with-hostname" listener
        // Should inherit listener's hostname "second-example.org"
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: "httproute-https-test-no-hostname".to_string() },
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: vec![], // no hostname — inherits from listener
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: ns.to_string(),
                    gateway_name: "same-namespace-with-https-listener".to_string(),
                    section_name: Some("https-with-hostname".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: ns.to_string(),
                        name: "infra-backend-v2".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // Should have routes for both hostnames
        let v1_route = config.routes.iter().find(|r| r.service_name == "infra-backend-v1");
        let v2_route = config.routes.iter().find(|r| r.service_name == "infra-backend-v2");

        assert!(v1_route.is_some(), "should have route for infra-backend-v1");
        assert!(v2_route.is_some(), "should have route for infra-backend-v2, routes: {:?}",
            config.routes.iter().map(|r| (&r.host, &r.service_name, r.listener_port)).collect::<Vec<_>>());

        let v1 = v1_route.unwrap();
        assert_eq!(v1.host, "example.org");
        assert_eq!(v1.listener_port, 443, "HTTPS listener route should have listener_port=443");

        let v2 = v2_route.unwrap();
        assert_eq!(v2.host, "second-example.org", "route with no hostname should inherit listener hostname");
        assert_eq!(v2.listener_port, 443, "HTTPS listener route should have listener_port=443");
    }

    // ========================================================================
    // Policy compiler tests
    // ========================================================================

    /// Helper: insert an HTTPRoute named `route_name` in namespace `ns` with a
    /// single backend named `backend`, attached to the default gateway.
    fn setup_route_with_backend(
        store: &ConfigStore,
        ns: &str,
        route_name: &str,
        backend: &str,
    ) {
        let parent = setup_default_gateway(store);
        store.http_routes.insert(
            NamespacedName { namespace: ns.to_string(), name: route_name.to_string() },
            make_http_route(ns, vec!["example.com"], vec![parent], "/", backend),
        );
    }

    /// Helper: build a PolicyTargetKey targeting an HTTPRoute.
    fn route_target(ns: &str, name: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "HTTPRoute".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: None,
        }
    }

    /// Helper: build a PolicyTargetKey targeting a Service.
    fn service_target(ns: &str, name: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: String::new(),
            kind: "Service".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: None,
        }
    }

    // ---- RetryPolicy -------------------------------------------------------

    #[test]
    fn test_retry_policy_applies_to_matching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.retry_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "retry-pol".to_string() },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 3,
                retry_on: vec!["5xx".to_string(), "reset".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_retries, 3);
        assert_eq!(route.retry_on, vec!["5xx".to_string(), "reset".to_string()]);
    }

    #[test]
    fn test_httproute_rule_retry_compiles_to_max_retries_and_codes_and_beats_retry_policy() {
        // httproute-retry.yaml, plus a RetryPolicy on the same route that must lose.
        let store = empty_store();
        setup_route_with_backend(&store, "default", "retries", "infra-backend-v3");
        {
            let key = NamespacedName { namespace: "default".into(), name: "retries".into() };
            let mut route = store.http_routes.get(&key).unwrap().clone();
            route.rules[0].retry = Some(crate::store::RouteRetryState { codes: vec![500, 502, 503, 504], attempts: 2 });
            store.http_routes.insert(key, route);
        }
        store.retry_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "retry-pol".to_string() },
            RetryPolicyState {
                target: route_target("default", "retries"),
                max_retries: 7,
                retry_on: vec!["connect-failure".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );
        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "infra-backend-v3").unwrap();
        assert_eq!(route.max_retries, 2, "rule attempts, not the policy's 7");
        assert_eq!(route.retry_codes, vec![500, 502, 503, 504]);
        assert!(route.retry_on.is_empty(), "the policy did not apply");

        // Without a rule-level retry the policy applies as before.
        let store = empty_store();
        setup_route_with_backend(&store, "default", "plain", "backend-v1");
        store.retry_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "retry-pol".to_string() },
            RetryPolicyState {
                target: route_target("default", "plain"),
                max_retries: 7,
                retry_on: vec!["connect-failure".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );
        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_retries, 7);
        assert!(route.retry_codes.is_empty());
    }

    #[test]
    fn test_retry_policy_does_not_apply_to_nonmatching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.retry_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "retry-pol".to_string() },
            RetryPolicyState {
                target: route_target("default", "other-route"),
                max_retries: 5,
                retry_on: vec!["5xx".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_retries, 0);
        assert!(route.retry_on.is_empty());
    }

    #[test]
    fn test_retry_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.retry_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "retry-pol".to_string() },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 3,
                retry_on: vec!["5xx".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_retries, 0);
        assert!(route.retry_on.is_empty());
    }

    // ---- IPAllowlistPolicy -------------------------------------------------

    #[test]
    fn test_ip_allowlist_policy_applies_to_matching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.ip_allowlist_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "ip-pol".to_string() },
            IPAllowlistPolicyState {
                target: route_target("default", "my-route"),
                allow_cidrs: vec!["10.0.0.0/8".to_string()],
                deny_cidrs: vec!["10.0.1.0/24".to_string()],
                trusted_proxy_cidrs: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        let ip_cfg = route.ip_allowlist.as_ref().expect("ip_allowlist should be set");
        assert_eq!(ip_cfg.allow_cidrs, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(ip_cfg.deny_cidrs, vec!["10.0.1.0/24".to_string()]);
    }

    #[test]
    fn test_ip_allowlist_policy_does_not_apply_to_nonmatching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.ip_allowlist_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "ip-pol".to_string() },
            IPAllowlistPolicyState {
                target: route_target("default", "other-route"),
                allow_cidrs: vec!["10.0.0.0/8".to_string()],
                deny_cidrs: vec![],
                trusted_proxy_cidrs: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert!(route.ip_allowlist.is_none(), "ip_allowlist should not be set for non-matching route");
    }

    #[test]
    fn test_ip_allowlist_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.ip_allowlist_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "ip-pol".to_string() },
            IPAllowlistPolicyState {
                target: route_target("default", "my-route"),
                allow_cidrs: vec!["10.0.0.0/8".to_string()],
                deny_cidrs: vec![],
                trusted_proxy_cidrs: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert!(route.ip_allowlist.is_none(), "ip_allowlist should not be set for non-accepted policy");
    }

    // ---- RequestBodySizeLimitPolicy ----------------------------------------

    #[test]
    fn test_body_size_limit_policy_applies_to_matching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.request_body_size_limit_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "bsl-pol".to_string() },
            RequestBodySizeLimitPolicyState {
                target: route_target("default", "my-route"),
                max_bytes: 1_048_576,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_request_body_bytes, 1_048_576);
    }

    #[test]
    fn test_body_size_limit_policy_does_not_apply_to_nonmatching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.request_body_size_limit_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "bsl-pol".to_string() },
            RequestBodySizeLimitPolicyState {
                target: route_target("default", "other-route"),
                max_bytes: 1_048_576,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_request_body_bytes, 0, "default should be 0 when no policy matches");
    }

    #[test]
    fn test_body_size_limit_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.request_body_size_limit_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "bsl-pol".to_string() },
            RequestBodySizeLimitPolicyState {
                target: route_target("default", "my-route"),
                max_bytes: 1_048_576,
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.max_request_body_bytes, 0, "non-accepted policy should not set body size limit");
    }

    // ---- HealthCheckPolicy -------------------------------------------------

    #[test]
    fn test_health_check_policy_applies_to_matching_service() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        // Add endpoints so the backend appears in compiled config
        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "backend-v1".to_string(), port: 8080 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.health_check_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "hc-pol".to_string() },
            HealthCheckPolicyState {
                target: service_target("default", "backend-v1"),
                path: "/healthz".to_string(),
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 3,
                unhealthy_threshold: 2,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let bg = config.backends.iter()
            .find(|b| b.service_name == "backend-v1")
            .expect("backend-v1 should exist");
        let hc = bg.health_check.as_ref().expect("health_check should be set on BackendGroup");
        assert_eq!(hc.path, "/healthz");
        assert_eq!(hc.interval_secs, 10);
        assert_eq!(hc.timeout_secs, 5);
        assert_eq!(hc.healthy_threshold, 3);
        assert_eq!(hc.unhealthy_threshold, 2);
    }

    #[test]
    fn test_health_check_policy_does_not_apply_to_nonmatching_service() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "backend-v1".to_string(), port: 8080 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.health_check_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "hc-pol".to_string() },
            HealthCheckPolicyState {
                target: service_target("default", "other-service"),
                path: "/healthz".to_string(),
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 3,
                unhealthy_threshold: 2,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let bg = config.backends.iter()
            .find(|b| b.service_name == "backend-v1")
            .expect("backend-v1 should exist");
        assert!(bg.health_check.is_none(), "health_check should not be set for non-matching service");
    }

    #[test]
    fn test_health_check_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "backend-v1".to_string(), port: 8080 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.health_check_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "hc-pol".to_string() },
            HealthCheckPolicyState {
                target: service_target("default", "backend-v1"),
                path: "/healthz".to_string(),
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 3,
                unhealthy_threshold: 2,
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let bg = config.backends.iter()
            .find(|b| b.service_name == "backend-v1")
            .expect("backend-v1 should exist");
        assert!(bg.health_check.is_none(), "non-accepted health check policy should not apply");
    }

    #[test]
    fn test_health_check_policy_on_backend_group_not_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.endpoints.insert(
            ServiceKey { namespace: "default".to_string(), name: "backend-v1".to_string(), port: 8080 },
            vec![BackendEndpoint { address: "10.0.0.1".to_string(), port: 8080 }],
        );

        store.health_check_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "hc-pol".to_string() },
            HealthCheckPolicyState {
                target: service_target("default", "backend-v1"),
                path: "/healthz".to_string(),
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 3,
                unhealthy_threshold: 2,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        // HealthCheck is on BackendGroup, not on RouteConfig
        let bg = config.backends.iter()
            .find(|b| b.service_name == "backend-v1")
            .expect("backend-v1 should exist");
        assert!(bg.health_check.is_some(), "health_check should be on BackendGroup");

        // RouteConfig should NOT have a health_check field (it doesn't exist on RouteConfig proto)
        // This is verified structurally: HealthCheckConfig only appears on BackendGroup.
    }

    // ---- CORSPolicy --------------------------------------------------------

    #[test]
    fn test_cors_policy_applies_to_matching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.cors_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "cors-pol".to_string() },
            CORSPolicyState {
                target: route_target("default", "my-route"),
                allow_origins: vec!["https://example.com".to_string()],
                allow_methods: vec!["GET".to_string(), "POST".to_string()],
                allow_headers: vec!["Content-Type".to_string()],
                expose_headers: vec!["X-Custom".to_string()],
                allow_credentials: true,
                max_age: 3600,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        let cors = route.cors.as_ref().expect("cors should be set");
        assert_eq!(cors.allow_origins, vec!["https://example.com".to_string()]);
        assert_eq!(cors.allow_methods, vec!["GET".to_string(), "POST".to_string()]);
        assert_eq!(cors.allow_headers, vec!["Content-Type".to_string()]);
        assert_eq!(cors.expose_headers, vec!["X-Custom".to_string()]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, 3600);
    }

    #[test]
    fn test_cors_policy_does_not_apply_to_nonmatching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.cors_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "cors-pol".to_string() },
            CORSPolicyState {
                target: route_target("default", "other-route"),
                allow_origins: vec!["https://example.com".to_string()],
                allow_methods: vec!["GET".to_string()],
                allow_headers: vec![],
                expose_headers: vec![],
                allow_credentials: false,
                max_age: 0,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert!(route.cors.is_none(), "cors should not be set for non-matching route");
    }

    #[test]
    fn test_cors_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.cors_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "cors-pol".to_string() },
            CORSPolicyState {
                target: route_target("default", "my-route"),
                allow_origins: vec!["https://example.com".to_string()],
                allow_methods: vec!["GET".to_string()],
                allow_headers: vec![],
                expose_headers: vec![],
                allow_credentials: false,
                max_age: 0,
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert!(route.cors.is_none(), "non-accepted CORS policy should not apply");
    }

    #[test]
    fn test_cors_filter_takes_precedence_over_cors_policy() {
        let store = empty_store();
        let parent = setup_default_gateway(&store);

        // Create a route WITH a CORS filter on the rule
        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "my-route".to_string() },
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::CORS {
                        allow_origins: vec!["https://filter-origin.com".to_string()],
                        allow_methods: vec!["DELETE".to_string()],
                        allow_headers: vec!["Authorization".to_string()],
                        expose_headers: vec![],
                        allow_credentials: false,
                        max_age: Some(600),
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-v1".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // Also add a CORS policy targeting the same route
        store.cors_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "cors-pol".to_string() },
            CORSPolicyState {
                target: route_target("default", "my-route"),
                allow_origins: vec!["https://policy-origin.com".to_string()],
                allow_methods: vec!["GET".to_string()],
                allow_headers: vec![],
                expose_headers: vec![],
                allow_credentials: true,
                max_age: 3600,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        let cors = route.cors.as_ref().expect("cors should be set from filter");
        // Filter CORS should win over policy CORS
        assert_eq!(cors.allow_origins, vec!["https://filter-origin.com".to_string()],
            "filter-level CORS should take precedence over CORSPolicy");
        assert_eq!(cors.allow_methods, vec!["DELETE".to_string()]);
        assert!(!cors.allow_credentials, "filter credentials=false should win over policy credentials=true");
    }

    // ---- TimeoutPolicy -----------------------------------------------------

    #[test]
    fn test_timeout_policy_applies_to_matching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.timeout_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "timeout-pol".to_string() },
            TimeoutPolicyState {
                target: route_target("default", "my-route"),
                request_timeout_ms: 5000,
                backend_request_timeout_ms: 3000,
                connect_timeout_ms: 1000,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.request_timeout_ms, 5000);
        assert_eq!(route.backend_request_timeout_ms, 3000);
        let timeouts = route.timeouts.as_ref().expect("timeouts should be set");
        assert_eq!(timeouts.connect_timeout_ms, 1000);
    }

    #[test]
    fn test_timeout_policy_does_not_apply_to_nonmatching_route() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.timeout_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "timeout-pol".to_string() },
            TimeoutPolicyState {
                target: route_target("default", "other-route"),
                request_timeout_ms: 5000,
                backend_request_timeout_ms: 3000,
                connect_timeout_ms: 1000,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.request_timeout_ms, 0);
        assert_eq!(route.backend_request_timeout_ms, 0);
        assert!(route.timeouts.is_none(), "timeouts should not be set for non-matching route");
    }

    #[test]
    fn test_timeout_policy_not_accepted_does_not_apply() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        store.timeout_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "timeout-pol".to_string() },
            TimeoutPolicyState {
                target: route_target("default", "my-route"),
                request_timeout_ms: 5000,
                backend_request_timeout_ms: 3000,
                connect_timeout_ms: 1000,
                generation: 1,
                creation_timestamp: None,
                accepted: false,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        assert_eq!(route.request_timeout_ms, 0, "non-accepted timeout policy should not set request_timeout_ms");
        assert_eq!(route.backend_request_timeout_ms, 0);
        assert!(route.timeouts.is_none(), "non-accepted timeout policy should not set timeouts");
    }

    #[test]
    fn test_timeout_policy_zero_values_do_not_override() {
        let store = empty_store();
        setup_route_with_backend(&store, "default", "my-route", "backend-v1");

        // Only set connect_timeout_ms; request and backend timeouts are 0
        store.timeout_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "timeout-pol".to_string() },
            TimeoutPolicyState {
                target: route_target("default", "my-route"),
                request_timeout_ms: 0,
                backend_request_timeout_ms: 0,
                connect_timeout_ms: 2000,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = config.routes.iter().find(|r| r.service_name == "backend-v1").unwrap();
        // Zero values should not override (the apply_policies code checks > 0)
        assert_eq!(route.request_timeout_ms, 0);
        assert_eq!(route.backend_request_timeout_ms, 0);
        let timeouts = route.timeouts.as_ref().expect("timeouts should be set for connect_timeout_ms");
        assert_eq!(timeouts.connect_timeout_ms, 2000);
    }

    #[test]
    fn test_api_key_policy_uses_secret_values_not_keys() {
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "protected-route".to_string(),
        };
        store.http_routes.insert(
            route_key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // Secret with key "my-label" and value "sk-secret-token-123"
        let mut secret_data = std::collections::HashMap::new();
        secret_data.insert("my-label".to_string(), "sk-secret-token-123".to_string());
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "api-secret".to_string(),
            },
            SecretState { data: secret_data },
        );

        // APIKeyAuthPolicy targeting the route
        store.api_key_auth_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ak-policy".to_string(),
            },
            ApiKeyAuthPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                    name: "protected-route".to_string(),
                    section_name: None,
                },
                secret_namespace: "default".to_string(),
                secret_name: "api-secret".to_string(),
                header_name: "X-API-Key".to_string(),
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = &config.routes[0];
        let auth = route.auth.as_ref().expect("route should have auth");
        match auth.auth_type.as_ref().unwrap() {
            auth_config::AuthType::ApiKey(ak) => {
                assert!(
                    ak.valid_keys.contains(&"sk-secret-token-123".to_string()),
                    "valid_keys should contain the secret VALUE, got: {:?}",
                    ak.valid_keys
                );
                assert!(
                    !ak.valid_keys.contains(&"my-label".to_string()),
                    "valid_keys should NOT contain the secret KEY name"
                );
            }
            other => panic!("expected ApiKey auth, got {:?}", other),
        }
    }

    #[test]
    fn test_basic_auth_missing_secret_denies_all() {
        let store = empty_store();
        let parent = setup_default_gateway(&store);
        let route_key = NamespacedName {
            namespace: "default".to_string(),
            name: "protected-route".to_string(),
        };
        store.http_routes.insert(
            route_key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "backend-svc".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // BasicAuthPolicy targeting the route, but NO secret in the store
        store.basic_auth_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ba-policy".to_string(),
            },
            BasicAuthPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                    name: "protected-route".to_string(),
                    section_name: None,
                },
                secret_namespace: "default".to_string(),
                secret_name: "missing-secret".to_string(),
                realm: "Restricted".to_string(),
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);
        let route = &config.routes[0];
        let auth = route.auth.as_ref().expect("route should have auth even when secret is missing (deny-all)");
        match auth.auth_type.as_ref().unwrap() {
            auth_config::AuthType::BasicAuth(ba) => {
                assert!(
                    ba.credentials.is_empty(),
                    "credentials should be empty (deny-all) when secret is missing, got: {:?}",
                    ba.credentials
                );
            }
            other => panic!("expected BasicAuth auth, got {:?}", other),
        }
    }

    // ---- Policy sectionName targeting tests --------------------------------

    #[test]
    fn test_policy_section_name_matches_correct_listener() {
        // Gateway with two listeners: "http" (port 80) and "https" (port 443).
        // Policy targets Gateway with sectionName: "http".
        // Route bound to "http" listener -> policy matches (gets rate limit).
        // Route bound to "https" listener -> policy does NOT match (no rate limit).
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "multi-gw",
            vec![
                make_listener_on_port("http", None, 80),
                make_listener_on_port("https", None, 443),
            ],
        );

        // Route on "http" listener
        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "http-route".to_string() },
            make_http_route(
                "default",
                vec!["example.com"],
                vec![make_parent_ref("default", "multi-gw", Some("http"))],
                "/",
                "backend-http",
            ),
        );

        // Route on "https" listener
        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "https-route".to_string() },
            make_http_route(
                "default",
                vec!["example.com"],
                vec![make_parent_ref("default", "multi-gw", Some("https"))],
                "/",
                "backend-https",
            ),
        );

        // RateLimitPolicy targets Gateway "multi-gw" with sectionName "http"
        store.rate_limit_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "rl-http-only".to_string() },
            RateLimitPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "default".to_string(),
                    name: "multi-gw".to_string(),
                    section_name: Some("http".to_string()),
                },
                requests_per_second: 100,
                per_client: false,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let http_route = config.routes.iter().find(|r| r.service_name == "backend-http")
            .expect("should have http route");
        let https_route = config.routes.iter().find(|r| r.service_name == "backend-https")
            .expect("should have https route");

        assert!(
            http_route.rate_limit.is_some(),
            "Route on 'http' listener should get rate limit from Gateway policy with sectionName 'http'"
        );
        assert_eq!(http_route.rate_limit.as_ref().unwrap().requests_per_second, 100);

        assert!(
            https_route.rate_limit.is_none(),
            "Route on 'https' listener should NOT get rate limit from Gateway policy with sectionName 'http'"
        );
    }

    #[test]
    fn test_policy_no_section_name_matches_all_listeners() {
        // Gateway with two listeners: "http" (port 80) and "https" (port 443).
        // Policy targets Gateway with NO sectionName.
        // Both routes should get the policy applied.
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "multi-gw",
            vec![
                make_listener_on_port("http", None, 80),
                make_listener_on_port("https", None, 443),
            ],
        );

        // Route on "http" listener
        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "http-route".to_string() },
            make_http_route(
                "default",
                vec!["example.com"],
                vec![make_parent_ref("default", "multi-gw", Some("http"))],
                "/",
                "backend-http",
            ),
        );

        // Route on "https" listener
        store.http_routes.insert(
            NamespacedName { namespace: "default".to_string(), name: "https-route".to_string() },
            make_http_route(
                "default",
                vec!["example.com"],
                vec![make_parent_ref("default", "multi-gw", Some("https"))],
                "/",
                "backend-https",
            ),
        );

        // RateLimitPolicy targets Gateway "multi-gw" with NO sectionName
        store.rate_limit_policies.insert(
            NamespacedName { namespace: "default".to_string(), name: "rl-all".to_string() },
            RateLimitPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "default".to_string(),
                    name: "multi-gw".to_string(),
                    section_name: None,
                },
                requests_per_second: 50,
                per_client: false,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let http_route = config.routes.iter().find(|r| r.service_name == "backend-http")
            .expect("should have http route");
        let https_route = config.routes.iter().find(|r| r.service_name == "backend-https")
            .expect("should have https route");

        assert!(
            http_route.rate_limit.is_some(),
            "Route on 'http' listener should get rate limit from Gateway policy with no sectionName"
        );
        assert!(
            https_route.rate_limit.is_some(),
            "Route on 'https' listener should get rate limit from Gateway policy with no sectionName"
        );
    }


    // --- Gateway spec.tls: frontend client validation / backend client cert ---

    fn tls_gateway_store() -> ConfigStore {
        let store = empty_store();
        setup_gateway_with_listeners(
            &store,
            "default",
            "mtls-gw",
            vec![
                ListenerState { protocol: "HTTPS".to_string(), ..make_listener_on_port("https", None, 443) },
                ListenerState {
                    protocol: "HTTPS".to_string(),
                    ..make_listener_on_port("https-with-hostname", Some("second-example.org"), 8443)
                },
                make_listener_on_port("http", None, 80),
            ],
        );
        store.config_maps.insert(
            NamespacedName { namespace: "default".to_string(), name: "default-ca".to_string() },
            crate::store::SecretState {
                data: HashMap::from([("ca.crt".to_string(), "DEFAULT-CA-PEM".to_string())]),
            },
        );
        store.config_maps.insert(
            NamespacedName { namespace: "default".to_string(), name: "per-port-ca".to_string() },
            crate::store::SecretState {
                data: HashMap::from([("ca.crt".to_string(), "PER-PORT-CA-PEM".to_string())]),
            },
        );
        store
    }

    fn valid_refs(cm: &str, mode: &str) -> crate::store::ClientValidationOutcome {
        crate::store::ClientValidationOutcome::Valid(crate::store::ClientValidationRefs {
            ca_config_maps: vec![NamespacedName { namespace: "default".to_string(), name: cm.to_string() }],
            mode: mode.to_string(),
            ref_error: None,
        })
    }

    #[test]
    fn test_compile_listener_client_validation_default_and_per_port() {
        let store = tls_gateway_store();
        store.gateway_tls.insert(
            NamespacedName { namespace: "default".to_string(), name: "mtls-gw".to_string() },
            crate::store::GatewayTlsState {
                frontend_default: Some(valid_refs("default-ca", "AllowValidOnly")),
                frontend_per_port: HashMap::from([(8443u16, valid_refs("per-port-ca", "AllowInsecureFallback"))]),
                backend_client_cert_ref: None,
            },
        );

        let config = compile_config(&store);
        let by_name = |n: &str| config.listeners.iter().find(|l| l.name == n).unwrap();

        let https = by_name("https").client_validation.as_ref().expect("443 gets the default validation");
        assert_eq!(https.ca_cert_pems, vec!["DEFAULT-CA-PEM".to_string()]);
        assert_eq!(https.mode, "AllowValidOnly");

        let per_port = by_name("https-with-hostname").client_validation.as_ref().expect("8443 gets the override");
        assert_eq!(per_port.ca_cert_pems, vec!["PER-PORT-CA-PEM".to_string()]);
        assert_eq!(per_port.mode, "AllowInsecureFallback");

        assert!(by_name("http").client_validation.is_none(), "HTTP listeners never ask for client certs");
    }

    #[test]
    fn test_compile_listener_client_validation_absent_without_gateway_tls() {
        let store = tls_gateway_store();
        let config = compile_config(&store);
        assert!(config.listeners.iter().all(|l| l.client_validation.is_none()));
        assert!(config.gateway_backend_tls.is_empty());
    }

    #[test]
    fn test_compile_listener_client_validation_skips_missing_config_map_and_invalid_outcome() {
        let store = tls_gateway_store();
        store.gateway_tls.insert(
            NamespacedName { namespace: "default".to_string(), name: "mtls-gw".to_string() },
            crate::store::GatewayTlsState {
                frontend_default: Some(crate::store::ClientValidationOutcome::Valid(crate::store::ClientValidationRefs {
                    ca_config_maps: vec![
                        NamespacedName { namespace: "default".to_string(), name: "default-ca".to_string() },
                        NamespacedName { namespace: "default".to_string(), name: "gone".to_string() },
                    ],
                    mode: "AllowValidOnly".to_string(),
                    ref_error: None,
                })),
                frontend_per_port: HashMap::from([(
                    8443u16,
                    crate::store::ClientValidationOutcome::Invalid {
                        reason: "InvalidCACertificateRef".to_string(),
                        message: "gone".to_string(),
                    },
                )]),
                backend_client_cert_ref: None,
            },
        );
        let config = compile_config(&store);
        let https = config.listeners.iter().find(|l| l.name == "https").unwrap();
        assert_eq!(https.client_validation.as_ref().unwrap().ca_cert_pems, vec!["DEFAULT-CA-PEM".to_string()]);
        let per_port = config.listeners.iter().find(|l| l.name == "https-with-hostname").unwrap();
        assert!(per_port.client_validation.is_none(), "an invalid block compiles to no validation");
    }

    #[test]
    fn test_compile_gateway_backend_tls_and_scope() {
        let store = tls_gateway_store();
        setup_gateway_with_listeners(&store, "other", "plain-gw", vec![make_listener_on_port("http", None, 80)]);
        store.secrets.insert(
            NamespacedName { namespace: "default".to_string(), name: "client-cert".to_string() },
            crate::store::SecretState {
                data: HashMap::from([
                    ("tls.crt".to_string(), "CLIENT-CERT".to_string()),
                    ("tls.key".to_string(), "CLIENT-KEY".to_string()),
                ]),
            },
        );
        store.gateway_tls.insert(
            NamespacedName { namespace: "default".to_string(), name: "mtls-gw".to_string() },
            crate::store::GatewayTlsState {
                backend_client_cert_ref: Some(NamespacedName { namespace: "default".to_string(), name: "client-cert".to_string() }),
                ..Default::default()
            },
        );
        // A Gateway whose Secret is gone contributes nothing.
        store.gateway_tls.insert(
            NamespacedName { namespace: "other".to_string(), name: "plain-gw".to_string() },
            crate::store::GatewayTlsState {
                backend_client_cert_ref: Some(NamespacedName { namespace: "other".to_string(), name: "missing".to_string() }),
                ..Default::default()
            },
        );

        let config = compile_config(&store);
        assert_eq!(config.gateway_backend_tls.len(), 1);
        let entry = &config.gateway_backend_tls[0];
        assert_eq!((entry.gateway_namespace.as_str(), entry.gateway_name.as_str()), ("default", "mtls-gw"));
        assert_eq!(entry.cert_pem, "CLIENT-CERT");
        assert_eq!(entry.key_pem, "CLIENT-KEY");

        let own = scope_config(&config, "default", "mtls-gw");
        assert_eq!(own.gateway_backend_tls.len(), 1);
        let other = scope_config(&config, "other", "plain-gw");
        assert!(other.gateway_backend_tls.is_empty());
        assert_ne!(own.fingerprint, other.fingerprint);

        // The fingerprint follows the client certificate content.
        store.secrets.insert(
            NamespacedName { namespace: "default".to_string(), name: "client-cert".to_string() },
            crate::store::SecretState {
                data: HashMap::from([
                    ("tls.crt".to_string(), "CLIENT-CERT-ROTATED".to_string()),
                    ("tls.key".to_string(), "CLIENT-KEY-ROTATED".to_string()),
                ]),
            },
        );
        let rotated = compile_config(&store);
        assert_ne!(config_fingerprint(&config), config_fingerprint(&rotated));
        assert_ne!(own.fingerprint, scope_config(&rotated, "default", "mtls-gw").fingerprint);
    }
}
