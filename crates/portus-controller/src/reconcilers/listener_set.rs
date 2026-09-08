//! ListenerSet reconciler.
//!
//! Watches ListenerSet CRs and validates them against their parent Gateway:
//!   * parent Gateway must exist and have `allowedListeners` configured
//!     to permit attachment from this ListenerSet's namespace.
//!   * per-listener validation (port/protocol/hostname + TLS mode) mirrors
//!     Gateway listener validation so the compiler can treat ListenerSet
//!     listeners identically to Gateway listeners.
//!
//! The ListenerSet's accepted state is stored in `ConfigStore.listener_sets`
//! for the compiler and HTTPRoute reconciler to consult when resolving
//! parent refs with kind=ListenerSet.

use crate::gateway_types::ListenerSet;
use crate::reconcilers::{ReconcileContext, ReconcileError};
use crate::status;
use crate::store::{
    Event,
    AllowedRoutesState, ConfigStore, ListenerSetState, ListenerState, NamespacedName,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Determine whether the Gateway's `allowedListeners.namespaces.from` permits
/// attachment from `listener_set_namespace`. Default (None) = not allowed.
pub fn is_allowed(
    gateway_allowed_from: Option<&str>,
    gateway_namespace: &str,
    listener_set_namespace: &str,
    gateway_match_labels: &[(String, String)],
    listener_set_namespace_labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    match gateway_allowed_from {
        None => false,
        Some("All") => true,
        Some("Same") => gateway_namespace == listener_set_namespace,
        Some("Selector") => {
            if gateway_match_labels.is_empty() {
                // Empty selector matches nothing per K8s semantics when the
                // selector is required. Conservative default.
                return false;
            }
            gateway_match_labels.iter().all(|(k, v)| {
                listener_set_namespace_labels
                    .get(k)
                    .map(|lv| lv == v)
                    .unwrap_or(false)
            })
        }
        Some(_) => false,
    }
}

/// Build the ListenerSetState from a ListenerSet CR. Returns the state
/// plus a set of per-listener (name, conditions, supported_kinds) tuples
/// for status writing.
pub fn evaluate_listener_set(
    ls: &ListenerSet,
    store: &ConfigStore,
    ls_namespace_labels: &std::collections::BTreeMap<String, String>,
) -> (ListenerSetState, Vec<Condition>, super::PerListenerConditions) {
    let name = ls.metadata.name.clone().unwrap_or_default();
    let namespace = ls.metadata.namespace.clone().unwrap_or_default();
    let generation = ls.metadata.generation.unwrap_or(0);
    let my_creation_ts = ls
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0);

    let parent_name = ls.spec.parent_ref.name.clone();
    let parent_namespace = ls
        .spec
        .parent_ref
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.clone());
    let parent_key = NamespacedName {
        namespace: parent_namespace.clone(),
        name: parent_name.clone(),
    };

    // Look up the parent Gateway
    let gateway_entry = store.gateways.get(&parent_key);
    let (attach_allowed, reason, message) = match gateway_entry.as_ref() {
        None => (false, "Invalid", "parent Gateway not found"),
        Some(gw) => {
            if !is_allowed(
                gw.allowed_listener_namespaces_from.as_deref(),
                &gw.namespace,
                &namespace,
                &gw.allowed_listener_match_labels,
                ls_namespace_labels,
            ) {
                (false, "NotAllowed", "Gateway does not allow ListenerSet attachment from this namespace")
            } else {
                (true, "Accepted", "ListenerSet accepted")
            }
        }
    };

    // Build (port, hostname) claims from higher-precedence listeners for
    // hostname/protocol conflict detection.
    // Precedence: parent Gateway > older sibling ListenerSets > me.
    // Tie-break on creation time by (namespace, name) alphabetical.
    let mut hostname_claims: std::collections::HashSet<(u16, String)> =
        std::collections::HashSet::new();
    let mut protocol_claims: std::collections::HashMap<u16, String> =
        std::collections::HashMap::new();
    if let Some(gw) = gateway_entry.as_ref() {
        for l in &gw.listeners {
            let h = l.hostname.clone().unwrap_or_default();
            hostname_claims.insert((l.port, h));
            protocol_claims.insert(l.port, l.protocol.clone());
        }
    }
    // Sibling ListenerSets on the same Gateway with earlier creation time.
    for entry in store.listener_sets.iter() {
        let sibling = entry.value();
        if sibling.name == name && sibling.namespace == namespace {
            continue;
        }
        if sibling.parent_gateway != parent_key {
            continue;
        }
        // Sibling has precedence if it was created earlier, or if equal
        // timestamp and alphabetically before us.
        let earlier = sibling.creation_timestamp < my_creation_ts
            || (sibling.creation_timestamp == my_creation_ts
                && (sibling.namespace.as_str(), sibling.name.as_str())
                    < (namespace.as_str(), name.as_str()));
        if !earlier {
            continue;
        }
        for l in &sibling.listeners {
            if l.conflicted {
                continue;
            }
            let h = l.hostname.clone().unwrap_or_default();
            hostname_claims.insert((l.port, h));
            protocol_claims.entry(l.port).or_insert(l.protocol.clone());
        }
    }

    // Compile listeners (mirror of Gateway listener evaluation, simplified).
    let mut listener_states: Vec<ListenerState> = Vec::new();
    let mut per_listener: super::PerListenerConditions = Vec::new();

    for l in &ls.spec.listeners {
        let protocol_supported = matches!(l.protocol.as_str(), "HTTP" | "HTTPS" | "TLS" | "TCP");
        let hostname_key = l.hostname.clone().unwrap_or_default();
        let hostname_conflicted = hostname_claims.contains(&(l.port, hostname_key.clone()));
        let protocol_conflicted = protocol_claims
            .get(&l.port)
            .map(|p| p != &l.protocol)
            .unwrap_or(false);
        let conflicted = hostname_conflicted || protocol_conflicted;

        // Claim this (port, hostname) and protocol so later listeners in the
        // same ListenerSet can detect conflicts against my own earlier ones.
        if !conflicted {
            hostname_claims.insert((l.port, hostname_key));
            protocol_claims.entry(l.port).or_insert(l.protocol.clone());
        }

        // Parse allowedRoutes. `namespaces.selector.matchLabels` populates
        // namespace_selector so route reconcilers can filter by ns labels.
        let allowed_routes = l
            .allowed_routes
            .as_ref()
            .map(|ar| {
                let from = ar
                    .namespaces
                    .as_ref()
                    .and_then(|ns| ns.from.clone())
                    .unwrap_or_else(|| "Same".to_string());
                let namespace_selector = ar
                    .namespaces
                    .as_ref()
                    .and_then(|ns| ns.selector.as_ref())
                    .map(|sel| {
                        sel.match_labels
                            .as_ref()
                            .map(|ml| ml.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                            .unwrap_or_default()
                    });
                AllowedRoutesState {
                    namespaces_from: from,
                    namespace_selector,
                }
            })
            .unwrap_or(AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            });

        // Supported route kinds for this listener based on protocol. If
        // `allowedRoutes.kinds` is specified, intersect with protocol-allowed
        // kinds; any unsupported kind triggers `InvalidRouteKinds`.
        let default_kinds: Vec<(&str, &str)> = if !protocol_supported {
            vec![]
        } else {
            match l.protocol.as_str() {
                "HTTP" => vec![
                    ("gateway.networking.k8s.io", "HTTPRoute"),
                    ("gateway.networking.k8s.io", "GRPCRoute"),
                ],
                "HTTPS" => vec![
                    ("gateway.networking.k8s.io", "HTTPRoute"),
                    ("gateway.networking.k8s.io", "GRPCRoute"),
                ],
                "TLS" => vec![("gateway.networking.k8s.io", "TLSRoute")],
                "TCP" => vec![("gateway.networking.k8s.io", "TCPRoute")],
                _ => vec![],
            }
        };
        let mut invalid_route_kinds = false;
        let supported_kinds: Vec<(String, String)> =
            if let Some(ar) = l.allowed_routes.as_ref() {
                if !ar.kinds.is_empty() {
                    let mut valid = Vec::new();
                    for rgk in &ar.kinds {
                        let group = rgk.group.as_deref().unwrap_or("gateway.networking.k8s.io");
                        let kind = rgk.kind.as_str();
                        if default_kinds.iter().any(|(g, k)| *g == group && *k == kind) {
                            valid.push((group.to_string(), kind.to_string()));
                        } else {
                            invalid_route_kinds = true;
                        }
                    }
                    valid
                } else {
                    default_kinds
                        .iter()
                        .map(|(g, k)| (g.to_string(), k.to_string()))
                        .collect()
                }
            } else {
                default_kinds
                    .iter()
                    .map(|(g, k)| (g.to_string(), k.to_string()))
                    .collect()
            };

        let tls_mode = if l.protocol == "TLS" {
            Some(
                l.tls
                    .as_ref()
                    .and_then(|t| t.mode.as_deref())
                    .unwrap_or("Terminate")
                    .to_string(),
            )
        } else {
            None
        };

        let tls_cert_refs: Vec<(String, String)> = l
            .tls
            .as_ref()
            .map(|t| {
                t.certificate_refs
                    .iter()
                    .map(|r| {
                        (
                            r.namespace.clone().unwrap_or_else(|| namespace.clone()),
                            r.name.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Cross-namespace cert ref check via ReferenceGrant. HTTPS/TLS-Terminate
        // listeners whose certificateRefs point to a different namespace need a
        // ReferenceGrant(from: ListenerSet ns → to: Secret). Missing grant →
        // listener ResolvedRefs=False reason=RefNotPermitted.
        let mut ref_not_permitted = false;
        if matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
            let mode = l
                .tls
                .as_ref()
                .and_then(|t| t.mode.as_deref())
                .unwrap_or("Terminate");
            if mode == "Terminate"
                && let Some(tls_config) = l.tls.as_ref() {
                    for cert_ref in &tls_config.certificate_refs {
                        let cert_ns =
                            cert_ref.namespace.as_deref().unwrap_or(&namespace);
                        if cert_ns != namespace {
                            let has_grant = store.reference_grants.iter().any(|entry| {
                                let rg = entry.value();
                                rg.namespace == cert_ns
                                    && rg.from.iter().any(|f| {
                                        f.group == "gateway.networking.k8s.io"
                                            && f.kind == "ListenerSet"
                                            && f.namespace == namespace
                                    })
                                    && rg.to.iter().any(|t| {
                                        t.group.is_empty()
                                            && t.kind == "Secret"
                                            && t.name.as_deref().is_none_or(|n| n == cert_ref.name)
                                    })
                            });
                            if !has_grant {
                                ref_not_permitted = true;
                                break;
                            }
                        }
                    }
                }
        }

        // Frontend client certificate validation is configured on the parent
        // Gateway (spec.tls.frontend) and applies to every HTTPS listener on the
        // port, ListenerSet listeners included. An invalid block fails
        // ResolvedRefs and rejects the listener (NoValidCACertificate).
        let frontend_validation_error: Option<(String, String)> = if l.protocol == "HTTPS" {
            store
                .gateway_tls
                .get(&parent_key)
                .and_then(|tls| match tls.frontend_validation_for_port(l.port) {
                    Some(crate::store::ClientValidationOutcome::Invalid { reason, message }) => {
                        Some((reason.clone(), message.clone()))
                    }
                    Some(crate::store::ClientValidationOutcome::Valid(v)) => v.ref_error.clone(),
                    None => None,
                })
        } else {
            None
        };
        let no_valid_ca = l.protocol == "HTTPS"
            && store.gateway_tls.get(&parent_key).is_some_and(|tls| {
                matches!(
                    tls.frontend_validation_for_port(l.port),
                    Some(crate::store::ClientValidationOutcome::Invalid { .. })
                )
            });

        let resolved_refs =
            !invalid_route_kinds && !ref_not_permitted && frontend_validation_error.is_none();
        let l_accepted =
            attach_allowed && protocol_supported && !conflicted && resolved_refs && !no_valid_ca;
        let l_programmed = l_accepted;

        listener_states.push(ListenerState {
            name: l.name.clone(),
            port: l.port,
            protocol: l.protocol.clone(),
            hostname: l.hostname.clone(),
            accepted: l_accepted,
            conflicted,
            resolved_refs,
            allowed_routes,
            tls_cert_refs,
            tls_mode,
        });

        // Accepted/reason depends on what went wrong (priority: NotAllowed >
        // UnsupportedProtocol > HostnameConflict / ProtocolConflict >
        // InvalidRouteKinds / RefNotPermitted > Accepted).
        let (accept_reason, accept_msg): (&str, &str) = if !attach_allowed {
            ("NotAllowed", "ListenerSet not allowed on parent Gateway")
        } else if !protocol_supported {
            ("UnsupportedProtocol", "Protocol not supported")
        } else if hostname_conflicted {
            ("HostnameConflict", "Hostname conflicts with higher-precedence listener")
        } else if protocol_conflicted {
            ("ProtocolConflict", "Protocol conflicts with higher-precedence listener on same port")
        } else if invalid_route_kinds {
            ("InvalidRouteKinds", "allowedRoutes.kinds includes kinds incompatible with listener protocol")
        } else if ref_not_permitted {
            ("RefNotPermitted", "Cross-namespace certificate reference not permitted by ReferenceGrant")
        } else if no_valid_ca {
            ("NoValidCACertificate", "No valid CA certificate for frontend client certificate validation")
        } else {
            ("Accepted", "Listener accepted")
        };
        let accepted_cond = status::build_condition(
            "Accepted",
            l_accepted,
            accept_reason,
            accept_msg,
            generation,
        );
        // Programmed condition mirrors the Accepted failure reason when
        // not programmed — conformance expects the specific reason
        // (HostnameConflict / ProtocolConflict / NotAllowed / etc.) on
        // Programmed=False, not a generic "Pending".
        let programmed_cond = status::build_condition(
            "Programmed",
            l_programmed,
            if l_programmed { "Programmed" } else { accept_reason },
            if l_programmed {
                "Listener programmed"
            } else {
                accept_msg
            },
            generation,
        );
        let (resolved_reason, resolved_msg): (&str, &str) = if invalid_route_kinds {
            (
                "InvalidRouteKinds",
                "allowedRoutes.kinds includes kinds incompatible with listener protocol",
            )
        } else if ref_not_permitted {
            (
                "RefNotPermitted",
                "Cross-namespace certificate reference not permitted by ReferenceGrant",
            )
        } else if let Some((reason, message)) = frontend_validation_error.as_ref() {
            (reason.as_str(), message.as_str())
        } else {
            ("ResolvedRefs", "All refs resolved")
        };
        let resolved_cond = status::build_condition(
            "ResolvedRefs",
            resolved_refs,
            resolved_reason,
            resolved_msg,
            generation,
        );
        // Conflicted condition — True when hostname/protocol conflict detected.
        let conflicted_cond = status::build_condition(
            "Conflicted",
            conflicted,
            if hostname_conflicted {
                "HostnameConflict"
            } else if protocol_conflicted {
                "ProtocolConflict"
            } else {
                "NoConflicts"
            },
            if conflicted {
                accept_msg
            } else {
                "No conflicts"
            },
            generation,
        );
        per_listener.push((
            l.name.clone(),
            vec![accepted_cond, programmed_cond, resolved_cond, conflicted_cond],
            supported_kinds,
        ));
    }

    // ListenerSet-level Accepted: true when attachment is allowed AND at least
    // one listener is accepted. Otherwise False with a reason explaining why.
    let any_listener_ok = listener_states.iter().any(|l| l.accepted);
    let top_accepted = attach_allowed && any_listener_ok;
    let (top_reason, top_message) = if !attach_allowed {
        (reason, message)
    } else if !any_listener_ok {
        (
            "ListenersNotValid",
            "all listeners are invalid or conflict with higher-precedence listeners",
        )
    } else {
        ("Accepted", "ListenerSet accepted")
    };

    let top_conditions = vec![
        status::build_condition(
            "Accepted",
            top_accepted,
            top_reason,
            top_message,
            generation,
        ),
        status::build_condition(
            "Programmed",
            top_accepted,
            if top_accepted { "Programmed" } else { top_reason },
            if top_accepted {
                "ListenerSet programmed"
            } else {
                top_message
            },
            generation,
        ),
    ];

    let state = ListenerSetState {
        name,
        namespace,
        parent_gateway: parent_key,
        listeners: listener_states,
        accepted: top_accepted,
        generation,
        not_accepted_reason: if top_accepted {
            None
        } else {
            Some(top_reason.to_string())
        },
        creation_timestamp: my_creation_ts,
    };

    (state, top_conditions, per_listener)
}

pub async fn reconcile_listener_set(
    ls: Arc<ListenerSet>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = ls
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?
        .to_string();
    let namespace = ls
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?
        .to_string();

    // Skip deleted objects
    if ls.metadata.deletion_timestamp.is_some() {
        let key = NamespacedName {
            namespace: namespace.clone(),
            name: name.clone(),
        };
        if let Some((_, gone)) = ctx.store.remove_and_notify(&ctx.store.listener_sets, &key) {
            ctx.store.publish(Event::ListenerSet { key, parent: gone.parent_gateway });
        }
        return Ok(Action::await_change());
    }

    // Read ListenerSet's namespace labels from the store cache (populated by
    // the Namespace reconciler). Empty when the cache hasn't warmed yet —
    // the Gateway's Selector-mode allowedListeners then rejects; the next
    // reconcile fires once the Namespace watcher sees labels.
    let ns_labels: std::collections::BTreeMap<String, String> = ctx
        .store
        .namespace_labels
        .get(&namespace)
        .map(|v| v.value().clone())
        .unwrap_or_default();

    let (state, top_conditions, per_listener) =
        evaluate_listener_set(&ls, &ctx.store, &ns_labels);

    let key = NamespacedName {
        namespace: namespace.clone(),
        name: name.clone(),
    };
    // Keep listeners for the attached-routes counting closure below.
    let state_listeners = state.listeners.clone();
    let parent = state.parent_gateway.clone();
    if ctx.store.insert_and_notify(&ctx.store.listener_sets, key.clone(), state) {
        ctx.store.publish(Event::ListenerSet { key, parent });
    }

    // Write status. AttachedRoutes count is intentionally 0 here — the
    // compilation loop updates it after routes are reconciled (matches how
    // Gateway.listeners[].attachedRoutes is handled).
    let current_conditions = ls
        .status
        .as_ref()
        .map(|s| s.conditions.as_slice())
        .unwrap_or(&[]);

    // Count HTTPRoutes (+ GRPCRoutes) attached to each ListenerSet listener.
    // A route is attached when:
    //   * pref.parent_kind == ListenerSet AND gateway_name/ns match this LS
    //   * pref.accepted
    //   * (section_name is None OR matches listener name)
    //   * (pref.port if set matches listener port)
    //   * listener's protocol accepts HTTPRoute/GRPCRoute
    //   * listener hostname is compatible with route hostnames
    //   * listener's allowedRoutes.namespaces permits the route's namespace
    //     (Selector mode uses the route-ns labels cache)
    let ls_namespace = namespace.clone();
    let ls_name = name.clone();
    let listener_by_name: std::collections::HashMap<String, &crate::store::ListenerState> =
        state_listeners.iter().map(|l| (l.name.clone(), l)).collect();
    let count_attached = |listener_name: &str, listener_port: u16| -> i64 {
        let listener = match listener_by_name.get(listener_name) {
            Some(l) => l,
            None => return 0,
        };
        let accepts_http = matches!(listener.protocol.as_str(), "HTTP" | "HTTPS");
        let matches_pref = |pref: &crate::store::ParentRefState| -> bool {
            if pref.parent_kind != crate::store::ParentKind::ListenerSet {
                return false;
            }
            if !pref.accepted {
                return false;
            }
            if pref.gateway_namespace != ls_namespace
                || pref.gateway_name != ls_name
            {
                return false;
            }
            if let Some(ref sn) = pref.section_name
                && sn != listener_name {
                    return false;
                }
            if let Some(p) = pref.port
                && p != listener_port {
                    return false;
                }
            true
        };
        let passes_listener_filters =
            |route_ns: &str, route_hostnames: &[String]| -> bool {
                if !accepts_http {
                    return false;
                }
                if !crate::reconcilers::http_route::hostnames_compatible(
                    &listener.hostname,
                    route_hostnames,
                ) {
                    return false;
                }
                let route_ns_labels = ctx
                    .store
                    .namespace_labels
                    .get(route_ns)
                    .map(|v| v.value().clone())
                    .unwrap_or_default();
                crate::reconcilers::http_route::namespace_allowed(
                    &listener.allowed_routes,
                    route_ns,
                    &ls_namespace,
                    &route_ns_labels,
                )
            };
        let mut count = 0i64;
        for entry in ctx.store.http_routes.iter() {
            let route = entry.value();
            if route.parent_refs.iter().any(matches_pref)
                && passes_listener_filters(&route.namespace, &route.hostnames)
            {
                count += 1;
            }
        }
        for entry in ctx.store.grpc_routes.iter() {
            let route = entry.value();
            if route.parent_refs.iter().any(matches_pref)
                && passes_listener_filters(&route.namespace, &route.hostnames)
            {
                count += 1;
            }
        }
        count
    };

    let listener_port_by_name: std::collections::HashMap<String, u16> = ls
        .spec
        .listeners
        .iter()
        .map(|l| (l.name.clone(), l.port))
        .collect();

    let listener_statuses: Vec<serde_json::Value> = per_listener
        .iter()
        .map(|(lname, conds, supported_kinds)| {
            let port = listener_port_by_name.get(lname).copied().unwrap_or(0);
            let attached = count_attached(lname, port);
            json!({
                "name": lname,
                "attachedRoutes": attached,
                "conditions": conds.iter().map(|c| json!({
                    "type": c.type_,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message,
                    "observedGeneration": c.observed_generation,
                    "lastTransitionTime": c.last_transition_time.0.to_string(),
                })).collect::<Vec<_>>(),
                "supportedKinds": supported_kinds.iter().map(|(g, k)| json!({"group": g, "kind": k})).collect::<Vec<_>>(),
            })
        })
        .collect();

    let desired_status = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "status": {
            "conditions": top_conditions.iter().map(|c| json!({
                "type": c.type_,
                "status": c.status,
                "reason": c.reason,
                "message": c.message,
                "observedGeneration": c.observed_generation,
                "lastTransitionTime": c.last_transition_time.0.to_string(),
            })).collect::<Vec<_>>(),
            "listeners": listener_statuses,
        }
    });

    // Also detect listener-entry changes (attachedRoutes count, per-listener
    // conditions) so status re-patches when routes attach/detach.
    let attached_routes_changed = ls.status.as_ref().is_none_or(|s| {
        if s.listeners.len() != listener_statuses.len() {
            return true;
        }
        for (cur, desired) in s.listeners.iter().zip(listener_statuses.iter()) {
            let desired_count = desired
                .get("attachedRoutes")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if cur.attached_routes as i64 != desired_count {
                return true;
            }
            // Also compare per-listener condition statuses to catch
            // conflict transitions.
            let desired_conds = desired.get("conditions").and_then(|v| v.as_array());
            if let Some(desired_conds) = desired_conds {
                if cur.conditions.len() != desired_conds.len() {
                    return true;
                }
                for (cc, dc) in cur.conditions.iter().zip(desired_conds.iter()) {
                    let dt = dc.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let ds = dc.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    let dr = dc.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                    if cc.type_ != dt || cc.status != ds || cc.reason != dr {
                        return true;
                    }
                }
            }
        }
        false
    });

    let api: Api<ListenerSet> = Api::namespaced(ctx.client.clone(), &namespace);
    if attached_routes_changed
        || !status::conditions_equal(current_conditions, &top_conditions)
    {
        let pp = kube::api::PatchParams::apply("portus-gateway").force();
        status::with_write_timeout(
            "ListenerSet status patch",
            api.patch_status(&name, &pp, &kube::api::Patch::Apply(desired_status)),
        )
        .await?;
    }

    // Parent Gateway, siblings, attached routes, Namespace labels and data
    // plane acks all re-run this ListenerSet through the store's events.
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    fn empty() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn allowed_same_matches_same_namespace() {
        assert!(is_allowed(Some("Same"), "ns-a", "ns-a", &[], &empty()));
        assert!(!is_allowed(Some("Same"), "ns-a", "ns-b", &[], &empty()));
    }

    #[test]
    fn allowed_all_matches_any() {
        assert!(is_allowed(Some("All"), "ns-a", "ns-b", &[], &empty()));
        assert!(is_allowed(Some("All"), "ns-a", "ns-a", &[], &empty()));
    }

    #[test]
    fn allowed_none_rejects() {
        assert!(!is_allowed(None, "ns-a", "ns-a", &[], &empty()));
    }

    #[test]
    fn allowed_selector_matches_labels() {
        let selector = vec![("allowed".to_string(), "ns".to_string())];
        let mut labels = BTreeMap::new();
        labels.insert("allowed".to_string(), "ns".to_string());
        assert!(is_allowed(
            Some("Selector"),
            "ns-a",
            "ns-b",
            &selector,
            &labels,
        ));
        let wrong = BTreeMap::new();
        assert!(!is_allowed(
            Some("Selector"),
            "ns-a",
            "ns-b",
            &selector,
            &wrong,
        ));
    }

    #[test]
    fn allowed_selector_empty_rejects() {
        assert!(!is_allowed(
            Some("Selector"),
            "ns-a",
            "ns-a",
            &[],
            &empty(),
        ));
    }

    #[test]
    fn allowed_unknown_values_reject() {
        assert!(!is_allowed(Some("Nonsense"), "ns-a", "ns-a", &[], &empty()));
    }

    // -- gap-fix regression tests --

    use crate::gateway_types::{
        AllowedRoutes, GatewayTLSConfig, Listener, ListenerSet,
        ListenerSetSpec, ParentGatewayReference, RouteGroupKind, RouteNamespaces,
        SecretObjectReference,
    };
    use crate::store::{ConfigStore, GatewayState, NamespacedName, ReferenceGrantFrom,
        ReferenceGrantState, ReferenceGrantTo};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn base_gateway(ns: &str, name: &str) -> GatewayState {
        GatewayState {
            name: name.to_string(),
            namespace: ns.to_string(),
            listeners: Vec::new(),
            generation: 1,
            allowed_listener_namespaces_from: Some("All".to_string()),
            allowed_listener_match_labels: Vec::new(),
        }
    }

    fn ls_with_listener(ns: &str, name: &str, parent: &NamespacedName, listener: Listener)
        -> ListenerSet {
        ListenerSet {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: ListenerSetSpec {
                parent_ref: ParentGatewayReference {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    namespace: Some(parent.namespace.clone()),
                    name: parent.name.clone(),
                },
                listeners: vec![listener],
            },
            status: None,
        }
    }

    #[test]
    fn listener_set_invalid_route_kinds_on_tls_passthrough() {
        // Mirror of ListenerSetAllowedRoutesSupportedKinds: TLS Passthrough
        // listener with allowedRoutes.kinds: [HTTPRoute] must emit
        // ResolvedRefs=False reason=InvalidRouteKinds.
        let store = ConfigStore::new();
        let parent = NamespacedName {
            namespace: "infra".to_string(),
            name: "gw".to_string(),
        };
        store.gateways.insert(parent.clone(), base_gateway("infra", "gw"));

        let listener = Listener {
            name: "tls-only".to_string(),
            port: 443,
            protocol: "TLS".to_string(),
            hostname: Some("tls-only.com".to_string()),
            tls: Some(GatewayTLSConfig {
                mode: Some("Passthrough".to_string()),
                certificate_refs: Vec::new(),
            }),
            allowed_routes: Some(AllowedRoutes {
                namespaces: Some(RouteNamespaces {
                    from: Some("All".to_string()),
                    selector: None,
                }),
                kinds: vec![RouteGroupKind {
                    group: None,
                    kind: "HTTPRoute".to_string(),
                }],
            }),
        };
        let ls = ls_with_listener("infra", "ls", &parent, listener);

        let (state, _top, per_listener) = evaluate_listener_set(&ls, &store, &empty());
        assert!(!state.accepted, "LS must be not accepted");
        assert_eq!(state.not_accepted_reason.as_deref(), Some("ListenersNotValid"));
        let (_, conds, _kinds) = &per_listener[0];
        let resolved = conds.iter().find(|c| c.type_ == "ResolvedRefs").unwrap();
        assert_eq!(resolved.status, "False");
        assert_eq!(resolved.reason, "InvalidRouteKinds");
    }

    #[test]
    fn listener_set_ref_not_permitted_cross_ns_cert_without_grant() {
        // Mirror of ListenerSetReferenceGrant: HTTPS listener with cert in
        // another namespace and no ReferenceGrant → listener ResolvedRefs=False
        // reason=RefNotPermitted, LS Accepted=False reason=ListenersNotValid.
        let store = ConfigStore::new();
        let parent = NamespacedName {
            namespace: "infra".to_string(),
            name: "gw".to_string(),
        };
        store.gateways.insert(parent.clone(), base_gateway("infra", "gw"));

        let listener = Listener {
            name: "https".to_string(),
            port: 443,
            protocol: "HTTPS".to_string(),
            hostname: Some("no-grant.com".to_string()),
            tls: Some(GatewayTLSConfig {
                mode: Some("Terminate".to_string()),
                certificate_refs: vec![SecretObjectReference {
                    group: Some("".to_string()),
                    kind: Some("Secret".to_string()),
                    name: "certificate".to_string(),
                    namespace: Some("web-backend".to_string()),
                }],
            }),
            allowed_routes: None,
        };
        let ls = ls_with_listener("cross-ns", "ls-no-grant", &parent, listener);

        let (state, _top, per_listener) = evaluate_listener_set(&ls, &store, &empty());
        assert!(!state.accepted);
        assert_eq!(state.not_accepted_reason.as_deref(), Some("ListenersNotValid"));
        let (_, conds, _) = &per_listener[0];
        let resolved = conds.iter().find(|c| c.type_ == "ResolvedRefs").unwrap();
        assert_eq!(resolved.status, "False");
        assert_eq!(resolved.reason, "RefNotPermitted");
    }

    #[test]
    fn listener_set_cert_grant_permits_cross_ns() {
        // Same as above but with a matching ReferenceGrant → accepted.
        let store = ConfigStore::new();
        let parent = NamespacedName {
            namespace: "infra".to_string(),
            name: "gw".to_string(),
        };
        store.gateways.insert(parent.clone(), base_gateway("infra", "gw"));
        store.reference_grants.insert(
            NamespacedName {
                namespace: "web-backend".to_string(),
                name: "rg".to_string(),
            },
            ReferenceGrantState {
                namespace: "web-backend".to_string(),
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "ListenerSet".to_string(),
                    namespace: "infra".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Secret".to_string(),
                    name: None,
                }],
            },
        );

        let listener = Listener {
            name: "https".to_string(),
            port: 443,
            protocol: "HTTPS".to_string(),
            hostname: Some("with-grant.com".to_string()),
            tls: Some(GatewayTLSConfig {
                mode: Some("Terminate".to_string()),
                certificate_refs: vec![SecretObjectReference {
                    group: Some("".to_string()),
                    kind: Some("Secret".to_string()),
                    name: "certificate".to_string(),
                    namespace: Some("web-backend".to_string()),
                }],
            }),
            allowed_routes: None,
        };
        let ls = ls_with_listener("infra", "ls-grant", &parent, listener);

        let (state, _top, per_listener) = evaluate_listener_set(&ls, &store, &empty());
        assert!(state.accepted, "LS with matching grant must be accepted");
        let (_, conds, _) = &per_listener[0];
        let resolved = conds.iter().find(|c| c.type_ == "ResolvedRefs").unwrap();
        assert_eq!(resolved.status, "True");
    }

    #[test]
    fn namespace_allowed_selector_matches_labels() {
        use crate::reconcilers::http_route::namespace_allowed;
        use crate::store::AllowedRoutesState;
        let allowed = AllowedRoutesState {
            namespaces_from: "Selector".to_string(),
            namespace_selector: Some(vec![("allowed".to_string(), "ns".to_string())]),
        };
        let mut labels = BTreeMap::new();
        labels.insert("allowed".to_string(), "ns".to_string());
        assert!(namespace_allowed(&allowed, "other-ns", "gw-ns", &labels));

        let wrong = BTreeMap::new();
        assert!(!namespace_allowed(&allowed, "other-ns", "gw-ns", &wrong));
    }

    #[test]
    fn namespace_allowed_selector_empty_labels_match_all() {
        use crate::reconcilers::http_route::namespace_allowed;
        use crate::store::AllowedRoutesState;
        let allowed = AllowedRoutesState {
            namespaces_from: "Selector".to_string(),
            namespace_selector: Some(Vec::new()),
        };
        let labels = BTreeMap::new();
        assert!(namespace_allowed(&allowed, "any-ns", "gw-ns", &labels));
    }

    #[test]
    fn namespace_allowed_selector_no_selector_rejects() {
        use crate::reconcilers::http_route::namespace_allowed;
        use crate::store::AllowedRoutesState;
        let allowed = AllowedRoutesState {
            namespaces_from: "Selector".to_string(),
            namespace_selector: None,
        };
        let labels = BTreeMap::new();
        assert!(!namespace_allowed(&allowed, "any-ns", "gw-ns", &labels));
    }
}
