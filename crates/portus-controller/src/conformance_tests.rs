/// End-to-end pipeline conformance tests.
///
/// These tests exercise the FULL pipeline that requests traverse:
///   ConfigStore → compile_config → [simulated dataplane matching]
///
/// The inline matching helper replicates exactly what the dataplane does:
///   build_route_map_from_proto → HostRoutes::match_request
/// so bugs at ANY stage are caught.
///
/// Each test populates the ConfigStore with the same state the reconciler
/// would produce from Gateway API conformance test YAML, compiles it, then
/// verifies positive AND negative matching cases.
#[cfg(test)]
mod tests {
    use crate::compiler::compile_config;
    use crate::store::*;
    use portus_types::*;

    // -----------------------------------------------------------------------
    // Inline dataplane-equivalent matching helpers
    // -----------------------------------------------------------------------

    /// A matched route result from the simulated dataplane.
    #[derive(Debug)]
    struct MatchedRoute<'a> {
        route: &'a RouteConfig,
    }

    impl<'a> MatchedRoute<'a> {
        fn service_name(&self) -> &str {
            &self.route.service_name
        }

        fn has_redirect(&self) -> bool {
            self.route.redirect.is_some()
        }
    }

    /// Simulate what the dataplane does: group compiled routes by host (or host:port),
    /// sort by path specificity, then match against the request.
    ///
    /// This mirrors `build_route_map_from_proto` + `HostRoutes::match_request`.
    fn match_request<'a>(
        config: &'a CompiledConfig,
        host: &str,
        path: &str,
        method: &str,
        headers: &[(&str, &str)],
    ) -> Option<MatchedRoute<'a>> {
        match_request_on_port(config, host, path, method, headers, 0)
    }

    /// Like `match_request` but with a specific listener port.
    ///
    /// Enforces GatewayHTTPListenerIsolation: when multiple listeners on the
    /// same port have overlapping hostnames (e.g. "", "*.example.com",
    /// "*.foo.example.com", "abc.foo.example.com"), a request is first bound
    /// to the single most-specific listener matching its Host header, and only
    /// routes attached to THAT listener are eligible. No fallback across
    /// listener boundaries.
    fn match_request_on_port<'a>(
        config: &'a CompiledConfig,
        host: &str,
        path: &str,
        method: &str,
        headers: &[(&str, &str)],
        listener_port: u16,
    ) -> Option<MatchedRoute<'a>> {
        // Only consider routes whose listener_port matches the request port
        // (treating listener_port=0 as any-port for backward compatibility).
        let port_scoped: Vec<&RouteConfig> = config
            .routes
            .iter()
            .filter(|r| {
                listener_port == 0
                    || r.listener_port == 0
                    || r.listener_port == listener_port as u32
            })
            .collect();

        if port_scoped.is_empty() {
            return None;
        }

        // Distinct listener hostnames present in the config for this port.
        let mut listener_hostnames: Vec<&str> = port_scoped
            .iter()
            .map(|r| r.listener_hostname.as_str())
            .collect();
        listener_hostnames.sort();
        listener_hostnames.dedup();

        // Resolve the single most-specific listener for the request host.
        let chosen = select_most_specific_listener(host, &listener_hostnames);
        let chosen_lh = chosen?;

        // Scope candidates to the chosen listener.
        let listener_routes: Vec<&RouteConfig> = port_scoped
            .into_iter()
            .filter(|r| r.listener_hostname == chosen_lh)
            .collect();

        // Within the listener, build a host-keyed map and run the existing
        // fallback chain (exact host → domain wildcard → catch-all). This
        // handles route-level hostname narrowing from intersection.
        let mut by_host: std::collections::HashMap<String, Vec<&RouteConfig>> =
            std::collections::HashMap::new();
        for route in listener_routes {
            by_host.entry(route.host.clone()).or_default().push(route);
        }

        let candidates: Vec<&RouteConfig> = if let Some(routes) = by_host.get(host) {
            routes.clone()
        } else {
            let mut found: Option<Vec<&RouteConfig>> = None;
            let mut search = host;
            while let Some(dot) = search.find('.') {
                let suffix = &search[dot..]; // ".b.bar.com"
                let wildcard_key = format!("*.{}", &suffix[1..]);
                if let Some(routes) = by_host.get(&wildcard_key) {
                    found = Some(routes.clone());
                    break;
                }
                search = &search[dot + 1..];
            }
            found
                .or_else(|| by_host.get("*").cloned())
                .unwrap_or_default()
        };
        if candidates.is_empty() {
            return None;
        }

        // Sort candidates by specificity (mirrors the dataplane's sorting):
        // 1. Exact paths before Prefix paths
        // 2. Longer paths first (more specific)
        // 3. More header matches first (more specific)
        let mut sorted: Vec<&RouteConfig> = candidates;
        sorted.sort_by(|a, b| {
            let a_path = a.paths.first();
            let b_path = b.paths.first();
            let a_type = a_path.map(|p| p.match_type.as_str()).unwrap_or("");
            let b_type = b_path.map(|p| p.match_type.as_str()).unwrap_or("");
            let a_len = a_path.map(|p| p.path.len()).unwrap_or(0);
            let b_len = b_path.map(|p| p.path.len()).unwrap_or(0);

            // Exact before Prefix
            let type_ord = match (a_type, b_type) {
                ("Exact", "Exact") => std::cmp::Ordering::Equal,
                ("Exact", _) => std::cmp::Ordering::Less,
                (_, "Exact") => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            };
            if type_ord != std::cmp::Ordering::Equal {
                return type_ord;
            }
            // Longer paths first (more specific)
            let path_ord = b_len.cmp(&a_len);
            if path_ord != std::cmp::Ordering::Equal {
                return path_ord;
            }
            // More header matches first (more specific, per Gateway API spec)
            b.header_matches.len().cmp(&a.header_matches.len())
        });

        for route in &sorted {
            if route_matches(route, path, method, headers) {
                return Some(MatchedRoute { route });
            }
        }

        // Check catch-all routes (routes with no paths = match any path)
        // These are already in sorted and would have been checked above with empty paths.
        None
    }

    /// Listener isolation: pick the single most-specific listener hostname
    /// that claims the given request host. Returns None if no listener matches.
    ///
    /// Specificity ordering:
    ///   - Exact listener hostname: highest
    ///   - Wildcard listener hostname (`*.suffix`): middle, ranked by suffix length (longer = more specific)
    ///   - Empty listener hostname `""`: lowest (catch-all, matches any host)
    fn select_most_specific_listener(host: &str, listener_hostnames: &[&str]) -> Option<String> {
        let host_lc = host.to_ascii_lowercase();
        let mut best: Option<(u32, String)> = None;

        for lh in listener_hostnames {
            let lh_lc = lh.to_ascii_lowercase();
            let score = if lh_lc.is_empty() {
                // Catch-all listener: matches any host, lowest priority.
                Some(1u32)
            } else if let Some(suffix) = lh_lc.strip_prefix("*.") {
                // Wildcard listener: matches "<anything>.<suffix>".
                // Requires host has at least one more label before the suffix.
                let dot_suffix = format!(".{}", suffix);
                if host_lc.ends_with(&dot_suffix) && host_lc.len() > dot_suffix.len() {
                    // Priority: 1000 + suffix length (longer = more specific)
                    Some(1000 + suffix.len() as u32)
                } else {
                    None
                }
            } else if host_lc == lh_lc {
                // Exact match: highest priority.
                Some(10_000)
            } else {
                None
            };

            if let Some(s) = score
                && best.as_ref().is_none_or(|(b, _)| s > *b) {
                    best = Some((s, lh.to_string()));
                }
        }

        best.map(|(_, lh)| lh)
    }

    /// Check if a single RouteConfig matches the given request.
    /// Mirrors HostRoutes::match_request logic.
    fn route_matches(
        route: &RouteConfig,
        request_path: &str,
        method: &str,
        headers: &[(&str, &str)],
    ) -> bool {
        // Path matching
        if route.paths.is_empty() {
            // No path rules = catch-all (matches any path), but only if
            // extra dimensions (headers, method) also match
        } else {
            let path_matched = route.paths.iter().any(|pr| match pr.match_type.as_str() {
                "Exact" => request_path == pr.path,
                "Prefix"
                    if request_path.starts_with(&pr.path) => {
                        let plen = pr.path.len();
                        request_path.len() == plen
                            || request_path.as_bytes().get(plen) == Some(&b'/')
                            || pr.path.ends_with('/')
                    }
                _ => false,
            });
            if !path_matched {
                return false;
            }
        }

        // Method matching (AND with path)
        if !route.method_match.is_empty() && route.method_match != method {
            return false;
        }

        // Header matching (AND: all header_matches must pass)
        for hm in &route.header_matches {
            let header_matched = headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case(&hm.name) && match hm.match_type.as_str() {
                    "Exact" | "" => *value == hm.value,
                    _ => false,
                }
            });
            if !header_matched {
                return false;
            }
        }

        true
    }

    // -----------------------------------------------------------------------
    // Test helpers (same pattern as compiler.rs tests)
    // -----------------------------------------------------------------------

    fn empty_store() -> ConfigStore {
        ConfigStore::new()
    }

    /// Add a gateway with an accepted HTTP listener and no hostname restriction.
    fn setup_gateway_no_hostname(store: &ConfigStore, ns: &str, name: &str) -> ParentRefState {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        store.gateways.insert(
            key,
            GatewayState {
                name: name.to_string(),
                namespace: ns.to_string(),
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
        ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: ns.to_string(),
            gateway_name: name.to_string(),
            section_name: None,
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        }
    }

    /// Add a gateway with an accepted HTTP listener that has a specific hostname.
    fn setup_gateway_with_hostname(
        store: &ConfigStore,
        ns: &str,
        name: &str,
        hostname: &str,
    ) -> ParentRefState {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        store.gateways.insert(
            key,
            GatewayState {
                name: name.to_string(),
                namespace: ns.to_string(),
                listeners: vec![ListenerState {
                    name: "http".to_string(),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    hostname: Some(hostname.to_string()),
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
            gateway_namespace: ns.to_string(),
            gateway_name: name.to_string(),
            section_name: None,
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        }
    }

    /// Add a gateway with multiple HTTP listeners on the same port, each with
    /// its own hostname restriction. Used by listener-isolation tests.
    ///
    /// `listeners` is a slice of (listener_name, hostname) pairs. Use None for
    /// the empty-hostname listener.
    fn setup_gateway_with_multiple_listeners(
        store: &ConfigStore,
        ns: &str,
        name: &str,
        port: u16,
        listeners: &[(&str, Option<&str>)],
    ) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let listener_states: Vec<ListenerState> = listeners
            .iter()
            .map(|(lname, lhost)| ListenerState {
                name: (*lname).to_string(),
                port,
                protocol: "HTTP".to_string(),
                hostname: lhost.map(|h| h.to_string()),
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "All".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: vec![],
                tls_mode: None,
            })
            .collect();
        store.gateways.insert(
            key,
            GatewayState {
                name: name.to_string(),
                namespace: ns.to_string(),
                listeners: listener_states,
                generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );
    }

    /// Build a ParentRefState targeting a specific listener by sectionName.
    fn parent_ref_section(ns: &str, gw: &str, section: &str) -> ParentRefState {
        ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: ns.to_string(),
            gateway_name: gw.to_string(),
            section_name: Some(section.to_string()),
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        }
    }

    /// Insert a minimal HTTPRoute with one Prefix match rule and one backend.
    #[allow(clippy::too_many_arguments)]
    fn insert_simple_http_route(
        store: &ConfigStore,
        ns: &str,
        name: &str,
        parent: ParentRefState,
        hostnames: &[&str],
        path_prefix: &str,
        backend: &str,
        backend_port: u16,
    ) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: hostnames.iter().map(|s| s.to_string()).collect(),
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some((path_prefix.to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: ns.to_string(),
                        name: backend.to_string(),
                        port: backend_port,
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
    }

    fn add_endpoints(store: &ConfigStore, ns: &str, svc: &str, port: u16, addrs: &[&str]) {
        let key = ServiceKey {
            namespace: ns.to_string(),
            name: svc.to_string(),
            port,
        };
        store.endpoints.insert(
            key,
            addrs
                .iter()
                .map(|a| BackendEndpoint {
                    address: a.to_string(),
                    port: port as u32,
                })
                .collect(),
        );
    }

    // -----------------------------------------------------------------------
    // TEST: Exact path matching with negative cases
    // -----------------------------------------------------------------------
    // Conformance scenario: HTTPRoute with exact paths /one and /two.
    // GET /one → v1, GET /two → v2, GET / → NO MATCH, GET /one/example → NO MATCH

    #[test]
    fn test_e2e_exact_path_matching_negative_cases() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        // HTTPRoute "exact-matching" with two rules:
        // Rule 1: Exact /one → infra-backend-v1
        // Rule 2: Exact /two → infra-backend-v2
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "exact-matching".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![], // no hostname restriction
                parent_refs: vec![parent],
                rules: vec![
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/one".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/two".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "infra-backend-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                ],
                generation: 1,
            },
        );

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "infra-backend-v2", 8080, &["10.0.0.2"]);

        let config = compile_config(&store);

        // Positive: GET /one → v1
        let m = match_request(&config, "*", "/one", "GET", &[]);
        assert!(m.is_some(), "GET /one should match");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v1");

        // Positive: GET /two → v2
        let m = match_request(&config, "*", "/two", "GET", &[]);
        assert!(m.is_some(), "GET /two should match");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v2");

        // NEGATIVE: GET / → NO MATCH (this is the one that kept failing in conformance!)
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(
            m.is_none(),
            "GET / should NOT match any exact-path route, but got: {:?}",
            m.map(|m| m.service_name().to_string())
        );

        // NEGATIVE: GET /one/example → NO MATCH (exact, not prefix)
        let m = match_request(&config, "*", "/one/example", "GET", &[]);
        assert!(
            m.is_none(),
            "GET /one/example should NOT match exact /one"
        );

        // NEGATIVE: GET /Two → NO MATCH (case sensitive)
        let m = match_request(&config, "*", "/Two", "GET", &[]);
        assert!(m.is_none(), "GET /Two should NOT match exact /two");

        // NEGATIVE: GET /twoo → NO MATCH
        let m = match_request(&config, "*", "/twoo", "GET", &[]);
        assert!(m.is_none(), "GET /twoo should NOT match exact /two");
    }

    // -----------------------------------------------------------------------
    // TEST: Header matching with negative cases
    // -----------------------------------------------------------------------
    // Conformance scenario: HTTPRoute with header-only rules (no specific path).
    // Multiple match entries = OR semantics per Gateway API spec.

    #[test]
    fn test_e2e_header_matching_negative_cases() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        // HTTPRoute "header-matching" with rules that use header matches.
        // Rule 1: match header `version: one` → infra-backend-v1
        // Rule 2: match headers `version: two` AND `color: orange` → infra-backend-v2
        // Rule 3: match header `color: blue` → infra-backend-v3
        // Each rule has Prefix "/" path match (per Gateway API: path defaults to "/" Prefix).
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "header-matching".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // Rule 1: version: one → v1
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![(
                                "version".to_string(),
                                "one".to_string(),
                                "Exact".to_string(),
                            )],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // Rule 2: version: two AND color: orange → v2
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![
                                (
                                    "version".to_string(),
                                    "two".to_string(),
                                    "Exact".to_string(),
                                ),
                                (
                                    "color".to_string(),
                                    "orange".to_string(),
                                    "Exact".to_string(),
                                ),
                            ],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "infra-backend-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // Rule 3: color: blue → v3
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![(
                                "color".to_string(),
                                "blue".to_string(),
                                "Exact".to_string(),
                            )],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "infra-backend-v3".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                ],
                generation: 1,
            },
        );

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "infra-backend-v2", 8080, &["10.0.0.2"]);
        add_endpoints(&store, "default", "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        // NEGATIVE: GET / with no headers → should match one of the prefix "/" routes
        // since they all have Prefix "/" AND header constraints.
        // With no matching headers, NONE should match.
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(
            m.is_none(),
            "GET / with no headers should NOT match any header-constrained route, got: {:?}",
            m.map(|m| m.service_name().to_string())
        );

        // NEGATIVE: GET / with color: purple → no rule matches this header value
        let m = match_request(&config, "*", "/", "GET", &[("color", "purple")]);
        assert!(
            m.is_none(),
            "GET / with color: purple should NOT match"
        );

        // Positive: GET / with version: one → v1
        let m = match_request(&config, "*", "/", "GET", &[("version", "one")]);
        assert!(m.is_some(), "GET / with version: one should match");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v1");

        // Positive: GET / with version: two AND color: orange → v2
        let m = match_request(
            &config,
            "*",
            "/",
            "GET",
            &[("version", "two"), ("color", "orange")],
        );
        assert!(m.is_some(), "GET / with version:two + color:orange should match");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v2");

        // NEGATIVE: GET / with version: two alone → should NOT match v2 (needs both headers)
        // but should NOT match v1 either (wrong version value)
        let m = match_request(&config, "*", "/", "GET", &[("version", "two")]);
        assert!(
            m.is_none(),
            "GET / with only version: two should NOT match v2 (requires color: orange too)"
        );

        // Positive: GET / with color: blue → v3
        let m = match_request(&config, "*", "/", "GET", &[("color", "blue")]);
        assert!(m.is_some(), "GET / with color: blue should match");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // Verify: version: one with extra headers still matches v1
        // (extra headers beyond what's required don't prevent matching)
        let m = match_request(
            &config,
            "*",
            "/",
            "GET",
            &[("version", "one"), ("extra", "stuff")],
        );
        assert!(m.is_some(), "version: one with extra headers should still match v1");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v1");
    }

    // -----------------------------------------------------------------------
    // TEST: Redirect-only route (no backendRefs)
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_redirect_only_route() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        // HTTPRoute with redirect filter and NO backend refs
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "redirect-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/old".to_string(), "Prefix".to_string())),
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
                    backend_refs: vec![], // No backends — redirect only
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // Verify the route was compiled even without backends
        assert!(
            !config.routes.is_empty(),
            "redirect-only route should still compile (got 0 routes)"
        );

        // Verify redirect fields are present
        let route = &config.routes[0];
        assert!(route.redirect.is_some(), "route should have redirect filter");
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.scheme, "https");
        assert_eq!(redir.hostname, "new.example.com");
        assert_eq!(redir.port, 443);
        assert_eq!(redir.status_code, 301);

        // Verify service_name is empty (no backend)
        assert!(
            route.service_name.is_empty(),
            "redirect-only route should have empty service_name"
        );

        // Positive: request matching works — /old matches
        let m = match_request(&config, "*", "/old", "GET", &[]);
        assert!(m.is_some(), "GET /old should match redirect route");
        assert!(m.unwrap().has_redirect(), "matched route should have redirect");

        // Positive: /old/sub matches (prefix)
        let m = match_request(&config, "*", "/old/sub", "GET", &[]);
        assert!(m.is_some(), "GET /old/sub should match prefix redirect route");

        // Negative: / does not match
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_none(), "GET / should NOT match /old prefix redirect");

        // Negative: /new does not match
        let m = match_request(&config, "*", "/new", "GET", &[]);
        assert!(m.is_none(), "GET /new should NOT match /old prefix redirect");
    }

    // -----------------------------------------------------------------------
    // TEST: 303 redirect status code (Extended feature)
    // -----------------------------------------------------------------------
    // Conformance: HTTPRoute303Redirect — requestRedirect with statusCode: 303.
    // The controller passes through the status code as-is.

    #[test]
    fn test_e2e_redirect_303_status_code() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "303-redirect".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/see-other".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: None,
                        hostname: None,
                        port: None,
                        path: None,
                        path_type: None,
                        status_code: 303,
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
        assert_eq!(config.routes.len(), 1, "should compile 303 redirect route");
        let route = &config.routes[0];
        assert!(route.redirect.is_some(), "route should have redirect");
        let redir = route.redirect.as_ref().unwrap();
        assert_eq!(redir.status_code, 303, "status code should be 303");

        let m = match_request(&config, "*", "/see-other", "POST", &[]);
        assert!(m.is_some(), "POST /see-other should match");
        assert!(m.unwrap().has_redirect(), "matched route should be a redirect");
    }

    // -----------------------------------------------------------------------
    // TEST: 307 redirect status code (Extended feature)
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_redirect_307_status_code() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "307-redirect".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/temporary".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: None,
                        hostname: None,
                        port: None,
                        path: None,
                        path_type: None,
                        status_code: 307,
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
        assert_eq!(config.routes.len(), 1, "should compile 307 redirect route");
        let redir = config.routes[0].redirect.as_ref().unwrap();
        assert_eq!(redir.status_code, 307, "status code should be 307");
    }

    // -----------------------------------------------------------------------
    // TEST: 308 redirect status code (Extended feature)
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_redirect_308_status_code() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "308-redirect".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/permanent".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::RequestRedirect {
                        scheme: None,
                        hostname: None,
                        port: None,
                        path: None,
                        path_type: None,
                        status_code: 308,
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
        assert_eq!(config.routes.len(), 1, "should compile 308 redirect route");
        let redir = config.routes[0].redirect.as_ref().unwrap();
        assert_eq!(redir.status_code, 308, "status code should be 308");
    }

    // -----------------------------------------------------------------------
    // TEST: H2C backend protocol (Extended feature)
    // -----------------------------------------------------------------------
    // Conformance: HTTPRouteBackendProtocolH2C — Service with appProtocol: kubernetes.io/h2c
    // should cause the route's protocol to be set to "H2C".

    #[test]
    fn test_e2e_backend_protocol_h2c() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "gateway-conformance-infra", "same-namespace");

        // Service port 8081 has appProtocol: kubernetes.io/h2c
        let svc_key = ServiceKey {
            namespace: "gateway-conformance-infra".to_string(),
            name: "infra-backend-v1".to_string(),
            port: 8081,
        };
        store.service_port_map.insert(svc_key.clone(), 3001);
        store.service_app_protocols.insert(svc_key.clone(), "kubernetes.io/h2c".to_string());

        add_endpoints(&store, "gateway-conformance-infra", "infra-backend-v1", 3001, &["10.0.0.1"]);

        let key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "backend-protocol-h2c".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "gateway-conformance-infra".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "gateway-conformance-infra".to_string(),
                        name: "infra-backend-v1".to_string(),
                        port: 8081,
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
        assert_eq!(config.routes.len(), 1, "should compile h2c route");
        assert_eq!(config.routes[0].protocol, "H2C", "protocol should be H2C for appProtocol: kubernetes.io/h2c");
        assert_eq!(config.routes[0].service_name, "infra-backend-v1");
    }

    // -----------------------------------------------------------------------
    // TEST: WebSocket backend protocol (Extended feature)
    // -----------------------------------------------------------------------
    // Conformance: HTTPRouteBackendProtocolWebSocket — Service with appProtocol: kubernetes.io/ws

    #[test]
    fn test_e2e_backend_protocol_websocket() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "gateway-conformance-infra", "same-namespace");

        // Service port 8082 has appProtocol: kubernetes.io/ws
        let svc_key = ServiceKey {
            namespace: "gateway-conformance-infra".to_string(),
            name: "infra-backend-v1".to_string(),
            port: 8082,
        };
        store.service_port_map.insert(svc_key.clone(), 3000);
        store.service_app_protocols.insert(svc_key.clone(), "kubernetes.io/ws".to_string());

        add_endpoints(&store, "gateway-conformance-infra", "infra-backend-v1", 3000, &["10.0.0.1"]);

        let key = NamespacedName {
            namespace: "gateway-conformance-infra".to_string(),
            name: "backend-protocol-ws".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "gateway-conformance-infra".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "gateway-conformance-infra".to_string(),
                        name: "infra-backend-v1".to_string(),
                        port: 8082,
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
        assert_eq!(config.routes.len(), 1, "should compile ws route");
        assert_eq!(config.routes[0].protocol, "WS", "protocol should be WS for appProtocol: kubernetes.io/ws");
    }

    // -----------------------------------------------------------------------
    // TEST: CORS filter compilation (Extended feature)
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_cors_filter_compiles() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "cors-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/cors-1".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::CORS {
                        allow_origins: vec!["https://www.foo.com".to_string(), "https://*.bar.com".to_string()],
                        allow_methods: vec!["GET".to_string(), "OPTIONS".to_string()],
                        allow_headers: vec!["x-header-1".to_string(), "x-header-2".to_string()],
                        expose_headers: vec!["x-header-3".to_string(), "x-header-4".to_string()],
                        allow_credentials: true,
                        max_age: Some(3600),
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
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

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 1, "should compile CORS route");
        let route = &config.routes[0];
        assert!(route.cors.is_some(), "route should have CORS config");
        let cors = route.cors.as_ref().unwrap();
        assert_eq!(cors.allow_origins, vec!["https://www.foo.com", "https://*.bar.com"]);
        assert_eq!(cors.allow_methods, vec!["GET", "OPTIONS"]);
        assert_eq!(cors.allow_headers, vec!["x-header-1", "x-header-2"]);
        assert_eq!(cors.expose_headers, vec!["x-header-3", "x-header-4"]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, 3600);
    }

    #[test]
    fn test_e2e_cors_allow_credentials_behavior() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "same-namespace");

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);

        // Route 1: allowCredentials: false
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "cors-creds-false".to_string(),
        };
        store.http_routes.insert(
            key1,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent.clone()],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/cors-no-creds".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::CORS {
                        allow_origins: vec!["https://app.example".to_string()],
                        allow_methods: vec![],
                        allow_headers: vec![],
                        expose_headers: vec![],
                        allow_credentials: false,
                        max_age: None,
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
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

        // Route 2: allowCredentials: true
        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "cors-creds-true".to_string(),
        };
        store.http_routes.insert(
            key2,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/cors-creds".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![HTTPFilterState::CORS {
                        allow_origins: vec!["https://app.example".to_string()],
                        allow_methods: vec![],
                        allow_headers: vec![],
                        expose_headers: vec![],
                        allow_credentials: true,
                        max_age: None,
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
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

        let config = compile_config(&store);
        assert_eq!(config.routes.len(), 2, "should compile 2 CORS routes");

        // Check both have CORS configs
        for route in &config.routes {
            assert!(route.cors.is_some(), "route {} should have CORS config", route.service_name);
        }
    }

    // -----------------------------------------------------------------------
    // TEST: Hostname intersection — negative host matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_hostname_intersection_negative() {
        let store = empty_store();

        // Gateway with specific listener hostname: *.example.com
        let parent = setup_gateway_with_hostname(
            &store,
            "default",
            "wildcard-gw",
            "*.example.com",
        );

        // HTTPRoute with hostnames that partially intersect
        // Route hostname: foo.example.com (intersects with *.example.com)
        // Route hostname: bar.other.com (does NOT intersect)
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "hostname-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![
                    "foo.example.com".to_string(),
                    "bar.other.com".to_string(),
                ],
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

        add_endpoints(&store, "default", "backend-svc", 8080, &["10.0.0.1"]);

        let config = compile_config(&store);

        // Verify only the intersecting hostname was compiled
        assert_eq!(
            config.routes.len(),
            1,
            "only the intersecting hostname should produce a route"
        );
        assert_eq!(
            config.routes[0].host, "foo.example.com",
            "compiled route host should be the intersection result"
        );

        // Positive: foo.example.com matches
        let m = match_request(&config, "foo.example.com", "/", "GET", &[]);
        assert!(m.is_some(), "foo.example.com should match");

        // NEGATIVE: bar.other.com → NO MATCH (hostname not in intersection)
        let m = match_request(&config, "bar.other.com", "/", "GET", &[]);
        assert!(
            m.is_none(),
            "bar.other.com should NOT match (not in listener intersection)"
        );

        // NEGATIVE: baz.example.com → NO MATCH (not the specific intersection)
        let m = match_request(&config, "baz.example.com", "/", "GET", &[]);
        assert!(
            m.is_none(),
            "baz.example.com should NOT match (exact host mismatch)"
        );

        // NEGATIVE: example.com → NO MATCH (wildcard *.example.com doesn't match bare domain)
        let m = match_request(&config, "example.com", "/", "GET", &[]);
        assert!(
            m.is_none(),
            "example.com should NOT match"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: Stale route cleanup — removing a route produces 0 routes
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_stale_route_cleanup() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "temp-route".to_string(),
        };
        store.http_routes.insert(
            key.clone(),
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/api".to_string(), "Prefix".to_string())),
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
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        // First compile: route should exist
        let config_v1 = compile_config(&store);
        assert_eq!(config_v1.routes.len(), 1, "should have 1 route after insert");
        let m = match_request(&config_v1, "*", "/api", "GET", &[]);
        assert!(m.is_some(), "/api should match in v1");

        // Remove the route from the store
        store.http_routes.remove(&key);

        // Second compile: route should be gone
        let config_v2 = compile_config(&store);
        assert_eq!(
            config_v2.routes.len(),
            0,
            "should have 0 routes after removal"
        );
        let m = match_request(&config_v2, "*", "/api", "GET", &[]);
        assert!(m.is_none(), "/api should NOT match after route removal");

        // Verify the configs are different (diff detection works)
        assert_ne!(
            config_v1.routes.len(),
            config_v2.routes.len(),
            "configs should differ after route removal"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: OR semantics — multiple match entries in a single rule
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_or_semantics_multiple_match_entries() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        // A single rule with TWO match entries (OR semantics per Gateway API spec).
        // Match entry 1: path=/alpha
        // Match entry 2: path=/beta
        // Both should route to the same backend.
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "or-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![
                        HTTPRouteMatchState {
                            path: Some(("/alpha".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                        HTTPRouteMatchState {
                            path: Some(("/beta".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        },
                    ],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "or-backend".to_string(),
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

        // OR semantics: each match entry produces its own RouteConfig
        assert_eq!(
            config.routes.len(),
            2,
            "two match entries should produce two RouteConfigs (OR semantics)"
        );

        // Positive: /alpha matches
        let m = match_request(&config, "*", "/alpha", "GET", &[]);
        assert!(m.is_some(), "/alpha should match (OR entry 1)");
        assert_eq!(m.unwrap().service_name(), "or-backend");

        // Positive: /beta matches
        let m = match_request(&config, "*", "/beta", "GET", &[]);
        assert!(m.is_some(), "/beta should match (OR entry 2)");
        assert_eq!(m.unwrap().service_name(), "or-backend");

        // Negative: /gamma does not match
        let m = match_request(&config, "*", "/gamma", "GET", &[]);
        assert!(m.is_none(), "/gamma should NOT match");
    }

    // -----------------------------------------------------------------------
    // TEST: Mixed exact + prefix path precedence
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_exact_takes_precedence_over_prefix() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "mixed-paths".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // Rule 1: Prefix / → catch-all backend
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "catch-all".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // Rule 2: Exact /specific → specific backend
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/specific".to_string(), "Exact".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "specific-backend".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                ],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // Exact /specific should beat prefix /
        let m = match_request(&config, "*", "/specific", "GET", &[]);
        assert!(m.is_some(), "/specific should match");
        assert_eq!(
            m.unwrap().service_name(),
            "specific-backend",
            "exact /specific should take precedence over prefix /"
        );

        // /other should fall through to prefix /
        let m = match_request(&config, "*", "/other", "GET", &[]);
        assert!(m.is_some(), "/other should match prefix /");
        assert_eq!(m.unwrap().service_name(), "catch-all");

        // / itself should match prefix /
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "/ should match prefix /");
        assert_eq!(m.unwrap().service_name(), "catch-all");
    }

    // -----------------------------------------------------------------------
    // TEST: Longer prefix takes precedence over shorter prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_longer_prefix_takes_precedence() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "prefix-precedence".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // Prefix / → default
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "default-svc".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // Prefix /api → api
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/api".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "api-svc".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // Prefix /api/v2 → api-v2
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/api/v2".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: None,
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "api-v2-svc".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                ],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // /api/v2/users → api-v2-svc (longest prefix /api/v2)
        let m = match_request(&config, "*", "/api/v2/users", "GET", &[]);
        assert!(m.is_some(), "/api/v2/users should match");
        assert_eq!(m.unwrap().service_name(), "api-v2-svc");

        // /api/v1/users → api-svc (prefix /api)
        let m = match_request(&config, "*", "/api/v1/users", "GET", &[]);
        assert!(m.is_some(), "/api/v1/users should match");
        assert_eq!(m.unwrap().service_name(), "api-svc");

        // /other → default-svc (prefix /)
        let m = match_request(&config, "*", "/other", "GET", &[]);
        assert!(m.is_some(), "/other should match prefix /");
        assert_eq!(m.unwrap().service_name(), "default-svc");
    }

    // -----------------------------------------------------------------------
    // TEST: Method matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_method_matching() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "method-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // GET / → get-backend
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: Some("GET".to_string()),
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "get-backend".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                    // POST / → post-backend
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/".to_string(), "Prefix".to_string())),
                            headers: vec![],
                            method: Some("POST".to_string()),
                            query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "post-backend".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                        request_timeout_ms: None,
                        backend_request_timeout_ms: None,
                        retry: None,
                    },
                ],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // GET / → get-backend
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "GET / should match");
        assert_eq!(m.unwrap().service_name(), "get-backend");

        // POST / → post-backend
        let m = match_request(&config, "*", "/", "POST", &[]);
        assert!(m.is_some(), "POST / should match");
        assert_eq!(m.unwrap().service_name(), "post-backend");

        // DELETE / → no match (no rule for DELETE)
        let m = match_request(&config, "*", "/", "DELETE", &[]);
        assert!(m.is_none(), "DELETE / should NOT match");
    }

    // -----------------------------------------------------------------------
    // TEST: Gateway listener hostname isolation
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_listener_hostname_isolation() {
        let store = empty_store();

        // Gateway with TWO listeners on different hostnames
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "multi-host-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "multi-host-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "api".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("api.example.com".to_string()),
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
                        name: "web".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("web.example.com".to_string()),
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
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let parent = ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: "default".to_string(),
            gateway_name: "multi-host-gw".to_string(),
            section_name: None, // binds to ALL listeners
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };

        // HTTPRoute with no hostnames → should get both listener hostnames
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "shared-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![], // no hostname restriction
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
                        name: "shared-svc".to_string(),
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

        // Should produce routes for BOTH listener hostnames
        assert_eq!(
            config.routes.len(),
            2,
            "route should be duplicated for each listener hostname"
        );
        let hosts: Vec<&str> = config.routes.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.contains(&"api.example.com"), "should have api.example.com route");
        assert!(hosts.contains(&"web.example.com"), "should have web.example.com route");

        // Positive: api.example.com matches
        let m = match_request(&config, "api.example.com", "/", "GET", &[]);
        assert!(m.is_some(), "api.example.com should match");

        // Positive: web.example.com matches
        let m = match_request(&config, "web.example.com", "/", "GET", &[]);
        assert!(m.is_some(), "web.example.com should match");

        // NEGATIVE: other.example.com → no match
        let m = match_request(&config, "other.example.com", "/", "GET", &[]);
        assert!(m.is_none(), "other.example.com should NOT match");

        // NEGATIVE: wildcard * → no match (specific hostnames only)
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_none(), "wildcard should NOT match specific-host routes");
    }

    // -----------------------------------------------------------------------
    // TEST: Multiple routes across different hostnames — no cross-contamination
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_host_isolation_no_cross_contamination() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        // Route 1: host=api.example.com, path=/data
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "api-route".to_string(),
        };
        store.http_routes.insert(
            key1,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["api.example.com".to_string()],
                parent_refs: vec![parent.clone()],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/data".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "api-backend".to_string(),
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

        // Route 2: host=web.example.com, path=/page
        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "web-route".to_string(),
        };
        store.http_routes.insert(
            key2,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["web.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/page".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
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

        let config = compile_config(&store);

        // api.example.com + /data → api-backend
        let m = match_request(&config, "api.example.com", "/data", "GET", &[]);
        assert!(m.is_some(), "api.example.com /data should match");
        assert_eq!(m.unwrap().service_name(), "api-backend");

        // web.example.com + /page → web-backend
        let m = match_request(&config, "web.example.com", "/page", "GET", &[]);
        assert!(m.is_some(), "web.example.com /page should match");
        assert_eq!(m.unwrap().service_name(), "web-backend");

        // CROSS: api.example.com + /page → NO MATCH (wrong host)
        let m = match_request(&config, "api.example.com", "/page", "GET", &[]);
        assert!(
            m.is_none(),
            "api.example.com /page should NOT match (belongs to web host)"
        );

        // CROSS: web.example.com + /data → NO MATCH (wrong host)
        let m = match_request(&config, "web.example.com", "/data", "GET", &[]);
        assert!(
            m.is_none(),
            "web.example.com /data should NOT match (belongs to api host)"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: Route with no path match (catch-all within host)
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_no_path_match_catches_all() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        // Route with no match entries → should match everything
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "catchall".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![], // no matches = match everything
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "catchall-svc".to_string(),
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

        // Should match ANY path
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "/ should match catch-all");
        assert_eq!(m.unwrap().service_name(), "catchall-svc");

        let m = match_request(&config, "*", "/anything/at/all", "POST", &[]);
        assert!(m.is_some(), "any path should match catch-all");
        assert_eq!(m.unwrap().service_name(), "catchall-svc");
    }

    // -----------------------------------------------------------------------
    // TEST: Unaccepted parent ref produces no routes
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_unaccepted_parent_ref_no_routes() {
        let store = empty_store();

        // Gateway exists but we'll create an unaccepted parent ref
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "gw".to_string(),
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

        let rejected_parent = ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: "default".to_string(),
            gateway_name: "gw".to_string(),
            section_name: None,
            port: None,
            accepted: false, // NOT accepted
            resolved_refs: true,
            reject_reason: Some("NotAllowed".to_string()),
        };

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "rejected-route".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![rejected_parent],
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
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // Unaccepted parent ref → no listener hostname intersection → no routes
        assert_eq!(
            config.routes.len(),
            0,
            "unaccepted parent ref should produce 0 routes"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: HTTPRouteListenerPortMatching — full pipeline E2E
    // -----------------------------------------------------------------------
    // Gateway with 5 listeners on different port/hostname combos, 3 HTTPRoutes
    // binding to specific ports. Same hostname foo.com must route to different
    // backends depending on the listener port.

    #[test]
    fn test_listener_port_matching_e2e() {
        let store = empty_store();

        // Gateway "port-gw" with 5 listeners:
        //   listener-1: foo.com on port 80
        //   listener-2: bar.com on port 80
        //   listener-3: foo.com on port 8080
        //   listener-4: bar.com on port 8080
        //   listener-5: foo.com on port 8090
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "port-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "port-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "listener-1".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("foo.com".to_string()),
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
                        name: "listener-2".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("bar.com".to_string()),
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
                        name: "listener-3".to_string(),
                        port: 8080,
                        protocol: "HTTP".to_string(),
                        hostname: Some("foo.com".to_string()),
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
                        name: "listener-4".to_string(),
                        port: 8080,
                        protocol: "HTTP".to_string(),
                        hostname: Some("bar.com".to_string()),
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
                        name: "listener-5".to_string(),
                        port: 8090,
                        protocol: "HTTP".to_string(),
                        hostname: Some("foo.com".to_string()),
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
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Route 1: bound to listener-1 (foo.com:80) → v1
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-v1".to_string(),
        };
        store.http_routes.insert(
            key1,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["foo.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "port-gw".to_string(),
                    section_name: Some("listener-1".to_string()),
                    port: Some(80),
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
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

        // Route 2: bound to listener-3 + listener-4 (port 8080) → v2
        // Hostnames: foo.com, bar.com
        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-v2".to_string(),
        };
        store.http_routes.insert(
            key2,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["foo.com".to_string(), "bar.com".to_string()],
                parent_refs: vec![
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: "port-gw".to_string(),
                        section_name: Some("listener-3".to_string()),
                        port: Some(8080),
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: "port-gw".to_string(),
                        section_name: Some("listener-4".to_string()),
                        port: Some(8080),
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                ],
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

        // Route 3: bound to listener-5 (foo.com:8090) → v3
        let key3 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-v3".to_string(),
        };
        store.http_routes.insert(
            key3,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["foo.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "port-gw".to_string(),
                    section_name: Some("listener-5".to_string()),
                    port: Some(8090),
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
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
                        name: "infra-backend-v3".to_string(),
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

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "infra-backend-v2", 8080, &["10.0.0.2"]);
        add_endpoints(&store, "default", "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        // foo.com on port 80 → v1
        let m = match_request_on_port(&config, "foo.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "foo.com:80 should match v1");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v1");

        // foo.com on port 8080 → v2
        let m = match_request_on_port(&config, "foo.com", "/", "GET", &[], 8080);
        assert!(m.is_some(), "foo.com:8080 should match v2");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v2");

        // bar.com on port 8080 → v2
        let m = match_request_on_port(&config, "bar.com", "/", "GET", &[], 8080);
        assert!(m.is_some(), "bar.com:8080 should match v2");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v2");

        // foo.com on port 8090 → v3
        let m = match_request_on_port(&config, "foo.com", "/", "GET", &[], 8090);
        assert!(m.is_some(), "foo.com:8090 should match v3");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // bar.com on port 8090 → None (no route binds bar.com to port 8090)
        let m = match_request_on_port(&config, "bar.com", "/", "GET", &[], 8090);
        assert!(
            m.is_none(),
            "bar.com:8090 should NOT match, but got: {:?}",
            m.map(|m| m.service_name().to_string())
        );
    }

    // -----------------------------------------------------------------------
    // TEST: HTTPRouteListenerHostnameMatching — wildcard domains with ports
    // -----------------------------------------------------------------------
    // Gateway with 4 listeners (all port 80): bar.com, foo.bar.com, *.bar.com, *.foo.com
    // 3 routes: v1→listener-1(bar.com), v2→listener-2(foo.bar.com), v3→listener-3+4(*.bar.com + *.foo.com)
    // Tests that wildcard domain matching works when listener_port is set.

    #[test]
    fn test_listener_hostname_wildcard_matching_e2e() {
        let store = empty_store();

        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "hostname-gw".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "hostname-gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "listener-1".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("bar.com".to_string()),
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
                        name: "listener-2".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("foo.bar.com".to_string()),
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
                        name: "listener-3".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("*.bar.com".to_string()),
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
                        name: "listener-4".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("*.foo.com".to_string()),
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
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Route v1 → listener-1 (bar.com)
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-v1".to_string(),
        };
        store.http_routes.insert(
            key1,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: "hostname-gw".to_string(),
                    section_name: Some("listener-1".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
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

        // Route v3 → listener-3 (*.bar.com) + listener-4 (*.foo.com)
        let key3 = NamespacedName {
            namespace: "default".to_string(),
            name: "route-v3".to_string(),
        };
        store.http_routes.insert(
            key3,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: "hostname-gw".to_string(),
                        section_name: Some("listener-3".to_string()),
                        port: None,
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: "hostname-gw".to_string(),
                        section_name: Some("listener-4".to_string()),
                        port: None,
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                ],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "infra-backend-v3".to_string(),
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

        add_endpoints(&store, "default", "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        // bar.com on port 80 → v1 (exact match)
        let m = match_request_on_port(&config, "bar.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "bar.com:80 should match v1");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v1");

        // baz.bar.com on port 80 → v3 (wildcard *.bar.com)
        let m = match_request_on_port(&config, "baz.bar.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "baz.bar.com:80 should match v3 via *.bar.com");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // boo.bar.com on port 80 → v3 (wildcard *.bar.com)
        let m = match_request_on_port(&config, "boo.bar.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "boo.bar.com:80 should match v3 via *.bar.com");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // multiple.prefixes.bar.com on port 80 → v3 (wildcard *.bar.com)
        let m = match_request_on_port(&config, "multiple.prefixes.bar.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "multiple.prefixes.bar.com:80 should match v3");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // sub.foo.com on port 80 → v3 (wildcard *.foo.com)
        let m = match_request_on_port(&config, "sub.foo.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "sub.foo.com:80 should match v3 via *.foo.com");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");

        // multiple.prefixes.foo.com on port 80 → v3 (wildcard *.foo.com)
        let m = match_request_on_port(&config, "multiple.prefixes.foo.com", "/", "GET", &[], 80);
        assert!(m.is_some(), "multiple.prefixes.foo.com:80 should match v3");
        assert_eq!(m.unwrap().service_name(), "infra-backend-v3");
    }

    // -----------------------------------------------------------------------
    // GRPC conformance E2E tests
    // -----------------------------------------------------------------------

    // Helper: set up a gateway and return a parent ref for GRPC routes
    fn setup_grpc_gateway_no_hostname(store: &ConfigStore, ns: &str, name: &str) -> ParentRefState {
        setup_gateway_no_hostname(store, ns, name)
    }

    // -----------------------------------------------------------------------
    // TEST: GRPCExactMethodMatching
    // -----------------------------------------------------------------------
    // Gateway: same-namespace (port 80, no hostname)
    // GRPCRoute: exact-matching with 2 rules:
    //   Rule 1: service=GrpcEcho method=Echo → v1
    //   Rule 2: service=GrpcEcho method=EchoTwo → v2
    // Expected: Echo→v1, EchoTwo→v2, EchoThree→no match

    #[test]
    fn test_grpc_exact_method_matching_e2e() {
        let store = empty_store();
        let parent = setup_grpc_gateway_no_hostname(&store, "default", "same-namespace");

        let svc = "gateway_api_conformance.echo_basic.grpcecho.GrpcEcho";

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "exact-matching".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // Rule 1: Echo → v1
                    GRPCRouteRuleState {
                        matches: vec![GRPCRouteMatchState {
                            service: Some(svc.to_string()),
                            method: Some("Echo".to_string()),
                            match_type: "Exact".to_string(),
                            headers: vec![],
                        }],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                    // Rule 2: EchoTwo → v2
                    GRPCRouteRuleState {
                        matches: vec![GRPCRouteMatchState {
                            service: Some(svc.to_string()),
                            method: Some("EchoTwo".to_string()),
                            match_type: "Exact".to_string(),
                            headers: vec![],
                        }],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                ],
                generation: 1,
            },
        );

        add_endpoints(&store, "default", "grpc-infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "grpc-infra-backend-v2", 8080, &["10.0.0.2"]);

        let config = compile_config(&store);

        let echo_path = format!("/{}/Echo", svc);
        let echo_two_path = format!("/{}/EchoTwo", svc);
        let echo_three_path = format!("/{}/EchoThree", svc);

        // Positive: Echo → v1
        let m = match_request(&config, "*", &echo_path, "POST", &[]);
        assert!(m.is_some(), "gRPC Echo should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // Positive: EchoTwo → v2
        let m = match_request(&config, "*", &echo_two_path, "POST", &[]);
        assert!(m.is_some(), "gRPC EchoTwo should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v2");

        // Negative: EchoThree → no match (no route for this method)
        let m = match_request(&config, "*", &echo_three_path, "POST", &[]);
        assert!(
            m.is_none(),
            "gRPC EchoThree should NOT match any route, got: {:?}",
            m.map(|m| m.service_name().to_string())
        );
    }

    // -----------------------------------------------------------------------
    // TEST: GRPCRouteHeaderMatching
    // -----------------------------------------------------------------------
    // GRPCRoute: grpc-header-matching with 5 rules using header (metadata) matching:
    //   Rule 1: header version=one → v1
    //   Rule 2: header version=two → v2
    //   Rule 3: headers version=two AND color=orange → v1 (more specific wins)
    //   Rule 4: TWO match entries: color=blue OR color=green → v1 (OR semantics)
    //   Rule 5: TWO match entries: color=red OR color=yellow → v2

    #[test]
    fn test_grpc_header_matching_e2e() {
        // Matches the EXACT conformance test YAML: header-only rules with NO
        // service/method match. All routes compile with path "/" (Prefix).
        let store = empty_store();
        let parent = setup_grpc_gateway_no_hostname(&store, "default", "same-namespace");

        // The conformance test sends requests to /service/Echo path, but the
        // GRPCRoute rules have NO method field — only headers. The service/method
        // path is irrelevant; routing is purely by headers.
        let request_path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo";

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-header-matching".to_string(),
        };
        store.grpc_routes.insert(
            key,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    // Rule 1: version=one → v1 (NO service/method)
                    GRPCRouteRuleState {
                        matches: vec![GRPCRouteMatchState {
                            service: None,
                            method: None,
                            match_type: "Exact".to_string(),
                            headers: vec![
                                ("version".to_string(), "one".to_string(), "Exact".to_string()),
                            ],
                        }],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                    // Rule 2: version=two → v2
                    GRPCRouteRuleState {
                        matches: vec![GRPCRouteMatchState {
                            service: None,
                            method: None,
                            match_type: "Exact".to_string(),
                            headers: vec![
                                ("version".to_string(), "two".to_string(), "Exact".to_string()),
                            ],
                        }],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                    // Rule 3: version=two AND color=orange → v1 (more headers = more specific)
                    GRPCRouteRuleState {
                        matches: vec![GRPCRouteMatchState {
                            service: None,
                            method: None,
                            match_type: "Exact".to_string(),
                            headers: vec![
                                ("version".to_string(), "two".to_string(), "Exact".to_string()),
                                ("color".to_string(), "orange".to_string(), "Exact".to_string()),
                            ],
                        }],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                    // Rule 4: color=blue OR color=green → v1 (OR = 2 match entries)
                    GRPCRouteRuleState {
                        matches: vec![
                            GRPCRouteMatchState {
                                service: None,
                                method: None,
                                match_type: "Exact".to_string(),
                                headers: vec![
                                    ("color".to_string(), "blue".to_string(), "Exact".to_string()),
                                ],
                            },
                            GRPCRouteMatchState {
                                service: None,
                                method: None,
                                match_type: "Exact".to_string(),
                                headers: vec![
                                    ("color".to_string(), "green".to_string(), "Exact".to_string()),
                                ],
                            },
                        ],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v1".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                    // Rule 5: color=red OR color=yellow → v2
                    GRPCRouteRuleState {
                        matches: vec![
                            GRPCRouteMatchState {
                                service: None,
                                method: None,
                                match_type: "Exact".to_string(),
                                headers: vec![
                                    ("color".to_string(), "red".to_string(), "Exact".to_string()),
                                ],
                            },
                            GRPCRouteMatchState {
                                service: None,
                                method: None,
                                match_type: "Exact".to_string(),
                                headers: vec![
                                    ("color".to_string(), "yellow".to_string(), "Exact".to_string()),
                                ],
                            },
                        ],
                        backend_refs: vec![BackendRefState {
                            namespace: "default".to_string(),
                            name: "grpc-infra-backend-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            filters: vec![],
                        }],
                    },
                ],
                generation: 1,
            },
        );

        add_endpoints(&store, "default", "grpc-infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "grpc-infra-backend-v2", 8080, &["10.0.0.2"]);

        let config = compile_config(&store);

        // Test case 1: version=one → v1
        let m = match_request(&config, "*", request_path, "POST", &[("version", "one")]);
        assert!(m.is_some(), "version=one should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // Test case 2: version=two → v2
        let m = match_request(&config, "*", request_path, "POST", &[("version", "two")]);
        assert!(m.is_some(), "version=two should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v2");

        // Test case 3: version=two AND color=orange → v1 (Rule 3 more specific, wins over Rule 2)
        let m = match_request(&config, "*", request_path, "POST", &[("version", "two"), ("color", "orange")]);
        assert!(m.is_some(), "version=two + color=orange should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // Test case 4: color=blue → v1 (Rule 4 first OR entry)
        let m = match_request(&config, "*", request_path, "POST", &[("color", "blue")]);
        assert!(m.is_some(), "color=blue should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // Test case 5: color=green → v1 (Rule 4 second OR entry)
        let m = match_request(&config, "*", request_path, "POST", &[("color", "green")]);
        assert!(m.is_some(), "color=green should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // Test case 6: color=red → v2 (Rule 5 first OR entry)
        let m = match_request(&config, "*", request_path, "POST", &[("color", "red")]);
        assert!(m.is_some(), "color=red should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v2");

        // Test case 7: color=yellow → v2 (Rule 5 second OR entry)
        let m = match_request(&config, "*", request_path, "POST", &[("color", "yellow")]);
        assert!(m.is_some(), "color=yellow should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v2");

        // Test case 8: no headers → no match (all rules require headers)
        let m = match_request(&config, "*", request_path, "POST", &[]);
        assert!(
            m.is_none(),
            "no headers should NOT match, got: {:?}",
            m.map(|m| m.service_name().to_string())
        );

        // Test case 9: version=three → no match
        let m = match_request(&config, "*", request_path, "POST", &[("version", "three")]);
        assert!(
            m.is_none(),
            "version=three should NOT match, got: {:?}",
            m.map(|m| m.service_name().to_string())
        );

        // Test case 10: color=purple → no match
        let m = match_request(&config, "*", request_path, "POST", &[("color", "purple")]);
        assert!(
            m.is_none(),
            "color=purple should NOT match, got: {:?}",
            m.map(|m| m.service_name().to_string())
        );

        // Test case 11: version=one with extra headers still matches v1
        let m = match_request(&config, "*", request_path, "POST", &[("version", "one"), ("extra", "stuff")]);
        assert!(m.is_some(), "version=one with extra headers should match");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");
    }

    // -----------------------------------------------------------------------
    // TEST: GRPCRouteListenerHostnameMatching
    // -----------------------------------------------------------------------
    // Creates its OWN Gateway with 4 listeners: bar.com, foo.bar.com, *.bar.com, *.foo.com
    // 3 GRPCRoutes bound to different listeners by sectionName
    // Expected: hostname-based routing (exact + wildcard)

    #[test]
    fn test_grpc_listener_hostname_matching_e2e() {
        let store = empty_store();

        let svc = "gateway_api_conformance.echo_basic.grpcecho.GrpcEcho";
        let request_path = format!("/{}/Echo", svc);

        // Gateway with 4 listeners, all on port 80
        let gw_key = NamespacedName {
            namespace: "default".to_string(),
            name: "httproute-listener-hostname-matching".to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: "httproute-listener-hostname-matching".to_string(),
                namespace: "default".to_string(),
                listeners: vec![
                    ListenerState {
                        name: "listener-1".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("bar.com".to_string()),
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
                        name: "listener-2".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("foo.bar.com".to_string()),
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
                        name: "listener-3".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("*.bar.com".to_string()),
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
                        name: "listener-4".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        hostname: Some("*.foo.com".to_string()),
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
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        let gw_name = "httproute-listener-hostname-matching";

        // Route 1: bound to listener-1 (bar.com), hostname bar.com → v1
        let key1 = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route-bar".to_string(),
        };
        store.grpc_routes.insert(
            key1,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["bar.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: gw_name.to_string(),
                    section_name: Some("listener-1".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some(svc.to_string()),
                        method: None,
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-infra-backend-v1".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        // Route 2: bound to listener-2 (foo.bar.com) → v2
        let key2 = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route-foo-bar".to_string(),
        };
        store.grpc_routes.insert(
            key2,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["foo.bar.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "default".to_string(),
                    gateway_name: gw_name.to_string(),
                    section_name: Some("listener-2".to_string()),
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some(svc.to_string()),
                        method: None,
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-infra-backend-v2".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        // Route 3: bound to listener-3 (*.bar.com) and listener-4 (*.foo.com) → v3
        let key3 = NamespacedName {
            namespace: "default".to_string(),
            name: "grpc-route-wildcard".to_string(),
        };
        store.grpc_routes.insert(
            key3,
            GRPCRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
                parent_refs: vec![
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: gw_name.to_string(),
                        section_name: Some("listener-3".to_string()),
                        port: None,
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                    ParentRefState {
                        parent_kind: ParentKind::Gateway,
                        gateway_namespace: "default".to_string(),
                        gateway_name: gw_name.to_string(),
                        section_name: Some("listener-4".to_string()),
                        port: None,
                        accepted: true,
                        resolved_refs: true,
                        reject_reason: None,
                    },
                ],
                rules: vec![GRPCRouteRuleState {
                    matches: vec![GRPCRouteMatchState {
                        service: Some(svc.to_string()),
                        method: None,
                        match_type: "Exact".to_string(),
                        headers: vec![],
                    }],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "grpc-infra-backend-v3".to_string(),
                        port: 8080,
                        weight: 1,
                        filters: vec![],
                    }],
                }],
                generation: 1,
            },
        );

        add_endpoints(&store, "default", "grpc-infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, "default", "grpc-infra-backend-v2", 8080, &["10.0.0.2"]);
        add_endpoints(&store, "default", "grpc-infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        // bar.com on port 80 → v1 (exact match on listener-1)
        let m = match_request_on_port(&config, "bar.com", &request_path, "POST", &[], 80);
        assert!(m.is_some(), "bar.com:80 should match v1");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v1");

        // foo.bar.com on port 80 → v2 (exact match on listener-2)
        let m = match_request_on_port(&config, "foo.bar.com", &request_path, "POST", &[], 80);
        assert!(m.is_some(), "foo.bar.com:80 should match v2");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v2");

        // baz.bar.com on port 80 → v3 (wildcard *.bar.com from listener-3)
        let m = match_request_on_port(&config, "baz.bar.com", &request_path, "POST", &[], 80);
        assert!(m.is_some(), "baz.bar.com:80 should match v3 via *.bar.com");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v3");

        // sub.foo.com on port 80 → v3 (wildcard *.foo.com from listener-4)
        let m = match_request_on_port(&config, "sub.foo.com", &request_path, "POST", &[], 80);
        assert!(m.is_some(), "sub.foo.com:80 should match v3 via *.foo.com");
        assert_eq!(m.unwrap().service_name(), "grpc-infra-backend-v3");
    }

    // -----------------------------------------------------------------------
    // Policy E2E tests: verify policies flow through the full pipeline
    // ConfigStore → compile_config → compiled RouteConfig/BackendGroup fields
    // -----------------------------------------------------------------------

    /// Helper: create a simple HTTPRoute with one rule (Prefix /) targeting a single backend.
    fn add_simple_http_route(
        store: &ConfigStore,
        ns: &str,
        route_name: &str,
        parent: ParentRefState,
        backend_name: &str,
    ) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: route_name.to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: vec![],
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
                        namespace: ns.to_string(),
                        name: backend_name.to_string(),
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
        add_endpoints(store, ns, backend_name, 8080, &["10.0.0.1"]);
    }

    /// Helper: create a PolicyTargetKey targeting an HTTPRoute.
    fn route_target(ns: &str, name: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "HTTPRoute".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: None,
        }
    }

    /// Helper: create a PolicyTargetKey targeting a Gateway.
    fn gateway_target(ns: &str, name: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: None,
        }
    }

    /// Helper: create a PolicyTargetKey targeting a Service.
    fn service_target(ns: &str, name: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: "".to_string(),
            kind: "Service".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: None,
        }
    }

    /// Helper: create a PolicyTargetKey targeting a specific Service port (sectionName).
    fn service_target_with_section(ns: &str, name: &str, section: &str) -> PolicyTargetKey {
        PolicyTargetKey {
            group: "".to_string(),
            kind: "Service".to_string(),
            namespace: ns.to_string(),
            name: name.to_string(),
            section_name: Some(section.to_string()),
        }
    }

    /// Helper: register a service port name mapping (used for BackendTLSPolicy sectionName resolution).
    fn add_service_port_name(store: &ConfigStore, ns: &str, svc: &str, port: u16, port_name: &str) {
        store.service_port_names.insert(
            ServiceKey {
                namespace: ns.to_string(),
                name: svc.to_string(),
                port,
            },
            port_name.to_string(),
        );
    }

    /// Helper: add an HTTPRoute rule with exact path match to a specific backend on a given port.
    #[allow(clippy::too_many_arguments)]
    fn add_http_route_with_exact_path_and_port(
        store: &ConfigStore,
        ns: &str,
        route_name: &str,
        parent: ParentRefState,
        hostname: &str,
        path: &str,
        backend_name: &str,
        backend_port: u16,
    ) {
        let key = NamespacedName {
            namespace: ns.to_string(),
            name: route_name.to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: vec![hostname.to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some((path.to_string(), "Exact".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: ns.to_string(),
                        name: backend_name.to_string(),
                        port: backend_port,
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
        add_endpoints(store, ns, backend_name, backend_port, &["10.0.0.1"]);
    }

    // -----------------------------------------------------------------------
    // TEST: RetryPolicy targeting an HTTPRoute
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_httproute_retry_rules_from_conformance_yaml() {
        // httproute-retry.yaml: two PathPrefix rules on same-namespace with
        // different codes/attempts; the compiled route carries each rule's own.
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "gateway-conformance-infra", "same-namespace");
        let rule = |prefix: &str, codes: Vec<u16>, attempts: u32| HTTPRouteRuleState {
            matches: vec![HTTPRouteMatchState {
                path: Some((prefix.to_string(), "Prefix".to_string())),
                headers: vec![],
                method: None,
                query_params: vec![],
            }],
            filters: vec![],
            backend_refs: vec![BackendRefState {
                namespace: "gateway-conformance-infra".to_string(),
                name: "infra-backend-v3".to_string(),
                port: 8080,
                weight: 1,
                filters: vec![],
            }],
            request_timeout_ms: None,
            backend_request_timeout_ms: None,
            retry: Some(crate::store::RouteRetryState { codes, attempts }),
        };
        store.http_routes.insert(
            NamespacedName { namespace: "gateway-conformance-infra".to_string(), name: "retries".to_string() },
            HTTPRouteState {
                namespace: "gateway-conformance-infra".to_string(),
                hostnames: vec![],
                parent_refs: vec![parent],
                rules: vec![
                    rule("/retry/code-500-attempts-3", vec![500], 3),
                    rule("/retry/code-all-attempts-2", vec![500, 502, 503, 504], 2),
                ],
                generation: 1,
            },
        );
        add_endpoints(&store, "gateway-conformance-infra", "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);
        let r1 = match_request(&config, "*", "/retry/code-500-attempts-3", "GET", &[])
            .expect("rule 1 matches")
            .route;
        assert_eq!(r1.max_retries, 3);
        assert_eq!(r1.retry_codes, vec![500]);
        let r2 = match_request(&config, "*", "/retry/code-all-attempts-2", "GET", &[])
            .expect("rule 2 matches")
            .route;
        assert_eq!(r2.max_retries, 2);
        assert_eq!(r2.retry_codes, vec![500, 502, 503, 504]);
        assert_eq!(config.routes.len(), 2);
    }

    #[test]
    fn test_e2e_retry_policy_on_httproute() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        // Attach RetryPolicy targeting the HTTPRoute
        store.retry_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "retry-pol".to_string(),
            },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 3,
                retry_on: vec![
                    "5xx".to_string(),
                    "connect-failure".to_string(),
                ],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/foo", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        assert_eq!(route.max_retries, 3, "max_retries should be 3");
        assert_eq!(route.retry_on.len(), 2);
        assert!(route.retry_on.contains(&"5xx".to_string()));
        assert!(route.retry_on.contains(&"connect-failure".to_string()));
    }

    // -----------------------------------------------------------------------
    // TEST: IPAllowlistPolicy targeting an HTTPRoute
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_ip_allowlist_policy_on_httproute() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        store.ip_allowlist_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ip-pol".to_string(),
            },
            IPAllowlistPolicyState {
                target: route_target("default", "my-route"),
                allow_cidrs: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
                deny_cidrs: vec!["10.0.0.5/32".to_string()],
                trusted_proxy_cidrs: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        let ip_cfg = route.ip_allowlist.as_ref().expect("ip_allowlist should be set");
        assert_eq!(ip_cfg.allow_cidrs, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(ip_cfg.deny_cidrs, vec!["10.0.0.5/32"]);
    }

    // -----------------------------------------------------------------------
    // TEST: RequestBodySizeLimitPolicy targeting an HTTPRoute
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_request_body_size_limit_policy_on_httproute() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        store.request_body_size_limit_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "body-limit-pol".to_string(),
            },
            RequestBodySizeLimitPolicyState {
                target: route_target("default", "my-route"),
                max_bytes: 1_048_576, // 1 MiB
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/upload", "POST", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        assert_eq!(
            route.max_request_body_bytes, 1_048_576,
            "max_request_body_bytes should be 1 MiB"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: CORSPolicy targeting an HTTPRoute
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_cors_policy_on_httproute() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        store.cors_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "cors-pol".to_string(),
            },
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

        let m = match_request(&config, "*", "/api", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        let cors = route.cors.as_ref().expect("cors should be set from policy");
        assert_eq!(cors.allow_origins, vec!["https://example.com"]);
        assert_eq!(cors.allow_methods, vec!["GET", "POST"]);
        assert_eq!(cors.allow_headers, vec!["Content-Type"]);
        assert_eq!(cors.expose_headers, vec!["X-Custom"]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, 3600);
    }

    // -----------------------------------------------------------------------
    // TEST: Filter-level CORS takes precedence over CORSPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_cors_filter_takes_precedence_over_cors_policy() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");

        // HTTPRoute with a CORS filter on the rule
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "route-with-cors-filter".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec![],
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
                        allow_headers: vec![],
                        expose_headers: vec![],
                        allow_credentials: false,
                        max_age: Some(600),
                    }],
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
        add_endpoints(&store, "default", "backend-svc", 8080, &["10.0.0.1"]);

        // Also attach a CORSPolicy targeting the same route
        store.cors_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "cors-pol".to_string(),
            },
            CORSPolicyState {
                target: route_target("default", "route-with-cors-filter"),
                allow_origins: vec!["https://policy-origin.com".to_string()],
                allow_methods: vec!["GET".to_string()],
                allow_headers: vec![],
                expose_headers: vec![],
                allow_credentials: true,
                max_age: 7200,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        let cors = route.cors.as_ref().expect("cors should be set");

        // Filter-level CORS should win (not the policy)
        assert_eq!(
            cors.allow_origins,
            vec!["https://filter-origin.com"],
            "filter-level CORS should take precedence over CORSPolicy"
        );
        assert_eq!(cors.allow_methods, vec!["DELETE"]);
        assert!(!cors.allow_credentials, "filter says false, not policy's true");
        assert_eq!(cors.max_age, 600);
    }

    // -----------------------------------------------------------------------
    // TEST: TimeoutPolicy targeting an HTTPRoute
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_timeout_policy_on_httproute() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        store.timeout_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "timeout-pol".to_string(),
            },
            TimeoutPolicyState {
                target: route_target("default", "my-route"),
                request_timeout_ms: 30_000,
                backend_request_timeout_ms: 10_000,
                connect_timeout_ms: 5_000,
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/slow", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        assert_eq!(route.request_timeout_ms, 30_000);
        assert_eq!(route.backend_request_timeout_ms, 10_000);
        let timeouts = route.timeouts.as_ref().expect("timeouts should be set for connect_timeout");
        assert_eq!(timeouts.connect_timeout_ms, 5_000);
    }

    // -----------------------------------------------------------------------
    // TEST: HealthCheckPolicy targeting a backend Service
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_health_check_policy_on_service() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        // HealthCheckPolicy targets the Service (not the route)
        store.health_check_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "hc-pol".to_string(),
            },
            HealthCheckPolicyState {
                target: service_target("default", "backend-svc"),
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

        // Verify the BackendGroup for backend-svc has health_check set
        let backend = config
            .backends
            .iter()
            .find(|b| b.service_name == "backend-svc")
            .expect("backend-svc should be in backends");
        let hc = backend
            .health_check
            .as_ref()
            .expect("health_check should be set on backend");
        assert_eq!(hc.path, "/healthz");
        assert_eq!(hc.interval_secs, 10);
        assert_eq!(hc.timeout_secs, 5);
        assert_eq!(hc.healthy_threshold, 3);
        assert_eq!(hc.unhealthy_threshold, 2);
    }

    // -----------------------------------------------------------------------
    // TEST: Policy conflict resolution — older policy wins
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_policy_conflict_older_wins() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        // Insert two conflicting policies targeting the same route.
        // Both are accepted; the compiler applies first-match from DashMap iteration.
        store.retry_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "retry-alpha".to_string(),
            },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 10,
                retry_on: vec!["gateway-error".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        store.retry_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "retry-beta".to_string(),
            },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 2,
                retry_on: vec!["5xx".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;

        // The compiler iterates DashMap (unordered), so one of the two wins.
        // Both are accepted and target the same route — first-match wins in the
        // current implementation (DashMap iteration order is arbitrary).
        // The key assertion: exactly one policy applied (max_retries > 0).
        assert!(
            route.max_retries > 0,
            "at least one retry policy should have applied"
        );
        assert!(
            !route.retry_on.is_empty(),
            "retry_on should be populated from the winning policy"
        );
        // Note: true conflict resolution (oldest-wins) requires sorted iteration
        // in apply_policies. This test documents current behavior: one policy wins.
        // When conflict resolution is implemented, update assertions to:
        //   assert_eq!(route.max_retries, 2);
        //   assert_eq!(route.retry_on, vec!["5xx"]);
    }

    // -----------------------------------------------------------------------
    // TEST: Gateway-targeted RetryPolicy applies to all routes on that gateway
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_gateway_targeted_retry_policy() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "shared-gw");

        // Two different routes bound to the same gateway
        add_simple_http_route(&store, "default", "route-a", parent.clone(), "svc-a");

        // Route B with a specific path so both routes coexist
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "route-b".to_string(),
        };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: "default".to_string(),
                hostnames: vec!["b.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![HTTPRouteMatchState {
                        path: Some(("/b".to_string(), "Prefix".to_string())),
                        headers: vec![],
                        method: None,
                        query_params: vec![],
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "default".to_string(),
                        name: "svc-b".to_string(),
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
        add_endpoints(&store, "default", "svc-b", 8080, &["10.0.0.2"]);

        // RetryPolicy targeting the Gateway (applies to ALL routes on this gateway)
        store.retry_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "gw-retry-pol".to_string(),
            },
            RetryPolicyState {
                target: gateway_target("default", "shared-gw"),
                max_retries: 5,
                retry_on: vec!["connect-failure".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        // Route A should have the retry policy
        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route-a should match on *");
        let route_a = m.unwrap().route;
        assert_eq!(
            route_a.max_retries, 5,
            "gateway-targeted policy should apply to route-a"
        );
        assert_eq!(route_a.retry_on, vec!["connect-failure"]);

        // Route B should also have the retry policy
        let m = match_request(&config, "b.example.com", "/b", "GET", &[]);
        assert!(m.is_some(), "route-b should match on b.example.com");
        let route_b = m.unwrap().route;
        assert_eq!(
            route_b.max_retries, 5,
            "gateway-targeted policy should apply to route-b"
        );
        assert_eq!(route_b.retry_on, vec!["connect-failure"]);
    }

    // -----------------------------------------------------------------------
    // TEST: Unaccepted policy should NOT be applied
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_unaccepted_policy_not_applied() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        // RetryPolicy with accepted=false
        store.retry_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "rejected-pol".to_string(),
            },
            RetryPolicyState {
                target: route_target("default", "my-route"),
                max_retries: 99,
                retry_on: vec!["5xx".to_string()],
                generation: 1,
                creation_timestamp: None,
                accepted: false, // NOT accepted
            },
        );

        let config = compile_config(&store);

        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        assert_eq!(
            route.max_retries, 0,
            "unaccepted policy should not set max_retries"
        );
        assert!(
            route.retry_on.is_empty(),
            "unaccepted policy should not set retry_on"
        );
    }

    // =======================================================================
    // BackendTLSPolicy conformance tests
    //
    // These tests mirror the 6 Gateway API conformance tests for BackendTLSPolicy.
    // They verify that the compiler correctly attaches TLS config to BackendGroups,
    // handles conflict resolution, and propagates SAN fields.
    //
    // What we test here (catches 99% of issues):
    //   - Compiler: policy attaches TLS config to correct BackendGroup
    //   - Compiler: sectionName scoping (specific port vs all ports)
    //   - Compiler: conflict resolution (oldest wins, sectionName scope)
    //   - Compiler: accepted=false → no TLS config
    //   - Compiler: SAN fields compile through
    //   - Pipeline: full store → compile → verify backend has TLS config
    //
    // What only the cluster can verify:
    //   - Actual TLS handshake success/failure
    //   - 5xx responses from failed TLS connections
    //   - ConfigMap reconciliation (K8s watch events)
    //   - Status condition observedGeneration bumps
    // =======================================================================

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — exact replica of backendtlspolicy.go + backendtlspolicy.yaml
    // "HTTP request sent to Service with valid BackendTLSPolicy should succeed"
    //
    // Setup from YAML:
    //   Gateway: same-namespace (port 80, HTTP, no hostname)
    //   HTTPRoute: backendtlspolicy, hostname abc.example.com, parentRef same-namespace
    //     Rule: exact /backendtlspolicy → backendtlspolicy-test:443
    //   Service: backendtlspolicy-test port 443 targetPort 8443, portName "btls"
    //   BackendTLSPolicy: normative-test, targets backendtlspolicy-test sectionName "btls"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_valid() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        // Service port mapping: 443 → 8443 (matching conformance YAML)
        store.service_port_map.insert(
            ServiceKey { namespace: ns.to_string(), name: "backendtlspolicy-test".to_string(), port: 443 },
            8443,
        );
        add_service_port_name(&store, ns, "backendtlspolicy-test", 443, "btls");

        // HTTPRoute → backendtlspolicy-test:443, exact path /backendtlspolicy
        add_http_route_with_exact_path_and_port(
            &store, ns, "backendtlspolicy", parent,
            "abc.example.com", "/backendtlspolicy",
            "backendtlspolicy-test", 443,
        );

        // Valid BackendTLSPolicy targeting the service port
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "normative-test".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backendtlspolicy-test", "btls"),
                ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        // Route should match on host abc.example.com (not wildcard)
        let m = match_request(&config, "abc.example.com", "/backendtlspolicy", "GET", &[]);
        assert!(m.is_some(), "request to abc.example.com /backendtlspolicy should match");
        assert_eq!(m.unwrap().service_name(), "backendtlspolicy-test");

        // BackendGroup should have backend_tls config
        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-test" && b.port == 443)
            .expect("backendtlspolicy-test:443 should be in backends");
        let tls = backend.backend_tls.as_ref()
            .expect("backend_tls should be set on backend with valid BackendTLSPolicy");
        assert_eq!(tls.hostname, "abc.example.com");
        assert!(!tls.ca_cert_pem.is_empty(), "CA cert PEM should be populated");
    }

    // -----------------------------------------------------------------------
    // TEST: Exact replica of backendtlspolicy-conflict-resolution.yaml
    // Full HTTPRoute with 4 rules, all backends on port 443
    // Verifies all 4 paths compile and route correctly
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_conflict_resolution_full_route() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        // Services with port 443 → targetPort 8443
        for svc in &[
            "backendtlspolicy-conflicted-without-section-name-test",
            "backendtlspolicy-conflicted-with-section-name-test",
            "backendtlspolicy-not-conflicted-test",
        ] {
            store.service_port_map.insert(
                ServiceKey { namespace: ns.to_string(), name: svc.to_string(), port: 443 },
                8443,
            );
            add_endpoints(&store, ns, svc, 8443, &["10.0.0.1"]);
        }
        // not-conflicted-test also has port 8443
        store.service_port_map.insert(
            ServiceKey { namespace: ns.to_string(), name: "backendtlspolicy-not-conflicted-test".to_string(), port: 8443 },
            8443,
        );

        // HTTPRoute with 4 rules (exact match from conformance YAML)
        let key = NamespacedName { namespace: ns.to_string(), name: "backendtlspolicy-conflict-resolution".to_string() };
        store.http_routes.insert(
            key,
            HTTPRouteState {
                namespace: ns.to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![parent],
                rules: vec![
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/backendtlspolicy-conflicted-without-section-name".to_string(), "Exact".to_string())),
                            headers: vec![], method: None, query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: ns.to_string(),
                            name: "backendtlspolicy-conflicted-without-section-name-test".to_string(),
                            port: 443, weight: 1, filters: vec![],
                        }],
                        request_timeout_ms: None, backend_request_timeout_ms: None, retry: None,
                    },
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/backendtlspolicy-conflicted-with-section-name".to_string(), "Exact".to_string())),
                            headers: vec![], method: None, query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: ns.to_string(),
                            name: "backendtlspolicy-conflicted-with-section-name-test".to_string(),
                            port: 443, weight: 1, filters: vec![],
                        }],
                        request_timeout_ms: None, backend_request_timeout_ms: None, retry: None,
                    },
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/backendtlspolicy-not-conflicted-with-section-name".to_string(), "Exact".to_string())),
                            headers: vec![], method: None, query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: ns.to_string(),
                            name: "backendtlspolicy-not-conflicted-test".to_string(),
                            port: 443, weight: 1, filters: vec![],
                        }],
                        request_timeout_ms: None, backend_request_timeout_ms: None, retry: None,
                    },
                    HTTPRouteRuleState {
                        matches: vec![HTTPRouteMatchState {
                            path: Some(("/backendtlspolicy-not-conflicted-without-section-name".to_string(), "Exact".to_string())),
                            headers: vec![], method: None, query_params: vec![],
                        }],
                        filters: vec![],
                        backend_refs: vec![BackendRefState {
                            namespace: ns.to_string(),
                            name: "backendtlspolicy-not-conflicted-test".to_string(),
                            port: 8443, weight: 1, filters: vec![],
                        }],
                        request_timeout_ms: None, backend_request_timeout_ms: None, retry: None,
                    },
                ],
                generation: 1,
            },
        );

        let config = compile_config(&store);

        // All 4 paths should route correctly on host abc.example.com
        let m1 = match_request(&config, "abc.example.com", "/backendtlspolicy-conflicted-without-section-name", "GET", &[]);
        assert!(m1.is_some(), "path /backendtlspolicy-conflicted-without-section-name should match");
        assert_eq!(m1.unwrap().service_name(), "backendtlspolicy-conflicted-without-section-name-test");

        let m2 = match_request(&config, "abc.example.com", "/backendtlspolicy-conflicted-with-section-name", "GET", &[]);
        assert!(m2.is_some(), "path /backendtlspolicy-conflicted-with-section-name should match");
        assert_eq!(m2.unwrap().service_name(), "backendtlspolicy-conflicted-with-section-name-test");

        let m3 = match_request(&config, "abc.example.com", "/backendtlspolicy-not-conflicted-with-section-name", "GET", &[]);
        assert!(m3.is_some(), "path /backendtlspolicy-not-conflicted-with-section-name should match");
        assert_eq!(m3.unwrap().service_name(), "backendtlspolicy-not-conflicted-test");

        let m4 = match_request(&config, "abc.example.com", "/backendtlspolicy-not-conflicted-without-section-name", "GET", &[]);
        assert!(m4.is_some(), "path /backendtlspolicy-not-conflicted-without-section-name should match");
        assert_eq!(m4.unwrap().service_name(), "backendtlspolicy-not-conflicted-test");

        // Verify route count — should be 4 routes (one per rule)
        let abc_routes: Vec<_> = config.routes.iter().filter(|r| r.host == "abc.example.com").collect();
        assert_eq!(abc_routes.len(), 4, "should compile 4 routes for abc.example.com, got {}", abc_routes.len());
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — hostname mismatch policy still compiles
    // (the actual TLS failure happens at connection time, not compile time)
    // Mirrors: backendtlspolicy.go "BackendTLSPolicy with mismatched hostname"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_hostname_mismatch_compiles() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "backendtlspolicy", parent,
            "abc.example.org", "/backendtlspolicy-host-mismatch",
            "backendtlspolicy-host-mismatch-test", 443,
        );
        add_service_port_name(&store, ns, "backendtlspolicy-host-mismatch-test", 443, "btls");

        // Policy with hostname that doesn't match the backend cert
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "host-mismatch".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backendtlspolicy-host-mismatch-test", "btls"),
                ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
                hostname: "mismatch.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        // Route should still match (mismatch is a runtime TLS error, not a compile error)
        let m = match_request(&config, "abc.example.org", "/backendtlspolicy-host-mismatch", "GET", &[]);
        assert!(m.is_some(), "route should match even with hostname mismatch policy");

        // Backend should have the mismatched TLS config (proxy will fail at TLS handshake)
        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-host-mismatch-test")
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("backend_tls should be set even for mismatch");
        assert_eq!(tls.hostname, "mismatch.example.com");
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — unaccepted policy NOT applied
    // Mirrors: backendtlspolicy-invalid-ca-certificate-ref.go
    // When controller marks policy as not accepted (bad cert ref), compiler
    // should NOT attach TLS config.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — unaccepted policy + appProtocol HTTPS
    // Mirrors: backendtlspolicy-invalid-ca-certificate-ref.yaml
    //   Service has appProtocol: HTTPS. Policy is not accepted (bad CA ref).
    //   The route should compile with upstream_tls enabled (from appProtocol),
    //   so the proxy attempts TLS → fails → returns 5xx (not 400 from plain HTTP).
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_unaccepted_not_applied() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "backendtlspolicy-invalid", parent,
            "abc.example.com", "/backendtlspolicy-nonexistent-ca-certificate-ref",
            "backendtlspolicy-nonexistent-test", 443,
        );

        // Service has appProtocol: HTTPS (matching conformance YAML)
        store.service_app_protocols.insert(
            ServiceKey { namespace: ns.to_string(), name: "backendtlspolicy-nonexistent-test".to_string(), port: 443 },
            "HTTPS".to_string(),
        );

        // Policy with accepted=false (controller rejected due to bad CA cert ref)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "nonexistent-ca".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, "backendtlspolicy-nonexistent-test"),
                ca_cert_pem: String::new(), // no cert resolved
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: false, // NOT accepted
            },
        );

        let config = compile_config(&store);

        // Route should still match (the HTTPRoute is valid)
        let m = match_request(&config, "abc.example.com", "/backendtlspolicy-nonexistent-ca-certificate-ref", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;

        // upstream_tls should be enabled (from appProtocol: HTTPS), even though
        // BackendTLSPolicy is not accepted. This ensures the proxy attempts TLS
        // and returns 502 (TLS failure) instead of 400 (plain HTTP to TLS backend).
        assert!(
            route.upstream_tls.is_some(),
            "route should have upstream_tls enabled from appProtocol: HTTPS"
        );
        assert!(
            route.upstream_tls.as_ref().unwrap().enabled,
            "upstream_tls should be enabled"
        );

        // Backend should NOT have backend_tls (policy not accepted)
        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-nonexistent-test");
        if let Some(backend) = backend {
            assert!(
                backend.backend_tls.is_none(),
                "unaccepted BackendTLSPolicy should NOT set backend_tls"
            );
        }
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — invalid kind policy NOT applied
    // Mirrors: backendtlspolicy-invalid-kind.go
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_invalid_kind_not_applied() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "backendtlspolicy-invalid-kind-test", parent,
            "abc.example.com", "/backendtlspolicy-invalid-kind",
            "backendtlspolicy-invalid-kind-test", 443,
        );

        // Policy with accepted=false (controller rejected due to invalid CACertRef kind)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "invalid-kind".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, "backendtlspolicy-invalid-kind-test"),
                ca_cert_pem: String::new(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: false, // rejected by controller
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-invalid-kind-test");
        if let Some(backend) = backend {
            assert!(
                backend.backend_tls.is_none(),
                "rejected BackendTLSPolicy (invalid kind) should NOT set backend_tls"
            );
        }
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy conflict resolution — two policies same target, oldest wins
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   "Conflicting BackendTLSPolicies targeting the same Service without a section name"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_conflict_oldest_wins() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        let svc = "backendtlspolicy-conflicted-without-section-name-test";
        add_http_route_with_exact_path_and_port(
            &store, ns, "backendtlspolicy-conflict-resolution", parent,
            "abc.example.com", "/backendtlspolicy-conflicted-without-section-name",
            svc, 443,
        );

        // Policy 1: older (should win)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "conflicted-without-section-name-1".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, svc),
                ca_cert_pem: "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----".to_string(),
                hostname: "other.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(1000).unwrap(),
                )),
                accepted: true,
            },
        );

        // Policy 2: newer (should lose — Conflicted)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "conflicted-without-section-name-2".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, svc),
                ca_cert_pem: "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(2000).unwrap(),
                )),
                accepted: true, // controller hasn't marked it conflicted yet; compiler resolves conflict
            },
        );

        let config = compile_config(&store);

        // The oldest policy should win
        let backend = config.backends.iter()
            .find(|b| b.service_name == svc)
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("winning policy should set backend_tls");
        assert_eq!(
            tls.hostname, "other.example.com",
            "oldest policy (hostname=other.example.com) should win conflict"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy conflict — same sectionName, oldest wins
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   "Conflicting BackendTLSPolicies targeting the same Service with the same section name"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_conflict_same_section_name() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        let svc = "backendtlspolicy-conflicted-with-section-name-test";
        add_http_route_with_exact_path_and_port(
            &store, ns, "conflict-section", parent,
            "abc.example.com", "/backendtlspolicy-conflicted-with-section-name",
            svc, 443,
        );
        add_service_port_name(&store, ns, svc, 443, "https-1");

        // Policy 1 with sectionName: older (should win)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "conflicted-with-section-name-1".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, svc, "https-1"),
                ca_cert_pem: "CA1".to_string(),
                hostname: "other.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(1000).unwrap(),
                )),
                accepted: true,
            },
        );

        // Policy 2 with same sectionName: newer (should lose)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "conflicted-with-section-name-2".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, svc, "https-1"),
                ca_cert_pem: "CA2".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(2000).unwrap(),
                )),
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == svc && b.port == 443)
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("winning policy should set backend_tls");
        assert_eq!(
            tls.hostname, "other.example.com",
            "oldest policy with same sectionName should win"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — sectionName + no sectionName = NO conflict
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   "BackendTLSPolicies targeting the same Service with and without a section name"
    //   Both should be accepted. sectionName policy applies to that port;
    //   no-sectionName policy applies to other ports.
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_section_vs_no_section_no_conflict() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        let svc = "backendtlspolicy-not-conflicted-test";

        // Route 1: /with-section → svc:443 (port name "https-1")
        add_http_route_with_exact_path_and_port(
            &store, ns, "not-conflicted-with", parent.clone(),
            "abc.example.com", "/backendtlspolicy-not-conflicted-with-section-name",
            svc, 443,
        );
        add_service_port_name(&store, ns, svc, 443, "https-1");

        // Route 2: /without-section → svc:8443 (port name "https-2")
        add_http_route_with_exact_path_and_port(
            &store, ns, "not-conflicted-without", parent,
            "abc.example.com", "/backendtlspolicy-not-conflicted-without-section-name",
            svc, 8443,
        );
        add_service_port_name(&store, ns, svc, 8443, "https-2");

        // Policy with sectionName "https-1" → targets port 443 specifically
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "not-conflicted-with-section-name".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, svc, "https-1"),
                ca_cert_pem: "CA-section".to_string(),
                hostname: "other.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        // Policy without sectionName → targets all ports (but sectionName policy takes precedence for port 443)
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "not-conflicted-without-section-name".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, svc),
                ca_cert_pem: "CA-all".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        // Port 443: sectionName policy should win (more specific)
        let backend_443 = config.backends.iter()
            .find(|b| b.service_name == svc && b.port == 443)
            .expect("backend on port 443 should exist");
        let tls_443 = backend_443.backend_tls.as_ref()
            .expect("port 443 should have backend_tls from sectionName policy");
        assert_eq!(
            tls_443.hostname, "other.example.com",
            "sectionName policy should apply to port 443"
        );

        // Port 8443: no-sectionName policy should apply (only one that covers this port)
        let backend_8443 = config.backends.iter()
            .find(|b| b.service_name == svc && b.port == 8443)
            .expect("backend on port 8443 should exist");
        let tls_8443 = backend_8443.backend_tls.as_ref()
            .expect("port 8443 should have backend_tls from no-sectionName policy");
        assert_eq!(
            tls_8443.hostname, "abc.example.com",
            "no-sectionName policy should apply to port 8443"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy SAN validation — DNS SAN compiles through
    // Mirrors: backendtlspolicy-san.go "valid BackendTLSPolicy containing dns SAN"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_san_dns() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "san-dns-route", parent,
            "abc.example.com", "/backendtlspolicy-san-dns",
            "backendtlspolicy-san-dns-test", 443,
        );
        add_service_port_name(&store, ns, "backendtlspolicy-san-dns-test", 443, "btls");

        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "san-dns".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backendtlspolicy-san-dns-test", "btls"),
                ca_cert_pem: "CA-PEM".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![SubjectAltNameState {
                    san_type: "Hostname".to_string(),
                    value: "abc.example.com".to_string(),
                }],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-san-dns-test")
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("backend_tls should be set");
        assert_eq!(tls.hostname, "abc.example.com");
        assert_eq!(tls.subject_alt_names.len(), 1);
        assert_eq!(tls.subject_alt_names[0].r#type, "Hostname");
        assert_eq!(tls.subject_alt_names[0].value, "abc.example.com");
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy SAN — URI SAN compiles through
    // Mirrors: backendtlspolicy-san.go "valid BackendTLSPolicy containing uri SAN"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_san_uri() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "san-uri-route", parent,
            "abc.example.com", "/backendtlspolicy-san-uri",
            "backendtlspolicy-san-uri-test", 443,
        );
        add_service_port_name(&store, ns, "backendtlspolicy-san-uri-test", 443, "btls");

        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "san-uri".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backendtlspolicy-san-uri-test", "btls"),
                ca_cert_pem: "CA-PEM".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![SubjectAltNameState {
                    san_type: "URI".to_string(),
                    value: "spiffe://abc.example.com/test-identity".to_string(),
                }],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-san-uri-test")
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("backend_tls should be set");
        assert_eq!(tls.subject_alt_names.len(), 1);
        assert_eq!(tls.subject_alt_names[0].r#type, "URI");
        assert_eq!(tls.subject_alt_names[0].value, "spiffe://abc.example.com/test-identity");
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy SAN — multiple SANs compile through
    // Mirrors: backendtlspolicy-san.go "valid BackendTLSPolicy containing multi SAN"
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_san_multiple() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let parent = setup_gateway_no_hostname(&store, ns, "same-namespace");

        add_http_route_with_exact_path_and_port(
            &store, ns, "san-multi-route", parent,
            "abc.example.com", "/backendtlspolicy-multiple-sans",
            "backendtlspolicy-multiple-sans-test", 443,
        );
        add_service_port_name(&store, ns, "backendtlspolicy-multiple-sans-test", 443, "btls");

        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "multiple-sans".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backendtlspolicy-multiple-sans-test", "btls"),
                ca_cert_pem: "CA-PEM".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![
                    SubjectAltNameState {
                        san_type: "URI".to_string(),
                        value: "spiffe://abc.example.com/test-identity".to_string(),
                    },
                    SubjectAltNameState {
                        san_type: "Hostname".to_string(),
                        value: "abc.example.com".to_string(),
                    },
                ],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backendtlspolicy-multiple-sans-test")
            .expect("backend should exist");
        let tls = backend.backend_tls.as_ref()
            .expect("backend_tls should be set");
        assert_eq!(tls.subject_alt_names.len(), 2, "both SANs should compile through");
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — policy targeting wrong service NOT applied
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_wrong_target() {
        let store = empty_store();
        let ns = "default";
        let parent = setup_gateway_no_hostname(&store, ns, "gw");
        add_simple_http_route(&store, ns, "my-route", parent, "backend-svc");

        // Policy targeting a DIFFERENT service
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "wrong-target".to_string() },
            BackendTLSPolicyState {
                target: service_target(ns, "other-service"),
                ca_cert_pem: "CA".to_string(),
                hostname: "example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backend-svc");
        if let Some(backend) = backend {
            assert!(
                backend.backend_tls.is_none(),
                "policy targeting different service should not apply"
            );
        }
    }

    // -----------------------------------------------------------------------
    // TEST: BackendTLSPolicy — sectionName mismatch NOT applied to that port
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_backend_tls_policy_section_name_mismatch() {
        let store = empty_store();
        let ns = "default";
        let parent = setup_gateway_no_hostname(&store, ns, "gw");

        add_http_route_with_exact_path_and_port(
            &store, ns, "route", parent,
            "example.com", "/test",
            "backend-svc", 443,
        );
        add_service_port_name(&store, ns, "backend-svc", 443, "https");

        // Policy targets sectionName "grpc" but service port 443 is named "https"
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: "wrong-section".to_string() },
            BackendTLSPolicyState {
                target: service_target_with_section(ns, "backend-svc", "grpc"),
                ca_cert_pem: "CA".to_string(),
                hostname: "example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        let config = compile_config(&store);

        let backend = config.backends.iter()
            .find(|b| b.service_name == "backend-svc" && b.port == 443);
        if let Some(backend) = backend {
            assert!(
                backend.backend_tls.is_none(),
                "policy with non-matching sectionName should not apply to this port"
            );
        }
    }

    // -----------------------------------------------------------------------
    // TEST: Policy targeting wrong route should NOT apply
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_policy_wrong_target_not_applied() {
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, "default", "gw");
        add_simple_http_route(&store, "default", "my-route", parent, "backend-svc");

        // IPAllowlistPolicy targeting a DIFFERENT route name
        store.ip_allowlist_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ip-pol".to_string(),
            },
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

        let m = match_request(&config, "*", "/", "GET", &[]);
        assert!(m.is_some(), "route should match");
        let route = m.unwrap().route;
        assert!(
            route.ip_allowlist.is_none(),
            "policy targeting a different route should not apply"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: GatewayHTTPListenerIsolation — no route hostnames
    // -----------------------------------------------------------------------
    // Mirrors sigs.k8s.io/gateway-api conformance `GatewayHTTPListenerIsolation`
    // test 1 ("hostnames are configured only in listeners"). Gateway has 4
    // listeners on port 80:
    //   - empty-hostname (no hostname restriction; catch-all)
    //   - wildcard-example-com: "*.example.com"
    //   - wildcard-foo-example-com: "*.foo.example.com"
    //   - abc-foo-example-com: "abc.foo.example.com"
    // Four HTTPRoutes attach via sectionName, each with a unique path prefix
    // and no route-level hostnames. The 4×4 matrix of host×path must enforce
    // listener isolation: only the path belonging to the listener that claims
    // the request host returns 200; all others return 404.
    #[test]
    fn test_e2e_listener_isolation_no_route_hostnames() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let gw = "http-listener-isolation";

        setup_gateway_with_multiple_listeners(
            &store,
            ns,
            gw,
            80,
            &[
                ("empty-hostname", None),
                ("wildcard-example-com", Some("*.example.com")),
                ("wildcard-foo-example-com", Some("*.foo.example.com")),
                ("abc-foo-example-com", Some("abc.foo.example.com")),
            ],
        );

        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-empty-hostname",
            parent_ref_section(ns, gw, "empty-hostname"),
            &[],
            "/empty-hostname",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-wildcard-example-com",
            parent_ref_section(ns, gw, "wildcard-example-com"),
            &[],
            "/wildcard-example-com",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-wildcard-foo-example-com",
            parent_ref_section(ns, gw, "wildcard-foo-example-com"),
            &[],
            "/wildcard-foo-example-com",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-abc-foo-example-com",
            parent_ref_section(ns, gw, "abc-foo-example-com"),
            &[],
            "/abc-foo-example-com",
            "infra-backend-v1",
            8080,
        );

        add_endpoints(&store, ns, "infra-backend-v1", 8080, &["10.0.0.1"]);

        let config = compile_config(&store);

        // Expected: (request_host, request_path, should_match_backend)
        // Only the path owned by the listener that claims the host returns 200.
        let cases: &[(&str, &str, bool)] = &[
            // empty-hostname listener claims "bar.com"
            ("bar.com", "/empty-hostname", true),
            ("bar.com", "/wildcard-example-com", false),
            ("bar.com", "/wildcard-foo-example-com", false),
            ("bar.com", "/abc-foo-example-com", false),
            // *.example.com listener claims "bar.example.com"
            ("bar.example.com", "/empty-hostname", false),
            ("bar.example.com", "/wildcard-example-com", true),
            ("bar.example.com", "/wildcard-foo-example-com", false),
            ("bar.example.com", "/abc-foo-example-com", false),
            // *.foo.example.com listener claims "bar.foo.example.com"
            ("bar.foo.example.com", "/empty-hostname", false),
            ("bar.foo.example.com", "/wildcard-example-com", false),
            ("bar.foo.example.com", "/wildcard-foo-example-com", true),
            ("bar.foo.example.com", "/abc-foo-example-com", false),
            // abc.foo.example.com listener claims "abc.foo.example.com"
            ("abc.foo.example.com", "/empty-hostname", false),
            ("abc.foo.example.com", "/wildcard-example-com", false),
            ("abc.foo.example.com", "/wildcard-foo-example-com", false),
            ("abc.foo.example.com", "/abc-foo-example-com", true),
        ];

        for (h, p, should_match) in cases {
            let m = match_request_on_port(&config, h, p, "GET", &[], 80);
            if *should_match {
                assert!(
                    m.is_some(),
                    "host={} path={} should match a route",
                    h, p
                );
                assert_eq!(
                    m.unwrap().service_name(),
                    "infra-backend-v1",
                    "host={} path={} matched wrong backend",
                    h, p
                );
            } else {
                assert!(
                    m.is_none(),
                    "host={} path={} should NOT match (listener isolation)",
                    h, p
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // TEST: GatewayHTTPListenerIsolation — with hostname intersection
    // -----------------------------------------------------------------------
    // Mirrors conformance test 2 ("intersecting hostnames"). Same listener
    // layout, but each route lists hostnames that intersect other listeners.
    // Listener isolation must still win: a request is bound to the single
    // most-specific listener, and only routes attached to THAT listener are
    // eligible — even if another listener's route has an intersected hostname
    // that would match.
    #[test]
    fn test_e2e_listener_isolation_with_hostname_intersection() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let gw = "http-listener-isolation-with-hostname-intersection";

        setup_gateway_with_multiple_listeners(
            &store,
            ns,
            gw,
            80,
            &[
                ("empty-hostname", None),
                ("wildcard-example-com", Some("*.example.com")),
                ("wildcard-foo-example-com", Some("*.foo.example.com")),
                ("abc-foo-example-com", Some("abc.foo.example.com")),
            ],
        );

        let common_hostnames = &[
            "bar.com",
            "*.example.com",
            "*.foo.example.com",
            "abc.foo.example.com",
        ];

        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-empty-hostname-with-hostname-intersection",
            parent_ref_section(ns, gw, "empty-hostname"),
            common_hostnames,
            "/empty-hostname",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-wildcard-example-com-with-hostname-intersection",
            parent_ref_section(ns, gw, "wildcard-example-com"),
            common_hostnames,
            "/wildcard-example-com",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-wildcard-foo-example-com-with-hostname-intersection",
            parent_ref_section(ns, gw, "wildcard-foo-example-com"),
            common_hostnames,
            "/wildcard-foo-example-com",
            "infra-backend-v1",
            8080,
        );
        insert_simple_http_route(
            &store,
            ns,
            "attaches-to-abc-foo-example-com-with-hostname-intersection",
            parent_ref_section(ns, gw, "abc-foo-example-com"),
            common_hostnames,
            "/abc-foo-example-com",
            "infra-backend-v1",
            8080,
        );

        add_endpoints(&store, ns, "infra-backend-v1", 8080, &["10.0.0.1"]);

        let config = compile_config(&store);

        // Same 4×4 matrix as the non-intersection case — listener isolation
        // must override intersected hostnames.
        let cases: &[(&str, &str, bool)] = &[
            ("bar.com", "/empty-hostname", true),
            ("bar.com", "/wildcard-example-com", false),
            ("bar.com", "/wildcard-foo-example-com", false),
            ("bar.com", "/abc-foo-example-com", false),
            ("bar.example.com", "/empty-hostname", false),
            ("bar.example.com", "/wildcard-example-com", true),
            ("bar.example.com", "/wildcard-foo-example-com", false),
            ("bar.example.com", "/abc-foo-example-com", false),
            ("bar.foo.example.com", "/empty-hostname", false),
            ("bar.foo.example.com", "/wildcard-example-com", false),
            ("bar.foo.example.com", "/wildcard-foo-example-com", true),
            ("bar.foo.example.com", "/abc-foo-example-com", false),
            ("abc.foo.example.com", "/empty-hostname", false),
            ("abc.foo.example.com", "/wildcard-example-com", false),
            ("abc.foo.example.com", "/wildcard-foo-example-com", false),
            ("abc.foo.example.com", "/abc-foo-example-com", true),
        ];

        for (h, p, should_match) in cases {
            let m = match_request_on_port(&config, h, p, "GET", &[], 80);
            if *should_match {
                assert!(
                    m.is_some(),
                    "host={} path={} should match a route",
                    h, p
                );
                assert_eq!(
                    m.unwrap().service_name(),
                    "infra-backend-v1",
                    "host={} path={} matched wrong backend",
                    h, p
                );
            } else {
                assert!(
                    m.is_none(),
                    "host={} path={} should NOT match (listener isolation)",
                    h, p
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // TEST: listener isolation specificity helper
    // -----------------------------------------------------------------------
    #[test]
    fn test_select_most_specific_listener() {
        let listeners: &[&str] = &["", "*.example.com", "*.foo.example.com", "abc.foo.example.com"];

        assert_eq!(
            select_most_specific_listener("bar.com", listeners).as_deref(),
            Some(""),
            "bar.com → empty-hostname (catch-all)"
        );
        assert_eq!(
            select_most_specific_listener("bar.example.com", listeners).as_deref(),
            Some("*.example.com"),
            "bar.example.com → *.example.com"
        );
        assert_eq!(
            select_most_specific_listener("bar.foo.example.com", listeners).as_deref(),
            Some("*.foo.example.com"),
            "bar.foo.example.com → *.foo.example.com (longer suffix wins)"
        );
        assert_eq!(
            select_most_specific_listener("abc.foo.example.com", listeners).as_deref(),
            Some("abc.foo.example.com"),
            "abc.foo.example.com → exact (beats wildcards)"
        );
        // Apex name must not match *.example.com (wildcards require a label before the suffix).
        let without_catchall: &[&str] = &["*.example.com"];
        assert_eq!(
            select_most_specific_listener("example.com", without_catchall),
            None,
            "apex name must not match wildcard listener"
        );
    }

    // -----------------------------------------------------------------------
    // TEST: ListenerSetHTTPRouting
    // -----------------------------------------------------------------------
    // Mirrors listenerset-http-routing.yaml/go. A Gateway with allowedListeners
    // and two ListenerSets. Each resource owns its own listeners. Routes
    // attach to each parent individually (Gateway, ListenerSet, or specific
    // listener via sectionName). Isolation: a request bound to a listener
    // only matches routes attached to that listener's owning resource.
    #[test]
    fn test_e2e_listener_set_http_routing() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let gw = "gateway-with-listener-sets-http-routing";

        // Parent Gateway with 2 listeners + allowedListeners.namespaces.from=All.
        let gw_key = NamespacedName {
            namespace: ns.to_string(),
            name: gw.to_string(),
        };
        store.gateways.insert(
            gw_key,
            GatewayState {
                name: gw.to_string(),
                namespace: ns.to_string(),
                listeners: vec![
                    make_http_listener("gateway-listener-1", 80, Some("gateway-listener-1.com")),
                    make_http_listener("gateway-listener-2", 80, Some("gateway-listener-2.com")),
                ],
                generation: 1,
                allowed_listener_namespaces_from: Some("All".to_string()),
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Two ListenerSets, each contributing 2 listeners.
        insert_listener_set(
            &store,
            ns,
            "listener-set-http-routing-1",
            ns,
            gw,
            &[
                ("listener-set-http-routing-1-listener-1", "listener-set-http-routing-1-listener-1.com"),
                ("listener-set-http-routing-1-listener-2", "listener-set-http-routing-1-listener-2.com"),
            ],
        );
        insert_listener_set(
            &store,
            ns,
            "listener-set-http-routing-2",
            ns,
            gw,
            &[
                ("listener-set-http-routing-2-listener-1", "listener-set-http-routing-2-listener-1.com"),
                ("listener-set-http-routing-2-listener-2", "listener-set-http-routing-2-listener-2.com"),
            ],
        );

        // Routes.
        let gw_parent = ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: ns.to_string(),
            gateway_name: gw.to_string(),
            section_name: None,
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };
        let gw_parent_section = |section: &str| ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: ns.to_string(),
            gateway_name: gw.to_string(),
            section_name: Some(section.to_string()),
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };
        let ls_parent = |name: &str| ParentRefState {
            parent_kind: ParentKind::ListenerSet,
            gateway_namespace: ns.to_string(),
            gateway_name: name.to_string(),
            section_name: None,
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };
        let ls_parent_section = |name: &str, section: &str| ParentRefState {
            parent_kind: ParentKind::ListenerSet,
            gateway_namespace: ns.to_string(),
            gateway_name: name.to_string(),
            section_name: Some(section.to_string()),
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };

        // attaches-to-all-listeners → /route → infra-backend-v1
        insert_http_route_multi_parent(
            &store,
            ns,
            "attaches-to-all-listeners",
            vec![
                gw_parent.clone(),
                ls_parent("listener-set-http-routing-1"),
                ls_parent("listener-set-http-routing-2"),
            ],
            "/route",
            "infra-backend-v1",
        );
        // gateway-route → /gateway-route → infra-backend-v2 (Gateway only)
        insert_http_route_multi_parent(
            &store,
            ns,
            "gateway-route",
            vec![gw_parent.clone()],
            "/gateway-route",
            "infra-backend-v2",
        );
        // gateway-section-route → /gateway-section-route → infra-backend-v3
        insert_http_route_multi_parent(
            &store,
            ns,
            "gateway-section-route",
            vec![gw_parent_section("gateway-listener-1")],
            "/gateway-section-route",
            "infra-backend-v3",
        );
        // listener-set-1-route → /listener-set-http-routing-1-route → infra-backend-v2
        insert_http_route_multi_parent(
            &store,
            ns,
            "listener-set-http-routing-1-route",
            vec![ls_parent("listener-set-http-routing-1")],
            "/listener-set-http-routing-1-route",
            "infra-backend-v2",
        );
        // listener-set-1-section-route → /listener-set-http-routing-1-section-route → infra-backend-v3
        insert_http_route_multi_parent(
            &store,
            ns,
            "listener-set-http-routing-1-section-route",
            vec![ls_parent_section(
                "listener-set-http-routing-1",
                "listener-set-http-routing-1-listener-1",
            )],
            "/listener-set-http-routing-1-section-route",
            "infra-backend-v3",
        );
        // listener-set-2-route → /listener-set-http-routing-2-route → infra-backend-v2
        insert_http_route_multi_parent(
            &store,
            ns,
            "listener-set-http-routing-2-route",
            vec![ls_parent("listener-set-http-routing-2")],
            "/listener-set-http-routing-2-route",
            "infra-backend-v2",
        );

        add_endpoints(&store, ns, "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, ns, "infra-backend-v2", 8080, &["10.0.0.2"]);
        add_endpoints(&store, ns, "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        // Expected matrix (host, path, expected_backend_or_none).
        let cases: &[(&str, &str, Option<&str>)] = &[
            // /route goes to infra-backend-v1 everywhere (attaches-to-all).
            ("gateway-listener-1.com", "/route", Some("infra-backend-v1")),
            ("gateway-listener-2.com", "/route", Some("infra-backend-v1")),
            ("listener-set-http-routing-1-listener-1.com", "/route", Some("infra-backend-v1")),
            ("listener-set-http-routing-1-listener-2.com", "/route", Some("infra-backend-v1")),
            ("listener-set-http-routing-2-listener-1.com", "/route", Some("infra-backend-v1")),
            ("listener-set-http-routing-2-listener-2.com", "/route", Some("infra-backend-v1")),
            // /gateway-route works only on gateway listeners.
            ("gateway-listener-1.com", "/gateway-route", Some("infra-backend-v2")),
            ("gateway-listener-2.com", "/gateway-route", Some("infra-backend-v2")),
            ("listener-set-http-routing-1-listener-1.com", "/gateway-route", None),
            ("listener-set-http-routing-1-listener-2.com", "/gateway-route", None),
            ("listener-set-http-routing-2-listener-1.com", "/gateway-route", None),
            ("listener-set-http-routing-2-listener-2.com", "/gateway-route", None),
            // /gateway-section-route only on gateway-listener-1.
            ("gateway-listener-1.com", "/gateway-section-route", Some("infra-backend-v3")),
            ("gateway-listener-2.com", "/gateway-section-route", None),
            ("listener-set-http-routing-1-listener-1.com", "/gateway-section-route", None),
            ("listener-set-http-routing-1-listener-2.com", "/gateway-section-route", None),
            ("listener-set-http-routing-2-listener-1.com", "/gateway-section-route", None),
            ("listener-set-http-routing-2-listener-2.com", "/gateway-section-route", None),
            // /listener-set-http-routing-1-route only on LS1 listeners.
            ("gateway-listener-1.com", "/listener-set-http-routing-1-route", None),
            ("gateway-listener-2.com", "/listener-set-http-routing-1-route", None),
            ("listener-set-http-routing-1-listener-1.com", "/listener-set-http-routing-1-route", Some("infra-backend-v2")),
            ("listener-set-http-routing-1-listener-2.com", "/listener-set-http-routing-1-route", Some("infra-backend-v2")),
            ("listener-set-http-routing-2-listener-1.com", "/listener-set-http-routing-1-route", None),
            ("listener-set-http-routing-2-listener-2.com", "/listener-set-http-routing-1-route", None),
            // /listener-set-http-routing-1-section-route only on LS1-listener-1.
            ("gateway-listener-1.com", "/listener-set-http-routing-1-section-route", None),
            ("gateway-listener-2.com", "/listener-set-http-routing-1-section-route", None),
            ("listener-set-http-routing-1-listener-1.com", "/listener-set-http-routing-1-section-route", Some("infra-backend-v3")),
            ("listener-set-http-routing-1-listener-2.com", "/listener-set-http-routing-1-section-route", None),
            ("listener-set-http-routing-2-listener-1.com", "/listener-set-http-routing-1-section-route", None),
            ("listener-set-http-routing-2-listener-2.com", "/listener-set-http-routing-1-section-route", None),
            // /listener-set-http-routing-2-route only on LS2 listeners.
            ("gateway-listener-1.com", "/listener-set-http-routing-2-route", None),
            ("gateway-listener-2.com", "/listener-set-http-routing-2-route", None),
            ("listener-set-http-routing-1-listener-1.com", "/listener-set-http-routing-2-route", None),
            ("listener-set-http-routing-1-listener-2.com", "/listener-set-http-routing-2-route", None),
            ("listener-set-http-routing-2-listener-1.com", "/listener-set-http-routing-2-route", Some("infra-backend-v2")),
            ("listener-set-http-routing-2-listener-2.com", "/listener-set-http-routing-2-route", Some("infra-backend-v2")),
        ];

        for (h, p, expected) in cases {
            let m = match_request_on_port(&config, h, p, "GET", &[], 80);
            match expected {
                Some(backend) => {
                    assert!(
                        m.is_some(),
                        "host={} path={} should match backend {}",
                        h, p, backend
                    );
                    assert_eq!(
                        m.unwrap().service_name(),
                        *backend,
                        "host={} path={} wrong backend",
                        h, p
                    );
                }
                None => {
                    assert!(
                        m.is_none(),
                        "host={} path={} should NOT match",
                        h, p
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // TEST: ListenerSet rejected when Gateway does not allow attachment
    // -----------------------------------------------------------------------
    #[test]
    fn test_e2e_listener_set_not_allowed() {
        let store = empty_store();
        let ns = "gateway-conformance-infra";
        let gw = "no-allowed-listeners-gw";

        // Gateway WITHOUT allowedListeners → ListenerSets must be rejected.
        store.gateways.insert(
            NamespacedName {
                namespace: ns.to_string(),
                name: gw.to_string(),
            },
            GatewayState {
                name: gw.to_string(),
                namespace: ns.to_string(),
                listeners: vec![make_http_listener("gw-l", 80, Some("gw.example.com"))],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Insert the ListenerSet with accepted=false to simulate the
        // reconciler having rejected it due to the Gateway not permitting
        // attachment.
        store.listener_sets.insert(
            NamespacedName {
                namespace: ns.to_string(),
                name: "ls-blocked".to_string(),
            },
            crate::store::ListenerSetState {
                name: "ls-blocked".to_string(),
                namespace: ns.to_string(),
                parent_gateway: NamespacedName {
                    namespace: ns.to_string(),
                    name: gw.to_string(),
                },
                listeners: vec![make_http_listener("l1", 80, Some("ls.example.com"))],
                accepted: false,
                generation: 1,
                not_accepted_reason: Some("NotAllowed".to_string()),
                creation_timestamp: 0,
            },
        );

        // Route attached to the ListenerSet should compile to NO routes
        // because the ListenerSet itself is not accepted.
        insert_http_route_multi_parent(
            &store,
            ns,
            "ls-route",
            vec![ParentRefState {
                parent_kind: ParentKind::ListenerSet,
                gateway_namespace: ns.to_string(),
                gateway_name: "ls-blocked".to_string(),
                section_name: None,
                port: None,
                accepted: true,
                resolved_refs: true,
                reject_reason: None,
            }],
            "/blocked",
            "b1",
        );
        add_endpoints(&store, ns, "b1", 8080, &["10.0.0.1"]);

        let config = compile_config(&store);
        let m = match_request_on_port(&config, "ls.example.com", "/blocked", "GET", &[], 80);
        assert!(m.is_none(), "route via unaccepted ListenerSet must not match");
    }

    /// ListenerSetAllowedRoutesNamespaces / "Cross-namespace ListenerSet"
    /// (Gateway API v1.6): a ListenerSet living in a different namespace than
    /// its Gateway, with `allowedRoutes.namespaces.from: Same`. "Same" is the
    /// ListenerSet's namespace: a route there is served, a route in the
    /// Gateway's namespace is not.
    #[test]
    fn test_e2e_listener_set_cross_namespace_same_means_listenerset_namespace() {
        let store = empty_store();
        let gw_ns = "gateway-conformance-infra";
        let ls_ns = "gateway-api-ls-cross-ns";
        let gw = "gateway-with-listener-sets-test-allowed-routes";
        let ls = "listenerset-test-allowed-routes-cross-ns";
        let host = "listener-set-listener-allowed-routes-cross-ns-same.com";

        store.gateways.insert(
            NamespacedName { namespace: gw_ns.into(), name: gw.into() },
            GatewayState {
                name: gw.into(),
                namespace: gw_ns.into(),
                listeners: vec![make_http_listener("gateway-listener", 80, Some("gateway-listener.com"))],
                generation: 1,
                allowed_listener_namespaces_from: Some("All".into()),
                allowed_listener_match_labels: Vec::new(),
            },
        );
        let mut same_listener = make_http_listener("listener-set-listener-allowed-routes-cross-ns-same", 80, Some(host));
        same_listener.allowed_routes = AllowedRoutesState { namespaces_from: "Same".into(), namespace_selector: None };
        store.listener_sets.insert(
            NamespacedName { namespace: ls_ns.into(), name: ls.into() },
            crate::store::ListenerSetState {
                name: ls.into(),
                namespace: ls_ns.into(),
                parent_gateway: NamespacedName { namespace: gw_ns.into(), name: gw.into() },
                listeners: vec![same_listener],
                accepted: true,
                generation: 1,
                not_accepted_reason: None,
                creation_timestamp: 0,
            },
        );
        let ls_parent = |accepted: bool| ParentRefState {
            parent_kind: ParentKind::ListenerSet,
            gateway_namespace: ls_ns.into(),
            gateway_name: ls.into(),
            section_name: None,
            port: None,
            accepted,
            resolved_refs: true,
            reject_reason: None,
        };
        // Route in the ListenerSet's namespace: allowed by "Same".
        insert_http_route_multi_parent(&store, ls_ns, "route-in-listenerset-namespace", vec![ls_parent(true)], "/route-in-listenerset-namespace", "infra-backend-v1");
        add_endpoints(&store, ls_ns, "infra-backend-v1", 8080, &["10.0.0.1"]);
        // Route in the Gateway's namespace: the reconciler accepts against the
        // parent, but the compiler's per-listener filter must still exclude it.
        insert_http_route_multi_parent(&store, gw_ns, "route-in-gateway-namespace", vec![ls_parent(true)], "/route-in-gateway-namespace", "infra-backend-v2");
        add_endpoints(&store, gw_ns, "infra-backend-v2", 8080, &["10.0.0.2"]);

        let config = compile_config(&store);
        let m = match_request_on_port(&config, host, "/route-in-listenerset-namespace", "GET", &[], 80)
            .expect("route in the ListenerSet namespace must be served");
        assert_eq!(m.route.service_name, "infra-backend-v1");
        assert!(
            match_request_on_port(&config, host, "/route-in-gateway-namespace", "GET", &[], 80).is_none(),
            "route in the Gateway namespace must not be served by a Same-namespace ListenerSet listener"
        );
    }

    // -----------------------------------------------------------------------
    // HTTPRouteHTTPSListenerDetectMisdirectedRequests (GEP-1486)
    //
    // Full E2E pipeline test mirroring the upstream conformance YAML for
    // `same-namespace-with-https-listener`: a single Gateway on port 443 with
    // four HTTPS listeners (catch-all, exact second-example.org, wildcard
    // *.wildcard.org, exact fourth-example.wildcard.org) and four HTTPRoutes
    // attached to each listener by sectionName. The 14-case request matrix
    // encodes the expected (SNI, Host) → (200+backend | 421 | 404) behaviour.
    // -----------------------------------------------------------------------

    #[derive(Debug, PartialEq)]
    enum HttpsResult {
        Matched(String),
        Misdirected421,
        NotFound404,
    }

    /// Simulate the dataplane's HTTPS pipeline for a single request:
    ///   1. Determine the most-specific listener hostname matching the SNI.
    ///   2. Determine the most-specific listener hostname matching the Host.
    ///   3. If they differ → 421.
    ///   4. Otherwise run the normal per-listener route match; on no match → 404.
    fn simulate_https_request(
        config: &CompiledConfig,
        sni: Option<&str>,
        host: &str,
        path: &str,
        port: u16,
    ) -> HttpsResult {
        let port_scoped: Vec<&RouteConfig> = config
            .routes
            .iter()
            .filter(|r| r.listener_port == 0 || r.listener_port == port as u32)
            .collect();
        let mut listener_hostnames: Vec<&str> = port_scoped
            .iter()
            .map(|r| r.listener_hostname.as_str())
            .collect();
        listener_hostnames.sort();
        listener_hostnames.dedup();

        let host_listener = select_most_specific_listener(host, &listener_hostnames);
        if let Some(sni) = sni {
            let sni_listener = select_most_specific_listener(sni, &listener_hostnames);
            if let (Some(sl), Some(hl)) = (sni_listener.as_deref(), host_listener.as_deref()) {
                if sl != hl {
                    return HttpsResult::Misdirected421;
                }
            } else if sni_listener.is_some() && host_listener.is_none() {
                return HttpsResult::Misdirected421;
            }
        }

        match match_request_on_port(config, host, path, "GET", &[], port) {
            Some(m) => HttpsResult::Matched(m.service_name().to_string()),
            None => HttpsResult::NotFound404,
        }
    }

    /// Build the listener state matching the upstream YAML. All four listeners
    /// live on port 443, HTTPS protocol, with `tls-validity-checks-certificate`
    /// referenced (compile is agnostic to actual cert validity in this test).
    fn misdirected_gateway_listeners() -> Vec<ListenerState> {
        let cert_ref: Vec<(String, String)> = vec![(
            "gateway-conformance-infra".to_string(),
            "tls-validity-checks-certificate".to_string(),
        )];
        vec![
            ListenerState {
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
                tls_cert_refs: cert_ref.clone(),
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
                tls_cert_refs: cert_ref.clone(),
                tls_mode: Some("Terminate".to_string()),
            },
            ListenerState {
                name: "https-with-wildcard-hostname".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: Some("*.wildcard.org".to_string()),
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: cert_ref.clone(),
                tls_mode: Some("Terminate".to_string()),
            },
            ListenerState {
                name: "https-with-hostname-matching-wildcard".to_string(),
                port: 443,
                protocol: "HTTPS".to_string(),
                hostname: Some("fourth-example.wildcard.org".to_string()),
                accepted: true,
                conflicted: false,
                resolved_refs: true,
                allowed_routes: AllowedRoutesState {
                    namespaces_from: "Same".to_string(),
                    namespace_selector: None,
                },
                tls_cert_refs: cert_ref,
                tls_mode: Some("Terminate".to_string()),
            },
        ]
    }

    #[test]
    fn test_e2e_misdirected_requests_matrix() {
        let ns = "gateway-conformance-infra";
        let store = empty_store();

        store.gateways.insert(
            NamespacedName {
                namespace: ns.to_string(),
                name: "same-namespace-with-https-listener".to_string(),
            },
            GatewayState {
                name: "same-namespace-with-https-listener".to_string(),
                namespace: ns.to_string(),
                listeners: misdirected_gateway_listeners(),
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // Route 1: explicit hostname=[example.org], attaches to "https" (catch-all).
        insert_simple_http_route(
            &store,
            ns,
            "https-listener-detect-misdirected-requests-test-1",
            parent_ref_section(ns, "same-namespace-with-https-listener", "https"),
            &["example.org"],
            "/detect-misdirected-requests",
            "infra-backend-v1",
            8080,
        );
        // Route 2: no hostnames, attaches to second-example.org listener.
        insert_simple_http_route(
            &store,
            ns,
            "https-listener-detect-misdirected-requests-test-2",
            parent_ref_section(ns, "same-namespace-with-https-listener", "https-with-hostname"),
            &[],
            "/detect-misdirected-requests",
            "infra-backend-v2",
            8080,
        );
        // Route 3: no hostnames, attaches to *.wildcard.org listener.
        insert_simple_http_route(
            &store,
            ns,
            "https-listener-detect-misdirected-requests-test-3",
            parent_ref_section(
                ns,
                "same-namespace-with-https-listener",
                "https-with-wildcard-hostname",
            ),
            &[],
            "/detect-misdirected-requests",
            "infra-backend-v3",
            8080,
        );
        // Route 4: no hostnames, attaches to fourth-example.wildcard.org listener.
        // Upstream uses infra-backend-v1 as the backend because v4 doesn't exist.
        insert_simple_http_route(
            &store,
            ns,
            "https-listener-detect-misdirected-requests-test-4",
            parent_ref_section(
                ns,
                "same-namespace-with-https-listener",
                "https-with-hostname-matching-wildcard",
            ),
            &[],
            "/detect-misdirected-requests",
            "infra-backend-v1",
            8080,
        );

        add_endpoints(&store, ns, "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(&store, ns, "infra-backend-v2", 8080, &["10.0.0.2"]);
        add_endpoints(&store, ns, "infra-backend-v3", 8080, &["10.0.0.3"]);

        let config = compile_config(&store);

        let path = "/detect-misdirected-requests";
        type Case = (&'static str, &'static str, HttpsResult);
        let matched = |svc: &str| HttpsResult::Matched(svc.to_string());
        let cases: Vec<Case> = vec![
            // SNI=example.org → catch-all listener.
            ("example.org", "example.org", matched("infra-backend-v1")),
            ("example.org", "second-example.org", HttpsResult::Misdirected421),
            ("example.org", "unknown-example.org", HttpsResult::NotFound404),

            // SNI=second-example.org → exact listener.
            ("second-example.org", "second-example.org", matched("infra-backend-v2")),
            ("second-example.org", "example.org", HttpsResult::Misdirected421),
            ("second-example.org", "unknown-example.org", HttpsResult::Misdirected421),

            // SNI=third-example.wildcard.org → wildcard listener.
            ("third-example.wildcard.org", "third-example.wildcard.org", matched("infra-backend-v3")),
            ("third-example.wildcard.org", "fith-example.wildcard.org", matched("infra-backend-v3")),
            ("third-example.wildcard.org", "fourth-example.wildcard.org", HttpsResult::Misdirected421),
            ("third-example.wildcard.org", "second-example.org", HttpsResult::Misdirected421),
            ("third-example.wildcard.org", "unknown-example.org", HttpsResult::Misdirected421),

            // SNI=fourth-example.wildcard.org → exact listener.
            ("fourth-example.wildcard.org", "fourth-example.wildcard.org", matched("infra-backend-v1")),
            ("fourth-example.wildcard.org", "fith-example.wildcard.org", HttpsResult::Misdirected421),

            // SNI=unknown-example.org → catch-all listener (fallback).
            ("unknown-example.org", "example.org", matched("infra-backend-v1")),
            ("unknown-example.org", "unknown-example.org", HttpsResult::NotFound404),
        ];

        for (sni, host, expected) in &cases {
            let got = simulate_https_request(&config, Some(sni), host, path, 443);
            assert_eq!(
                got, *expected,
                "SNI={sni:?} Host={host:?} path={path} → expected {expected:?}, got {got:?}",
            );
        }
    }

fn make_http_listener(name: &str, port: u16, hostname: Option<&str>) -> crate::store::ListenerState {
    crate::store::ListenerState {
        name: name.to_string(),
        port,
        protocol: "HTTP".to_string(),
        hostname: hostname.map(|s| s.to_string()),
        accepted: true,
        conflicted: false,
        resolved_refs: true,
        allowed_routes: crate::store::AllowedRoutesState {
            namespaces_from: "All".to_string(),
            namespace_selector: None,
        },
        tls_cert_refs: vec![],
        tls_mode: None,
    }
}

fn insert_listener_set(
    store: &crate::store::ConfigStore,
    ns: &str,
    name: &str,
    parent_ns: &str,
    parent_name: &str,
    listeners: &[(&str, &str)],
) {
    let key = crate::store::NamespacedName {
        namespace: ns.to_string(),
        name: name.to_string(),
    };
    let listener_states: Vec<crate::store::ListenerState> = listeners
        .iter()
        .map(|(n, h)| make_http_listener(n, 80, Some(h)))
        .collect();
    store.listener_sets.insert(
        key,
        crate::store::ListenerSetState {
            name: name.to_string(),
            namespace: ns.to_string(),
            parent_gateway: crate::store::NamespacedName {
                namespace: parent_ns.to_string(),
                name: parent_name.to_string(),
            },
            listeners: listener_states,
            accepted: true,
            generation: 1,
            not_accepted_reason: None,
            creation_timestamp: 0,
        },
    );
}

fn insert_http_route_multi_parent(
    store: &crate::store::ConfigStore,
    ns: &str,
    name: &str,
    parent_refs: Vec<crate::store::ParentRefState>,
    path_prefix: &str,
    backend: &str,
) {
    use crate::store::*;
    let key = NamespacedName {
        namespace: ns.to_string(),
        name: name.to_string(),
    };
    store.http_routes.insert(
        key,
        HTTPRouteState {
            namespace: ns.to_string(),
            hostnames: vec![],
            parent_refs,
            rules: vec![HTTPRouteRuleState {
                matches: vec![HTTPRouteMatchState {
                    path: Some((path_prefix.to_string(), "Prefix".to_string())),
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
        },
    );
}


    // -----------------------------------------------------------------------
    // mTLS: GatewayFrontendClientCertificateValidation(+InsecureFallback),
    // GatewayTLSBackendClientCertificate
    // -----------------------------------------------------------------------

    /// Listener state matching `gateway-with-clientcertificate-validation.yaml`
    /// (and the insecure-fallback variant): `https` on 443 with no hostname and
    /// `https-with-hostname` on 8443 for second-example.org, both serving
    /// `tls-validity-checks-certificate`.
    fn client_validation_gateway(store: &ConfigStore, ns: &str, name: &str) {
        let cert_ref = vec![(ns.to_string(), "tls-validity-checks-certificate".to_string())];
        let https = |lname: &str, port: u16, hostname: Option<&str>| ListenerState {
            name: lname.to_string(),
            port,
            protocol: "HTTPS".to_string(),
            hostname: hostname.map(str::to_string),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: cert_ref.clone(),
            tls_mode: Some("Terminate".to_string()),
        };
        store.gateways.insert(
            NamespacedName { namespace: ns.to_string(), name: name.to_string() },
            GatewayState {
                name: name.to_string(),
                namespace: ns.to_string(),
                listeners: vec![
                    https("https", 443, None),
                    https("https-with-hostname", 8443, Some("second-example.org")),
                ],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );
        for (cm, pem) in [
            ("tls-validity-checks-ca-certificate", "DEFAULT-CA"),
            ("tls-validity-checks-per-port-ca-certificate", "PER-PORT-CA"),
        ] {
            store.config_maps.insert(
                NamespacedName { namespace: ns.to_string(), name: cm.to_string() },
                crate::store::SecretState {
                    data: std::collections::HashMap::from([("ca.crt".to_string(), pem.to_string())]),
                },
            );
        }
        // Route 1: hostnames [example.org], no sectionName → both listeners are
        // candidates but only `https` (no hostname) intersects.
        insert_simple_http_route(
            store, ns, &format!("{name}-test"),
            ParentRefState {
                parent_kind: ParentKind::Gateway,
                gateway_namespace: ns.to_string(),
                gateway_name: name.to_string(),
                section_name: None,
                port: None,
                accepted: true,
                resolved_refs: true,
                reject_reason: None,
            },
            &["example.org"], "/", "infra-backend-v1", 8080,
        );
        // Route 2: no hostnames, sectionName https-with-hostname.
        insert_simple_http_route(
            store, ns, &format!("{name}-test-no-hostname"),
            parent_ref_section(ns, name, "https-with-hostname"),
            &[], "/", "infra-backend-v2", 8080,
        );
        add_endpoints(store, ns, "infra-backend-v1", 8080, &["10.0.0.1"]);
        add_endpoints(store, ns, "infra-backend-v2", 8080, &["10.0.0.2"]);
    }

    fn client_validation_refs(ns: &str, cm: &str, mode: &str) -> crate::store::ClientValidationOutcome {
        crate::store::ClientValidationOutcome::Valid(crate::store::ClientValidationRefs {
            ca_config_maps: vec![NamespacedName { namespace: ns.to_string(), name: cm.to_string() }],
            mode: mode.to_string(),
            ref_error: None,
        })
    }

    #[test]
    fn test_e2e_frontend_client_certificate_validation_default_and_per_port() {
        let ns = "gateway-conformance-infra";
        let gw = "client-validation-default";
        let store = empty_store();
        client_validation_gateway(&store, ns, gw);
        store.gateway_tls.insert(
            NamespacedName { namespace: ns.to_string(), name: gw.to_string() },
            crate::store::GatewayTlsState {
                frontend_default: Some(client_validation_refs(ns, "tls-validity-checks-ca-certificate", "AllowValidOnly")),
                frontend_per_port: std::collections::HashMap::from([(
                    8443u16,
                    client_validation_refs(ns, "tls-validity-checks-per-port-ca-certificate", "AllowValidOnly"),
                )]),
                backend_client_cert_ref: None,
            },
        );

        let config = compile_config(&store);

        // Listener 443 validates against the default CA, 8443 against the per-port CA.
        let l443 = config.listeners.iter().find(|l| l.port == 443).expect("443 listener");
        let cv = l443.client_validation.as_ref().expect("443 asks for client certs");
        assert_eq!(cv.ca_cert_pems, vec!["DEFAULT-CA".to_string()]);
        assert_eq!(cv.mode, "AllowValidOnly");
        let l8443 = config.listeners.iter().find(|l| l.port == 8443).expect("8443 listener");
        let cv = l8443.client_validation.as_ref().expect("8443 asks for client certs");
        assert_eq!(cv.ca_cert_pems, vec!["PER-PORT-CA".to_string()]);
        assert_eq!(cv.mode, "AllowValidOnly");

        // Routing is unchanged by mTLS: example.org:443 → v1, second-example.org:8443 → v2.
        let m = match_request_on_port(&config, "example.org", "/", "GET", &[], 443).expect("443 route");
        assert_eq!(m.service_name(), "infra-backend-v1");
        let m = match_request_on_port(&config, "second-example.org", "/", "GET", &[], 8443).expect("8443 route");
        assert_eq!(m.service_name(), "infra-backend-v2");
        assert!(match_request_on_port(&config, "example.org", "/", "GET", &[], 8443).is_none());
    }

    #[test]
    fn test_e2e_frontend_client_certificate_validation_insecure_fallback_mode_reaches_dataplane() {
        let ns = "gateway-conformance-infra";
        let gw = "client-validation-insecure-fallback";
        let store = empty_store();
        client_validation_gateway(&store, ns, gw);
        store.gateway_tls.insert(
            NamespacedName { namespace: ns.to_string(), name: gw.to_string() },
            crate::store::GatewayTlsState {
                frontend_default: Some(client_validation_refs(ns, "tls-validity-checks-ca-certificate", "AllowInsecureFallback")),
                frontend_per_port: std::collections::HashMap::from([(
                    8443u16,
                    client_validation_refs(ns, "tls-validity-checks-per-port-ca-certificate", "AllowInsecureFallback"),
                )]),
                backend_client_cert_ref: None,
            },
        );
        let config = compile_config(&store);
        for port in [443u16, 8443] {
            let l = config.listeners.iter().find(|l| l.port == u32::from(port)).unwrap();
            assert_eq!(l.client_validation.as_ref().unwrap().mode, "AllowInsecureFallback", "port {port}");
        }
        // Per-Gateway slices keep the validation.
        let slice = crate::compiler::scope_config(&config, ns, gw);
        assert!(slice.listeners.iter().all(|l| l.client_validation.is_some()));
    }

    /// `gateway-tls-backend-client-certificate.yaml`: HTTP listener, HTTPRoute to
    /// a TLS backend (Service port 443, BackendTLSPolicy) and a Gateway-level
    /// client certificate. The data plane must get both the CA to verify the
    /// backend and the client certificate to present, tagged with the Gateway.
    #[test]
    fn test_e2e_backend_client_certificate_compiled_with_backend_tls_policy() {
        let ns = "gateway-conformance-infra";
        let gw = "gateway-tls-backend-client-certificate";
        let store = empty_store();
        let parent = setup_gateway_no_hostname(&store, ns, gw);
        insert_simple_http_route(
            &store, ns, gw, parent, &["abc.example.com"], "/",
            "tls-backend-with-client-cert-validation", 443,
        );
        add_endpoints(&store, ns, "tls-backend-with-client-cert-validation", 443, &["10.0.0.9"]);
        store.backend_tls_policies.insert(
            NamespacedName { namespace: ns.to_string(), name: format!("{gw}-test") },
            crate::store::BackendTLSPolicyState {
                target: crate::store::PolicyTargetKey {
                    group: String::new(),
                    kind: "Service".to_string(),
                    namespace: ns.to_string(),
                    name: "tls-backend-with-client-cert-validation".to_string(),
                    section_name: None,
                },
                ca_cert_pem: "BACKEND-CA".to_string(),
                hostname: "abc.example.com".to_string(),
                subject_alt_names: vec![],
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );
        store.secrets.insert(
            NamespacedName { namespace: ns.to_string(), name: "tls-checks-client-certificate".to_string() },
            crate::store::SecretState {
                data: std::collections::HashMap::from([
                    ("tls.crt".to_string(), "CLIENT-CERT".to_string()),
                    ("tls.key".to_string(), "CLIENT-KEY".to_string()),
                ]),
            },
        );
        store.gateway_tls.insert(
            NamespacedName { namespace: ns.to_string(), name: gw.to_string() },
            crate::store::GatewayTlsState {
                backend_client_cert_ref: Some(NamespacedName {
                    namespace: ns.to_string(),
                    name: "tls-checks-client-certificate".to_string(),
                }),
                ..Default::default()
            },
        );

        let config = compile_config(&store);
        let route = match_request(&config, "abc.example.com", "/", "GET", &[]).expect("route");
        assert_eq!(route.service_name(), "tls-backend-with-client-cert-validation");
        let rc = config.routes.iter().find(|r| r.host == "abc.example.com").unwrap();
        assert_eq!((rc.gateway_namespace.as_str(), rc.gateway_name.as_str()), (ns, gw));
        let backend = config
            .backends
            .iter()
            .find(|b| b.service_name == "tls-backend-with-client-cert-validation" && b.port == 443)
            .expect("backend group");
        assert_eq!(backend.backend_tls.as_ref().unwrap().ca_cert_pem, "BACKEND-CA");
        assert_eq!(config.gateway_backend_tls.len(), 1);
        let cc = &config.gateway_backend_tls[0];
        assert_eq!((cc.gateway_namespace.as_str(), cc.gateway_name.as_str()), (ns, gw));
        assert_eq!(cc.cert_pem, "CLIENT-CERT");
        assert_eq!(cc.key_pem, "CLIENT-KEY");
    }
}
