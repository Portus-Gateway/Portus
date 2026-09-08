use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;

use portus_controller::compiler::compile_config;
use portus_controller::store::*;
use portus_types::*;

// ---------------------------------------------------------------------------
// Helpers (mirror conformance_tests.rs)
// ---------------------------------------------------------------------------

fn empty_store() -> ConfigStore {
    ConfigStore::new()
}

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

fn add_http_route(
    store: &ConfigStore,
    ns: &str,
    name: &str,
    hostnames: Vec<&str>,
    parent: &ParentRefState,
    rules: Vec<HTTPRouteRuleState>,
) {
    let key = NamespacedName {
        namespace: ns.to_string(),
        name: name.to_string(),
    };
    store.http_routes.insert(
        key,
        HTTPRouteState {
            namespace: ns.to_string(),
            hostnames: hostnames.into_iter().map(|s| s.to_string()).collect(),
            parent_refs: vec![parent.clone()],
            rules,
            generation: 1,
        },
    );
}

fn make_rule(path: &str, match_type: &str, svc: &str, port: u16) -> HTTPRouteRuleState {
    HTTPRouteRuleState {
        matches: vec![HTTPRouteMatchState {
            path: Some((path.to_string(), match_type.to_string())),
            headers: vec![],
            method: None,
            query_params: vec![],
        }],
        filters: vec![],
        backend_refs: vec![BackendRefState {
            namespace: "default".to_string(),
            name: svc.to_string(),
            port,
            weight: 1,
            filters: vec![],
        }],
        request_timeout_ms: None,
        backend_request_timeout_ms: None,
        retry: None,
    }
}

// ---------------------------------------------------------------------------
// Pre-built route map (mirrors dataplane build_route_map_from_proto)
// ---------------------------------------------------------------------------

/// Pre-sorted routes for a host, built once at config time.
struct BuiltHostRoutes<'a> {
    /// Exact paths → route indices for O(1) lookup.
    exact_map: HashMap<&'a str, Vec<&'a RouteConfig>>,
    /// Prefix rules sorted longest-first for linear scan.
    prefix_rules: Vec<&'a RouteConfig>,
    /// Catch-all routes (no paths).
    catch_all: Vec<&'a RouteConfig>,
}

/// Pre-built route map keyed by host.
struct BuiltRouteMap<'a> {
    by_host: HashMap<&'a str, BuiltHostRoutes<'a>>,
}

impl<'a> BuiltRouteMap<'a> {
    fn build(config: &'a CompiledConfig) -> Self {
        let mut by_host_raw: HashMap<&str, Vec<&RouteConfig>> = HashMap::new();
        for route in &config.routes {
            let key = if route.listener_port > 0 {
                // Skip port-specific for now in benchmarks
                route.host.as_str()
            } else {
                route.host.as_str()
            };
            by_host_raw.entry(key).or_default().push(route);
        }

        let mut by_host = HashMap::new();
        for (host, routes) in by_host_raw {
            let mut exact_map: HashMap<&str, Vec<&RouteConfig>> = HashMap::new();
            let mut prefix_rules: Vec<&RouteConfig> = Vec::new();
            let mut catch_all: Vec<&RouteConfig> = Vec::new();

            for route in routes {
                if route.paths.is_empty() {
                    catch_all.push(route);
                } else {
                    let first = &route.paths[0];
                    match first.match_type.as_str() {
                        "Exact" => exact_map.entry(first.path.as_str()).or_default().push(route),
                        _ => prefix_rules.push(route),
                    }
                }
            }

            // Sort prefix rules: longest path first, then by specificity
            prefix_rules.sort_by(|a, b| {
                let a_len = a.paths.first().map(|p| p.path.len()).unwrap_or(0);
                let b_len = b.paths.first().map(|p| p.path.len()).unwrap_or(0);
                b_len.cmp(&a_len)
                    .then_with(|| b.header_matches.len().cmp(&a.header_matches.len()))
            });

            by_host.insert(host, BuiltHostRoutes { exact_map, prefix_rules, catch_all });
        }

        BuiltRouteMap { by_host }
    }

    fn match_request(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &[(&str, &str)],
    ) -> Option<&'a RouteConfig> {
        let hr = self.by_host.get(host).or_else(|| self.by_host.get("*"))?;

        // O(1) exact path lookup
        if let Some(routes) = hr.exact_map.get(path) {
            for route in routes {
                if extra_matches(route, method, headers) {
                    return Some(route);
                }
            }
        }

        // Linear scan of prefix rules (sorted longest-first)
        for route in &hr.prefix_rules {
            if let Some(pr) = route.paths.first() {
                let prefix = pr.path.as_str();
                if path.starts_with(prefix) {
                    let plen = prefix.len();
                    let boundary_ok = path.len() == plen
                        || path.as_bytes().get(plen) == Some(&b'/')
                        || prefix.ends_with('/');
                    if boundary_ok && extra_matches(route, method, headers) {
                        return Some(route);
                    }
                }
            }
        }

        // Catch-all
        hr.catch_all.iter().find(|&route| extra_matches(route, method, headers)).map(|v| v as _)
    }
}

fn extra_matches(route: &RouteConfig, method: &str, headers: &[(&str, &str)]) -> bool {
    if !route.method_match.is_empty() && route.method_match != method {
        return false;
    }
    for hm in &route.header_matches {
        let matched = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(&hm.name)
                && match hm.match_type.as_str() {
                    "Exact" | "" => *value == hm.value,
                    _ => false,
                }
        });
        if !matched {
            return false;
        }
    }
    true
}

/// Legacy linear-scan matching (for comparison benchmarks).
fn match_request_linear<'a>(
    config: &'a CompiledConfig,
    host: &str,
    path: &str,
    method: &str,
    headers: &[(&str, &str)],
) -> Option<&'a RouteConfig> {
    let mut by_key: HashMap<String, Vec<&RouteConfig>> = HashMap::new();
    for route in &config.routes {
        by_key.entry(route.host.clone()).or_default().push(route);
    }

    let candidates = by_key.get(host).or_else(|| by_key.get("*"))?;

    let mut sorted: Vec<&RouteConfig> = candidates.clone();
    sorted.sort_by(|a, b| {
        let a_path = a.paths.first();
        let b_path = b.paths.first();
        let a_type = a_path.map(|p| p.match_type.as_str()).unwrap_or("");
        let b_type = b_path.map(|p| p.match_type.as_str()).unwrap_or("");
        let a_len = a_path.map(|p| p.path.len()).unwrap_or(0);
        let b_len = b_path.map(|p| p.path.len()).unwrap_or(0);
        let type_ord = match (a_type, b_type) {
            ("Exact", "Exact") => std::cmp::Ordering::Equal,
            ("Exact", _) => std::cmp::Ordering::Less,
            (_, "Exact") => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        };
        if type_ord != std::cmp::Ordering::Equal {
            return type_ord;
        }
        b_len.cmp(&a_len)
            .then_with(|| b.header_matches.len().cmp(&a.header_matches.len()))
    });

    sorted.iter().find(|&route| route_matches_inline(route, path, method, headers)).map(|v| v as _)
}

fn route_matches_inline(
    route: &RouteConfig,
    request_path: &str,
    method: &str,
    headers: &[(&str, &str)],
) -> bool {
    if !route.paths.is_empty() {
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
    if !route.method_match.is_empty() && route.method_match != method {
        return false;
    }
    for hm in &route.header_matches {
        let header_matched = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(&hm.name)
                && match hm.match_type.as_str() {
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

// ---------------------------------------------------------------------------
// Store population helpers for different scale levels
// ---------------------------------------------------------------------------

/// Create a store with N routes across M hosts.
fn populate_store(num_hosts: usize, routes_per_host: usize) -> (ConfigStore, Vec<String>) {
    let store = empty_store();
    let mut hosts = Vec::new();

    for h in 0..num_hosts {
        let hostname = format!("host-{}.example.com", h);
        let parent = setup_gateway_with_hostname(&store, "default", &format!("gw-{}", h), &hostname);

        for r in 0..routes_per_host {
            let path = format!("/api/v1/resource-{}/items", r);
            let svc = format!("svc-{}-{}", h, r);
            add_endpoints(&store, "default", &svc, 8080, &["10.0.0.1", "10.0.0.2"]);
            add_http_route(
                &store,
                "default",
                &format!("route-{}-{}", h, r),
                vec![&hostname],
                &parent,
                vec![make_rule(&path, "Prefix", &svc, 8080)],
            );
        }
        hosts.push(hostname);
    }
    (store, hosts)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_compile_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_config");

    for &(hosts, routes) in &[(1, 10), (10, 10), (10, 100), (50, 100)] {
        let (store, _) = populate_store(hosts, routes);
        let total = hosts * routes;
        group.bench_with_input(
            BenchmarkId::new("routes", total),
            &store,
            |b, store| {
                b.iter(|| {
                    black_box(compile_config(store));
                });
            },
        );
    }
    group.finish();
}

fn bench_match_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("match_request_optimized");

    for &(hosts, routes) in &[(1, 10), (10, 10), (10, 100), (50, 100)] {
        let (store, host_list) = populate_store(hosts, routes);
        let config = compile_config(&store);
        let route_map = BuiltRouteMap::build(&config);
        let total = hosts * routes;

        let host = &host_list[0];
        let mid = routes / 2;
        let path = format!("/api/v1/resource-{}/items/123", mid);

        group.bench_with_input(
            BenchmarkId::new("routes", total),
            &(&route_map, host.as_str(), path.as_str()),
            |b, &(rm, host, path)| {
                b.iter(|| {
                    black_box(rm.match_request(host, path, "GET", &[]));
                });
            },
        );
    }
    group.finish();
}

fn bench_match_request_linear(c: &mut Criterion) {
    let mut group = c.benchmark_group("match_request_linear");

    for &(hosts, routes) in &[(1, 10), (10, 10), (10, 100), (50, 100)] {
        let (store, host_list) = populate_store(hosts, routes);
        let config = compile_config(&store);
        let total = hosts * routes;

        let host = &host_list[0];
        let mid = routes / 2;
        let path = format!("/api/v1/resource-{}/items/123", mid);

        group.bench_with_input(
            BenchmarkId::new("routes", total),
            &(&config, host.as_str(), path.as_str()),
            |b, &(config, host, path)| {
                b.iter(|| {
                    black_box(match_request_linear(config, host, path, "GET", &[]));
                });
            },
        );
    }
    group.finish();
}

fn bench_build_route_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_route_map");

    for &(hosts, routes) in &[(1, 10), (10, 10), (10, 100), (50, 100)] {
        let (store, _) = populate_store(hosts, routes);
        let config = compile_config(&store);
        let total = hosts * routes;

        group.bench_with_input(
            BenchmarkId::new("routes", total),
            &config,
            |b, config| {
                b.iter(|| {
                    black_box(BuiltRouteMap::build(config));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compile_config,
    bench_match_request,
    bench_match_request_linear,
    bench_build_route_map,
);
criterion_main!(benches);
