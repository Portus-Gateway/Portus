//! AIProvider reconciler: validate the provider URL, keep its state, and
//! keep its endpoints resolved so the compiler can emit it as a backend.
//!
//! Providers live outside the cluster, so there is no EndpointSlice. A
//! resolver task re-resolves every provider host on an interval and writes
//! the addresses under the provider's synthetic Service key in
//! `store.endpoints`, the same map the EndpointSlice reconciler fills.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;

use super::{ReconcileContext, ReconcileError};
use crate::ai_types::{AIProvider, AIProviderSpec};
use crate::status;
use crate::store::{AICredentialState, AIFederationMember, AIProviderState, ConfigStore, NamespacedName, ServiceKey};
use portus_types::BackendEndpoint;

/// How often provider hostnames are re-resolved.
pub const RESOLVE_INTERVAL: Duration = Duration::from_secs(30);

const KINDS: &[&str] = &["anthropic", "openai", "openai-compatible", "mcp", "mcp-federation"];
const FEDERATION: &str = "mcp-federation";

/// `spec.members` of a federation, validated: at least one, unique prefixes
/// of `[A-Za-z0-9_-]`, paths starting with `/` (default `/mcp`), and every
/// member provider an accepted `mcp` provider in the same namespace.
fn federation_members(spec: &AIProviderSpec, namespace: &str, store: &ConfigStore) -> Result<Vec<AIFederationMember>, String> {
    if spec.members.is_empty() {
        return Err("mcp-federation needs at least one member".to_string());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(spec.members.len());
    for m in &spec.members {
        let name = m.name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("member name {:?} must be letters, digits, - or _", m.name));
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("member name {name:?} is used twice"));
        }
        let provider = m.provider.as_deref().map(str::trim).filter(|p| !p.is_empty()).unwrap_or(name).to_string();
        match store.ai_providers.get(&NamespacedName { namespace: namespace.to_string(), name: provider.clone() }) {
            Some(p) if p.kind == "mcp" => {}
            Some(p) => return Err(format!("member {name}: AIProvider {provider} is kind {}, not mcp", p.kind)),
            None => return Err(format!("member {name}: AIProvider {namespace}/{provider} not found or not accepted")),
        }
        let path = m.path.as_deref().map(str::trim).filter(|p| !p.is_empty()).unwrap_or("/mcp");
        if !path.starts_with('/') {
            return Err(format!("member {name}: path {path:?} must start with /"));
        }
        out.push(AIFederationMember { name: name.to_string(), provider, path: path.to_string() });
    }
    Ok(out)
}

/// Parse `spec.url` into (tls, host, port). Only scheme and authority are
/// allowed: a path prefix would have to be prepended to every request.
pub fn parse_provider_url(url: &str) -> Result<(bool, String, u16), String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("url must start with https:// or http://".to_string());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err("url must be scheme://host[:port] with no path".to_string());
    }
    let default_port = if tls { 443 } else { 80 };
    let parse_port = |p: &str| p.parse::<u16>().map_err(|_| format!("invalid port {p:?}"));
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally with a port.
        let (h, tail) = r.split_once(']').ok_or_else(|| "unclosed [ in host".to_string())?;
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if tail.is_empty() => default_port,
            None => return Err("unexpected text after ]".to_string()),
        };
        (h.to_string(), port)
    } else {
        match rest.split_once(':') {
            Some((h, p)) => {
                if p.contains(':') {
                    return Err("host has more than one ':' (bracket IPv6 literals)".to_string());
                }
                (h.to_string(), parse_port(p)?)
            }
            None => (rest.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err("url has no host".to_string());
    }
    Ok((tls, host, port))
}

/// `spec.sessionAffinity`: `header` pins `Mcp-Session-Id` sessions to an
/// endpoint, `none` load-balances every request. Defaults to `header` for
/// MCP providers and `none` for LLM ones (those are stateless).
fn session_affinity(spec: &AIProviderSpec) -> bool {
    match spec.session_affinity.as_deref() {
        Some("header") => true,
        Some(_) => false,
        None => spec.kind == "mcp",
    }
}

/// Header and prefix a provider kind authenticates with unless overridden.
fn default_credential_header(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "anthropic" => ("x-api-key", ""),
        _ => ("authorization", "Bearer "),
    }
}

pub fn reconcile_inner(provider: &AIProvider, store: &ConfigStore) -> Result<Vec<Condition>, ReconcileError> {
    let name = provider.metadata.name.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.name".into()))?;
    let namespace = provider
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".into()))?;
    let generation = provider.metadata.generation.unwrap_or(0);
    let key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };

    let spec = &provider.spec;
    let mut problems = Vec::new();
    if !KINDS.contains(&spec.kind.as_str()) {
        problems.push(format!("kind must be one of {}", KINDS.join(", ")));
    }
    if let Some(a) = spec.session_affinity.as_deref()
        && !matches!(a, "header" | "none")
    {
        problems.push(format!("sessionAffinity must be header or none, not {a:?}"));
    }
    let is_federation = spec.kind == FEDERATION;
    // A federation has no address of its own; its members do.
    let parsed = if is_federation { Ok((false, String::new(), 0)) } else { parse_provider_url(&spec.url) };
    if let Err(e) = &parsed {
        problems.push(e.clone());
    }
    let members = if is_federation {
        match federation_members(spec, namespace, store) {
            Ok(m) => m,
            Err(e) => {
                problems.push(e);
                Vec::new()
            }
        }
    } else {
        if !spec.members.is_empty() {
            problems.push("members is only for kind mcp-federation".to_string());
        }
        Vec::new()
    };
    let credential = spec.credential.as_ref().map(|c| {
        let (header, prefix) = default_credential_header(&spec.kind);
        AICredentialState {
            secret_name: c.secret_ref.name.clone(),
            secret_key: c.secret_ref.key.clone().unwrap_or_else(|| "api-key".to_string()),
            header: c.header.clone().unwrap_or_else(|| header.to_string()).to_ascii_lowercase(),
            prefix: c.prefix.clone().unwrap_or_else(|| prefix.to_string()),
        }
    });
    if let Some(c) = &credential
        && !store.secrets.get(&NamespacedName { namespace: namespace.to_string(), name: c.secret_name.clone() })
            .is_some_and(|s| s.data.contains_key(&c.secret_key))
    {
        problems.push(format!("Secret {}/{} has no key {:?}", namespace, c.secret_name, c.secret_key));
    }

    let accepted = problems.is_empty();
    if let (true, Ok((tls, host, port))) = (accepted, parsed) {
        let state = AIProviderState {
            namespace: namespace.to_string(),
            name: name.to_string(),
            kind: spec.kind.clone(),
            tls,
            host,
            port,
            credential,
            session_affinity: session_affinity(spec),
            members,
            generation,
        };
        store.insert_and_notify(&store.ai_providers, key, state);
    } else if let Some((_, gone)) = store.remove_and_notify(&store.ai_providers, &key) {
        store.endpoints.remove(&gone.service_key());
    }

    let problem_text = problems.join("; ");
    let mut conditions = vec![status::build_condition(
        "Accepted",
        accepted,
        if accepted { "Accepted" } else { "Invalid" },
        if accepted { "Provider accepted" } else { &problem_text },
        generation,
    )];
    let programmed = accepted && store.is_programmed();
    conditions.push(status::build_condition(
        "Programmed",
        programmed,
        if programmed { "Programmed" } else { "NotProgrammed" },
        if programmed { "Configuration programmed in data plane" } else { "Waiting for data plane to apply configuration" },
        generation,
    ));
    Ok(conditions)
}

/// Drop a provider that left the cluster, with its endpoints.
pub fn forget(store: &ConfigStore, namespace: &str, name: &str) -> bool {
    let key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };
    match store.remove_and_notify(&store.ai_providers, &key) {
        Some((_, gone)) => {
            store.endpoints.remove(&gone.service_key());
            true
        }
        None => false,
    }
}

pub async fn reconcile_ai_provider(provider: Arc<AIProvider>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    let name = provider.metadata.name.as_deref().unwrap_or_default();
    let namespace = provider.metadata.namespace.as_deref().unwrap_or_default();
    if provider.metadata.deletion_timestamp.is_some() {
        forget(&ctx.store, namespace, name);
        return Ok(Action::await_change());
    }
    let desired_conditions = reconcile_inner(&provider, &ctx.store)?;
    // Endpoints for a new provider should not wait for the next tick.
    resolve_all(&ctx.store).await;

    let current_conditions: Vec<Condition> =
        provider.status.as_ref().map(|s| s.conditions.clone()).unwrap_or_default();
    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1alpha1",
        "kind": "AIProvider",
        "metadata": { "name": name, "namespace": namespace },
        "status": { "conditions": desired_conditions.iter().map(|c| json!({
            "type": c.type_,
            "status": c.status,
            "reason": c.reason,
            "message": c.message,
            "observedGeneration": c.observed_generation,
            "lastTransitionTime": c.last_transition_time.0.to_string(),
        })).collect::<Vec<_>>() }
    });
    let accepted = desired_conditions.iter().any(|c| c.type_ == "Accepted" && c.status == "True");
    let api: Api<AIProvider> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(&api, name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write AIProvider status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    // A provider rejected for a Secret that has not been seen yet (the
    // Secret cache may fill after the provider on a cold start) is looked
    // at again shortly; nothing else re-triggers it.
    Ok(if accepted { Action::await_change() } else { Action::requeue(std::time::Duration::from_secs(10)) })
}

/// A host that names a Kubernetes Service in this cluster: `name`,
/// `name.namespace`, `name.namespace.svc` or `name.namespace.svc.cluster.local`
/// (a bare name is a Service in the provider's own namespace). Returns
/// (namespace, name).
pub fn cluster_local_service(host: &str, own_namespace: &str) -> Option<(String, String)> {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    match labels.as_slice() {
        [name] if !name.is_empty() => Some((own_namespace.to_string(), name.to_string())),
        [name, ns, "svc"] | [name, ns, "svc", "cluster", "local"] => Some((ns.to_string(), name.to_string())),
        _ => None,
    }
}

/// For a provider whose host is a Service in this cluster, the Service's
/// ready pod endpoints (via the EndpointSlice watcher and the port map) become
/// the provider's endpoints, so the pool sees pods, not the ClusterIP: session
/// affinity, outlier ejection and health checks then work per pod. Returns
/// whether the provider is cluster-local (whatever happened to its endpoints).
pub fn sync_cluster_local(store: &ConfigStore, provider: &AIProviderState) -> bool {
    let Some((ns, name)) = cluster_local_service(&provider.host, &provider.namespace) else { return false };
    let service_port = ServiceKey { namespace: ns.clone(), name: name.clone(), port: provider.port };
    let target_port = store.service_port_map.get(&service_port).map(|p| *p).unwrap_or(provider.port);
    let endpoints = store
        .endpoints
        .get(&ServiceKey { namespace: ns.clone(), name: name.clone(), port: target_port })
        .map(|e| e.value().clone())
        .unwrap_or_default();
    if endpoints.is_empty() {
        // Keep the last good set: a Service between rollouts must not empty the pool.
        log::warn!("AIProvider {}/{}: Service {ns}/{name} port {} has no ready endpoints", provider.namespace, provider.name, provider.port);
        return true;
    }
    if store.insert_and_notify(&store.endpoints, provider.service_key(), endpoints) {
        log::info!("AIProvider {}/{}: endpoints follow Service {ns}/{name}", provider.namespace, provider.name);
    }
    true
}

/// An EndpointSlice or Service changed: providers fronting that Service
/// follow it at once instead of at the next resolve tick.
pub fn refresh_for_service(store: &ConfigStore, namespace: &str, service: &str) {
    let providers: Vec<AIProviderState> = store
        .ai_providers
        .iter()
        .filter(|e| cluster_local_service(&e.value().host, &e.value().namespace).is_some_and(|(ns, n)| ns == namespace && n == service))
        .map(|e| e.value().clone())
        .collect();
    for provider in providers {
        sync_cluster_local(store, &provider);
    }
}

/// Resolve every provider host once and record the addresses that changed.
pub async fn resolve_all(store: &ConfigStore) {
    let providers: Vec<AIProviderState> = store.ai_providers.iter().map(|e| e.value().clone()).collect();
    for provider in providers {
        // A federation has no address; its members resolve on their own.
        if provider.kind == FEDERATION || sync_cluster_local(store, &provider) {
            continue;
        }
        let key = provider.service_key();
        match tokio::net::lookup_host((provider.host.as_str(), provider.port)).await {
            Ok(addrs) => {
                let mut endpoints: Vec<BackendEndpoint> = addrs
                    .map(|a| BackendEndpoint { address: a.ip().to_string(), port: u32::from(provider.port) })
                    .collect();
                endpoints.sort_by(|a, b| a.address.cmp(&b.address));
                endpoints.dedup();
                if endpoints.is_empty() {
                    log::warn!("AIProvider {}/{}: {} resolved to no addresses", provider.namespace, provider.name, provider.host);
                    continue;
                }
                if store.insert_and_notify(&store.endpoints, key, endpoints) {
                    log::info!("AIProvider {}/{}: {} resolved, endpoints updated", provider.namespace, provider.name, provider.host);
                }
            }
            Err(e) => {
                // Keep the last good addresses: a resolver blip must not empty
                // the pool.
                log::warn!("AIProvider {}/{}: resolving {} failed: {e}", provider.namespace, provider.name, provider.host);
            }
        }
    }
}

/// Re-resolve provider hosts forever.
pub async fn resolve_loop(store: Arc<ConfigStore>) {
    let mut tick = tokio::time::interval(RESOLVE_INTERVAL);
    loop {
        tick.tick().await;
        resolve_all(&store).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_types::{AICredentialSpec, AIProviderSpec, AISecretKeyRef};
    use crate::store::SecretState;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn provider(kind: &str, url: &str, credential: Option<AICredentialSpec>) -> AIProvider {
        AIProvider {
            metadata: ObjectMeta {
                name: Some("anthropic".into()),
                namespace: Some("llm".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: AIProviderSpec { kind: kind.into(), url: url.into(), credential, session_affinity: None, members: Vec::new() },
            status: None,
        }
    }

    fn secret(store: &ConfigStore, name: &str, key: &str, value: &str) {
        store.secrets.insert(
            NamespacedName { namespace: "llm".into(), name: name.into() },
            SecretState { data: [(key.to_string(), value.to_string())].into_iter().collect() },
        );
    }

    #[test]
    fn urls_parse_to_scheme_host_and_port_only() {
        assert_eq!(parse_provider_url("https://api.anthropic.com"), Ok((true, "api.anthropic.com".into(), 443)));
        assert_eq!(parse_provider_url("https://api.anthropic.com/"), Ok((true, "api.anthropic.com".into(), 443)));
        assert_eq!(parse_provider_url("http://vllm.llm.svc:8000"), Ok((false, "vllm.llm.svc".into(), 8000)));
        assert_eq!(parse_provider_url("http://[::1]:8000"), Ok((false, "::1".into(), 8000)));
        for bad in ["api.anthropic.com", "https://api.anthropic.com/v1", "https://", "https://a:b:c", "https://user@host"] {
            assert!(parse_provider_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_accepted_provider_lands_in_the_store_with_default_credential_header() {
        let store = ConfigStore::new();
        secret(&store, "anthropic-key", "api-key", "sk-ant");
        let p = provider(
            "anthropic",
            "https://api.anthropic.com",
            Some(AICredentialSpec { secret_ref: AISecretKeyRef { name: "anthropic-key".into(), key: None }, header: None, prefix: None }),
        );
        let conditions = reconcile_inner(&p, &store).unwrap();
        assert_eq!(conditions[0].status, "True", "{}", conditions[0].message);
        // Clone out of the map: holding a DashMap guard across the next
        // reconcile would deadlock on the shard.
        let state = store.ai_providers.get(&NamespacedName { namespace: "llm".into(), name: "anthropic".into() }).unwrap().clone();
        assert_eq!(state.service_name(), "aiprovider/llm/anthropic");
        assert_eq!((state.tls, state.host.as_str(), state.port), (true, "api.anthropic.com", 443));
        let cred = state.credential.clone().unwrap();
        assert_eq!((cred.header.as_str(), cred.prefix.as_str(), cred.secret_key.as_str()), ("x-api-key", "", "api-key"));

        let openai = provider(
            "openai",
            "https://api.openai.com",
            Some(AICredentialSpec { secret_ref: AISecretKeyRef { name: "anthropic-key".into(), key: None }, header: None, prefix: None }),
        );
        reconcile_inner(&openai, &store).unwrap();
        let cred = store.ai_providers.get(&NamespacedName { namespace: "llm".into(), name: "anthropic".into() }).unwrap().credential.clone().unwrap();
        assert_eq!((cred.header.as_str(), cred.prefix.as_str()), ("authorization", "Bearer "));

        // An MCP server is a provider too: bearer credential, plain HTTP allowed.
        let mcp = provider(
            "mcp",
            "http://github-mcp.tools:8080",
            Some(AICredentialSpec { secret_ref: AISecretKeyRef { name: "anthropic-key".into(), key: None }, header: None, prefix: None }),
        );
        let conditions = reconcile_inner(&mcp, &store).unwrap();
        assert_eq!(conditions[0].status, "True", "{}", conditions[0].message);
        let state = store.ai_providers.get(&NamespacedName { namespace: "llm".into(), name: "anthropic".into() }).unwrap().clone();
        assert_eq!((state.kind.as_str(), state.tls, state.host.as_str(), state.port), ("mcp", false, "github-mcp.tools", 8080));
        assert_eq!(state.credential.unwrap().header, "authorization");
        assert!(state.session_affinity, "MCP providers pin sessions by default");
        let llm = store.ai_providers.get(&NamespacedName { namespace: "llm".into(), name: "anthropic".into() });
        drop(llm);
        let mut off = provider("mcp", "http://github-mcp.tools:8080", None);
        off.spec.session_affinity = Some("none".into());
        reconcile_inner(&off, &store).unwrap();
        assert!(!store.ai_providers.get(&NamespacedName { namespace: "llm".into(), name: "anthropic".into() }).unwrap().session_affinity);
        let mut bad = provider("mcp", "http://github-mcp.tools:8080", None);
        bad.spec.session_affinity = Some("cookie".into());
        let conditions = reconcile_inner(&bad, &store).unwrap();
        assert_eq!(conditions[0].status, "False");
        assert!(conditions[0].message.contains("sessionAffinity"), "{}", conditions[0].message);
    }

    #[test]
    fn a_federation_needs_valid_unique_members_that_are_mcp_providers() {
        use crate::ai_types::AIFederationMemberSpec;
        let store = ConfigStore::new();
        reconcile_inner(&provider("mcp", "http://github-mcp.tools:8080", None), &store).unwrap(); // named "anthropic" by the helper
        let fed = |members: Vec<AIFederationMemberSpec>| {
            let mut p = provider("mcp-federation", "", None);
            p.metadata.name = Some("fed".into());
            p.spec.members = members;
            p
        };
        let m = |name: &str, provider: Option<&str>, path: Option<&str>| AIFederationMemberSpec { name: name.into(), provider: provider.map(str::to_string), path: path.map(str::to_string) };
        let key = NamespacedName { namespace: "llm".into(), name: "fed".into() };

        let ok = reconcile_inner(&fed(vec![m("gh", Some("anthropic"), None), m("wiki", Some("anthropic"), Some("/"))]), &store).unwrap();
        assert_eq!(ok[0].status, "True", "{}", ok[0].message);
        let state = store.ai_providers.get(&key).unwrap().clone();
        assert_eq!((state.kind.as_str(), state.host.as_str(), state.port), ("mcp-federation", "", 0));
        assert_eq!(state.members, vec![AIFederationMember { name: "gh".into(), provider: "anthropic".into(), path: "/mcp".into() }, AIFederationMember { name: "wiki".into(), provider: "anthropic".into(), path: "/".into() }]);

        for (members, expect) in [
            (vec![], "at least one member"),
            (vec![m("gh", Some("anthropic"), None), m("gh", Some("anthropic"), None)], "used twice"),
            (vec![m("bad name", Some("anthropic"), None)], "letters, digits"),
            (vec![m("gh", Some("nope"), None)], "not found"),
            (vec![m("gh", Some("anthropic"), Some("mcp"))], "must start with /"),
        ] {
            let conditions = reconcile_inner(&fed(members), &store).unwrap();
            assert_eq!(conditions[0].status, "False", "{expect}");
            assert!(conditions[0].message.contains(expect), "{} should mention {expect}", conditions[0].message);
        }
        assert!(store.ai_providers.get(&key).is_none(), "a rejected federation leaves the store");
        // A member that is an LLM provider is refused; members on a non-federation are refused.
        let mut llm = provider("anthropic", "https://api.anthropic.com", None);
        llm.metadata.name = Some("claude".into());
        reconcile_inner(&llm, &store).unwrap();
        let c = reconcile_inner(&fed(vec![m("c", Some("claude"), None)]), &store).unwrap();
        assert!(c[0].message.contains("not mcp"), "{}", c[0].message);
        let mut plain = provider("mcp", "http://x:1", None);
        plain.spec.members = vec![m("a", None, None)];
        let c = reconcile_inner(&plain, &store).unwrap();
        assert!(c[0].message.contains("only for kind mcp-federation"), "{}", c[0].message);
    }

    #[test]
    fn cluster_local_hosts_are_recognised_in_their_four_forms_only() {
        assert_eq!(cluster_local_service("everything.bench.svc.cluster.local", "x"), Some(("bench".into(), "everything".into())));
        assert_eq!(cluster_local_service("everything.bench.svc", "x"), Some(("bench".into(), "everything".into())));
        assert_eq!(cluster_local_service("everything.bench.svc.cluster.local.", "x"), Some(("bench".into(), "everything".into())));
        assert_eq!(cluster_local_service("everything", "bench"), Some(("bench".into(), "everything".into())));
        assert_eq!(cluster_local_service("api.anthropic.com", "x"), None);
        assert_eq!(cluster_local_service("mcp.internal", "x"), None, "two labels could be a real domain");
        assert_eq!(cluster_local_service("a.b.c.d", "x"), None);
    }

    #[test]
    fn a_provider_fronting_a_service_takes_the_services_pod_endpoints() {
        let store = ConfigStore::new();
        // Service everything: port 3001 -> targetPort 8080, two ready pods.
        store.service_port_map.insert(ServiceKey { namespace: "bench".into(), name: "everything".into(), port: 3001 }, 8080);
        store.endpoints.insert(
            ServiceKey { namespace: "bench".into(), name: "everything".into(), port: 8080 },
            vec![BackendEndpoint { address: "10.42.0.5".into(), port: 8080 }, BackendEndpoint { address: "10.42.0.9".into(), port: 8080 }],
        );
        let mut p = provider("mcp", "http://everything.bench.svc.cluster.local:3001", None);
        p.metadata.namespace = Some("bench".into());
        reconcile_inner(&p, &store).unwrap();
        let state = store.ai_providers.get(&NamespacedName { namespace: "bench".into(), name: "anthropic".into() }).unwrap().clone();
        assert!(sync_cluster_local(&store, &state));
        let eps = store.endpoints.get(&state.service_key()).unwrap().clone();
        assert_eq!(eps.iter().map(|e| (e.address.as_str(), e.port)).collect::<Vec<_>>(), vec![("10.42.0.5", 8080), ("10.42.0.9", 8080)]);

        // A pod goes away: the EndpointSlice path refreshes the provider at once.
        store.endpoints.insert(ServiceKey { namespace: "bench".into(), name: "everything".into(), port: 8080 }, vec![BackendEndpoint { address: "10.42.0.9".into(), port: 8080 }]);
        refresh_for_service(&store, "bench", "everything");
        assert_eq!(store.endpoints.get(&state.service_key()).unwrap().len(), 1);
        // No ready pods: the last good set stays.
        store.endpoints.remove(&ServiceKey { namespace: "bench".into(), name: "everything".into(), port: 8080 });
        refresh_for_service(&store, "bench", "everything");
        assert_eq!(store.endpoints.get(&state.service_key()).unwrap().len(), 1);
        // An internet host is not cluster-local.
        let ext = store.ai_providers.get(&NamespacedName { namespace: "bench".into(), name: "anthropic".into() }).unwrap().clone();
        let ext = AIProviderState { host: "api.anthropic.com".into(), ..ext };
        assert!(!sync_cluster_local(&store, &ext));
    }

    #[test]
    fn invalid_providers_are_rejected_and_removed_from_the_store() {
        let store = ConfigStore::new();
        secret(&store, "k", "api-key", "x");
        let good = provider("anthropic", "https://api.anthropic.com", None);
        reconcile_inner(&good, &store).unwrap();
        assert_eq!(store.ai_providers.len(), 1);

        for (kind, url, cred) in [
            ("cohere", "https://api.anthropic.com", None),
            ("anthropic", "api.anthropic.com", None),
            ("anthropic", "https://api.anthropic.com", Some(AICredentialSpec { secret_ref: AISecretKeyRef { name: "missing".into(), key: None }, header: None, prefix: None })),
            ("anthropic", "https://api.anthropic.com", Some(AICredentialSpec { secret_ref: AISecretKeyRef { name: "k".into(), key: Some("other".into()) }, header: None, prefix: None })),
        ] {
            let conditions = reconcile_inner(&provider(kind, url, cred), &store).unwrap();
            assert_eq!(conditions[0].status, "False", "{kind} {url}");
            assert_eq!(conditions[0].reason, "Invalid");
            assert!(store.ai_providers.is_empty(), "{kind} {url}: an invalid provider must not stay routable");
        }
    }
}
