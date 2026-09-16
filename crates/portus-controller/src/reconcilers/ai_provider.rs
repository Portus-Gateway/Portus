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
use crate::ai_types::AIProvider;
use crate::status;
use crate::store::{AICredentialState, AIProviderState, ConfigStore, NamespacedName};
use portus_types::BackendEndpoint;

/// How often provider hostnames are re-resolved.
pub const RESOLVE_INTERVAL: Duration = Duration::from_secs(30);

const KINDS: &[&str] = &["anthropic", "openai", "openai-compatible"];

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
    let parsed = parse_provider_url(&spec.url);
    if let Err(e) = &parsed {
        problems.push(e.clone());
    }
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
    let api: Api<AIProvider> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(&api, name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write AIProvider status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    Ok(Action::await_change())
}

/// Resolve every provider host once and record the addresses that changed.
pub async fn resolve_all(store: &ConfigStore) {
    let providers: Vec<AIProviderState> = store.ai_providers.iter().map(|e| e.value().clone()).collect();
    for provider in providers {
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
            spec: AIProviderSpec { kind: kind.into(), url: url.into(), credential },
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
