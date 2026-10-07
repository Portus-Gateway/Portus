//! JWTAuthPolicy reconciler.
//!
//! Validates the providers, fetches each issuer's JWKS into the store
//! (`ConfigStore::issuer_keys`; at most once a minute per issuer, and again
//! on the five-minute requeue so key rotation reaches the data planes),
//! resolves conflicts (oldest-timestamp-wins) and writes status. The data
//! planes never call an issuer: the compiled config carries the keys.
//!
//! A JWKS that cannot be fetched does not un-accept the policy: the route
//! stays protected and refuses every token until keys arrive (fail closed),
//! and `ResolvedRefs=False` says why.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use super::policy_common::{find_winner_key, is_header_name, is_http_url, resolve_conflicts, RESERVED_HEADERS};
use super::{ReconcileContext, ReconcileError};
use crate::policy_types::{JWTAuthPolicy, JWTAuthPolicySpec};
use crate::status;
use crate::store::{ConfigStore, IssuerKeysState, JwtAuthPolicyState, JwtProviderState, NamespacedName, PolicyTargetKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;

/// How often each policy re-runs to pick up rotated keys.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);
/// An issuer fetched more recently than this is not fetched again, however
/// many policies or reconciles name it.
const MIN_REFETCH: Duration = Duration::from_secs(60);

/// The providers as the store keeps them, or what is wrong with the spec.
pub fn validate(spec: &JWTAuthPolicySpec) -> Result<Vec<JwtProviderState>, String> {
    if spec.jwt.providers.is_empty() {
        return Err("jwt.providers must name at least one issuer".to_string());
    }
    spec.jwt
        .providers
        .iter()
        .map(|p| {
            let issuer = p.issuer.trim_end_matches('/');
            if !is_http_url(issuer) {
                return Err(format!("issuer {:?} is not an http(s) URL", p.issuer));
            }
            if let Some(uri) = &p.jwks_uri
                && !is_http_url(uri)
            {
                return Err(format!("jwksUri {uri:?} of issuer {issuer} is not an http(s) URL"));
            }
            let mut claim_to_headers: Vec<(String, String)> = Vec::new();
            for c in &p.claim_to_headers {
                let header = c.header.to_ascii_lowercase();
                if c.claim.is_empty() {
                    return Err(format!("issuer {issuer}: claimToHeaders entry for header {:?} names no claim", c.header));
                }
                if !is_header_name(&header) {
                    return Err(format!("issuer {issuer}: {:?} is not a valid header name", c.header));
                }
                if RESERVED_HEADERS.contains(&header.as_str()) {
                    return Err(format!("issuer {issuer}: claims cannot be written to the {header} header"));
                }
                if claim_to_headers.iter().any(|(_, h)| *h == header) {
                    return Err(format!("issuer {issuer}: header {header} is set from two claims"));
                }
                claim_to_headers.push((c.claim.clone(), header));
            }
            Ok(JwtProviderState {
                issuer: issuer.to_string(),
                audiences: p.audiences.clone(),
                jwks_uri: p.jwks_uri.clone(),
                claim_to_headers,
            })
        })
        .collect()
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(portus_types::jwks::client)
}

/// Fetch the keys of every provider's issuer that has not been fetched in
/// the last minute (or whose JWKS URI changed). A changed key set triggers a
/// compile; a failed fetch keeps the keys already held.
pub async fn refresh_issuer_keys(store: &ConfigStore, providers: &[JwtProviderState], client: &reqwest::Client) {
    for p in providers {
        let previous = store.issuer_keys.get(&p.issuer).map(|e| e.clone());
        if let Some(prev) = &previous
            && prev.jwks_uri == p.jwks_uri
            && prev.fetched_at.elapsed() < MIN_REFETCH
        {
            continue;
        }
        let same_source = previous.as_ref().filter(|prev| prev.jwks_uri == p.jwks_uri);
        let fetched = portus_types::jwks::fetch(client, &p.issuer, p.jwks_uri.as_deref()).await;
        let state = match fetched {
            Ok(json) => IssuerKeysState { jwks_uri: p.jwks_uri.clone(), jwks_json: Some(json), error: None, fetched_at: Instant::now() },
            Err(e) => {
                log::warn!("JWTAuthPolicy issuer {}: {e}", p.issuer);
                IssuerKeysState {
                    jwks_uri: p.jwks_uri.clone(),
                    jwks_json: same_source.and_then(|prev| prev.jwks_json.clone()),
                    error: Some(e),
                    fetched_at: Instant::now(),
                }
            }
        };
        let changed = previous.as_ref().map(|prev| &prev.jwks_json) != Some(&state.jwks_json);
        store.issuer_keys.insert(p.issuer.clone(), state);
        if changed {
            store.notify_change();
        }
    }
}

fn programmed_condition(store: &ConfigStore, generation: i64) -> Condition {
    let programmed = store.is_programmed();
    status::build_condition(
        "Programmed",
        programmed,
        if programmed { "Programmed" } else { "NotProgrammed" },
        if programmed { "Configuration programmed in data plane" } else { "Waiting for data plane to apply configuration" },
        generation,
    )
}

/// `ResolvedRefs`: whether every issuer has keys.
fn keys_condition(store: &ConfigStore, providers: &[JwtProviderState], generation: i64) -> Condition {
    let mut missing = Vec::new();
    let mut stale = Vec::new();
    for p in providers {
        match store.issuer_keys.get(&p.issuer) {
            Some(k) if k.jwks_json.is_some() => {
                if let Some(e) = &k.error {
                    stale.push(format!("{}: {e}", p.issuer));
                }
            }
            Some(k) => missing.push(format!("{}: {}", p.issuer, k.error.as_deref().unwrap_or("not fetched yet"))),
            None => missing.push(format!("{}: not fetched yet", p.issuer)),
        }
    }
    if !missing.is_empty() {
        let message = format!("No keys, tokens from these issuers are refused: {}", missing.join("; "));
        return status::build_condition("ResolvedRefs", false, "JWKSUnavailable", &message, generation);
    }
    let message = if stale.is_empty() {
        "Keys fetched for every issuer".to_string()
    } else {
        format!("Using previously fetched keys, the last refresh failed: {}", stale.join("; "))
    };
    status::build_condition("ResolvedRefs", true, "ResolvedRefs", &message, generation)
}

/// Core reconciliation logic (store manipulation only; keys are fetched
/// beforehand by [`refresh_issuer_keys`]).
pub fn reconcile_inner(policy: &JWTAuthPolicy, store: &ConfigStore) -> Result<Vec<Condition>, ReconcileError> {
    let name = policy.metadata.name.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace =
        policy.metadata.namespace.as_deref().ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let generation = policy.metadata.generation.unwrap_or(0);
    let target_ref = &policy.spec.target_ref;
    let target = PolicyTargetKey {
        group: target_ref.group.clone(),
        kind: target_ref.kind.clone(),
        namespace: namespace.to_string(),
        name: target_ref.name.clone(),
        section_name: target_ref.section_name.clone(),
    };
    let my_key = NamespacedName { namespace: namespace.to_string(), name: name.to_string() };

    let providers = match validate(&policy.spec) {
        Ok(p) => p,
        Err(message) => {
            store.jwt_auth_policies.insert(
                my_key,
                JwtAuthPolicyState {
                    target,
                    providers: Vec::new(),
                    generation,
                    creation_timestamp: policy.metadata.creation_timestamp.clone(),
                    accepted: false,
                },
            );
            store.notify_change();
            return Ok(vec![
                status::build_condition("Accepted", false, "Invalid", &message, generation),
                programmed_condition(store, generation),
            ]);
        }
    };

    store.jwt_auth_policies.insert(
        my_key.clone(),
        JwtAuthPolicyState {
            target: target.clone(),
            providers: providers.clone(),
            generation,
            creation_timestamp: policy.metadata.creation_timestamp.clone(),
            accepted: true,
        },
    );
    resolve_conflicts(&my_key, &target, &store.jwt_auth_policies);
    let accepted = store.jwt_auth_policies.get(&my_key).is_some_and(|s| s.accepted);
    let accepted_condition = if accepted {
        status::build_condition("Accepted", true, "Accepted", "Policy accepted", generation)
    } else {
        let winner = find_winner_key(&target, &my_key, &store.jwt_auth_policies)
            .map(|k| format!("Older JWTAuthPolicy {k} takes precedence"))
            .unwrap_or_else(|| "Conflicted with another policy".to_string());
        status::build_condition("Accepted", false, "Conflicted", &winner, generation)
    };
    store.notify_change();
    Ok(vec![accepted_condition, keys_condition(store, &providers, generation), programmed_condition(store, generation)])
}

/// Main reconcile function for JWTAuthPolicy resources.
pub async fn reconcile_jwt_auth_policy(policy: Arc<JWTAuthPolicy>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    if let Ok(providers) = validate(&policy.spec) {
        refresh_issuer_keys(&ctx.store, &providers, http_client()).await;
    }
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.jwt_auth_policies,
        "JWTAuthPolicy",
        &policy.metadata,
        || reconcile_inner(&policy, &ctx.store),
    )?;

    let name = policy.metadata.name.as_deref().unwrap_or_default();
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();
    let current_conditions: Vec<Condition> = policy.status.as_ref().map(|s| s.conditions.clone()).unwrap_or_default();
    let desired_status = json!({
        "apiVersion": "portus-gateway.dev/v1beta1",
        "kind": "JWTAuthPolicy",
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
    let api: Api<JWTAuthPolicy> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(&api, name, desired_status, &current_conditions, &desired_conditions).await {
        log::warn!("failed to write JWTAuthPolicy status for {namespace}/{name}: {e}; retrying");
        return Err(e.into());
    }
    // Siblings and data plane acks re-run this policy through store events;
    // the requeue refreshes the keys.
    Ok(Action::requeue(REFRESH_INTERVAL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_types::{ClaimToHeader, JwtProviderSpec, JwtSpec, PolicyTargetRef};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"x","y":"y"}]}"#;

    fn provider(issuer: &str) -> JwtProviderSpec {
        JwtProviderSpec { issuer: issuer.to_string(), ..Default::default() }
    }

    fn make_policy(name: &str, providers: Vec<JwtProviderSpec>) -> JWTAuthPolicy {
        JWTAuthPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: JWTAuthPolicySpec {
                target_ref: PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: "api".to_string(),
                    section_name: None,
                },
                jwt: JwtSpec { providers },
            },
            status: None,
        }
    }

    fn condition<'a>(conditions: &'a [Condition], type_: &str) -> &'a Condition {
        conditions.iter().find(|c| c.type_ == type_).expect(type_)
    }

    type Routes = Arc<std::sync::Mutex<Vec<(&'static str, u16, String)>>>;

    /// A minimal issuer: answers `path → (status, body)` from `routes`
    /// (which a test may change) and counts requests.
    async fn issuer(routes: Vec<(&'static str, u16, String)>) -> (String, Routes, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let routes: Routes = Arc::new(std::sync::Mutex::new(routes));
        let (counter, table) = (Arc::clone(&hits), Arc::clone(&routes));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let table = Arc::clone(&table);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (status, body) = table
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|(p, _, _)| *p == path)
                        .map(|(_, s, b)| (*s, b.clone()))
                        .unwrap_or((404, String::new()));
                    let resp = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (base, routes, hits)
    }

    fn state(issuer: &str, jwks_uri: Option<String>) -> Vec<JwtProviderState> {
        vec![JwtProviderState { issuer: issuer.to_string(), audiences: vec![], jwks_uri, claim_to_headers: vec![] }]
    }

    /// Pretend the last fetch was a minute ago.
    fn age(store: &ConfigStore, issuer: &str) {
        store.issuer_keys.alter(issuer, |_, mut k| {
            k.fetched_at = Instant::now() - MIN_REFETCH;
            k
        });
    }

    #[test]
    fn invalid_specs_are_not_accepted_and_say_why() {
        let cases: Vec<(Vec<JwtProviderSpec>, &str)> = vec![
            (vec![], "at least one issuer"),
            (vec![provider("dex.example.com")], "not an http(s) URL"),
            (vec![JwtProviderSpec { jwks_uri: Some("file:///keys".into()), ..provider("https://dex.example.com") }], "jwksUri"),
            (vec![JwtProviderSpec { claim_to_headers: vec![ClaimToHeader { claim: "sub".into(), header: "x user".into() }], ..provider("https://dex.example.com") }], "not a valid header name"),
            (vec![JwtProviderSpec { claim_to_headers: vec![ClaimToHeader { claim: "sub".into(), header: "Authorization".into() }], ..provider("https://dex.example.com") }], "authorization"),
            (vec![JwtProviderSpec { claim_to_headers: vec![ClaimToHeader { claim: "".into(), header: "x-user".into() }], ..provider("https://dex.example.com") }], "names no claim"),
            (
                vec![JwtProviderSpec {
                    claim_to_headers: vec![ClaimToHeader { claim: "sub".into(), header: "x-user".into() }, ClaimToHeader { claim: "email".into(), header: "X-User".into() }],
                    ..provider("https://dex.example.com")
                }],
                "two claims",
            ),
        ];
        for (providers, why) in cases {
            let store = ConfigStore::new();
            let conditions = reconcile_inner(&make_policy("p", providers), &store).unwrap();
            let accepted = condition(&conditions, "Accepted");
            assert_eq!((accepted.status.as_str(), accepted.reason.as_str()), ("False", "Invalid"), "{why}");
            assert!(accepted.message.contains(why), "{} should mention {why}", accepted.message);
            assert!(!store.jwt_auth_policies.iter().next().unwrap().accepted);
        }
    }

    #[test]
    fn a_valid_policy_is_accepted_and_reports_missing_keys() {
        let store = ConfigStore::new();
        let spec = JwtProviderSpec {
            issuer: "https://dex.example.com/".into(),
            audiences: vec!["api".into()],
            claim_to_headers: vec![ClaimToHeader { claim: "sub".into(), header: "X-User".into() }],
            ..Default::default()
        };
        let conditions = reconcile_inner(&make_policy("p", vec![spec]), &store).unwrap();
        assert_eq!(condition(&conditions, "Accepted").status, "True");
        let keys = condition(&conditions, "ResolvedRefs");
        assert_eq!((keys.status.as_str(), keys.reason.as_str()), ("False", "JWKSUnavailable"));
        let state = store.jwt_auth_policies.iter().next().unwrap().clone();
        assert_eq!(state.providers[0].issuer, "https://dex.example.com", "trailing slash dropped");
        assert_eq!(state.providers[0].claim_to_headers, vec![("sub".to_string(), "x-user".to_string())]);

        store.issuer_keys.insert(
            "https://dex.example.com".into(),
            IssuerKeysState { jwks_uri: None, jwks_json: Some(JWKS.into()), error: Some("GET …: HTTP 503".into()), fetched_at: Instant::now() },
        );
        let conditions = reconcile_inner(&make_policy("p", vec![provider("https://dex.example.com")]), &store).unwrap();
        let keys = condition(&conditions, "ResolvedRefs");
        assert_eq!(keys.status, "True");
        assert!(keys.message.contains("previously fetched"), "{}", keys.message);
    }

    #[test]
    fn the_oldest_policy_on_a_target_wins() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        let store = ConfigStore::new();
        let mut older = make_policy("older", vec![provider("https://a.example.com")]);
        older.metadata.creation_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::from_second(1_000).unwrap()));
        let mut newer = make_policy("newer", vec![provider("https://b.example.com")]);
        newer.metadata.creation_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::from_second(2_000).unwrap()));
        reconcile_inner(&older, &store).unwrap();
        let conditions = reconcile_inner(&newer, &store).unwrap();
        let accepted = condition(&conditions, "Accepted");
        assert_eq!((accepted.status.as_str(), accepted.reason.as_str()), ("False", "Conflicted"));
        assert!(accepted.message.contains("default/older"), "{}", accepted.message);
    }

    #[tokio::test]
    async fn keys_are_fetched_once_a_minute_and_kept_when_the_issuer_fails() {
        let (base, routes, hits) = issuer(vec![("/keys", 200, JWKS.to_string())]).await;
        let store = ConfigStore::new();
        let client = portus_types::jwks::client();
        let providers = state(&base, None);

        refresh_issuer_keys(&store, &providers, &client).await;
        let keys = store.issuer_keys.get(&base).unwrap().clone();
        assert_eq!(keys.jwks_json.as_deref(), Some(JWKS), "no discovery document: <issuer>/keys");
        assert!(keys.error.is_none());
        let after_first = hits.load(std::sync::atomic::Ordering::SeqCst);

        refresh_issuer_keys(&store, &providers, &client).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), after_first, "fetched less than a minute ago");

        routes.lock().unwrap().clear();
        age(&store, &base);
        refresh_issuer_keys(&store, &providers, &client).await;
        let keys = store.issuer_keys.get(&base).unwrap().clone();
        assert_eq!(keys.jwks_json.as_deref(), Some(JWKS), "a failed refresh keeps the previous keys");
        assert!(keys.error.as_deref().is_some_and(|e| e.contains("404")), "{:?}", keys.error);

        // A new jwksUri that fails does not inherit keys from the old source.
        age(&store, &base);
        refresh_issuer_keys(&store, &state(&base, Some(format!("{base}/elsewhere"))), &client).await;
        assert!(store.issuer_keys.get(&base).unwrap().jwks_json.is_none());
    }

    #[tokio::test]
    async fn discovery_documents_name_the_jwks_uri() {
        let (keys_base, _, _) = issuer(vec![("/certs", 200, JWKS.to_string())]).await;
        let (base, _, _) = issuer(vec![("/.well-known/openid-configuration", 200, format!(r#"{{"jwks_uri":"{keys_base}/certs"}}"#))]).await;
        let store = ConfigStore::new();
        refresh_issuer_keys(&store, &state(&base, None), &portus_types::jwks::client()).await;
        assert_eq!(store.issuer_keys.get(&base).unwrap().jwks_json.as_deref(), Some(JWKS));
    }
}
