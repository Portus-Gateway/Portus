//! One way to run a controller.
//!
//! Every kind the controller watches goes through [`spawn`]: it wires the
//! kube-runtime `Controller`, applies the single error policy (a 404 evicts
//! the object from the [`ConfigStore`], anything else requeues), evicts on
//! `ObjectNotFound` from the runtime, records per-kind reconcile statistics,
//! and hands back the reflector store the prune task reads. Kind-specific
//! behaviour is limited to the reconcile function, the watches a caller adds
//! to the `Controller` before passing it in, and the [`Gone`] eviction hook.

use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::StreamExt;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Resource, ResourceExt};
use serde::de::DeserializeOwned;

use crate::reconcilers::{ReconcileContext, ReconcileError};
use crate::store::{ConfigStore, NamespacedName};

/// Requeue after a failed reconcile. One value for every kind: the API server
/// or a dependency was unavailable, and thirty seconds is long enough not to
/// hammer it and short enough that conformance-style waits still pass.
pub const ERROR_REQUEUE: Duration = Duration::from_secs(30);

/// A reconcile that takes longer than this is logged at warn level; the usual
/// cause is an API write stuck until `status::API_WRITE_TIMEOUT`.
const SLOW_RECONCILE: Duration = Duration::from_secs(5);

/// Evict an object that Kubernetes no longer has from the store. Called with
/// the object's namespace (None for cluster-scoped kinds) and name; returns
/// true when something was removed.
pub type Gone = Arc<dyn Fn(&ConfigStore, Option<&str>, &str) -> bool + Send + Sync>;

/// [`Gone`] for kinds stored in a `DashMap<NamespacedName, _>`: remove the key
/// and wake the compiler.
pub fn gone_map<V>(map: fn(&ConfigStore) -> &DashMap<NamespacedName, V>) -> Gone
where
    V: Send + Sync + 'static,
{
    Arc::new(move |store, ns, name| {
        let key = NamespacedName {
            namespace: ns.unwrap_or_default().to_string(),
            name: name.to_string(),
        };
        store.remove_and_notify(map(store), &key).is_some()
    })
}

/// A `watches` mapper that caches the watched object in the [`ConfigStore`]
/// before naming the objects that depend on it.
///
/// Dependents (a BackendTLSPolicy reading a CA ConfigMap, a Gateway reading a
/// client-cert Secret) resolve their references from the store, and the
/// controller that owns the cache runs on its own schedule. Without this the
/// dependent reconcile can run first and see the previous contents; the
/// conformance suite's "change the CA ConfigMap" step catches exactly that.
/// `cache` is the owning reconciler's pure store update, so both writers agree.
pub fn cache_then<O, K, D>(
    store: Arc<ConfigStore>,
    cache: fn(&O, &ConfigStore) -> Result<(), ReconcileError>,
    dependents: D,
) -> impl Fn(O) -> Vec<ObjectRef<K>> + Send + Sync + 'static
where
    O: Send + Sync + 'static,
    K: Resource<DynamicType = ()>,
    D: Fn(&O) -> Vec<ObjectRef<K>> + Send + Sync + 'static,
{
    move |obj: O| {
        // The only failure is missing metadata, and such an object has no
        // dependents to name either.
        let _ = cache(&obj, &store);
        dependents(&obj)
    }
}

/// Per-kind reconcile statistics, exposed as Prometheus text on the
/// controller's health port (`/metrics`).
#[derive(Default)]
pub struct KindStats {
    pub reconciles: AtomicU64,
    pub errors: AtomicU64,
    pub duration_micros: AtomicU64,
    pub max_micros: AtomicU64,
}

#[derive(Default)]
pub struct ReconcileStats {
    kinds: DashMap<&'static str, KindStats>,
}

pub static STATS: LazyLock<ReconcileStats> = LazyLock::new(ReconcileStats::default);

impl ReconcileStats {
    pub fn record(&self, kind: &'static str, took: Duration, failed: bool) {
        let entry = self.kinds.entry(kind).or_default();
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        entry.reconciles.fetch_add(1, Ordering::Relaxed);
        if failed {
            entry.errors.fetch_add(1, Ordering::Relaxed);
        }
        entry.duration_micros.fetch_add(micros, Ordering::Relaxed);
        entry.max_micros.fetch_max(micros, Ordering::Relaxed);
    }

    /// Prometheus text exposition of every kind seen so far.
    pub fn render(&self) -> String {
        let mut kinds: Vec<_> = self
            .kinds
            .iter()
            .map(|e| {
                (
                    *e.key(),
                    e.reconciles.load(Ordering::Relaxed),
                    e.errors.load(Ordering::Relaxed),
                    e.duration_micros.load(Ordering::Relaxed),
                    e.max_micros.load(Ordering::Relaxed),
                )
            })
            .collect();
        kinds.sort_by_key(|k| k.0);
        let mut out = String::new();
        out.push_str("# TYPE portus_controller_reconciles_total counter\n");
        for (k, n, ..) in &kinds {
            out.push_str(&format!("portus_controller_reconciles_total{{kind=\"{k}\"}} {n}\n"));
        }
        out.push_str("# TYPE portus_controller_reconcile_errors_total counter\n");
        for (k, _, e, ..) in &kinds {
            out.push_str(&format!("portus_controller_reconcile_errors_total{{kind=\"{k}\"}} {e}\n"));
        }
        out.push_str("# TYPE portus_controller_reconcile_duration_seconds_sum counter\n");
        for (k, _, _, d, _) in &kinds {
            out.push_str(&format!(
                "portus_controller_reconcile_duration_seconds_sum{{kind=\"{k}\"}} {:.6}\n",
                *d as f64 / 1e6
            ));
        }
        out.push_str("# TYPE portus_controller_reconcile_duration_seconds_max gauge\n");
        for (k, _, _, _, m) in &kinds {
            out.push_str(&format!(
                "portus_controller_reconcile_duration_seconds_max{{kind=\"{k}\"}} {:.6}\n",
                *m as f64 / 1e6
            ));
        }
        out
    }
}

/// True for the API server telling us the object is gone.
pub fn is_not_found(err: &ReconcileError) -> bool {
    matches!(err, ReconcileError::Kube(kube::Error::Api(resp)) if resp.code == 404)
}

/// The controller for a kind, fed by a watch that includes deletions.
///
/// `Controller::new` reconciles on applied objects only: a deleted object
/// produces no reconcile request, so the runtime never reports it as
/// `ObjectNotFound` and the [`Gone`] hook never runs. The timed requeues used
/// to paper over this (the next tick found the object gone); without them the
/// compiled config kept every route ever created (seen 2026-09-07: 180 routes
/// compiled for a suite that has ~30 live at any time). `touched_objects`
/// includes deletes, so a deletion is evicted as soon as the watch reports it.
pub fn controller<K>(client: &kube::Client) -> Controller<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Send + Sync + DeserializeOwned + 'static,
{
    let (reader, writer) = reflector::store::<K>();
    let stream = reflector::reflector(writer, watcher(Api::<K>::all(client.clone()), watcher::Config::default()))
        .default_backoff()
        .touched_objects();
    Controller::for_stream(stream, reader)
}

/// The controller for a Gateway API kind: [`controller`] plus a filter that
/// drops watch events carrying no change to what a reconcile reads.
///
/// Every status write the controller makes comes straight back on the kind's
/// own watch as an `Apply`, so without the filter each route event cost a
/// second Gateway reconcile that found nothing to do (the attached-routes bench
/// reconciled Gateways about twice per route). The filter keys on
/// `metadata.generation` (the API server bumps it on spec changes only, for
/// kinds with a status subresource), labels, annotations and whether a
/// deletion timestamp is set; a status-only or `managedFields`-only update
/// hashes the same and is skipped. The reflector still sees every event, so
/// the store the reconcilers read stays current. Only for kinds whose
/// `generation` is maintained: core kinds without a status subresource
/// (Service, EndpointSlice, Secret, ConfigMap, Namespace) never bump it, and
/// the filter would swallow their data changes; they keep [`controller`].
pub fn spec_controller<K>(client: &kube::Client) -> Controller<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Send + Sync + DeserializeOwned + 'static,
{
    let (reader, writer) = reflector::store::<K>();
    let stream = spec_changes(
        reflector::reflector(writer, watcher(Api::<K>::all(client.clone()), watcher::Config::default()))
            .default_backoff(),
    )
    .touched_objects();
    Controller::for_stream(stream, reader)
}

/// What a reconcile can observe change on an object short of its spec:
/// generation stands in for the spec itself.
fn spec_change_key<K: Resource>(obj: &K) -> u64 {
    use std::hash::{Hash, Hasher};
    let meta = obj.meta();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    meta.generation.hash(&mut h);
    meta.deletion_timestamp.is_some().hash(&mut h);
    if let Some(labels) = meta.labels.as_ref() {
        for (k, v) in labels.iter() {
            (k, v).hash(&mut h);
        }
    }
    if let Some(annotations) = meta.annotations.as_ref() {
        for (k, v) in annotations.iter() {
            (k, v).hash(&mut h);
        }
    }
    h.finish()
}

/// Drop `Apply`/`InitApply` events whose [`spec_change_key`] matches the last
/// one seen for the object; pass everything else (deletes, init markers,
/// errors) through. Deletes forget the object so a recreate is a change.
pub fn spec_changes<K, S>(stream: S) -> impl futures::Stream<Item = Result<watcher::Event<K>, watcher::Error>>
where
    K: Resource<DynamicType = ()> + 'static,
    S: futures::Stream<Item = Result<watcher::Event<K>, watcher::Error>>,
{
    let mut seen: std::collections::HashMap<ObjectRef<K>, u64> = std::collections::HashMap::new();
    stream.filter_map(move |item| {
        let keep = match &item {
            Ok(watcher::Event::Apply(obj)) | Ok(watcher::Event::InitApply(obj)) => {
                let key = spec_change_key(obj);
                seen.insert(ObjectRef::from_obj(obj), key) != Some(key)
            }
            Ok(watcher::Event::Delete(obj)) => {
                seen.remove(&ObjectRef::from_obj(obj));
                true
            }
            _ => true,
        };
        futures::future::ready(keep.then_some(item))
    })
}

/// Run `ctrl` for `kind` with the shared policies and return its reflector
/// store. `ctrl` arrives with its watches already attached; `gone` says how to
/// evict a deleted object from the [`ConfigStore`] (None: nothing cached by
/// key, or eviction handled elsewhere).
pub fn spawn<K, R, Fut>(
    kind: &'static str,
    ctrl: Controller<K>,
    reconcile: R,
    ctx: Arc<ReconcileContext>,
    gone: Option<Gone>,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Send + Sync + DeserializeOwned + 'static,
    R: Fn(Arc<K>, Arc<ReconcileContext>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Action, ReconcileError>> + Send + 'static,
{
    let reader = ctrl.store();

    let timed = move |obj: Arc<K>, ctx: Arc<ReconcileContext>| {
        let started = Instant::now();
        let label = format!("{}/{}", obj.namespace().unwrap_or_default(), obj.name_any());
        let fut = reconcile(obj, ctx);
        async move {
            let result = fut.await;
            let took = started.elapsed();
            STATS.record(kind, took, result.is_err());
            if took > SLOW_RECONCILE {
                log::warn!("{kind} {label}: reconcile took {took:?}");
            }
            result
        }
    };

    let gone_for_errors = gone.clone();
    let error_policy = move |obj: Arc<K>, err: &ReconcileError, ctx: Arc<ReconcileContext>| -> Action {
        if is_not_found(err) {
            if let Some(evict) = gone_for_errors.as_ref()
                && evict(&ctx.store, obj.namespace().as_deref(), &obj.name_any())
            {
                log::info!(
                    "{kind} {}/{}: removed from store (object deleted)",
                    obj.namespace().unwrap_or_default(),
                    obj.name_any()
                );
            }
            return Action::await_change();
        }
        log::warn!(
            "{kind} {}/{}: reconcile failed: {err}; requeue in {ERROR_REQUEUE:?}",
            obj.namespace().unwrap_or_default(),
            obj.name_any()
        );
        Action::requeue(ERROR_REQUEUE)
    };

    let store = Arc::clone(&ctx.store);
    tokio::spawn(ctrl.run(timed, error_policy, ctx).for_each(move |res| {
        let store = Arc::clone(&store);
        let gone = gone.clone();
        async move {
            match res {
                Ok(o) => log::debug!("reconciled {kind}: {:?}", o),
                Err(kube::runtime::controller::Error::ObjectNotFound(obj_ref)) => {
                    if let Some(evict) = gone.as_ref()
                        && evict(&store, obj_ref.namespace.as_deref(), &obj_ref.name)
                    {
                        log::info!(
                            "{kind} {}/{}: removed from store (object deleted)",
                            obj_ref.namespace.unwrap_or_default(),
                            obj_ref.name
                        );
                    }
                }
                Err(e) => log::warn!("{kind} controller error: {e:?}"),
            }
        }
    }));

    reader
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gone_map_removes_the_key_and_reports_it() {
        let store = ConfigStore::new();
        let key = NamespacedName { namespace: "ns".into(), name: "r".into() };
        store.http_routes.insert(
            key.clone(),
            crate::store::HTTPRouteState {
                namespace: "ns".into(),
                hostnames: vec![],
                parent_refs: vec![],
                rules: vec![],
                generation: 1,
            },
        );
        let evict = gone_map(|s| &s.http_routes);
        assert!(evict(&store, Some("ns"), "r"));
        assert!(store.http_routes.is_empty());
        assert!(!evict(&store, Some("ns"), "r"), "second eviction is a no-op");
    }

    fn gateway(generation: i64, programmed: &str) -> crate::gateway_types::Gateway {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        let mut gw = crate::gateway_types::Gateway::new("gw", Default::default());
        gw.metadata = ObjectMeta {
            name: Some("gw".into()),
            namespace: Some("ns".into()),
            generation: Some(generation),
            ..Default::default()
        };
        gw.status = Some(serde_json::from_value(serde_json::json!({
            "conditions": [{"type": "Programmed", "status": programmed, "reason": "x", "message": "", "lastTransitionTime": "2026-09-10T00:00:00Z"}]
        }))
        .expect("status"));
        gw
    }

    fn passed(events: Vec<watcher::Event<crate::gateway_types::Gateway>>) -> Vec<String> {
        futures::executor::block_on(async {
            spec_changes(futures::stream::iter(events.into_iter().map(Ok)))
                .map(|e| match e.expect("no errors") {
                    watcher::Event::Apply(o) => format!("apply gen={}", o.metadata.generation.unwrap_or(0)),
                    watcher::Event::InitApply(o) => format!("init-apply gen={}", o.metadata.generation.unwrap_or(0)),
                    watcher::Event::Delete(_) => "delete".to_string(),
                    watcher::Event::Init => "init".to_string(),
                    watcher::Event::InitDone => "init-done".to_string(),
                })
                .collect()
                .await
        })
    }

    /// The controller's own status write comes back on the watch as an Apply
    /// with the same generation: it must not cost a reconcile. A spec change
    /// (generation bump) must.
    #[test]
    fn spec_changes_drops_status_only_applies_and_keeps_spec_changes() {
        use watcher::Event::*;
        let got = passed(vec![
            Init,
            InitApply(gateway(1, "False")),
            InitDone,
            Apply(gateway(1, "True")),  // our Programmed write echoed back
            Apply(gateway(1, "True")),  // attachedRoutes bump, still generation 1
            Apply(gateway(2, "True")),  // user edited the spec
            Apply(gateway(2, "False")), // status only again
        ]);
        assert_eq!(got, vec!["init", "init-apply gen=1", "init-done", "apply gen=2"]);
    }

    /// Labels and annotations are read by reconcilers, so a change to either
    /// passes even at the same generation; a delete always passes and forgets
    /// the object so that a recreate at the same generation is seen.
    #[test]
    fn spec_changes_keeps_metadata_changes_and_deletes() {
        use watcher::Event::*;
        let mut relabelled = gateway(1, "True");
        relabelled.metadata.labels = Some([("team".to_string(), "a".to_string())].into_iter().collect());
        let mut annotated = gateway(1, "True");
        annotated.metadata.annotations = Some([("note".to_string(), "b".to_string())].into_iter().collect());
        let mut deleting = gateway(1, "True");
        deleting.metadata.deletion_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        ));
        let got = passed(vec![
            Apply(gateway(1, "True")),
            Apply(relabelled),
            Apply(annotated),
            Apply(deleting),
            Delete(gateway(1, "True")),
            Apply(gateway(1, "True")), // recreated at generation 1
        ]);
        assert_eq!(
            got,
            vec!["apply gen=1", "apply gen=1", "apply gen=1", "apply gen=1", "delete", "apply gen=1"]
        );
    }

    #[test]
    fn stats_render_prometheus_text_per_kind() {
        let stats = ReconcileStats::default();
        stats.record("HTTPRoute", Duration::from_millis(10), false);
        stats.record("HTTPRoute", Duration::from_millis(30), true);
        stats.record("Gateway", Duration::from_millis(5), false);
        let text = stats.render();
        assert!(text.contains("portus_controller_reconciles_total{kind=\"HTTPRoute\"} 2"));
        assert!(text.contains("portus_controller_reconcile_errors_total{kind=\"HTTPRoute\"} 1"));
        assert!(text.contains("portus_controller_reconcile_errors_total{kind=\"Gateway\"} 0"));
        assert!(text.contains("portus_controller_reconcile_duration_seconds_sum{kind=\"HTTPRoute\"} 0.040000"));
        assert!(text.contains("portus_controller_reconcile_duration_seconds_max{kind=\"HTTPRoute\"} 0.030000"));
        // Kinds are sorted for stable scrapes.
        assert!(text.find("kind=\"Gateway\"").unwrap() < text.find("kind=\"HTTPRoute\"").unwrap());
    }

    #[test]
    fn cache_then_stores_the_object_before_naming_dependents() {
        use crate::gateway_types::BackendTLSPolicy;
        use k8s_openapi::api::core::v1::ConfigMap;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let store = Arc::new(ConfigStore::new());
        let seen_by_dependents = Arc::clone(&store);
        let mapper = cache_then::<ConfigMap, BackendTLSPolicy, _>(
            Arc::clone(&store),
            crate::reconcilers::configmap::reconcile_configmap_inner,
            move |cm: &ConfigMap| {
                let key = NamespacedName { namespace: "ns".into(), name: "ca".into() };
                let cached = seen_by_dependents.config_maps.get(&key).expect("cached before fan-out");
                assert_eq!(cached.data.get("ca.crt").map(String::as_str), Some("NEW"));
                assert_eq!(cm.metadata.name.as_deref(), Some("ca"));
                vec![ObjectRef::new("policy").within("ns")]
            },
        );
        let refs = mapper(ConfigMap {
            metadata: ObjectMeta { name: Some("ca".into()), namespace: Some("ns".into()), ..Default::default() },
            data: Some([("ca.crt".to_string(), "NEW".to_string())].into_iter().collect()),
            ..Default::default()
        });
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "policy");
    }

    #[test]
    fn not_found_is_the_only_eviction_error() {
        let api_error = |code: u16, reason: &str| {
            ReconcileError::Kube(kube::Error::Api(
                serde_json::from_value(serde_json::json!({
                    "status": "Failure",
                    "message": reason,
                    "reason": reason,
                    "code": code,
                }))
                .unwrap(),
            ))
        };
        assert!(is_not_found(&api_error(404, "NotFound")));
        assert!(!is_not_found(&api_error(409, "Conflict")));
        assert!(!is_not_found(&ReconcileError::MissingField("x".into())));
    }
}
