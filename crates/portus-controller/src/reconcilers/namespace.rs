//! Namespace reconciler.
//!
//! Watches core v1 Namespaces cluster-wide and caches their labels into
//! `ConfigStore.namespace_labels`. Downstream reconcilers (HTTPRoute,
//! GRPCRoute, Gateway attached-routes counter, ListenerSet compile path)
//! read labels from the cache to evaluate `allowedRoutes.namespaces.Selector`
//! matching without per-reconcile kube API calls.
//!
//! Rationale: route reconciles fire frequently during conformance runs.
//! Fetching Namespace labels synchronously inside each reconcile adds real
//! latency and caused the `HTTPRouteObservedGenerationBump` test to exceed
//! its 60 s poll window. A dedicated watcher keeps the cache fresh at
//! startup and on namespace label edits with zero per-route overhead.
//!
//! When a namespace's labels change this reconciler wakes the compiler and
//! publishes `Event::Namespace`, so the routes in that namespace and every
//! listener selecting by label re-evaluate — in `Selector` mode a label change
//! can flip which routes a listener accepts.

use crate::reconcilers::{ReconcileContext, ReconcileError};
use crate::store::Event;
use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::controller::Action;
use std::sync::Arc;

pub async fn reconcile_namespace(
    ns: Arc<Namespace>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = ns
        .metadata
        .name
        .clone()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;

    // Deleted namespace — drop cached labels so Selector rejects any routes
    // that were tagged to this namespace.
    if ns.metadata.deletion_timestamp.is_some() {
        forget(&ctx.store, &name);
        return Ok(Action::await_change());
    }

    let new_labels = ns.metadata.labels.clone().unwrap_or_default();
    let changed = !ctx
        .store
        .namespace_labels
        .get(&name)
        .is_some_and(|existing| *existing.value() == new_labels);

    if changed {
        ctx.store.namespace_labels.insert(name.clone(), new_labels);
        // The compiler and the routes/Gateways/ListenerSets selecting by label.
        ctx.store.notify_change();
        ctx.store.publish(Event::Namespace(name));
    }

    Ok(Action::await_change())
}

/// Drop a Namespace's labels (deleted); selector-mode listeners re-evaluate.
pub fn forget(store: &crate::store::ConfigStore, name: &str) -> bool {
    let removed = store.namespace_labels.remove(name).is_some();
    if removed {
        store.notify_change();
        store.publish(Event::Namespace(name.to_string()));
    }
    removed
}

