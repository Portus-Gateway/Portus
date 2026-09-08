//! Shared generic functions for policy conflict resolution.
//!
//! All policy reconcilers use the same conflict resolution algorithm:
//! oldest creation timestamp wins, with namespace/name tiebreaking.
//! This module provides generic `resolve_conflicts` and `find_winner_key`
//! functions that work with any DashMap of types implementing `PolicyState`.

use crate::policy_types::is_policy_winner;
use crate::reconcilers::ReconcileError;
use crate::store::{ConfigStore, Event, NamespacedName, PolicyTargetKey};
use dashmap::DashMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta, Time};

/// Run a policy's store update and publish [`Event::Policy`] if the stored
/// state changed (including appearing or disappearing), so siblings on the
/// same target re-evaluate their conflict status. An unchanged reconcile
/// publishes nothing, which is what stops siblings re-triggering each other.
pub fn reconcile_publishing<S, F>(
    store: &ConfigStore,
    policies: &DashMap<NamespacedName, S>,
    kind: &'static str,
    meta: &ObjectMeta,
    reconcile: F,
) -> Result<Vec<Condition>, ReconcileError>
where
    S: PolicyState + PartialEq,
    F: FnOnce() -> Result<Vec<Condition>, ReconcileError>,
{
    let key = NamespacedName {
        namespace: meta.namespace.clone().unwrap_or_default(),
        name: meta.name.clone().unwrap_or_default(),
    };
    let before = policies.get(&key).map(|s| s.clone());
    let conditions = reconcile()?;
    let after = policies.get(&key).map(|s| s.clone());
    if before != after
        && let Some(target) = after.as_ref().or(before.as_ref()).map(|s| s.target().clone())
    {
        store.publish(Event::Policy { kind, key, target });
    }
    Ok(conditions)
}

/// Trait implemented by all policy state structs in the ConfigStore.
///
/// Provides the common fields needed for conflict resolution:
/// target key, creation timestamp, and accepted flag.
pub trait PolicyState: Clone {
    fn target(&self) -> &PolicyTargetKey;
    fn creation_timestamp(&self) -> &Option<Time>;
    fn accepted(&self) -> bool;
    fn set_accepted(&mut self, v: bool);
}

/// Evaluate all policies in the given DashMap that target the same resource
/// and set accepted flags. Oldest creation timestamp wins; ties broken
/// alphabetically by namespace/name.
pub fn resolve_conflicts<S: PolicyState>(
    current_key: &NamespacedName,
    target: &PolicyTargetKey,
    policies: &DashMap<NamespacedName, S>,
) {
    // Collect all policies targeting the same resource
    let mut contenders: Vec<(NamespacedName, Option<Time>)> = Vec::new();

    for entry in policies.iter() {
        let t = entry.value().target();
        if t.group == target.group
            && t.kind == target.kind
            && t.namespace == target.namespace
            && t.name == target.name
            && t.section_name == target.section_name
        {
            contenders.push((
                entry.key().clone(),
                entry.value().creation_timestamp().clone(),
            ));
        }
    }

    if contenders.len() <= 1 {
        // No conflict -- ensure the single policy is accepted
        if let Some(mut entry) = policies.get_mut(current_key) {
            entry.set_accepted(true);
        }
        return;
    }

    // Find the winner (oldest timestamp, tiebreak by key)
    let mut winner_key = contenders[0].0.clone();
    let mut winner_ts = contenders[0].1.clone();

    for (key, ts) in &contenders[1..] {
        if !is_policy_winner(&winner_ts, &winner_key, ts, key) {
            winner_key = key.clone();
            winner_ts = ts.clone();
        }
    }

    // Update accepted flags
    for (key, _) in &contenders {
        if let Some(mut entry) = policies.get_mut(key) {
            entry.set_accepted(*key == winner_key);
        }
    }
}

/// Find the winning (accepted) policy key for a given target, excluding
/// the specified key. Used to build conflict messages.
pub fn find_winner_key<S: PolicyState>(
    target: &PolicyTargetKey,
    exclude: &NamespacedName,
    policies: &DashMap<NamespacedName, S>,
) -> Option<NamespacedName> {
    for entry in policies.iter() {
        let t = entry.value().target();
        if t.group == target.group
            && t.kind == target.kind
            && t.namespace == target.namespace
            && t.name == target.name
            && t.section_name == target.section_name
            && entry.value().accepted()
            && entry.key() != exclude
        {
            return Some(entry.key().clone());
        }
    }
    None
}
