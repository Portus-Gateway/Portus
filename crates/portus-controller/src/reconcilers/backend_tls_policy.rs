//! BackendTLSPolicy reconciler.
//!
//! Watches BackendTLSPolicy resources (gateway.networking.k8s.io/v1).
//! These target Services, configuring TLS for proxy-to-backend connections.
//! Validates CA certificate references (ConfigMap lookup), handles conflict
//! detection via GEP-713 rules, and sets Accepted + ResolvedRefs conditions.

use super::policy_common::{find_winner_key, resolve_conflicts};
use super::{ReconcileContext, ReconcileError};
use crate::gateway_types::BackendTLSPolicy;
use crate::status;
use crate::store::{
    BackendTLSPolicyState, ConfigStore, NamespacedName, PolicyTargetKey, SubjectAltNameState,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::sync::Arc;

/// Result of CA certificate validation.
enum CaCertResult {
    /// Valid PEM data resolved from ConfigMap.
    Valid(String),
    /// Reference is invalid (nonexistent, malformed, or wrong kind).
    Invalid(String, String), // (reason, message)
}

/// Resolve a CA certificate reference to PEM data.
/// Only ConfigMap kind with group "" is supported per the Gateway API spec.
fn resolve_ca_cert(
    ca_ref: &crate::gateway_types::LocalObjectReference,
    namespace: &str,
    store: &ConfigStore,
) -> CaCertResult {
    // Only ConfigMap (core group) is supported
    if !ca_ref.group.is_empty() || (ca_ref.kind != "ConfigMap" && !ca_ref.kind.is_empty()) {
        return CaCertResult::Invalid(
            "InvalidKind".to_string(),
            format!(
                "CACertificateRef kind {} group {} is not supported; only ConfigMap is allowed",
                ca_ref.kind, ca_ref.group
            ),
        );
    }

    let cm_key = NamespacedName {
        namespace: namespace.to_string(),
        name: ca_ref.name.clone(),
    };

    match store.config_maps.get(&cm_key) {
        Some(secret_state) => {
            // Look for ca.crt key in the data
            if let Some(ca_pem) = secret_state.data.get("ca.crt") {
                if ca_pem.is_empty() {
                    CaCertResult::Invalid(
                        "InvalidCACertificateRef".to_string(),
                        format!("ConfigMap {}/{} has empty ca.crt data", namespace, ca_ref.name),
                    )
                } else {
                    CaCertResult::Valid(ca_pem.clone())
                }
            } else {
                CaCertResult::Invalid(
                    "InvalidCACertificateRef".to_string(),
                    format!(
                        "ConfigMap {}/{} does not contain ca.crt key",
                        namespace, ca_ref.name
                    ),
                )
            }
        }
        None => CaCertResult::Invalid(
            "InvalidCACertificateRef".to_string(),
            format!(
                "ConfigMap {}/{} not found",
                namespace, ca_ref.name
            ),
        ),
    }
}

pub fn reconcile_inner(
    policy: &BackendTLSPolicy,
    store: &ConfigStore,
) -> Result<Vec<Condition>, ReconcileError> {
    let name = policy
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = policy
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;
    let generation = policy.metadata.generation.unwrap_or(0);
    let creation_ts = policy.metadata.creation_timestamp.clone();

    let validation = &policy.spec.validation;

    // Resolve CA certificate(s). We need at least one valid CA cert.
    let mut ca_cert_pem = String::new();
    let mut resolved_refs_ok = true;
    let mut resolved_refs_reason = "ResolvedRefs".to_string();
    let mut resolved_refs_message = "All references resolved".to_string();

    if validation.ca_certificate_refs.is_empty() {
        resolved_refs_ok = false;
        resolved_refs_reason = "InvalidCACertificateRef".to_string();
        resolved_refs_message = "No caCertificateRefs specified".to_string();
    } else {
        // Try each CA cert ref; we need at least one valid one
        let mut found_valid = false;
        for ca_ref in &validation.ca_certificate_refs {
            match resolve_ca_cert(ca_ref, namespace, store) {
                CaCertResult::Valid(pem) => {
                    if !found_valid {
                        ca_cert_pem = pem;
                        found_valid = true;
                    } else {
                        // Append additional CA certs
                        ca_cert_pem.push('\n');
                        ca_cert_pem.push_str(&pem);
                    }
                }
                CaCertResult::Invalid(reason, message) => {
                    if !found_valid {
                        resolved_refs_ok = false;
                        resolved_refs_reason = reason;
                        resolved_refs_message = message;
                    }
                }
            }
        }
        if found_valid {
            resolved_refs_ok = true;
            resolved_refs_reason = "ResolvedRefs".to_string();
            resolved_refs_message = "All references resolved".to_string();
        }
    }

    // Build SAN list
    let subject_alt_names: Vec<SubjectAltNameState> = validation
        .subject_alt_names
        .iter()
        .map(|san| SubjectAltNameState {
            san_type: san.san_type.clone(),
            value: san.hostname.clone().or_else(|| san.uri.clone()).unwrap_or_default(),
        })
        .collect();

    // Process each targetRef (BackendTLSPolicy supports multiple targetRefs)
    for target_ref in &policy.spec.target_refs {
        let target = PolicyTargetKey {
            group: target_ref.group.clone(),
            kind: target_ref.kind.clone(),
            namespace: namespace.to_string(),
            name: target_ref.name.clone(),
            section_name: target_ref.section_name.clone(),
        };

        let my_key = NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };

        let state = BackendTLSPolicyState {
            target: target.clone(),
            ca_cert_pem: ca_cert_pem.clone(),
            hostname: validation.hostname.clone(),
            subject_alt_names: subject_alt_names.clone(),
            generation,
            creation_timestamp: creation_ts.clone(),
            accepted: resolved_refs_ok, // Only accept if refs resolved
        };

        store.backend_tls_policies.insert(my_key.clone(), state);

        if resolved_refs_ok {
            resolve_conflicts(&my_key, &target, &store.backend_tls_policies);
        }
    }

    // Check final accepted state
    let my_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    let accepted = store
        .backend_tls_policies
        .get(&my_key)
        .map(|s| s.accepted)
        .unwrap_or(false);

    store.notify_change();

    // Build conditions
    let mut conditions = Vec::new();

    // Accepted condition
    if !resolved_refs_ok {
        // CA cert resolution failed → not accepted with NoValidCACertificate reason
        conditions.push(status::build_condition(
            "Accepted",
            false,
            "NoValidCACertificate",
            &resolved_refs_message,
            generation,
        ));
    } else if accepted {
        conditions.push(status::build_condition(
            "Accepted",
            true,
            "Accepted",
            "Policy accepted",
            generation,
        ));
    } else {
        let target = &policy.spec.target_refs[0];
        let target_key = PolicyTargetKey {
            group: target.group.clone(),
            kind: target.kind.clone(),
            namespace: namespace.to_string(),
            name: target.name.clone(),
            section_name: target.section_name.clone(),
        };
        let winner_msg = find_winner_key(&target_key, &my_key, &store.backend_tls_policies)
            .map(|k| format!("Older BackendTLSPolicy {} takes precedence", k))
            .unwrap_or_else(|| "Conflicted with another policy".to_string());
        conditions.push(status::build_condition(
            "Accepted",
            false,
            "Conflicted",
            &winner_msg,
            generation,
        ));
    }

    // ResolvedRefs condition
    conditions.push(status::build_condition(
        "ResolvedRefs",
        resolved_refs_ok,
        &resolved_refs_reason,
        &resolved_refs_message,
        generation,
    ));

    Ok(conditions)
}

/// Find which Gateways are ancestors of this BackendTLSPolicy.
/// An ancestor Gateway is one that has accepted routes referencing the target Service(s).
pub fn find_ancestor_gateways(
    policy: &BackendTLSPolicy,
    store: &ConfigStore,
) -> Vec<(String, String)> {
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();
    let target_services: Vec<(String, String)> = policy.spec.target_refs.iter()
        .map(|t| (namespace.to_string(), t.name.clone()))
        .collect();

    let mut ancestors: Vec<(String, String)> = Vec::new();
    for entry in store.http_routes.iter() {
        let route = entry.value();
        let references_target = route.rules.iter().any(|rule| {
            rule.backend_refs.iter().any(|br| {
                target_services.iter().any(|(ns, name)| br.namespace == *ns && br.name == *name)
            })
        });
        if references_target {
            for parent in &route.parent_refs {
                if parent.accepted {
                    let gw = (parent.gateway_namespace.clone(), parent.gateway_name.clone());
                    if !ancestors.contains(&gw) {
                        ancestors.push(gw);
                    }
                }
            }
        }
    }

    // Fallback while no reconciled route references the target yet (the policy
    // is often created before, or in the same instant as, its route): the
    // Gateways in the policy's own namespace. Never other namespaces — with
    // many Gateways in the cluster that blew past the API's 16-ancestor cap and
    // the status write was rejected (422) until the 300 s requeue.
    if ancestors.is_empty() {
        for entry in store.gateways.iter() {
            let gw = entry.value();
            if gw.namespace == namespace {
                ancestors.push((gw.namespace.clone(), gw.name.clone()));
            }
        }
    }

    // `status.ancestors` allows at most 16 items; deterministic order so the
    // truncation and the status diff are stable across reconciles.
    ancestors.sort();
    ancestors.truncate(MAX_POLICY_ANCESTORS);
    ancestors
}

/// Gateway API `PolicyStatus.ancestors` `MaxItems`.
pub const MAX_POLICY_ANCESTORS: usize = 16;

pub async fn reconcile_backend_tls_policy(
    policy: Arc<BackendTLSPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let desired_conditions = super::policy_common::reconcile_publishing(
        &ctx.store,
        &ctx.store.backend_tls_policies,
        "BackendTLSPolicy",
        &policy.metadata,
        || reconcile_inner(&policy, &ctx.store),
    )?;

    let name = policy.metadata.name.as_deref().unwrap_or_default();
    let namespace = policy.metadata.namespace.as_deref().unwrap_or_default();

    // BackendTLSPolicy uses per-ancestor status format.
    let ancestor_gateways = find_ancestor_gateways(&policy, &ctx.store);

    let ancestors_json: Vec<_> = ancestor_gateways.iter().map(|(gw_ns, gw_name)| {
        json!({
            "ancestorRef": {
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": gw_name,
                "namespace": gw_ns,
            },
            "controllerName": "portus-gateway.dev/controller",
            "conditions": desired_conditions.iter().map(|c| json!({
                "type": c.type_,
                "status": c.status,
                "reason": c.reason,
                "message": c.message,
                "observedGeneration": c.observed_generation,
                "lastTransitionTime": c.last_transition_time.0.to_string(),
            })).collect::<Vec<_>>()
        })
    }).collect();

    let desired_status = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "BackendTLSPolicy",
        "metadata": { "name": name, "namespace": namespace },
        "status": { "ancestors": ancestors_json }
    });

    let current_conditions: Vec<Condition> = policy
        .status
        .as_ref()
        .and_then(|s| s.ancestors.first())
        .map(|a| a.conditions.clone())
        .unwrap_or_default();

    let api: Api<BackendTLSPolicy> = Api::namespaced(ctx.client.clone(), namespace);
    if let Err(e) = status::patch_status_if_changed(
        &api,
        name,
        desired_status,
        &current_conditions,
        &desired_conditions,
    )
    .await
    {
        // Surface the failure so error_policy_backend_tls requeues in 30 s
        // rather than leaving the policy without status for 300 s.
        log::warn!(
            "failed to write BackendTLSPolicy status for {}/{}: {}; retrying shortly",
            namespace,
            name,
            e
        );
        return Err(e.into());
    }

    // Siblings on the same target and data plane acks re-run this policy
    // through the store's events.
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_types::{
        BackendTLSPolicySpec, BackendTLSPolicySubjectAltName, BackendTLSPolicyTargetRef,
        BackendTLSPolicyValidation, LocalObjectReference,
    };
    use crate::store::{ConfigStore, SecretState};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
    use std::collections::HashMap;

    fn make_ca_configmap(store: &ConfigStore, ns: &str, name: &str, ca_pem: &str) {
        let mut data = HashMap::new();
        data.insert("ca.crt".to_string(), ca_pem.to_string());
        store.config_maps.insert(
            NamespacedName {
                namespace: ns.to_string(),
                name: name.to_string(),
            },
            SecretState { data },
        );
    }

    fn make_policy(
        name: &str,
        ns: &str,
        target_name: &str,
        section_name: Option<&str>,
        ca_configmap: &str,
        hostname: &str,
    ) -> BackendTLSPolicy {
        BackendTLSPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: BackendTLSPolicySpec {
                target_refs: vec![BackendTLSPolicyTargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: target_name.to_string(),
                    section_name: section_name.map(|s| s.to_string()),
                }],
                validation: BackendTLSPolicyValidation {
                    ca_certificate_refs: vec![LocalObjectReference {
                        group: String::new(),
                        kind: "ConfigMap".to_string(),
                        name: ca_configmap.to_string(),
                    }],
                    hostname: hostname.to_string(),
                    subject_alt_names: vec![],
                },
            },
            status: None,
        }
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy.go
    //   "HTTP request sent to Service with valid BackendTLSPolicy should succeed"
    //   → Accepted=True, ResolvedRefs=True
    // -----------------------------------------------------------------------
    #[test]
    fn test_valid_policy_accepted_and_resolved() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");

        let policy = make_policy("normative-test", "default", "my-svc", Some("btls"), "tls-ca", "abc.example.com");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[0].reason, "Accepted");
        assert_eq!(conditions[1].type_, "ResolvedRefs");
        assert_eq!(conditions[1].status, "True");
        assert_eq!(conditions[1].reason, "ResolvedRefs");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-invalid-ca-certificate-ref.go
    //   "BackendTLSPolicy with nonexistent ConfigMap"
    //   → Accepted=False(NoValidCACertificate), ResolvedRefs=False(InvalidCACertificateRef)
    // -----------------------------------------------------------------------
    #[test]
    fn test_nonexistent_ca_cert_ref_rejected() {
        let store = ConfigStore::new();
        // Do NOT add the configmap — it's nonexistent

        let policy = make_policy("nonexistent-ca", "default", "my-svc", None, "nonexistent-ca-certificate", "abc.example.com");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "NoValidCACertificate");

        assert_eq!(conditions[1].type_, "ResolvedRefs");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "InvalidCACertificateRef");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-invalid-ca-certificate-ref.go
    //   "BackendTLSPolicy with malformed ConfigMap (empty data)"
    //   → Accepted=False(NoValidCACertificate), ResolvedRefs=False(InvalidCACertificateRef)
    // -----------------------------------------------------------------------
    #[test]
    fn test_malformed_ca_cert_ref_rejected() {
        let store = ConfigStore::new();
        // Add configmap with empty data (no ca.crt key)
        store.config_maps.insert(
            NamespacedName { namespace: "default".to_string(), name: "malformed-ca".to_string() },
            SecretState { data: HashMap::new() },
        );

        let policy = make_policy("malformed-ca-ref", "default", "my-svc", None, "malformed-ca", "abc.example.com");
        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "NoValidCACertificate");

        assert_eq!(conditions[1].type_, "ResolvedRefs");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "InvalidCACertificateRef");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-invalid-kind.go
    //   "BackendTLSPolicy with invalid CACertificateRef kind"
    //   → Accepted=False(NoValidCACertificate), ResolvedRefs=False(InvalidKind)
    // -----------------------------------------------------------------------
    #[test]
    fn test_invalid_kind_ca_cert_ref_rejected() {
        let store = ConfigStore::new();

        let mut policy = make_policy("invalid-kind", "default", "my-svc", None, "whatever", "abc.example.com");
        // Override the CA cert ref to have an invalid kind
        policy.spec.validation.ca_certificate_refs = vec![LocalObjectReference {
            group: "invalid.io".to_string(),
            kind: "InvalidKind".to_string(),
            name: "invalid-kind".to_string(),
        }];

        let conditions = reconcile_inner(&policy, &store).unwrap();

        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, "NoValidCACertificate");

        assert_eq!(conditions[1].type_, "ResolvedRefs");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "InvalidKind");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   "Conflicting BackendTLSPolicies targeting same Service without section name"
    //   → Older=Accepted, Newer=Conflicted
    // -----------------------------------------------------------------------
    #[test]
    fn test_conflict_oldest_wins() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let mut older = make_policy("policy-old", "default", "my-svc", None, "tls-ca", "old.example.com");
        older.metadata.creation_timestamp = Some(Time(
            k8s_openapi::jiff::Timestamp::from_second(1000).unwrap(),
        ));

        let mut newer = make_policy("policy-new", "default", "my-svc", None, "tls-ca", "new.example.com");
        newer.metadata.creation_timestamp = Some(Time(
            k8s_openapi::jiff::Timestamp::from_second(2000).unwrap(),
        ));

        let conds_old = reconcile_inner(&older, &store).unwrap();
        assert_eq!(conds_old[0].status, "True", "older should be accepted");

        let conds_new = reconcile_inner(&newer, &store).unwrap();
        assert_eq!(conds_new[0].type_, "Accepted");
        assert_eq!(conds_new[0].status, "False");
        assert_eq!(conds_new[0].reason, "Conflicted");

        // Verify store state
        let old_key = NamespacedName { namespace: "default".to_string(), name: "policy-old".to_string() };
        let new_key = NamespacedName { namespace: "default".to_string(), name: "policy-new".to_string() };
        assert!(store.backend_tls_policies.get(&old_key).unwrap().accepted);
        assert!(!store.backend_tls_policies.get(&new_key).unwrap().accepted);
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   "BackendTLSPolicies targeting same Service with and without section name"
    //   → Both accepted (different scope, no conflict)
    // -----------------------------------------------------------------------
    #[test]
    fn test_section_vs_no_section_no_conflict() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let with_section = make_policy("with-section", "default", "my-svc", Some("https-1"), "tls-ca", "other.example.com");
        let without_section = make_policy("without-section", "default", "my-svc", None, "tls-ca", "abc.example.com");

        let conds1 = reconcile_inner(&with_section, &store).unwrap();
        let conds2 = reconcile_inner(&without_section, &store).unwrap();

        assert_eq!(conds1[0].status, "True", "with-section should be accepted");
        assert_eq!(conds2[0].status, "True", "without-section should be accepted (different scope)");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-san.go
    //   "valid BackendTLSPolicy containing dns SAN"
    //   → Accepted, SAN stored in state
    // -----------------------------------------------------------------------
    #[test]
    fn test_san_dns_stored_in_state() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let mut policy = make_policy("san-dns", "default", "my-svc", Some("btls"), "tls-ca", "abc.example.com");
        policy.spec.validation.subject_alt_names = vec![BackendTLSPolicySubjectAltName {
            san_type: "Hostname".to_string(),
            hostname: Some("abc.example.com".to_string()),
            uri: None,
        }];

        let conditions = reconcile_inner(&policy, &store).unwrap();
        assert_eq!(conditions[0].status, "True");

        let key = NamespacedName { namespace: "default".to_string(), name: "san-dns".to_string() };
        let state = store.backend_tls_policies.get(&key).unwrap();
        assert_eq!(state.subject_alt_names.len(), 1);
        assert_eq!(state.subject_alt_names[0].san_type, "Hostname");
        assert_eq!(state.subject_alt_names[0].value, "abc.example.com");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-san.go
    //   "valid BackendTLSPolicy containing uri SAN"
    // -----------------------------------------------------------------------
    #[test]
    fn test_san_uri_stored_in_state() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let mut policy = make_policy("san-uri", "default", "my-svc", Some("btls"), "tls-ca", "abc.example.com");
        policy.spec.validation.subject_alt_names = vec![BackendTLSPolicySubjectAltName {
            san_type: "URI".to_string(),
            hostname: None,
            uri: Some("spiffe://abc.example.com/test-identity".to_string()),
        }];

        let conditions = reconcile_inner(&policy, &store).unwrap();
        assert_eq!(conditions[0].status, "True");

        let key = NamespacedName { namespace: "default".to_string(), name: "san-uri".to_string() };
        let state = store.backend_tls_policies.get(&key).unwrap();
        assert_eq!(state.subject_alt_names[0].san_type, "URI");
        assert_eq!(state.subject_alt_names[0].value, "spiffe://abc.example.com/test-identity");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-san.go
    //   "valid BackendTLSPolicy containing multi SAN"
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiple_sans_stored() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let mut policy = make_policy("multi-san", "default", "my-svc", Some("btls"), "tls-ca", "abc.example.com");
        policy.spec.validation.subject_alt_names = vec![
            BackendTLSPolicySubjectAltName {
                san_type: "URI".to_string(),
                hostname: None,
                uri: Some("spiffe://abc.example.com/test-identity".to_string()),
            },
            BackendTLSPolicySubjectAltName {
                san_type: "Hostname".to_string(),
                hostname: Some("abc.example.com".to_string()),
                uri: None,
            },
        ];

        let conditions = reconcile_inner(&policy, &store).unwrap();
        assert_eq!(conditions[0].status, "True");

        let key = NamespacedName { namespace: "default".to_string(), name: "multi-san".to_string() };
        let state = store.backend_tls_policies.get(&key).unwrap();
        assert_eq!(state.subject_alt_names.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test: different services = no conflict
    // -----------------------------------------------------------------------
    #[test]
    fn test_different_targets_no_conflict() {
        let store = ConfigStore::new();
        make_ca_configmap(&store, "default", "tls-ca", "CA-PEM");

        let p1 = make_policy("pol-a", "default", "svc-a", None, "tls-ca", "a.example.com");
        let p2 = make_policy("pol-b", "default", "svc-b", None, "tls-ca", "b.example.com");

        let c1 = reconcile_inner(&p1, &store).unwrap();
        let c2 = reconcile_inner(&p2, &store).unwrap();

        assert_eq!(c1[0].status, "True");
        assert_eq!(c2[0].status, "True");
    }

    // -----------------------------------------------------------------------
    // Mirrors: backendtlspolicy-conflict-resolution.go
    //   BackendTLSPolicyMustHaveCondition checks condition against a specific
    //   Gateway (gwNN). The ancestor ref must point to the Gateway that has
    //   routes referencing the target Service, not a random gateway.
    // -----------------------------------------------------------------------
    #[test]
    fn test_find_ancestor_gateway_from_route() {
        use crate::store::*;

        let store = ConfigStore::new();

        // Two gateways
        store.gateways.insert(
            NamespacedName { namespace: "ns".to_string(), name: "gw-a".to_string() },
            GatewayState {
                name: "gw-a".to_string(), namespace: "ns".to_string(),
                listeners: vec![], generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );
        store.gateways.insert(
            NamespacedName { namespace: "ns".to_string(), name: "gw-b".to_string() },
            GatewayState {
                name: "gw-b".to_string(), namespace: "ns".to_string(),
                listeners: vec![], generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );

        // HTTPRoute attached to gw-a, referencing "target-svc"
        store.http_routes.insert(
            NamespacedName { namespace: "ns".to_string(), name: "route-1".to_string() },
            HTTPRouteState {
                namespace: "ns".to_string(),
                hostnames: vec![],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "ns".to_string(),
                    gateway_name: "gw-a".to_string(),
                    section_name: None, port: None,
                    accepted: true, resolved_refs: true, reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "ns".to_string(),
                        name: "target-svc".to_string(),
                        port: 443, weight: 1, filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );

        let policy = make_policy("test-pol", "ns", "target-svc", None, "ca", "example.com");
        let ancestors = find_ancestor_gateways(&policy, &store);

        assert_eq!(ancestors.len(), 1, "should find exactly one ancestor gateway");
        assert_eq!(ancestors[0], ("ns".to_string(), "gw-a".to_string()),
            "ancestor should be gw-a (the gateway with the route referencing target-svc)");
    }

    #[test]
    fn test_find_ancestor_gateway_no_routes_falls_back_to_all() {
        use crate::store::*;

        let store = ConfigStore::new();

        store.gateways.insert(
            NamespacedName { namespace: "ns".to_string(), name: "gw-x".to_string() },
            GatewayState {
                name: "gw-x".to_string(), namespace: "ns".to_string(),
                listeners: vec![], generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );

        // A Gateway in another namespace is never an ancestor.
        store.gateways.insert(
            NamespacedName { namespace: "elsewhere".to_string(), name: "gw-far".to_string() },
            GatewayState {
                name: "gw-far".to_string(), namespace: "elsewhere".to_string(),
                listeners: vec![], generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        // No routes reference the target service
        let policy = make_policy("test-pol", "ns", "orphan-svc", None, "ca", "example.com");
        let ancestors = find_ancestor_gateways(&policy, &store);

        assert_eq!(ancestors, vec![("ns".to_string(), "gw-x".to_string())],
            "fallback is the policy's own namespace only");
    }

    /// Live failure 2026-09-05: with 27 Gateways in the store the fallback
    /// produced 27 ancestors and the API server rejected the status
    /// (`status.ancestors: Too many: 27: must have at most 16 items`), so the
    /// policy never became Accepted for the suite.
    #[test]
    fn test_find_ancestor_gateways_capped_at_api_maximum() {
        use crate::store::*;

        let store = ConfigStore::new();
        for i in 0..27 {
            let name = format!("gw-{i:02}");
            store.gateways.insert(
                NamespacedName { namespace: "ns".to_string(), name: name.clone() },
                GatewayState {
                    name, namespace: "ns".to_string(),
                    listeners: vec![], generation: 1,
                    allowed_listener_namespaces_from: None,
                    allowed_listener_match_labels: Vec::new(),
                },
            );
        }
        let policy = make_policy("test-pol", "ns", "orphan-svc", None, "ca", "example.com");
        let ancestors = find_ancestor_gateways(&policy, &store);
        assert_eq!(ancestors.len(), MAX_POLICY_ANCESTORS);
        let names: Vec<&str> = ancestors.iter().map(|(_, n)| n.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "deterministic order so truncation is stable");
        assert_eq!(names[0], "gw-00");

        // Route-derived ancestors are exact even when many Gateways exist.
        store.http_routes.insert(
            NamespacedName { namespace: "ns".to_string(), name: "route".to_string() },
            HTTPRouteState {
                namespace: "ns".to_string(),
                hostnames: vec![],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "ns".to_string(),
                    gateway_name: "gw-26".to_string(),
                    section_name: None, port: None,
                    accepted: true, resolved_refs: true, reject_reason: None,
                }],
                rules: vec![HTTPRouteRuleState {
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![BackendRefState {
                        namespace: "ns".to_string(),
                        name: "orphan-svc".to_string(),
                        port: 443, weight: 1, filters: vec![],
                    }],
                    request_timeout_ms: None,
                    backend_request_timeout_ms: None,
                    retry: None,
                }],
                generation: 1,
            },
        );
        assert_eq!(find_ancestor_gateways(&policy, &store), vec![("ns".to_string(), "gw-26".to_string())]);
    }
}
