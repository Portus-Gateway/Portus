use crate::gateway_types::Gateway;
use crate::reconcilers::{ReconcileContext, ReconcileError};
use crate::status;
use crate::store::{
    Event,
    AllowedRoutesState, ClientValidationOutcome, ClientValidationRefs, ConfigStore, GatewayState,
    GatewayTlsState, ListenerState, NamespacedName,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The dataplane template is read from the controller's environment once.
pub fn dataplane_template() -> &'static super::provisioner::DataplaneTemplate {
    static TEMPLATE: std::sync::OnceLock<super::provisioner::DataplaneTemplate> = std::sync::OnceLock::new();
    TEMPLATE.get_or_init(super::provisioner::DataplaneTemplate::from_env)
}

/// Check if two hostnames overlap according to Gateway API rules.
///
/// - (None, _) or (_, None) => true (empty hostname = match all)
/// - Same string => true
/// - Wildcard: *.example.com overlaps with foo.example.com (and vice versa)
pub fn hostnames_overlap(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => super::hostname_matches(a, b),
    }
}

/// Detect hostname conflicts among listeners on the same port+protocol.
///
/// Input: Vec of (name, port, protocol, hostname)
/// Returns map of listener_name -> conflicted (true = has conflict)
pub fn detect_listener_conflicts(
    listeners: &[(String, u16, String, Option<String>)],
) -> HashMap<String, bool> {
    let mut results: HashMap<String, bool> = HashMap::new();

    // Group by (port, protocol) → [(listener name, hostname)]
    type Groups<'a> = HashMap<(u16, &'a str), Vec<(&'a str, Option<&'a str>)>>;
    let mut groups: Groups<'_> = HashMap::new();
    for (name, port, protocol, hostname) in listeners {
        groups
            .entry((*port, protocol.as_str()))
            .or_default()
            .push((name.as_str(), hostname.as_deref()));
    }

    // Check each group for hostname conflicts
    for members in groups.values() {
        for (i, (name_a, host_a)) in members.iter().enumerate() {
            for (name_b, host_b) in members.iter().skip(i + 1) {
                if hostnames_overlap(*host_a, *host_b) {
                    results.insert(name_a.to_string(), true);
                    results.insert(name_b.to_string(), true);
                }
            }
        }
    }

    results
}

/// Evaluate a Gateway resource against its GatewayClass and listener rules.
///
/// Returns (GatewayState, per-listener conditions) for the store and status writes.
/// The Gateway-level `Accepted` condition: (status, reason, message).
///
/// Gateway API semantics: an unknown `infrastructure.parametersRef` kind is
/// `InvalidParameters`; otherwise the Gateway is accepted iff at least one
/// listener is accepted, and the reason is `ListenersNotValid` whenever any
/// listener was rejected (even when the Gateway itself is still accepted).
fn gateway_accepted_condition(
    gc_accepted: bool,
    gc_reject_msg: &str,
    parameters_ref: Option<&crate::gateway_types::LocalParametersReference>,
    addresses: &[crate::gateway_types::GatewayAddress],
    listener_count: usize,
    accepted_listeners: usize,
) -> (bool, &'static str, String) {
    if !gc_accepted {
        return (false, "InvalidGatewayClass", gc_reject_msg.to_string());
    }
    if let Some(pr) = parameters_ref {
        // This controller defines no Gateway parameters object; any reference
        // is to something it cannot interpret.
        return (
            false,
            "InvalidParameters",
            format!(
                "infrastructure.parametersRef {}/{} '{}' is not a supported parameters kind",
                pr.group, pr.kind, pr.name
            ),
        );
    }
    // spec.addresses: an address with a supported type and no value asks the
    // implementation to assign one (GatewayAddressEmpty) - the per-Gateway
    // Service does exactly that. Requesting a specific value (static
    // addresses) is not supported yet, nor are non-standard address types.
    for addr in addresses {
        let ty = addr.type_.as_deref().unwrap_or("IPAddress");
        if !matches!(ty, "IPAddress" | "Hostname") {
            return (
                false,
                "UnsupportedAddress",
                format!("address type '{}' is not supported (IPAddress, Hostname)", ty),
            );
        }
        if !addr.value.is_empty() {
            return (
                false,
                "AddressNotUsable",
                format!(
                    "static address {} '{}' cannot be assigned; leave the value empty to have one assigned",
                    ty, addr.value
                ),
            );
        }
    }
    if listener_count > 0 && accepted_listeners == 0 {
        return (false, "ListenersNotValid", "No listener is accepted".to_string());
    }
    if accepted_listeners < listener_count {
        return (
            true,
            "ListenersNotValid",
            format!("{} of {} listeners accepted", accepted_listeners, listener_count),
        );
    }
    (true, "Accepted", "Gateway accepted".to_string())
}

/// True when a ReferenceGrant in `to_ns` allows `from_kind` objects in
/// `from_ns` to reference the core `to_kind` named `to_name` (or any name).
fn reference_grant_allows(
    store: &ConfigStore,
    from_kind: &str,
    from_ns: &str,
    to_kind: &str,
    to_ns: &str,
    to_name: &str,
) -> bool {
    store.reference_grants.iter().any(|entry| {
        let rg = entry.value();
        rg.namespace == to_ns
            && rg.from.iter().any(|f| {
                f.group == "gateway.networking.k8s.io" && f.kind == from_kind && f.namespace == from_ns
            })
            && rg.to.iter().any(|t| {
                t.group.is_empty()
                    && t.kind == to_kind
                    && t.name.as_deref().is_none_or(|n| n == to_name)
            })
    })
}

/// Resolve one `FrontendTLSValidation` block (Gateway `spec.tls.frontend.*.validation`).
///
/// Every `caCertificateRef` must be a core ConfigMap in the Gateway's namespace
/// (or granted by a ReferenceGrant) whose `ca.crt` key parses as PEM
/// certificates. A reference that fails makes the listener `ResolvedRefs=False`
/// with the reason the spec prescribes; when no reference is usable the
/// listener is also not accepted (`NoValidCACertificate`).
pub(crate) fn resolve_frontend_validation(
    validation: &crate::gateway_types::FrontendTLSValidation,
    gateway_namespace: &str,
    store: &ConfigStore,
) -> ClientValidationOutcome {
    let mode = validation
        .mode
        .as_deref()
        .unwrap_or(crate::store::CLIENT_VALIDATION_ALLOW_VALID_ONLY);
    if mode != crate::store::CLIENT_VALIDATION_ALLOW_VALID_ONLY
        && mode != crate::store::CLIENT_VALIDATION_INSECURE_FALLBACK
    {
        return ClientValidationOutcome::Invalid {
            reason: "UnsupportedValue".to_string(),
            message: format!("frontend validation mode '{}' is not supported", mode),
        };
    }
    if validation.ca_certificate_refs.is_empty() {
        return ClientValidationOutcome::Invalid {
            reason: "InvalidCACertificateRef".to_string(),
            message: "frontend validation has no caCertificateRefs".to_string(),
        };
    }

    let mut ca_config_maps = Vec::new();
    let mut first_error: Option<(String, String)> = None;
    for ca_ref in &validation.ca_certificate_refs {
        let kind = if ca_ref.kind.is_empty() { "ConfigMap" } else { ca_ref.kind.as_str() };
        let outcome: Result<NamespacedName, (&str, String)> = if !ca_ref.group.is_empty() || kind != "ConfigMap" {
            Err((
                "InvalidCACertificateKind",
                format!(
                    "caCertificateRef {} has unsupported kind {}/{}; only core ConfigMaps are supported",
                    ca_ref.name, ca_ref.group, kind
                ),
            ))
        } else {
            let ns = ca_ref.namespace.as_deref().unwrap_or(gateway_namespace);
            if ns != gateway_namespace
                && !reference_grant_allows(store, "Gateway", gateway_namespace, "ConfigMap", ns, &ca_ref.name)
            {
                Err((
                    "RefNotPermitted",
                    format!(
                        "caCertificateRef {}/{} is in another namespace and no ReferenceGrant permits it",
                        ns, ca_ref.name
                    ),
                ))
            } else {
                let key = NamespacedName { namespace: ns.to_string(), name: ca_ref.name.clone() };
                match store.config_maps.get(&key) {
                    None => Err((
                        "InvalidCACertificateRef",
                        format!("ConfigMap {}/{} not found", ns, ca_ref.name),
                    )),
                    Some(cm) => {
                        let pem = cm.data.get("ca.crt").map(String::as_str).unwrap_or("");
                        let has_cert = rustls_pemfile::certs(&mut pem.as_bytes())
                            .next()
                            .is_some_and(|c| c.is_ok());
                        if has_cert {
                            Ok(key)
                        } else {
                            Err((
                                "InvalidCACertificateRef",
                                format!(
                                    "ConfigMap {}/{} has no PEM certificate under key ca.crt",
                                    ns, ca_ref.name
                                ),
                            ))
                        }
                    }
                }
            }
        };
        match outcome {
            Ok(key) => ca_config_maps.push(key),
            Err((reason, message)) => {
                if first_error.is_none() {
                    first_error = Some((reason.to_string(), message));
                }
            }
        }
    }

    match (ca_config_maps.is_empty(), first_error) {
        (true, Some((reason, message))) => ClientValidationOutcome::Invalid { reason, message },
        (_, ref_error) => ClientValidationOutcome::Valid(ClientValidationRefs {
            ca_config_maps,
            mode: mode.to_string(),
            ref_error,
        }),
    }
}

/// Outcome of resolving `spec.tls.backend.clientCertificateRef`: the Secret key
/// when usable, otherwise the Gateway `ResolvedRefs` reason and message.
pub(crate) fn resolve_backend_client_cert(
    cert_ref: &crate::gateway_types::SecretObjectReference,
    gateway_namespace: &str,
    store: &ConfigStore,
) -> Result<NamespacedName, (&'static str, String)> {
    let group = cert_ref.group.as_deref().unwrap_or("");
    let kind = cert_ref.kind.as_deref().unwrap_or("Secret");
    if !group.is_empty() || kind != "Secret" {
        return Err((
            "InvalidClientCertificateRef",
            format!(
                "clientCertificateRef {} has unsupported kind {}/{}; only core Secrets are supported",
                cert_ref.name, group, kind
            ),
        ));
    }
    let ns = cert_ref.namespace.as_deref().unwrap_or(gateway_namespace);
    if ns != gateway_namespace
        && !reference_grant_allows(store, "Gateway", gateway_namespace, "Secret", ns, &cert_ref.name)
    {
        return Err((
            "RefNotPermitted",
            format!(
                "clientCertificateRef {}/{} is in another namespace and no ReferenceGrant permits it",
                ns, cert_ref.name
            ),
        ));
    }
    let key = NamespacedName { namespace: ns.to_string(), name: cert_ref.name.clone() };
    let Some(secret) = store.secrets.get(&key) else {
        return Err((
            "InvalidClientCertificateRef",
            format!("Secret {}/{} not found", ns, cert_ref.name),
        ));
    };
    let cert_pem = secret.data.get("tls.crt").map(String::as_str).unwrap_or("");
    let key_pem = secret.data.get("tls.key").map(String::as_str).unwrap_or("");
    let cert_valid = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .is_some_and(|c| c.is_ok());
    let key_valid = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .ok()
        .flatten()
        .is_some();
    if !cert_valid || !key_valid {
        return Err((
            "InvalidClientCertificateRef",
            format!(
                "Secret {}/{} must contain PEM data under tls.crt and tls.key",
                ns, cert_ref.name
            ),
        ));
    }
    Ok(key)
}

/// Resolve `Gateway.spec.tls` into the store's [`GatewayTlsState`] plus the
/// Gateway-level `ResolvedRefs` condition (only reported when a backend client
/// certificate is configured): `(status, reason, message)`.
pub(crate) fn resolve_gateway_tls(
    tls: Option<&crate::gateway_types::GatewayTLS>,
    gateway_namespace: &str,
    store: &ConfigStore,
) -> (GatewayTlsState, Option<(bool, &'static str, String)>) {
    let mut state = GatewayTlsState::default();
    let Some(tls) = tls else {
        return (state, None);
    };
    if let Some(frontend) = tls.frontend.as_ref() {
        state.frontend_default = frontend
            .default
            .validation
            .as_ref()
            .map(|v| resolve_frontend_validation(v, gateway_namespace, store));
        for pp in &frontend.per_port {
            if let Some(v) = pp.tls.validation.as_ref() {
                state
                    .frontend_per_port
                    .insert(pp.port, resolve_frontend_validation(v, gateway_namespace, store));
            }
        }
    }
    let backend_condition = tls
        .backend
        .as_ref()
        .and_then(|b| b.client_certificate_ref.as_ref())
        .map(|cert_ref| match resolve_backend_client_cert(cert_ref, gateway_namespace, store) {
            Ok(key) => {
                state.backend_client_cert_ref = Some(key);
                (true, "ResolvedRefs", "Backend client certificate resolved".to_string())
            }
            Err((reason, message)) => (false, reason, message),
        });
    (state, backend_condition)
}

/// Returns None if the GatewayClass is not accepted (Gateway should be rejected).
#[allow(clippy::too_many_arguments)] // mirrors the Gateway spec fields it evaluates
fn evaluate_gateway(
    name: &str,
    namespace: &str,
    generation: i64,
    gateway_class_name: &str,
    listeners: &[crate::gateway_types::Listener],
    gateway_tls: &GatewayTlsState,
    allowed_listener_namespaces_from: Option<String>,
    allowed_listener_match_labels: Vec<(String, String)>,
    store: &ConfigStore,
) -> (GatewayState, super::PerListenerConditions, bool) {

    // Check GatewayClass exists and is accepted
    let gc_accepted = store
        .gateway_classes
        .get(gateway_class_name)
        .map(|gc| gc.accepted)
        .unwrap_or(false);

    // Extract listener info for conflict detection
    let listener_tuples: Vec<(String, u16, String, Option<String>)> = listeners
        .iter()
        .map(|l| {
            (
                l.name.clone(),
                l.port,
                l.protocol.clone(),
                l.hostname.clone(),
            )
        })
        .collect();

    let conflicts = detect_listener_conflicts(&listener_tuples);

    // Programmed means a data plane serving this Gateway is actually running
    // its current compiled config: data planes report every applied config (by
    // content fingerprint) over ReportApplied, and the store compares against
    // the latest compile of this Gateway's slice (or the global config for a
    // shared data plane).
    let is_programmed = store.is_programmed_for(&NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    });

    let mut listener_states = Vec::new();
    let mut per_listener_conditions = Vec::new();

    for l in listeners {
        let mut accepted = true;
        let mut resolved_refs = true;
        let mut resolved_refs_reason = "ResolvedRefs";
        let mut resolved_refs_message = "All references resolved";
        let conflicted = *conflicts.get(&l.name).unwrap_or(&false);
        let mut tls_cert_refs: Vec<(String, String)> = Vec::new();

        let mut conditions = Vec::new();

        if !gc_accepted {
            // GatewayClass not accepted -- reject all listeners
            accepted = false;
            conditions.push(status::build_condition(
                "Accepted",
                false,
                "InvalidGatewayClass",
                &format!(
                    "GatewayClass '{}' is not accepted by this controller",
                    gateway_class_name
                ),
                generation,
            ));
        } else {
            // Protocol check
            match l.protocol.as_str() {
                "HTTP" | "HTTPS" | "TLS" | "TCP" | "UDP" => {}
                _ => {
                    accepted = false;
                    conditions.push(status::build_condition(
                        "Accepted",
                        false,
                        "UnsupportedProtocol",
                        &format!("Protocol '{}' is not supported", l.protocol),
                        generation,
                    ));
                }
            }

            if accepted {
                conditions.push(status::build_condition(
                    "Accepted",
                    true,
                    "Accepted",
                    "Listener accepted",
                    generation,
                ));
            }
        }

        // Determine supported route kinds for this listener based on protocol.
        // If the listener was rejected (e.g., unsupported TLS mode), report empty kinds.
        let default_kinds: Vec<(&str, &str)> = if !accepted {
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
            "UDP" => vec![("gateway.networking.k8s.io", "UDPRoute")],
            _ => vec![],
        }
        };

        // If allowedRoutes.kinds is specified, filter to only supported kinds
        let supported_kinds: Vec<(String, String)> = if let Some(ref ar) = l.allowed_routes {
            if !ar.kinds.is_empty() {
                let mut valid = Vec::new();
                let mut has_invalid = false;
                for rgk in &ar.kinds {
                    let group = rgk.group.as_deref().unwrap_or("gateway.networking.k8s.io");
                    let kind = rgk.kind.as_str();
                    if default_kinds.iter().any(|(g, k)| *g == group && *k == kind) {
                        valid.push((group.to_string(), kind.to_string()));
                    } else {
                        has_invalid = true;
                    }
                }
                if has_invalid && valid.is_empty() {
                    // All specified kinds are invalid
                    resolved_refs = false;
                    resolved_refs_reason = "InvalidRouteKinds";
                    resolved_refs_message = "None of the specified route kinds are supported for this listener protocol";
                } else if has_invalid {
                    resolved_refs = false;
                    resolved_refs_reason = "InvalidRouteKinds";
                    resolved_refs_message = "Some specified route kinds are not supported for this listener protocol";
                }
                valid
            } else {
                default_kinds.iter().map(|(g, k)| (g.to_string(), k.to_string())).collect()
            }
        } else {
            default_kinds.iter().map(|(g, k)| (g.to_string(), k.to_string())).collect()
        };

        // Validate certificateRefs for HTTPS/TLS listeners
        if resolved_refs && matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
            if let Some(ref tls_config) = l.tls {
                let mode = tls_config.mode.as_deref().unwrap_or("Terminate");
                if mode == "Terminate" {
                    if tls_config.certificate_refs.is_empty() {
                        resolved_refs = false;
                        resolved_refs_reason = "InvalidCertificateRef";
                        resolved_refs_message = "No certificateRefs specified for Terminate mode listener";
                    } else {
                        for cert_ref in &tls_config.certificate_refs {
                            let group = cert_ref.group.as_deref().unwrap_or("");
                            let kind = cert_ref.kind.as_deref().unwrap_or("Secret");
                            // Only core group Secrets are supported
                            if !group.is_empty() || kind != "Secret" {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_message = "CertificateRef must reference a core Secret";
                                break;
                            }
                            // Check cross-namespace reference permission
                            let cert_ns = cert_ref.namespace.as_deref().unwrap_or(namespace);
                            if cert_ns != namespace {
                                // Cross-namespace ref requires a ReferenceGrant in the target namespace
                                let has_grant = store.reference_grants.iter().any(|entry| {
                                    let rg = entry.value();
                                    rg.namespace == cert_ns
                                        && rg.from.iter().any(|f| {
                                            f.group == "gateway.networking.k8s.io"
                                                && f.kind == "Gateway"
                                                && f.namespace == namespace
                                        })
                                        && rg.to.iter().any(|t| {
                                            t.group.is_empty()
                                                && t.kind == "Secret"
                                                && t.name.as_deref().is_none_or(|n| n == cert_ref.name)
                                        })
                                });
                                if !has_grant {
                                    resolved_refs = false;
                                    resolved_refs_reason = "RefNotPermitted";
                                    resolved_refs_message = "Cross-namespace certificate reference not permitted by ReferenceGrant";
                                    break;
                                }
                            }
                            // Check if the secret exists in the store
                            let secret_key = NamespacedName {
                                namespace: cert_ns.to_string(),
                                name: cert_ref.name.clone(),
                            };
                            let secret_entry = store.secrets.get(&secret_key);
                            if secret_entry.is_none() {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_message = "Referenced Secret not found";
                                break;
                            }
                            // Validate that the PEM data in the Secret is well-formed
                            let secret_data = &secret_entry.unwrap();
                            let cert_pem = secret_data.data.get("tls.crt").map(|v| v.as_str()).unwrap_or("");
                            let key_pem = secret_data.data.get("tls.key").map(|v| v.as_str()).unwrap_or("");
                            let cert_valid = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                                .next()
                                .is_some_and(|r| r.is_ok());
                            let key_valid = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                                .ok()
                                .flatten()
                                .is_some();
                            if !cert_valid || !key_valid {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_message = "Referenced Secret contains malformed TLS certificate or key data";
                                break;
                            }
                            tls_cert_refs.push((cert_ns.to_string(), cert_ref.name.clone()));
                        }
                    }
                }
            } else {
                // HTTPS/TLS listener without TLS config
                resolved_refs = false;
                resolved_refs_reason = "InvalidCertificateRef";
                resolved_refs_message = "HTTPS/TLS listener requires TLS configuration";
            }
        }

        // Frontend client certificate validation (spec.tls.frontend) applies to
        // HTTPS listeners: a per-port override or the default. An unusable CA
        // reference fails ResolvedRefs; no usable CA at all also rejects the
        // listener with NoValidCACertificate.
        let mut client_validation_message = String::new();
        if resolved_refs && l.protocol == "HTTPS" {
            match gateway_tls.frontend_validation_for_port(l.port) {
                Some(ClientValidationOutcome::Invalid { reason, message }) => {
                    resolved_refs = false;
                    resolved_refs_reason = reason.as_str();
                    client_validation_message = message.clone();
                    accepted = false;
                    if let Some(c) = conditions.iter_mut().find(|c| c.type_ == "Accepted") {
                        *c = status::build_condition(
                            "Accepted",
                            false,
                            "NoValidCACertificate",
                            "No valid CA certificate for frontend client certificate validation",
                            generation,
                        );
                    }
                }
                Some(ClientValidationOutcome::Valid(v)) => {
                    if let Some((reason, message)) = v.ref_error.as_ref() {
                        resolved_refs = false;
                        resolved_refs_reason = reason.as_str();
                        client_validation_message = message.clone();
                    }
                }
                None => {}
            }
        }
        if !client_validation_message.is_empty() {
            resolved_refs_message = client_validation_message.as_str();
        }

        // Programmed check: once the compiler has produced config, the listener is
        // considered programmed. The data plane DaemonSet binds all configured ports
        // at startup, so port availability is guaranteed by the Helm chart.
        let programmed = is_programmed && resolved_refs;
        if programmed {
            conditions.push(status::build_condition(
                "Programmed",
                true,
                "Programmed",
                "Configuration compiled and available to data plane",
                generation,
            ));
        } else {
            conditions.push(status::build_condition(
                "Programmed",
                false,
                "Pending",
                "Waiting for initial configuration compilation",
                generation,
            ));
        }

        // Conflict condition
        if conflicted {
            conditions.push(status::build_condition(
                "Conflicted",
                true,
                "HostnameConflict",
                "Listener hostname conflicts with another listener on the same port and protocol",
                generation,
            ));
        } else {
            conditions.push(status::build_condition(
                "Conflicted",
                false,
                "NoConflicts",
                "No conflicts detected",
                generation,
            ));
        }

        // ResolvedRefs condition
        conditions.push(status::build_condition(
            "ResolvedRefs",
            resolved_refs,
            resolved_refs_reason,
            resolved_refs_message,
            generation,
        ));

        // AllowedRoutes defaults. Parse selector.matchLabels when `Selector`
        // mode is used so route reconcilers can filter by namespace labels.
        let allowed_routes = l
            .allowed_routes
            .as_ref()
            .map(|ar| {
                let namespaces_from = ar
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
                    namespaces_from,
                    namespace_selector,
                }
            })
            .unwrap_or(AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            });

        // Extract TLS mode for TLS protocol listeners
        let tls_mode = if l.protocol == "TLS" {
            Some(
                l.tls
                    .as_ref()
                    .and_then(|t| t.mode.as_deref())
                    .unwrap_or("Terminate") // Gateway API default is Terminate
                    .to_string(),
            )
        } else {
            None
        };

        listener_states.push(ListenerState {
            name: l.name.clone(),
            port: l.port,
            protocol: l.protocol.clone(),
            hostname: l.hostname.clone(),
            accepted,
            conflicted,
            resolved_refs,
            allowed_routes,
            tls_cert_refs,
            tls_mode,
        });

        per_listener_conditions.push((l.name.clone(), conditions, supported_kinds));
    }

    let gateway_state = GatewayState {
        name: name.to_string(),
        namespace: namespace.to_string(),
        listeners: listener_states,
        generation,
        allowed_listener_namespaces_from,
        allowed_listener_match_labels,
    };

    (gateway_state, per_listener_conditions, gc_accepted)
}

/// How often a Gateway whose dataplane Service is not yet reachable re-probes
/// it. kube-proxy programming a new ClusterIP produces no Kubernetes event.
pub const ADDRESS_PROBE_INTERVAL: Duration = Duration::from_secs(1);

pub async fn reconcile_gateway(
    gw: Arc<Gateway>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    let name = gw
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.name".to_string()))?;
    let namespace = gw
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::MissingField("metadata.namespace".to_string()))?;

    // Skip reconciliation for objects being deleted
    if gw.metadata.deletion_timestamp.is_some() {
        log::info!("Gateway {}/{} is being deleted, skipping reconciliation", namespace, name);
        let key = NamespacedName {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        ctx.store.gateway_tls.remove(&key);
        ctx.store.remove_and_notify(&ctx.store.gateways, &key);
        return Ok(Action::await_change());
    }

    // Skip Gateways that don't use a GatewayClass we manage: writing status to
    // another controller's Gateway would have the two fight over it. Should the
    // class appear later (or be ours but not cached yet at startup), its
    // `Event::GatewayClass` re-runs this Gateway.
    let gateway_class_name = &gw.spec.gateway_class_name;
    if !ctx.store.gateway_classes.contains_key(gateway_class_name.as_str()) {
        log::info!("Gateway {}/{} references GatewayClass '{}', which is not ours (yet)", namespace, name, gateway_class_name);
        return Ok(Action::await_change());
    }

    log::info!("reconciling Gateway {}/{} (class={}, gen={:?})", namespace, name, gateway_class_name, gw.metadata.generation);

    // Kubernetes sets metadata.generation ≥ 1 on creation, but the informer
    // cache may deliver 0 or None for CRDs. Clamp to minimum 1 to avoid writing
    // observedGeneration:0 which conformance tests flag as stale.
    let generation = gw.metadata.generation.unwrap_or(0).max(1);

    let allowed_listener_namespaces_from = gw
        .spec
        .allowed_listeners
        .as_ref()
        .and_then(|al| al.namespaces.as_ref())
        .and_then(|n| n.from.clone());

    let allowed_listener_match_labels: Vec<(String, String)> = gw
        .spec
        .allowed_listeners
        .as_ref()
        .and_then(|al| al.namespaces.as_ref())
        .and_then(|n| n.selector.as_ref())
        .and_then(|s| s.match_labels.as_ref())
        .map(|ml| ml.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    // spec.tls (mTLS): frontend validation per port and the backend client
    // certificate reference, resolved once; the listener evaluation consumes
    // the outcomes and the Gateway-level ResolvedRefs condition the result.
    let (gateway_tls, backend_resolved_refs) = resolve_gateway_tls(gw.spec.tls.as_ref(), namespace, &ctx.store);
    let (state, per_listener_conditions, _gc_accepted) = evaluate_gateway(
        name,
        namespace,
        generation,
        gateway_class_name,
        &gw.spec.listeners,
        &gateway_tls,
        allowed_listener_namespaces_from,
        allowed_listener_match_labels,
        &ctx.store,
    );

    // Store the Gateway; wake the compiler and the dependents (routes bound to
    // it, its ListenerSets) only when something actually changed.
    let key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    let tls_changed = if gateway_tls == GatewayTlsState::default() {
        ctx.store.gateway_tls.remove(&key).is_some()
    } else {
        ctx.store.gateway_tls.insert(key.clone(), gateway_tls.clone()) != Some(gateway_tls.clone())
    };
    let state_changed = ctx.store.insert_and_notify(&ctx.store.gateways, key.clone(), state);
    if tls_changed && !state_changed {
        ctx.store.notify_change();
    }
    if state_changed || tls_changed {
        ctx.store.publish(Event::Gateway(key));
    }

    // Build status for each listener
    let gateway_key = NamespacedName {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    // Look up the gateway state we just inserted to get listener details
    let gateway_state_for_counting = ctx.store.gateways.get(&gateway_key).map(|g| g.clone());

    let listener_statuses: Vec<serde_json::Value> = per_listener_conditions
        .iter()
        .map(|(listener_name, conditions, supported_kinds)| {
            // Find this listener's details (hostname, port, protocol, allowed_routes)
            let listener_info = gateway_state_for_counting.as_ref().and_then(|gs| {
                gs.listeners.iter().find(|l| l.name == *listener_name)
            });

            // Count attached routes from the store — only routes that actually
            // match this specific listener (hostname intersection, protocol,
            // namespace, port, sectionName).
            let attached_routes = ctx.store.http_routes.iter().filter(|entry| {
                let route = entry.value();
                route.parent_refs.iter().any(|pr| {
                    // Must target this gateway and be accepted
                    if pr.gateway_namespace != gateway_key.namespace
                        || pr.gateway_name != gateway_key.name
                        || !pr.accepted
                    {
                        return false;
                    }

                    // If parentRef specifies a sectionName, it must match this listener
                    if let Some(ref sn) = pr.section_name {
                        return sn == listener_name;
                    }

                    // If parentRef specifies a port, it must match this listener's port
                    if let Some(li) = listener_info {
                        if let Some(requested_port) = pr.port
                            && li.port != requested_port {
                                return false;
                            }
                        // Protocol check: HTTPRoute only binds to HTTP/HTTPS
                        if li.protocol != "HTTP" && li.protocol != "HTTPS" {
                            return false;
                        }
                        // Hostname intersection check
                        if !crate::reconcilers::http_route::hostnames_compatible(&li.hostname, &route.hostnames) {
                            return false;
                        }
                        // Namespace check. Pull route-ns labels from the store
                        // cache (populated by http_route reconciler). Empty
                        // when the route hasn't been reconciled yet — in that
                        // case Selector rejects, which is fine: the Gateway
                        // will re-reconcile once labels land and the route is
                        // accepted upstream.
                        let route_ns_labels = ctx
                            .store
                            .namespace_labels
                            .get(&route.namespace)
                            .map(|v| v.value().clone())
                            .unwrap_or_default();
                        if !crate::reconcilers::http_route::namespace_allowed(
                            &li.allowed_routes,
                            &route.namespace,
                            &gateway_key.namespace,
                            &route_ns_labels,
                        ) {
                            return false;
                        }
                        true
                    } else {
                        false
                    }
                })
            }).count() as i64;

            // Also count GRPC routes attached to this listener
            let attached_grpc = ctx.store.grpc_routes.iter().filter(|entry| {
                let route = entry.value();
                route.parent_refs.iter().any(|pr| {
                    if pr.gateway_namespace != gateway_key.namespace
                        || pr.gateway_name != gateway_key.name
                        || !pr.accepted
                    {
                        return false;
                    }
                    if let Some(ref sn) = pr.section_name {
                        return sn == listener_name;
                    }
                    if let Some(li) = listener_info {
                        if li.protocol != "HTTP" && li.protocol != "HTTPS" {
                            return false;
                        }
                        true
                    } else {
                        false
                    }
                })
            }).count() as i64;

            // Also count TLS routes attached to this listener
            let attached_tls = ctx.store.tls_routes.iter().filter(|entry| {
                let route = entry.value();
                route.parent_refs.iter().any(|pr| {
                    if pr.gateway_namespace != gateway_key.namespace
                        || pr.gateway_name != gateway_key.name
                        || !pr.accepted
                    {
                        return false;
                    }
                    if let Some(ref sn) = pr.section_name {
                        return sn == listener_name;
                    }
                    if let Some(li) = listener_info {
                        if li.protocol != "TLS" {
                            return false;
                        }
                        // Hostname intersection: only count routes whose hostnames
                        // intersect with this listener's hostname
                        if let Some(ref lh) = li.hostname
                            && !route.hostnames.is_empty()
                                && !route.hostnames.iter().any(|rh| {
                                    crate::reconcilers::tls_route::hostname_matches_pub(lh, rh)
                                })
                            {
                                return false;
                            }
                        true
                    } else {
                        false
                    }
                })
            }).count() as i64;

            // Also count TCP and UDP routes attached to this listener. Every
            // accepted route counts, including ones the compiler later drops as
            // conflict losers (the spec counts attachment, not programming).
            let attached_l4 = |routes: &dashmap::DashMap<NamespacedName, crate::store::L4RouteState>, protocol: &str| {
                routes.iter().filter(|entry| {
                    let route = entry.value();
                    route.parent_refs.iter().any(|pr| {
                        if pr.gateway_namespace != gateway_key.namespace
                            || pr.gateway_name != gateway_key.name
                            || !pr.accepted
                        {
                            return false;
                        }
                        let Some(li) = listener_info else { return false };
                        if li.protocol != protocol {
                            return false;
                        }
                        if pr.section_name.as_deref().is_some_and(|sn| sn != listener_name) {
                            return false;
                        }
                        if pr.port.is_some_and(|p| p != li.port) {
                            return false;
                        }
                        let route_ns_labels = ctx
                            .store
                            .namespace_labels
                            .get(&route.namespace)
                            .map(|v| v.value().clone())
                            .unwrap_or_default();
                        crate::reconcilers::http_route::namespace_allowed(
                            &li.allowed_routes,
                            &route.namespace,
                            &gateway_key.namespace,
                            &route_ns_labels,
                        )
                    })
                }).count() as i64
            };
            let attached_tcp = attached_l4(&ctx.store.tcp_routes, "TCP");
            let attached_udp = attached_l4(&ctx.store.udp_routes, "UDP");

            let attached_routes = attached_routes + attached_grpc + attached_tls + attached_tcp + attached_udp;

            let kinds_json: Vec<serde_json::Value> = supported_kinds.iter()
                .map(|(g, k)| json!({"group": g, "kind": k}))
                .collect();

            json!({
                "name": listener_name,
                "attachedRoutes": attached_routes,
                "supportedKinds": kinds_json,
                "conditions": conditions.iter().map(|c| json!({
                    "type": c.type_,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message,
                    "observedGeneration": c.observed_generation,
                    "lastTransitionTime": c.last_transition_time.0.to_string(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Build overall gateway conditions.
    let is_programmed = ctx.store.is_programmed_for(&gateway_key);
    let accepted_listeners = per_listener_conditions
        .iter()
        .filter(|(_, conds, _)| conds.iter().any(|c| c.type_ == "Accepted" && c.status == "True"))
        .count();
    let gc_reject_msg = format!("GatewayClass '{}' is not accepted", gateway_class_name);
    let (gw_accepted, gw_reason, gw_message): (bool, &str, String) =
        gateway_accepted_condition(
            _gc_accepted,
            &gc_reject_msg,
            gw.spec.infrastructure.as_ref().and_then(|i| i.parameters_ref.as_ref()),
            &gw.spec.addresses,
            per_listener_conditions.len(),
            accepted_listeners,
        );
    let mut gateway_conditions = vec![status::build_condition(
            "Accepted",
            gw_accepted,
            gw_reason,
            &gw_message,
            generation,
        ),
        status::build_condition(
            "Programmed",
            is_programmed,
            if is_programmed { "Programmed" } else { "Pending" },
            if is_programmed {
                "Configuration applied by the data plane"
            } else {
                "Waiting for a data plane to apply the current configuration"
            },
            generation,
        )];
    // spec.tls.backend.clientCertificateRef → Gateway ResolvedRefs.
    if let Some((ok, reason, message)) = backend_resolved_refs.as_ref() {
        gateway_conditions.push(status::build_condition(
            "ResolvedRefs",
            *ok,
            reason,
            message,
            generation,
        ));
    }
    // Any AllowInsecureFallback frontend validation is surfaced on the Gateway;
    // the condition disappears (server-side apply) once every mode is strict.
    if gateway_tls.has_insecure_fallback() {
        gateway_conditions.push(status::build_condition(
            "InsecureFrontendValidationMode",
            true,
            "ConfigurationChanged",
            "Frontend client certificate validation allows insecure fallback: connections without a valid client certificate are accepted",
            generation,
        ));
    }

    // Gateway addresses: the provisioner owns a Deployment, Service and PDB
    // per Gateway and the Service's address is reported.
    let template = dataplane_template();
    // Set when a Gateway's address is being held back until its dataplane is
    // reachable; drives a fast requeue.
    let mut addresses_withheld = false;
    let addresses: Vec<serde_json::Value> = if gw_accepted {
        use super::provisioner::{L4Protocol, ListenerPort};
        let mut ports: Vec<ListenerPort> = gw
            .spec
            .listeners
            .iter()
            .map(|l| ListenerPort { port: l.port, protocol: L4Protocol::of_listener(&l.protocol) })
            .collect();
        ports.extend(
            ctx.store
                .listener_sets
                .iter()
                .filter(|e| {
                    let ls = e.value();
                    ls.accepted && ls.parent_gateway.namespace == namespace && ls.parent_gateway.name == name
                })
                .flat_map(|e| {
                    e.value()
                        .listeners
                        .iter()
                        .map(|l| ListenerPort { port: l.port, protocol: L4Protocol::of_listener(&l.protocol) })
                        .collect::<Vec<_>>()
                }),
        );
        match super::provisioner::gateway_ref(&gw, ports) {
            Some(gw_ref) => match super::provisioner::apply(&ctx.client, &gw_ref, template).await {
                Ok(svc) => {
                    // Publishing the ClusterIP before the node can route to it
                    // makes clients that dial at once hang on a never-DNAT'd
                    // conntrack entry. A ready endpoint is necessary (the
                    // EndpointSlice watch re-runs this reconcile) but not
                    // sufficient: kube-proxy programs the Service later still,
                    // so the controller also connects to the ClusterIP itself
                    // before it advertises it. Only done while unpublished.
                    let already_published = gw.status.as_ref().is_some_and(|s| !s.addresses.is_empty());
                    let reachable = if !super::provisioner::service_has_ready_endpoints(&ctx.store, &svc) {
                        log::info!(
                            "Gateway {}/{}: dataplane Service has no ready endpoint yet; withholding status.addresses",
                            namespace, name
                        );
                        false
                    } else if already_published {
                        true
                    } else {
                        match super::provisioner::probe_target(&svc) {
                            Some(target) => {
                                let ok = super::provisioner::tcp_reachable(target, Duration::from_millis(1500)).await;
                                if !ok {
                                    log::info!(
                                        "Gateway {}/{}: dataplane Service {} not reachable yet; withholding status.addresses",
                                        namespace, name, target
                                    );
                                }
                                ok
                            }
                            None => true,
                        }
                    };
                    if !reachable {
                        addresses_withheld = true;
                        Vec::new()
                    } else {
                        if super::provisioner::load_balancer_pending(&svc) {
                            log::info!(
                                "Gateway {}/{}: LoadBalancer address pending; reporting ClusterIP meanwhile",
                                namespace, name
                            );
                        }
                        super::provisioner::addresses_from_service(&svc)
                            .into_iter()
                            .map(|a| json!({"type": a.type_.unwrap_or_else(|| "IPAddress".into()), "value": a.value}))
                            .collect()
                    }
                }
                Err(e) => {
                    log::error!("Gateway {}/{}: provisioning failed: {}", namespace, name, e);
                    return Err(e.into());
                }
            },
            None => Vec::new(),
        }
    } else {
        // A Gateway that is not accepted gets no dataplane and therefore no address.
        Vec::new()
    };

    // Count accepted ListenerSets whose parent Gateway is this one. The
    // count is reported as `attachedListenerSets` in status per Gateway API
    // ListenerSet spec (used by conformance GatewayMustHaveAttachedListeners).
    let attached_listener_sets: i32 = ctx
        .store
        .listener_sets
        .iter()
        .filter(|entry| {
            let st = entry.value();
            st.accepted
                && st.parent_gateway.namespace == namespace
                && st.parent_gateway.name == name
        })
        .count() as i32;

    let desired_status = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "status": {
            "addresses": addresses,
            "conditions": gateway_conditions.iter().map(|c| json!({
                "type": c.type_,
                "status": c.status,
                "reason": c.reason,
                "message": c.message,
                "observedGeneration": c.observed_generation,
                "lastTransitionTime": c.last_transition_time.0.to_string(),
            })).collect::<Vec<_>>(),
            "listeners": listener_statuses,
            "attachedListenerSets": attached_listener_sets,
        }
    });

    // Build a combined list of all conditions (gateway + listener) for diff check.
    // This ensures we detect changes in listener conditions (e.g., ResolvedRefs
    // transitioning from False to True) without causing a write storm.
    let all_desired_conditions: Vec<Condition> = gateway_conditions
        .iter()
        .cloned()
        .chain(per_listener_conditions.iter().flat_map(|(_, conds, _)| conds.iter().cloned()))
        .collect();

    // Collect all current conditions (gateway-level + listener-level)
    let mut all_current_conditions: Vec<Condition> = gw
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    if let Some(ref status) = gw.status {
        for ls in &status.listeners {
            all_current_conditions.extend(ls.conditions.clone());
        }
    }

    // Also check if attachedRoutes changed (not captured by conditions diff)
    let attached_routes_changed = gw.status.as_ref().is_none_or(|s| {
        s.listeners.iter().zip(listener_statuses.iter()).any(|(current, desired)| {
            let desired_count = desired.get("attachedRoutes").and_then(|v| v.as_i64()).unwrap_or(0);
            current.attached_routes != desired_count as i32
        }) || s.listeners.len() != listener_statuses.len()
            || s.attached_listener_sets.unwrap_or(0) != attached_listener_sets
    });

    let conditions_changed = !status::conditions_equal(&all_current_conditions, &all_desired_conditions);
    // Addresses can change with no condition change (they appear once the
    // dataplane Service has a ready endpoint), so they need their own check.
    let desired_addresses: Vec<(String, String)> = addresses
        .iter()
        .map(|a| {
            (
                a.get("type").and_then(|v| v.as_str()).unwrap_or("IPAddress").to_string(),
                a.get("value").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            )
        })
        .collect();
    let current_addresses: Vec<crate::gateway_types::GatewayAddress> =
        gw.status.as_ref().map(|s| s.addresses.clone()).unwrap_or_default();
    let addresses_changed = super::provisioner::addresses_changed(&current_addresses, &desired_addresses);
    log::info!(
        "Gateway {}/{}: gen={}, gc_accepted={}, listeners={}, attached_routes_changed={}, conditions_changed={}, addresses_changed={}, current_status={}",
        namespace, name, generation, _gc_accepted,
        per_listener_conditions.len(), attached_routes_changed, conditions_changed, addresses_changed,
        if gw.status.is_some() { "present" } else { "none" }
    );

    let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), namespace);
    if attached_routes_changed || addresses_changed {
        log::info!("Gateway {}/{}: patching status (attached_routes_changed={}, addresses_changed={})", namespace, name, attached_routes_changed, addresses_changed);
        let pp = kube::api::PatchParams::apply("portus-gateway").force();
        match status::with_write_timeout(
            "Gateway status patch",
            api.patch_status(name, &pp, &kube::api::Patch::Apply(desired_status)),
        )
        .await
        {
            Ok(_) => log::info!("Gateway {}/{}: status patched successfully", namespace, name),
            Err(e) => {
                log::error!("Gateway {}/{}: status patch FAILED: {}", namespace, name, e);
                return Err(e.into());
            }
        }
    } else if conditions_changed {
        log::info!("Gateway {}/{}: patching status (conditions_changed)", namespace, name);
        match status::patch_status_if_changed(
            &api,
            name,
            desired_status,
            &all_current_conditions,
            &all_desired_conditions,
        ).await {
            Ok(_) => log::info!("Gateway {}/{}: status patched successfully", namespace, name),
            Err(e) => {
                log::error!("Gateway {}/{}: status patch FAILED: {}", namespace, name, e);
                return Err(e.into());
            }
        }
    } else {
        log::debug!("Gateway {}/{}: status unchanged, skipping patch", namespace, name);
    }

    // Everything this status derives from re-runs the Gateway through the
    // store's events (its class, routes and ListenerSets, data plane acks,
    // Secrets/ConfigMaps/ReferenceGrants its TLS refs name, Namespace labels);
    // see `triggers::gateways_for`. The one thing with no event is kube-proxy
    // programming the ClusterIP: while the address is withheld pending the
    // reachability probe, poll for it.
    if addresses_withheld {
        Ok(Action::requeue(ADDRESS_PROBE_INTERVAL))
    } else {
        Ok(Action::await_change())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;
    use crate::store::GatewayClassState;

    #[test]
    fn gateway_accepted_condition_matrix() {
        // gateway-invalid-listeners-unsupported-protocol: none accepted → False/ListenersNotValid
        let (ok, reason, _) = gateway_accepted_condition(true, "", None, &[], 1, 0);
        assert!(!ok);
        assert_eq!(reason, "ListenersNotValid");
        // one of two accepted → True but reason ListenersNotValid
        let (ok, reason, msg) = gateway_accepted_condition(true, "", None, &[], 2, 1);
        assert!(ok);
        assert_eq!(reason, "ListenersNotValid");
        assert!(msg.contains("1 of 2"));
        // all accepted → Accepted
        let (ok, reason, _) = gateway_accepted_condition(true, "", None, &[], 2, 2);
        assert!(ok);
        assert_eq!(reason, "Accepted");
        // gateway-invalid-parameters-ref: unknown parametersRef → False/InvalidParameters
        let pr = crate::gateway_types::LocalParametersReference {
            group: "invalid.io".into(),
            kind: "InvalidParameters".into(),
            name: "invalid".into(),
        };
        let (ok, reason, msg) = gateway_accepted_condition(true, "", Some(&pr), &[], 1, 1);
        assert!(!ok);
        assert_eq!(reason, "InvalidParameters");
        assert!(msg.contains("invalid.io/InvalidParameters"));
        // GatewayClass rejection wins over everything
        let (ok, reason, _) = gateway_accepted_condition(false, "no class", Some(&pr), &[], 1, 1);
        assert!(!ok);
        assert_eq!(reason, "InvalidGatewayClass");

        use crate::gateway_types::GatewayAddress;
        // gateway-optional-address-value: IPAddress with no value → assigned, Accepted
        let empty = [GatewayAddress { type_: Some("IPAddress".into()), value: String::new() }];
        let (ok, reason, _) = gateway_accepted_condition(true, "", None, &empty, 1, 1);
        assert!(ok);
        assert_eq!(reason, "Accepted");
        // type omitted defaults to IPAddress
        let untyped = [GatewayAddress { type_: None, value: String::new() }];
        assert!(gateway_accepted_condition(true, "", None, &untyped, 1, 1).0);
        // gateway-static-addresses: a made-up type → False/UnsupportedAddress
        let weird = [GatewayAddress { type_: Some("test/fake-invalid-type".into()), value: "x".into() }];
        let (ok, reason, _) = gateway_accepted_condition(true, "", None, &weird, 1, 1);
        assert!(!ok);
        assert_eq!(reason, "UnsupportedAddress");
        // a specific value we cannot honour → False/AddressNotUsable
        let fixed = [GatewayAddress { type_: Some("IPAddress".into()), value: "203.0.113.9".into() }];
        let (ok, reason, msg) = gateway_accepted_condition(true, "", None, &fixed, 1, 1);
        assert!(!ok);
        assert_eq!(reason, "AddressNotUsable");
        assert!(msg.contains("203.0.113.9"));
    }
    use std::sync::atomic::Ordering;

    /// Valid self-signed test certificate PEM for gateway reconciler tests.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUO6iOI0P6T4JEa3FQbF3xvHBRaaswDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTgxNDUwMTlaFw0yNzAzMTgxNDUw
MTlaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC1ZLq3y+22Bhwkm9oK8LnsWVeGrKpoxILfB569DkJ7FITvTsRn18WZZh4P
Egl5crq/o87aYfM2Qx9Ow+iMt+HxOw9j/mpya7cLh2m8zXspv28xKYHbWEDYjjah
Jb1V4ucumfA6hEv+h99k+WzKnrgTg2m1rLv/gtOKu9VbR2Tjv5VA0yA8XLgdHpxr
tR26h14ezPa/9v4YczcD9sgtZCNFwZqYBY7prBR/GrtPBXxKpYq3Meo+vzxGqGlA
h6VxAIoY9BKZM1vdHCHjNnwU0kj3Lztquo88DTLHQyBmfGWrzQrs1vPzuAvD+Arf
XLCeld9H9UYUNYdWT3WfMyZJ07O1AgMBAAGjUzBRMB0GA1UdDgQWBBSPQb95r2Ly
25Qgqmb9qE3KZEODWjAfBgNVHSMEGDAWgBSPQb95r2Ly25Qgqmb9qE3KZEODWjAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8l2bP9UMApJdLrF1B
HXfrM941pdxYjtmNI/oJrQzT00umgOckh+oJC7cncJPYg0jdPg56MLI9MrcBcBaq
AsCstyeQ1rL6EuE/hQGqCR/PQl25ZX/rIRFnTGA30/q0zFeGBGOddTlFvK+uD5O3
EYsgsl7mnTSGpqEW83+tgklXbtwxnf+jOMbahymNvdMV7t1CHgkbx4nRRkEEkzms
fEN9hrnfkBWqXxcQsGe4v+TkTBA7Z28/DU+Op8+HJXJMKgbgKIVHFJhs4gxX2KyG
b7EKBEd98V2A0gT9iRJtX3yROCne72040GT/L58tqmK9AoFEdO63cyNQW7Q+SPX3
HkQ2
-----END CERTIFICATE-----
";

    /// Valid test private key PEM for gateway reconciler tests.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1ZLq3y+22Bhwk
m9oK8LnsWVeGrKpoxILfB569DkJ7FITvTsRn18WZZh4PEgl5crq/o87aYfM2Qx9O
w+iMt+HxOw9j/mpya7cLh2m8zXspv28xKYHbWEDYjjahJb1V4ucumfA6hEv+h99k
+WzKnrgTg2m1rLv/gtOKu9VbR2Tjv5VA0yA8XLgdHpxrtR26h14ezPa/9v4YczcD
9sgtZCNFwZqYBY7prBR/GrtPBXxKpYq3Meo+vzxGqGlAh6VxAIoY9BKZM1vdHCHj
NnwU0kj3Lztquo88DTLHQyBmfGWrzQrs1vPzuAvD+ArfXLCeld9H9UYUNYdWT3Wf
MyZJ07O1AgMBAAECggEAAopkLaWRGfKPairCG1Me6PoVjDPLFiHW1q7aXdzH5zpR
5CWe6m0OyYqZynNWIbnJAotnQdSuSUjpY0Dw1BEu5TlruPH+1DlvohGdMWz0zGHk
S0BA8Ljm5idllQbz1jLAkCuHm2AHKwBKi4awQx6ctTn8a3/O2qNkipAU7ez+szUo
37rLbUKFMZzLAx6m032E/NvO35M8h7/mNxGuM5H1HlQVEoh2+2UxkWFyQA8cdZJW
iaK4HSjaXF07cL6L5QATmgjablwh1H+aX8/PCm9IQZdlb6LK/4JmGfx64GwVSPgV
rvbfiTO09lAsSuHR3Gd4OTvk3/f+oEGbY4aUe4M0BQKBgQDaP21QBmSMcaiYssp/
74a1GLlEFKnPslW9W9UaoqBF4TBlc6fJFd6yUOpuEc4iH2f+hNM06sAGV+ffTTiG
KfCGnxwGtkjMtHe/EaljBmDL1nZ0Bkxe9Lxeo/yg1PLs4owzqs+kxB154KvTkYRV
rm+7LNMQmV8J8rCdZzhzcx//6wKBgQDUxUyxy80lHeM3v3M9Ov8batCcGTtAevAT
cCDRBL/4mBTV5IbuTl2VFVZ2C4XbIdCFIVyfgbgzcCVgMuaWMBMQznnG46WEj/dH
UguUaYBHxHQwP2z45aSBEmemIktpIMyWg+uvnKJ1vUEYGmvPYKd5es/7DTfI80mn
C6TL9s/S3wKBgQCsL2hVv4VqjG1gc4Zx4w7bJ7Na9BZ5J5Cfgakih3V9TEm7cMDK
U/fLpS0fQ+rmXvLUCgT79c0j9AyazziuGL6L51HcNco/vo3O7+c8mhaaGwx/Q0zT
ibBn1mcEmJ1DqQTF6phBvPwoYMoPc/n9A09hU979dJNXrOIMfRg7dXOkmwKBgQDA
9PTqwPKYWJR5OCygOOKl0KbDCbbMcTFLz4JTTEV0gydSGt+rOnJwA1vXzfdklTPv
qCPBm/ia3Xdn2IF5bru7oCScFFNE9vLAQU2zGEJ301ezcbG3vzsCutg4uB0/h7lC
Pvz808YZlLp1y3A+L19yMchv2rreiJQg49ReDMTIbQKBgAVFIvfRHcJGFUBFgib5
stultj5NYwHr8G7RaufGxIjSFBBMCcM1q065B0rIJUAj6rva964eBw4TttbirWcw
pIUuKXreNfPmDYPLcXSYucPu5RcSjRaZkwzic97AN+hP2ouXLtwJAQWyT9qqOJVa
mlMFuOUI1YNH4Hyldg8G3cWE
-----END PRIVATE KEY-----
";

    /// Helper: create a valid TLS secret state with parseable PEM data.
    fn make_valid_tls_secret() -> crate::store::SecretState {
        crate::store::SecretState {
            data: std::collections::HashMap::from([
                ("tls.crt".to_string(), TEST_CERT_PEM.to_string()),
                ("tls.key".to_string(), TEST_KEY_PEM.to_string()),
            ]),
        }
    }

    // --- hostnames_overlap tests ---

    #[test]
    fn test_hostnames_overlap_same() {
        assert!(hostnames_overlap(
            Some("example.com"),
            Some("example.com")
        ));
    }

    #[test]
    fn test_hostnames_overlap_different() {
        assert!(!hostnames_overlap(
            Some("example.com"),
            Some("other.com")
        ));
    }

    #[test]
    fn test_hostnames_overlap_wildcard_match() {
        assert!(hostnames_overlap(
            Some("*.example.com"),
            Some("foo.example.com")
        ));
    }

    #[test]
    fn test_hostnames_overlap_wildcard_reverse() {
        assert!(hostnames_overlap(
            Some("foo.example.com"),
            Some("*.example.com")
        ));
    }

    #[test]
    fn test_hostnames_overlap_wildcard_no_match() {
        assert!(!hostnames_overlap(
            Some("*.example.com"),
            Some("bar.other.com")
        ));
    }

    #[test]
    fn test_hostnames_overlap_none_left() {
        assert!(hostnames_overlap(None, Some("foo.example.com")));
    }

    #[test]
    fn test_hostnames_overlap_none_right() {
        assert!(hostnames_overlap(Some("foo.example.com"), None));
    }

    #[test]
    fn test_hostnames_overlap_both_none() {
        assert!(hostnames_overlap(None, None));
    }

    #[test]
    fn test_hostnames_overlap_wildcard_does_not_match_wildcard_different_domain() {
        assert!(!hostnames_overlap(
            Some("*.example.com"),
            Some("*.other.com")
        ));
    }

    // --- detect_listener_conflicts tests ---

    #[test]
    fn test_conflict_same_port_same_hostname() {
        let listeners = vec![
            ("l1".to_string(), 80, "HTTP".to_string(), Some("example.com".to_string())),
            ("l2".to_string(), 80, "HTTP".to_string(), Some("example.com".to_string())),
        ];
        let conflicts = detect_listener_conflicts(&listeners);
        assert!(*conflicts.get("l1").unwrap_or(&false));
        assert!(*conflicts.get("l2").unwrap_or(&false));
    }

    #[test]
    fn test_no_conflict_different_ports() {
        let listeners = vec![
            ("l1".to_string(), 80, "HTTP".to_string(), Some("example.com".to_string())),
            ("l2".to_string(), 443, "HTTPS".to_string(), Some("example.com".to_string())),
        ];
        let conflicts = detect_listener_conflicts(&listeners);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflict_wildcard_overlap() {
        let listeners = vec![
            ("l1".to_string(), 80, "HTTP".to_string(), Some("*.example.com".to_string())),
            ("l2".to_string(), 80, "HTTP".to_string(), Some("foo.example.com".to_string())),
        ];
        let conflicts = detect_listener_conflicts(&listeners);
        assert!(*conflicts.get("l1").unwrap_or(&false));
        assert!(*conflicts.get("l2").unwrap_or(&false));
    }

    #[test]
    fn test_conflict_none_hostname_with_specific() {
        let listeners = vec![
            ("l1".to_string(), 80, "HTTP".to_string(), None),
            ("l2".to_string(), 80, "HTTP".to_string(), Some("example.com".to_string())),
        ];
        let conflicts = detect_listener_conflicts(&listeners);
        assert!(*conflicts.get("l1").unwrap_or(&false));
        assert!(*conflicts.get("l2").unwrap_or(&false));
    }

    #[test]
    fn test_no_conflict_different_protocols_same_port() {
        // Different protocols on same port should not conflict
        let listeners = vec![
            ("l1".to_string(), 80, "HTTP".to_string(), Some("example.com".to_string())),
            ("l2".to_string(), 80, "TCP".to_string(), Some("example.com".to_string())),
        ];
        let conflicts = detect_listener_conflicts(&listeners);
        assert!(conflicts.is_empty());
    }

    // --- evaluate_gateway tests ---

    fn make_store_with_class() -> Arc<ConfigStore> {
        let store = Arc::new(ConfigStore::new());
        store.gateway_classes.insert(
            "my-class".to_string(),
            GatewayClassState {
                accepted: true,
                generation: 1,
            },
        );
        store
    }

    fn make_listener_spec(name: &str, port: u16, protocol: &str, hostname: Option<&str>) -> crate::gateway_types::Listener {
        crate::gateway_types::Listener {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: hostname.map(|s| s.to_string()),
            tls: None,
            allowed_routes: None,
        }
    }

    #[test]
    fn test_gateway_accepted_with_valid_class() {
        let store = make_store_with_class();
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, conditions, gc_accepted) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(gc_accepted);
        assert_eq!(state.listeners.len(), 1);
        assert!(state.listeners[0].accepted);

        // Check per-listener conditions
        let (_, conds, _) = &conditions[0];
        let accepted_cond = conds.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted_cond.status, "True");
    }

    #[test]
    fn test_gateway_rejected_with_invalid_class() {
        let store = make_store_with_class();
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, conditions, gc_accepted) =
            evaluate_gateway("my-gw", "default", 1, "nonexistent-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(!gc_accepted);
        assert!(!state.listeners[0].accepted);

        let (_, conds, _) = &conditions[0];
        let accepted_cond = conds.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted_cond.status, "False");
        assert_eq!(accepted_cond.reason, "InvalidGatewayClass");
    }

    #[test]
    fn test_listener_not_programmed_when_no_compiled_config() {
        let store = make_store_with_class();
        // compiled_version is 0 (default) -- not yet programmed
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(state.listeners[0].accepted);

        let (_, conds, _) = &conditions[0];
        let prog_cond = conds.iter().find(|c| c.type_ == "Programmed").unwrap();
        assert_eq!(prog_cond.status, "False");
        assert_eq!(prog_cond.reason, "Pending");
    }

    #[test]
    fn test_listener_not_programmed_until_a_data_plane_applies_it() {
        let store = make_store_with_class();
        // Compiled, but no data plane has reported applying this content yet.
        store.compiled_version.store(1, Ordering::Release);
        store.compiled_fingerprint.store(0xf00d, Ordering::Release);
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(state.listeners[0].accepted);
        let (_, conds, _) = &conditions[0];
        let prog_cond = conds.iter().find(|c| c.type_ == "Programmed").unwrap();
        assert_eq!(prog_cond.status, "False");
        assert_eq!(prog_cond.reason, "Pending");

        // A data plane running *other* content does not count.
        store
            .data_plane_applied
            .insert("node-1".to_string(), crate::store::AppliedState { gateway: NamespacedName { namespace: "default".to_string(), name: "my-gw".to_string() }, fingerprint: 0xbad });
        let (_, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);
        let (_, conds, _) = &conditions[0];
        assert_eq!(conds.iter().find(|c| c.type_ == "Programmed").unwrap().status, "False");
    }

    #[test]
    fn test_listener_port_bound_and_programmed() {
        let store = make_store_with_class();
        store.compiled_version.store(5, Ordering::Release);
        store.compiled_fingerprint.store(0xf00d, Ordering::Release);
        store.compiled_gateway_fingerprints.insert(
            NamespacedName { namespace: "default".to_string(), name: "my-gw".to_string() },
            0xf00d,
        );
        store
            .data_plane_applied
            .insert("node-1".to_string(), crate::store::AppliedState { gateway: NamespacedName { namespace: "default".to_string(), name: "my-gw".to_string() }, fingerprint: 0xf00d });
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(state.listeners[0].accepted);

        let (_, conds, _) = &conditions[0];
        let prog_cond = conds.iter().find(|c| c.type_ == "Programmed").unwrap();
        assert_eq!(prog_cond.status, "True");
        assert_eq!(prog_cond.reason, "Programmed");
    }

    #[test]
    fn test_allowed_routes_defaults_to_same_namespace() {
        let store = make_store_with_class();

        // Listener with no allowedRoutes set
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, _, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert_eq!(state.listeners[0].allowed_routes.namespaces_from, "Same");
    }

    #[test]
    fn test_conflicting_listeners_detected() {
        let store = make_store_with_class();
        let listeners = vec![
            make_listener_spec("l1", 80, "HTTP", Some("example.com")),
            make_listener_spec("l2", 80, "HTTP", Some("example.com")),
        ];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(state.listeners[0].conflicted);
        assert!(state.listeners[1].conflicted);

        // Check Conflicted condition
        let (_, conds_l1, _) = &conditions[0];
        let conflict_cond = conds_l1.iter().find(|c| c.type_ == "Conflicted").unwrap();
        assert_eq!(conflict_cond.status, "True");
        assert_eq!(conflict_cond.reason, "HostnameConflict");
    }

    #[test]
    fn test_non_conflicting_listeners() {
        let store = make_store_with_class();
        let listeners = vec![
            make_listener_spec("l1", 80, "HTTP", Some("foo.example.com")),
            make_listener_spec("l2", 80, "HTTP", Some("bar.other.com")),
        ];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(!state.listeners[0].conflicted);
        assert!(!state.listeners[1].conflicted);

        let (_, conds_l1, _) = &conditions[0];
        let conflict_cond = conds_l1.iter().find(|c| c.type_ == "Conflicted").unwrap();
        assert_eq!(conflict_cond.status, "False");
    }

    #[test]
    fn test_gateway_inserts_into_store() {
        let store = make_store_with_class();
        let listeners = vec![make_listener_spec("http", 80, "HTTP", None)];

        let (state, _, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gw".to_string(),
        };
        store.gateways.insert(key.clone(), state);
        store.notify_change();

        assert!(store.gateways.contains_key(&key));
        let entry = store.gateways.get(&key).unwrap();
        assert_eq!(entry.listeners.len(), 1);
        assert_eq!(entry.generation, 1);
    }

    #[test]
    fn test_unsupported_protocol_rejected() {
        let store = make_store_with_class();
        let listeners = vec![make_listener_spec("weird", 80, "SCTP", None)];

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &listeners, &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(!state.listeners[0].accepted);
        let (_, conds, _) = &conditions[0];
        let accepted_cond = conds.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted_cond.reason, "UnsupportedProtocol");
    }

    #[test]
    fn test_tls_terminate_listener_accepted() {
        // TLS Terminate mode should be accepted (not rejected as UnsupportedValue).
        let store = make_store_with_class();
        let mut listener = make_listener_spec("tls-terminate", 8443, "TLS", Some("example.com"));
        listener.tls = Some(crate::gateway_types::GatewayTLSConfig {
            mode: Some("Terminate".to_string()),
            certificate_refs: vec![crate::gateway_types::SecretObjectReference {
                group: None,
                kind: None,
                name: "tls-secret".to_string(),
                namespace: None,
            }],
        });

        // Add the secret to the store so ResolvedRefs passes
        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-secret".to_string(),
            },
            make_valid_tls_secret(),
        );

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &[listener], &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(
            state.listeners[0].accepted,
            "TLS Terminate listener should be accepted"
        );
        assert_eq!(
            state.listeners[0].tls_mode,
            Some("Terminate".to_string()),
            "tls_mode should be set to Terminate"
        );
        assert_eq!(
            state.listeners[0].tls_cert_refs,
            vec![("default".to_string(), "tls-secret".to_string())],
            "cert refs should be populated"
        );

        let (_, conds, _) = &conditions[0];
        let accepted_cond = conds.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted_cond.status, "True");
    }

    #[test]
    fn test_tls_passthrough_listener_accepted() {
        // TLS Passthrough mode should still be accepted.
        let store = make_store_with_class();
        let mut listener = make_listener_spec("tls-passthrough", 443, "TLS", Some("*.example.com"));
        listener.tls = Some(crate::gateway_types::GatewayTLSConfig {
            mode: Some("Passthrough".to_string()),
            certificate_refs: vec![],
        });

        let (state, conditions, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &[listener], &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(
            state.listeners[0].accepted,
            "TLS Passthrough listener should be accepted"
        );
        assert_eq!(
            state.listeners[0].tls_mode,
            Some("Passthrough".to_string()),
            "tls_mode should be set to Passthrough"
        );

        let (_, conds, _) = &conditions[0];
        let accepted_cond = conds.iter().find(|c| c.type_ == "Accepted").unwrap();
        assert_eq!(accepted_cond.status, "True");
    }

    #[test]
    fn test_tls_default_mode_is_terminate() {
        // When no TLS mode is specified, Gateway API default is Terminate.
        let store = make_store_with_class();
        let mut listener = make_listener_spec("tls-default", 8443, "TLS", Some("example.com"));
        listener.tls = Some(crate::gateway_types::GatewayTLSConfig {
            mode: None, // Default
            certificate_refs: vec![crate::gateway_types::SecretObjectReference {
                group: None,
                kind: None,
                name: "tls-secret".to_string(),
                namespace: None,
            }],
        });

        store.secrets.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "tls-secret".to_string(),
            },
            make_valid_tls_secret(),
        );

        let (state, _, _) =
            evaluate_gateway("my-gw", "default", 1, "my-class", &[listener], &GatewayTlsState::default(), None, Vec::new(), &store);

        assert!(state.listeners[0].accepted);
        assert_eq!(
            state.listeners[0].tls_mode,
            Some("Terminate".to_string()),
            "Default TLS mode should be Terminate"
        );
    }

    // --- Issue 2: attachedRoutes count per-listener ---

    #[allow(unused_imports)]
    use crate::store::{HTTPRouteState, ParentKind, ParentRefState};

    /// Count attached routes for a specific listener using the same logic
    /// as the gateway reconciler (hostname intersection, protocol, namespace).
    fn count_attached_routes_for_listener(
        store: &ConfigStore,
        gateway_key: &NamespacedName,
        listener: &crate::store::ListenerState,
    ) -> i64 {
        store.http_routes.iter().filter(|entry| {
            let route = entry.value();
            route.parent_refs.iter().any(|pr| {
                if pr.gateway_namespace != gateway_key.namespace
                    || pr.gateway_name != gateway_key.name
                    || !pr.accepted
                {
                    return false;
                }
                if let Some(ref sn) = pr.section_name {
                    return sn == &listener.name;
                }
                if let Some(requested_port) = pr.port
                    && listener.port != requested_port {
                        return false;
                    }
                if listener.protocol != "HTTP" && listener.protocol != "HTTPS" {
                    return false;
                }
                if !crate::reconcilers::http_route::hostnames_compatible(&listener.hostname, &route.hostnames) {
                    return false;
                }
                let route_ns_labels = store
                    .namespace_labels
                    .get(&route.namespace)
                    .map(|v| v.value().clone())
                    .unwrap_or_default();
                if !crate::reconcilers::http_route::namespace_allowed(
                    &listener.allowed_routes,
                    &route.namespace,
                    &gateway_key.namespace,
                    &route_ns_labels,
                ) {
                    return false;
                }
                true
            })
        }).count() as i64
    }

    #[test]
    fn test_attached_routes_hostname_intersection() {
        // Mirrors the HostnameIntersection conformance test:
        // Gateway with 3 listeners, 5 routes. Expected counts: 2, 1, 1
        let store = Arc::new(ConfigStore::new());

        let gw_key = NamespacedName {
            namespace: "infra".to_string(),
            name: "gw".to_string(),
        };
        let listener1 = crate::store::ListenerState {
            name: "listener-1".to_string(),
            port: 80,
            protocol: "HTTP".to_string(),
            hostname: Some("very.specific.com".to_string()),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: crate::store::AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: None,
        };
        let listener2 = crate::store::ListenerState {
            name: "listener-2".to_string(),
            hostname: Some("*.wildcard.io".to_string()),
            ..listener1.clone()
        };
        let listener3 = crate::store::ListenerState {
            name: "listener-3".to_string(),
            hostname: Some("*.anotherwildcard.io".to_string()),
            ..listener1.clone()
        };
        store.gateways.insert(
            gw_key.clone(),
            GatewayState {
                name: "gw".to_string(),
                namespace: "infra".to_string(),
                listeners: vec![listener1.clone(), listener2.clone(), listener3.clone()],
                generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );

        let parent = ParentRefState {
            parent_kind: ParentKind::Gateway,
            gateway_namespace: "infra".to_string(),
            gateway_name: "gw".to_string(),
            section_name: None, // no sectionName — must match per-listener
            port: None,
            accepted: true,
            resolved_refs: true,
            reject_reason: None,
        };

        // Route 1: hostnames include "very.specific.com" -> matches listener-1
        store.http_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "route-specific".to_string() },
            HTTPRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["non.matching.com".to_string(), "very.specific.com".to_string()],
                parent_refs: vec![parent.clone()],
                rules: vec![],
                generation: 1,
            },
        );

        // Route 2: hostnames include "foo.wildcard.io" -> matches listener-2
        store.http_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "route-wildcard".to_string() },
            HTTPRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["foo.wildcard.io".to_string()],
                parent_refs: vec![parent.clone()],
                rules: vec![],
                generation: 1,
            },
        );

        // Route 3: hostnames include "*.specific.com" -> matches listener-1 (wildcard match)
        store.http_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "route-wildcard-specific".to_string() },
            HTTPRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["*.specific.com".to_string()],
                parent_refs: vec![parent.clone()],
                rules: vec![],
                generation: 1,
            },
        );

        // Route 4: hostnames include "*.anotherwildcard.io" -> matches listener-3
        store.http_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "route-another".to_string() },
            HTTPRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["*.anotherwildcard.io".to_string()],
                parent_refs: vec![parent.clone()],
                rules: vec![],
                generation: 1,
            },
        );

        // Route 5: hostnames don't intersect with any listener -> NOT accepted
        let rejected_parent = ParentRefState {
            accepted: false,
            reject_reason: Some("NoMatchingListenerHostname".to_string()),
            ..parent.clone()
        };
        store.http_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "route-no-match".to_string() },
            HTTPRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["specific.but.wrong.com".to_string()],
                parent_refs: vec![rejected_parent],
                rules: vec![],
                generation: 1,
            },
        );

        // listener-1 (very.specific.com): route-specific + route-wildcard-specific = 2
        assert_eq!(
            count_attached_routes_for_listener(&store, &gw_key, &listener1),
            2,
            "listener-1 should have 2 attached routes"
        );
        // listener-2 (*.wildcard.io): route-wildcard = 1
        assert_eq!(
            count_attached_routes_for_listener(&store, &gw_key, &listener2),
            1,
            "listener-2 should have 1 attached route"
        );
        // listener-3 (*.anotherwildcard.io): route-another = 1
        assert_eq!(
            count_attached_routes_for_listener(&store, &gw_key, &listener3),
            1,
            "listener-3 should have 1 attached route"
        );
    }

    #[test]
    fn test_attached_routes_rejected_route_not_counted() {
        // Conformance: InvalidCrossNamespaceParentRef
        // Route is rejected (accepted=false) -> should NOT be counted
        let store = Arc::new(ConfigStore::new());

        let gw_key = NamespacedName {
            namespace: "infra".to_string(),
            name: "gw".to_string(),
        };
        let listener = crate::store::ListenerState {
            name: "http".to_string(),
            port: 80,
            protocol: "HTTP".to_string(),
            hostname: None,
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: crate::store::AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: None,
        };
        store.gateways.insert(
            gw_key.clone(),
            GatewayState {
                name: "gw".to_string(),
                namespace: "infra".to_string(),
                listeners: vec![listener.clone()],
                generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );

        // Rejected route (cross-namespace, not allowed)
        store.http_routes.insert(
            NamespacedName { namespace: "other-ns".to_string(), name: "rejected-route".to_string() },
            HTTPRouteState {
                namespace: "other-ns".to_string(),
                hostnames: vec![],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "infra".to_string(),
                    gateway_name: "gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: false,
                    resolved_refs: true,
                    reject_reason: Some("NotAllowedByListeners".to_string()),
                }],
                rules: vec![],
                generation: 1,
            },
        );

        assert_eq!(
            count_attached_routes_for_listener(&store, &gw_key, &listener),
            0,
            "rejected route should not be counted in attachedRoutes"
        );
    }

    /// Count TLS routes attached to a specific listener (test helper).
    fn count_attached_tls_routes_for_listener(
        store: &ConfigStore,
        gateway_key: &NamespacedName,
        listener: &crate::store::ListenerState,
    ) -> i64 {
        store.tls_routes.iter().filter(|entry| {
            let route = entry.value();
            route.parent_refs.iter().any(|pr| {
                if pr.gateway_namespace != gateway_key.namespace
                    || pr.gateway_name != gateway_key.name
                    || !pr.accepted
                {
                    return false;
                }
                if let Some(ref sn) = pr.section_name {
                    return sn == &listener.name;
                }
                if listener.protocol != "TLS" {
                    return false;
                }
                // Hostname intersection
                if let Some(ref lh) = listener.hostname
                    && !route.hostnames.is_empty()
                        && !route.hostnames.iter().any(|rh| {
                            crate::reconcilers::tls_route::hostname_matches_pub(lh, rh)
                        })
                    {
                        return false;
                    }
                true
            })
        }).count() as i64
    }

    #[test]
    fn test_tls_attached_routes_mixed_termination_per_listener() {
        // Conformance: TLSRouteMixedTerminationSameNamespace
        // Two TLS listeners on same port with different hostnames.
        // Two TLS routes, each binding to one listener by hostname.
        // Each listener should report AttachedRoutes=1, not 2.
        let store = Arc::new(ConfigStore::new());

        let gw_key = NamespacedName {
            namespace: "infra".to_string(),
            name: "mixed-gw".to_string(),
        };

        let listener_terminate = crate::store::ListenerState {
            name: "tls-terminate".to_string(),
            port: 8883,
            protocol: "TLS".to_string(),
            hostname: Some("tls.example.com".to_string()),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: crate::store::AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: Some("Terminate".to_string()),
        };

        let listener_passthrough = crate::store::ListenerState {
            name: "tls-passthrough".to_string(),
            port: 8883,
            protocol: "TLS".to_string(),
            hostname: Some("abc.example.com".to_string()),
            accepted: true,
            conflicted: false,
            resolved_refs: true,
            allowed_routes: crate::store::AllowedRoutesState {
                namespaces_from: "Same".to_string(),
                namespace_selector: None,
            },
            tls_cert_refs: vec![],
            tls_mode: Some("Passthrough".to_string()),
        };

        store.gateways.insert(
            gw_key.clone(),
            GatewayState {
                name: "mixed-gw".to_string(),
                namespace: "infra".to_string(),
                listeners: vec![listener_terminate.clone(), listener_passthrough.clone()],
                generation: 1,
                allowed_listener_namespaces_from: None,
            allowed_listener_match_labels: Vec::new(),
        },
        );

        // Route for Terminate listener: hostname tls.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "terminate-route".to_string() },
            crate::store::TLSRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["tls.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "infra".to_string(),
                    gateway_name: "mixed-gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // Route for Passthrough listener: hostname abc.example.com
        store.tls_routes.insert(
            NamespacedName { namespace: "infra".to_string(), name: "passthrough-route".to_string() },
            crate::store::TLSRouteState {
                namespace: "infra".to_string(),
                hostnames: vec!["abc.example.com".to_string()],
                parent_refs: vec![ParentRefState {
                    parent_kind: ParentKind::Gateway,
                    gateway_namespace: "infra".to_string(),
                    gateway_name: "mixed-gw".to_string(),
                    section_name: None,
                    port: None,
                    accepted: true,
                    resolved_refs: true,
                    reject_reason: None,
                }],
                backend_refs: vec![],
                generation: 1,
                resolved_reason: "ResolvedRefs".to_string(),
            },
        );

        // Terminate listener should have 1 attached route (tls.example.com only)
        assert_eq!(
            count_attached_tls_routes_for_listener(&store, &gw_key, &listener_terminate),
            1,
            "Terminate listener (tls.example.com) should have 1 attached route"
        );

        // Passthrough listener should have 1 attached route (abc.example.com only)
        assert_eq!(
            count_attached_tls_routes_for_listener(&store, &gw_key, &listener_passthrough),
            1,
            "Passthrough listener (abc.example.com) should have 1 attached route"
        );
    }


    // --- Gateway spec.tls (mTLS) ---

    fn ca_config_map(store: &ConfigStore, ns: &str, name: &str, pem: &str) {
        store.config_maps.insert(
            NamespacedName { namespace: ns.to_string(), name: name.to_string() },
            crate::store::SecretState {
                data: std::collections::HashMap::from([("ca.crt".to_string(), pem.to_string())]),
            },
        );
    }

    fn ca_ref(name: &str) -> crate::gateway_types::ObjectReference {
        crate::gateway_types::ObjectReference {
            group: String::new(),
            kind: "ConfigMap".to_string(),
            name: name.to_string(),
            namespace: None,
        }
    }

    fn validation(refs: Vec<&str>, mode: Option<&str>) -> crate::gateway_types::FrontendTLSListenerConfig {
        crate::gateway_types::FrontendTLSListenerConfig {
            validation: Some(crate::gateway_types::FrontendTLSValidation {
                ca_certificate_refs: refs.into_iter().map(ca_ref).collect(),
                mode: mode.map(str::to_string),
            }),
        }
    }

    /// The Gateway of `gateway-with-clientcertificate-validation.yaml`: HTTPS on
    /// 443 (default validation) and 8443 (per-port validation), both serving the
    /// same certificate Secret.
    fn client_validation_listeners(store: &ConfigStore) -> Vec<crate::gateway_types::Listener> {
        store.secrets.insert(
            NamespacedName { namespace: "default".to_string(), name: "tls-validity-checks-certificate".to_string() },
            make_valid_tls_secret(),
        );
        let tls = |_: &str| crate::gateway_types::GatewayTLSConfig {
            mode: None,
            certificate_refs: vec![crate::gateway_types::SecretObjectReference {
                group: Some(String::new()),
                kind: Some("Secret".to_string()),
                name: "tls-validity-checks-certificate".to_string(),
                namespace: Some("default".to_string()),
            }],
        };
        let mut https = make_listener_spec("https", 443, "HTTPS", None);
        https.tls = Some(tls("https"));
        let mut per_port = make_listener_spec("https-with-hostname", 8443, "HTTPS", Some("second-example.org"));
        per_port.tls = Some(tls("per-port"));
        vec![https, per_port]
    }

    fn cond<'a>(conds: &'a [Condition], type_: &str) -> &'a Condition {
        conds.iter().find(|c| c.type_ == type_).unwrap_or_else(|| panic!("no {type_} condition"))
    }

    #[test]
    fn test_frontend_validation_default_and_per_port_resolve_to_their_config_maps() {
        let store = make_store_with_class();
        ca_config_map(&store, "default", "tls-validity-checks-ca-certificate", TEST_CERT_PEM);
        ca_config_map(&store, "default", "tls-validity-checks-per-port-ca-certificate", TEST_CERT_PEM);
        let listeners = client_validation_listeners(&store);
        let tls = crate::gateway_types::GatewayTLS {
            backend: None,
            frontend: Some(crate::gateway_types::FrontendTLSConfig {
                default: validation(vec!["tls-validity-checks-ca-certificate"], None),
                per_port: vec![crate::gateway_types::TLSPortConfig {
                    port: 8443,
                    tls: validation(vec!["tls-validity-checks-per-port-ca-certificate"], None),
                }],
            }),
        };

        let (gateway_tls, _) = resolve_gateway_tls(Some(&tls), "default", &store);
        let (state, conditions, _) =
            evaluate_gateway("client-validation-default", "default", 1, "my-class", &listeners, &gateway_tls, None, Vec::new(), &store);

        assert!(state.listeners.iter().all(|l| l.accepted && l.resolved_refs), "{:?}", state.listeners);
        for (_, conds, _) in &conditions {
            assert_eq!(cond(conds, "Accepted").status, "True");
            assert_eq!(cond(conds, "ResolvedRefs").status, "True");
        }
        let default_refs = match gateway_tls.frontend_validation_for_port(443) {
            Some(ClientValidationOutcome::Valid(v)) => v,
            other => panic!("port 443 should use the default validation, got {other:?}"),
        };
        assert_eq!(default_refs.ca_config_maps[0].name, "tls-validity-checks-ca-certificate");
        assert_eq!(default_refs.mode, crate::store::CLIENT_VALIDATION_ALLOW_VALID_ONLY);
        assert!(default_refs.ref_error.is_none());
        let per_port_refs = match gateway_tls.frontend_validation_for_port(8443) {
            Some(ClientValidationOutcome::Valid(v)) => v,
            other => panic!("port 8443 should use the per-port validation, got {other:?}"),
        };
        assert_eq!(per_port_refs.ca_config_maps[0].name, "tls-validity-checks-per-port-ca-certificate");
        assert!(!gateway_tls.has_insecure_fallback());
        // A port without listeners still resolves to the default (perPort is port-keyed).
        assert!(matches!(gateway_tls.frontend_validation_for_port(9443), Some(ClientValidationOutcome::Valid(_))));
    }

    #[test]
    fn test_frontend_validation_insecure_fallback_sets_gateway_flag() {
        let store = make_store_with_class();
        ca_config_map(&store, "default", "ca", TEST_CERT_PEM);
        ca_config_map(&store, "default", "per-port-ca", TEST_CERT_PEM);
        let listeners = client_validation_listeners(&store);
        let tls = crate::gateway_types::GatewayTLS {
            backend: None,
            frontend: Some(crate::gateway_types::FrontendTLSConfig {
                default: validation(vec!["ca"], Some("AllowInsecureFallback")),
                per_port: vec![crate::gateway_types::TLSPortConfig {
                    port: 8443,
                    tls: validation(vec!["per-port-ca"], Some("AllowInsecureFallback")),
                }],
            }),
        };
        let (gateway_tls, _) = resolve_gateway_tls(Some(&tls), "default", &store);
        let (state, _, _) =
            evaluate_gateway("gw", "default", 1, "my-class", &listeners, &gateway_tls, None, Vec::new(), &store);
        assert!(state.listeners.iter().all(|l| l.accepted && l.resolved_refs));
        assert!(gateway_tls.has_insecure_fallback());
        match gateway_tls.frontend_validation_for_port(443) {
            Some(ClientValidationOutcome::Valid(v)) => assert_eq!(v.mode, "AllowInsecureFallback"),
            other => panic!("{other:?}"),
        }

        // Strict everywhere → no flag.
        let strict = crate::gateway_types::GatewayTLS {
            backend: None,
            frontend: Some(crate::gateway_types::FrontendTLSConfig {
                default: validation(vec!["ca"], Some("AllowValidOnly")),
                per_port: vec![],
            }),
        };
        let (gateway_tls, _) = resolve_gateway_tls(Some(&strict), "default", &store);
        assert!(!gateway_tls.has_insecure_fallback());
    }

    /// `gateway-invalid-default-frontend-client-certificate-validation.yaml`: the
    /// default references a missing ConfigMap and perPort names port 80. Only the
    /// HTTPS listener is affected.
    #[test]
    fn test_frontend_validation_missing_config_map_rejects_only_https_listener() {
        let store = make_store_with_class();
        ca_config_map(&store, "default", "tls-validity-checks-per-port-ca-certificate", TEST_CERT_PEM);
        let mut listeners = client_validation_listeners(&store);
        listeners.truncate(1); // keep https:443
        listeners.push(make_listener_spec("http", 80, "HTTP", None));
        let tls = crate::gateway_types::GatewayTLS {
            backend: None,
            frontend: Some(crate::gateway_types::FrontendTLSConfig {
                default: validation(vec!["does-not-exist"], None),
                per_port: vec![crate::gateway_types::TLSPortConfig {
                    port: 80,
                    tls: validation(vec!["tls-validity-checks-per-port-ca-certificate"], None),
                }],
            }),
        };

        let (gateway_tls, _) = resolve_gateway_tls(Some(&tls), "default", &store);
        let (state, conditions, _) =
            evaluate_gateway("invalid-default-client-validation-config", "default", 1, "my-class", &listeners, &gateway_tls, None, Vec::new(), &store);

        let (_, https_conds, _) = &conditions[0];
        let resolved = cond(https_conds, "ResolvedRefs");
        assert_eq!(resolved.status, "False");
        assert_eq!(resolved.reason, "InvalidCACertificateRef");
        assert!(resolved.message.contains("does-not-exist"), "{}", resolved.message);
        let accepted = cond(https_conds, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "NoValidCACertificate");
        assert_eq!(cond(https_conds, "Programmed").status, "False");
        assert!(!state.listeners[0].accepted);
        assert!(!state.listeners[0].resolved_refs);

        let (_, http_conds, _) = &conditions[1];
        assert_eq!(cond(http_conds, "Accepted").status, "True");
        assert_eq!(cond(http_conds, "ResolvedRefs").status, "True");
        assert!(state.listeners[1].accepted && state.listeners[1].resolved_refs);
    }

    #[test]
    fn test_frontend_validation_partially_invalid_refs_keep_listener_accepted_but_unresolved() {
        let store = make_store_with_class();
        ca_config_map(&store, "default", "good-ca", TEST_CERT_PEM);
        let listeners = client_validation_listeners(&store);
        let tls = crate::gateway_types::GatewayTLS {
            backend: None,
            frontend: Some(crate::gateway_types::FrontendTLSConfig {
                default: validation(vec!["good-ca", "missing-ca"], None),
                per_port: vec![],
            }),
        };
        let (gateway_tls, _) = resolve_gateway_tls(Some(&tls), "default", &store);
        let (state, conditions, _) =
            evaluate_gateway("gw", "default", 1, "my-class", &listeners, &gateway_tls, None, Vec::new(), &store);
        assert!(state.listeners[0].accepted, "usable CA remains → listener accepted");
        assert!(!state.listeners[0].resolved_refs);
        let (_, conds, _) = &conditions[0];
        assert_eq!(cond(conds, "Accepted").status, "True");
        assert_eq!(cond(conds, "ResolvedRefs").reason, "InvalidCACertificateRef");
        match gateway_tls.frontend_validation_for_port(443) {
            Some(ClientValidationOutcome::Valid(v)) => {
                assert_eq!(v.ca_config_maps.len(), 1);
                assert_eq!(v.ca_config_maps[0].name, "good-ca");
                assert!(v.ref_error.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_frontend_validation_rejects_unsupported_kind_and_empty_ca_crt() {
        let store = make_store_with_class();
        let mut secret_kind = validation(vec!["some-secret"], None);
        secret_kind.validation.as_mut().unwrap().ca_certificate_refs[0].kind = "Secret".to_string();
        match resolve_frontend_validation(secret_kind.validation.as_ref().unwrap(), "default", &store) {
            ClientValidationOutcome::Invalid { reason, .. } => assert_eq!(reason, "InvalidCACertificateKind"),
            other => panic!("{other:?}"),
        }

        ca_config_map(&store, "default", "empty", "");
        let empty = validation(vec!["empty"], None);
        match resolve_frontend_validation(empty.validation.as_ref().unwrap(), "default", &store) {
            ClientValidationOutcome::Invalid { reason, message } => {
                assert_eq!(reason, "InvalidCACertificateRef");
                assert!(message.contains("ca.crt"), "{message}");
            }
            other => panic!("{other:?}"),
        }

        // Cross-namespace without a ReferenceGrant.
        ca_config_map(&store, "other", "ca", TEST_CERT_PEM);
        let mut cross = validation(vec!["ca"], None);
        cross.validation.as_mut().unwrap().ca_certificate_refs[0].namespace = Some("other".to_string());
        match resolve_frontend_validation(cross.validation.as_ref().unwrap(), "default", &store) {
            ClientValidationOutcome::Invalid { reason, .. } => assert_eq!(reason, "RefNotPermitted"),
            other => panic!("{other:?}"),
        }
        store.reference_grants.insert(
            NamespacedName { namespace: "other".to_string(), name: "allow".to_string() },
            crate::store::ReferenceGrantState {
                namespace: "other".to_string(),
                from: vec![crate::store::ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "default".to_string(),
                }],
                to: vec![crate::store::ReferenceGrantTo {
                    group: String::new(),
                    kind: "ConfigMap".to_string(),
                    name: None,
                }],
            },
        );
        assert!(matches!(
            resolve_frontend_validation(cross.validation.as_ref().unwrap(), "default", &store),
            ClientValidationOutcome::Valid(_)
        ));
    }

    /// `gateway-tls-backend-client-certificate.yaml`: the Gateway names a client
    /// certificate Secret; the Gateway reports ResolvedRefs for it.
    #[test]
    fn test_backend_client_certificate_ref_resolution() {
        let store = make_store_with_class();
        let cert_ref = crate::gateway_types::SecretObjectReference {
            group: Some(String::new()),
            kind: Some("Secret".to_string()),
            name: "tls-checks-client-certificate".to_string(),
            namespace: None,
        };
        let tls = crate::gateway_types::GatewayTLS {
            backend: Some(crate::gateway_types::GatewayBackendTLS { client_certificate_ref: Some(cert_ref.clone()) }),
            frontend: None,
        };

        // Missing Secret.
        let (state, cond) = resolve_gateway_tls(Some(&tls), "default", &store);
        assert!(state.backend_client_cert_ref.is_none());
        let (ok, reason, _) = cond.expect("a backend ref always yields a ResolvedRefs condition");
        assert!(!ok);
        assert_eq!(reason, "InvalidClientCertificateRef");

        // Present and well-formed.
        store.secrets.insert(
            NamespacedName { namespace: "default".to_string(), name: "tls-checks-client-certificate".to_string() },
            make_valid_tls_secret(),
        );
        let (state, cond) = resolve_gateway_tls(Some(&tls), "default", &store);
        assert_eq!(
            state.backend_client_cert_ref,
            Some(NamespacedName { namespace: "default".to_string(), name: "tls-checks-client-certificate".to_string() })
        );
        let (ok, reason, _) = cond.unwrap();
        assert!(ok);
        assert_eq!(reason, "ResolvedRefs");

        // Malformed key data.
        store.secrets.insert(
            NamespacedName { namespace: "default".to_string(), name: "tls-checks-client-certificate".to_string() },
            crate::store::SecretState {
                data: std::collections::HashMap::from([
                    ("tls.crt".to_string(), TEST_CERT_PEM.to_string()),
                    ("tls.key".to_string(), "not a key".to_string()),
                ]),
            },
        );
        let (_, cond) = resolve_gateway_tls(Some(&tls), "default", &store);
        assert_eq!(cond.unwrap().1, "InvalidClientCertificateRef");

        // Cross-namespace needs a ReferenceGrant.
        store.secrets.insert(
            NamespacedName { namespace: "certs".to_string(), name: "client".to_string() },
            make_valid_tls_secret(),
        );
        let mut cross = cert_ref;
        cross.name = "client".to_string();
        cross.namespace = Some("certs".to_string());
        assert_eq!(resolve_backend_client_cert(&cross, "default", &store).unwrap_err().0, "RefNotPermitted");

        // No spec.tls.backend → no Gateway ResolvedRefs condition at all.
        let (_, cond) = resolve_gateway_tls(None, "default", &store);
        assert!(cond.is_none());
    }

    #[test]
    fn test_gateway_tls_state_marks_client_cert_secret_as_referenced() {
        let store = ConfigStore::new();
        assert!(!store.is_secret_referenced("default", "client"));
        store.gateway_tls.insert(
            NamespacedName { namespace: "default".to_string(), name: "gw".to_string() },
            GatewayTlsState {
                backend_client_cert_ref: Some(NamespacedName { namespace: "default".to_string(), name: "client".to_string() }),
                ..Default::default()
            },
        );
        assert!(store.is_secret_referenced("default", "client"));
        assert!(!store.is_secret_referenced("default", "other"));
    }
}
