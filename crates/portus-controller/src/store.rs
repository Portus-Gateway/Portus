use dashmap::DashMap;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{broadcast, Notify};

use portus_types::BackendEndpoint;

/// Central shared state for all reconcilers. Each reconciler writes validated
/// state into the appropriate DashMap. The compilation task reads all maps to
/// build CompiledConfig. `change_notify` wakes compilation; `events` carries
/// dependency changes to the controllers that need them.
pub struct ConfigStore {
    pub gateway_classes: DashMap<String, GatewayClassState>,
    pub gateways: DashMap<NamespacedName, GatewayState>,
    pub listener_sets: DashMap<NamespacedName, ListenerSetState>,
    pub http_routes: DashMap<NamespacedName, HTTPRouteState>,
    pub grpc_routes: DashMap<NamespacedName, GRPCRouteState>,
    pub tls_routes: DashMap<NamespacedName, TLSRouteState>,
    pub tcp_routes: DashMap<NamespacedName, L4RouteState>,
    pub udp_routes: DashMap<NamespacedName, L4RouteState>,
    pub reference_grants: DashMap<NamespacedName, ReferenceGrantState>,
    pub endpoints: DashMap<ServiceKey, Vec<BackendEndpoint>>,
    pub rate_limit_policies: DashMap<NamespacedName, RateLimitPolicyState>,
    pub circuit_breaker_policies: DashMap<NamespacedName, CircuitBreakerPolicyState>,
    pub connection_policies: DashMap<NamespacedName, ConnectionPolicyState>,
    pub basic_auth_policies: DashMap<NamespacedName, BasicAuthPolicyState>,
    pub api_key_auth_policies: DashMap<NamespacedName, ApiKeyAuthPolicyState>,
    pub retry_policies: DashMap<NamespacedName, RetryPolicyState>,
    pub ip_allowlist_policies: DashMap<NamespacedName, IPAllowlistPolicyState>,
    pub request_body_size_limit_policies: DashMap<NamespacedName, RequestBodySizeLimitPolicyState>,
    pub health_check_policies: DashMap<NamespacedName, HealthCheckPolicyState>,
    pub cors_policies: DashMap<NamespacedName, CORSPolicyState>,
    pub timeout_policies: DashMap<NamespacedName, TimeoutPolicyState>,
    pub backend_tls_policies: DashMap<NamespacedName, BackendTLSPolicyState>,
    pub secrets: DashMap<NamespacedName, SecretState>,
    /// ConfigMap data, keyed by namespace/name. Used by BackendTLSPolicy and
    /// Gateway frontend validation to resolve CA certificate references.
    pub config_maps: DashMap<NamespacedName, SecretState>,
    /// Gateway-wide TLS settings (`spec.tls`), keyed by Gateway. Written by the
    /// Gateway reconciler next to `gateways`; absent = no mTLS on that Gateway.
    pub gateway_tls: DashMap<NamespacedName, GatewayTlsState>,
    /// Maps (namespace, service_name, service_port) → target_port.
    /// Populated by the Service reconciler. Used by the compiler to translate
    /// service ports (referenced in HTTPRoute backendRefs) to endpoint ports
    /// (stored by EndpointSlice reconciler).
    pub service_port_map: DashMap<ServiceKey, u16>,
    /// Maps (namespace, service_name, service_port) → appProtocol string.
    /// Populated by the Service reconciler. Used by the compiler to set the
    /// backend protocol (e.g., "kubernetes.io/h2c" → H2C, "kubernetes.io/ws" → WebSocket).
    pub service_app_protocols: DashMap<ServiceKey, String>,
    /// Maps (namespace, service_name, service_port) → port name (e.g., "https", "btls").
    /// Populated by the Service reconciler. Used by the compiler to match
    /// BackendTLSPolicy sectionName to a specific service port.
    pub service_port_names: DashMap<ServiceKey, String>,
    /// Cache of Namespace labels keyed by namespace name. Populated lazily by
    /// route + listener-set reconcilers (they already fetch ns labels for
    /// `allowedRoutes.namespaces.Selector` matching). Read by the Gateway
    /// reconciler's attached-routes counter so per-listener counts stay in
    /// sync with what the route reconciler actually bound.
    pub namespace_labels: DashMap<String, std::collections::BTreeMap<String, String>>,
    /// Generation counter of the last compiled config (restarts with the
    /// controller; informational, used for /readyz and logs).
    pub compiled_version: AtomicU64,
    /// Content fingerprint of the last compiled config. Stable across
    /// controller restarts and instances: identical content => identical value.
    pub compiled_fingerprint: AtomicU64,
    /// Fingerprint of each Gateway's slice of the last compiled config
    /// (`compiler::scope_config`), for per-Gateway Programmed decisions.
    pub compiled_gateway_fingerprints: DashMap<NamespacedName, u64>,
    /// node_id -> what that data plane runs: which Gateway it is dedicated to
    /// (None = shared data plane that receives everything) and the fingerprint
    /// of the config it has applied.
    pub data_plane_applied: DashMap<String, AppliedState>,
    /// Signaled when any reconciler writes new state (triggers compilation).
    pub change_notify: Notify,
    /// Set by `notify_change`, cleared by the compilation loop right before it
    /// compiles. Lets the loop's periodic safety tick skip a full recompile when
    /// nothing has changed since the last one. Starts `true` so the first tick
    /// always produces a config.
    pub dirty: AtomicBool,
    /// Dependency events: published by a reconciler right after it has written
    /// the store, consumed by the controllers whose objects derive status from
    /// that state (see `triggers`). Publishing after the write is what makes a
    /// dependent reconcile see the new state; there are no timed requeues.
    pub events: broadcast::Sender<Event>,
}

/// How many events a slow subscriber may fall behind before it is told it
/// lagged (and re-reconciles everything it owns).
pub const EVENT_CAPACITY: usize = 8192;

/// A store write another controller may need to react to. Every variant names
/// the object that changed; the receiver maps it to the objects whose status
/// depends on it. Publishers emit only when the stored state actually changed,
/// which is what keeps two controllers from re-triggering each other for ever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A GatewayClass we manage appeared, changed or went away.
    GatewayClass(String),
    /// A Gateway's store state (listeners, TLS) changed or the Gateway was removed.
    Gateway(NamespacedName),
    /// A ListenerSet's state changed or it was removed; `parent` is its Gateway.
    ListenerSet { key: NamespacedName, parent: NamespacedName },
    /// A route's state changed or it was removed. `parents` are the Gateway and
    /// ListenerSet keys it names; `backends` the Services its rules reference.
    Route { kind: RouteKind, key: NamespacedName, parents: Vec<(ParentKind, NamespacedName)>, backends: Vec<NamespacedName> },
    /// A ReferenceGrant in `namespace` changed or was removed.
    ReferenceGrant { namespace: String },
    /// A Service's ports changed or the Service was removed.
    Service(NamespacedName),
    /// A Namespace's labels changed or the Namespace was removed.
    Namespace(String),
    /// A policy's state changed or it was removed; siblings on the same target
    /// re-evaluate their conflict status. `kind` is the policy kind name.
    Policy { kind: &'static str, key: NamespacedName, target: PolicyTargetKey },
    /// Whether `gateway` runs its current config slice may have changed: a
    /// data plane acked or disconnected, or the slice was recompiled.
    Programmed(NamespacedName),
}

/// Route kinds the store tracks, for [`Event::Route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Http,
    Grpc,
    Tls,
    Tcp,
    Udp,
}

/// What one data plane node reported it is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedState {
    /// Gateway this data plane serves.
    pub gateway: NamespacedName,
    /// Fingerprint of the Gateway's config slice it applied.
    pub fingerprint: u64,
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            gateway_classes: DashMap::new(),
            gateways: DashMap::new(),
            listener_sets: DashMap::new(),
            http_routes: DashMap::new(),
            grpc_routes: DashMap::new(),
            tls_routes: DashMap::new(),
            tcp_routes: DashMap::new(),
            udp_routes: DashMap::new(),
            reference_grants: DashMap::new(),
            endpoints: DashMap::new(),
            rate_limit_policies: DashMap::new(),
            circuit_breaker_policies: DashMap::new(),
            connection_policies: DashMap::new(),
            basic_auth_policies: DashMap::new(),
            api_key_auth_policies: DashMap::new(),
            retry_policies: DashMap::new(),
            ip_allowlist_policies: DashMap::new(),
            request_body_size_limit_policies: DashMap::new(),
            health_check_policies: DashMap::new(),
            cors_policies: DashMap::new(),
            timeout_policies: DashMap::new(),
            backend_tls_policies: DashMap::new(),
            secrets: DashMap::new(),
            config_maps: DashMap::new(),
            gateway_tls: DashMap::new(),
            service_port_map: DashMap::new(),
            service_app_protocols: DashMap::new(),
            service_port_names: DashMap::new(),
            namespace_labels: DashMap::new(),
            compiled_version: AtomicU64::new(0),
            compiled_fingerprint: AtomicU64::new(0),
            compiled_gateway_fingerprints: DashMap::new(),
            data_plane_applied: DashMap::new(),
            change_notify: Notify::new(),
            dirty: AtomicBool::new(true),
            events: broadcast::channel(EVENT_CAPACITY).0,
        }
    }

    /// Signal the compilation task that something changed.
    pub fn notify_change(&self) {
        self.dirty.store(true, Ordering::Release);
        self.change_notify.notify_one();
    }

    /// Clear the dirty flag, returning whether it was set. Called by the
    /// compilation loop immediately before compiling, so any write that lands
    /// during compilation re-marks the store dirty.
    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }

    /// Publish an [`Event`] to every dependent controller. A send with no
    /// subscriber (unit tests, startup) is not an error.
    pub fn publish(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// `gateway`'s Programmed state may have moved: a data plane acked or
    /// left, or the compiled slice changed.
    pub fn notify_programmed(&self, gateway: &NamespacedName) {
        self.publish(Event::Programmed(gateway.clone()));
    }

    /// Insert a value and automatically notify the compilation loop.
    /// Use this instead of directly accessing DashMap fields + manual notify_change()
    /// to prevent silent config propagation delays from missed notifications.
    /// Insert `value` and wake the compiler only if it differs from what the
    /// map held. Returns whether it did: callers publish their dependency
    /// event on `true`, so an unchanged reconcile never fans out.
    pub fn insert_and_notify<K: std::hash::Hash + Eq, V: PartialEq>(
        &self,
        map: &DashMap<K, V>,
        key: K,
        value: V,
    ) -> bool {
        let changed = map.get(&key).is_none_or(|existing| *existing != value);
        if changed {
            map.insert(key, value);
            self.notify_change();
        }
        changed
    }

    /// Remove a value and automatically notify the compilation loop.
    pub fn remove_and_notify<K: std::hash::Hash + Eq, V>(
        &self,
        map: &DashMap<K, V>,
        key: &K,
    ) -> Option<(K, V)> {
        let removed = map.remove(key);
        if removed.is_some() {
            self.notify_change();
        }
        removed
    }

    /// Upper bound on distinct data plane node ids tracked, so a flood of fake
    /// node ids cannot grow the maps without bound.
    pub const MAX_DATA_PLANE_NODES: usize = 1000;

    /// True when at least one data plane runs its Gateway's current slice.
    /// False before the first compile or while every data plane still runs
    /// something else. Policies use this aggregate; Gateways use
    /// [`Self::is_programmed_for`].
    pub fn is_programmed(&self) -> bool {
        if self.compiled_fingerprint.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.data_plane_applied.iter().any(|entry| {
            let applied = entry.value();
            self.compiled_gateway_fingerprints
                .get(&applied.gateway)
                .is_some_and(|fp| *fp == applied.fingerprint)
        })
    }

    /// True when `gateway` is served by a data plane running the current
    /// fingerprint of its config slice.
    pub fn is_programmed_for(&self, gateway: &NamespacedName) -> bool {
        if self.compiled_fingerprint.load(Ordering::Acquire) == 0 {
            return false;
        }
        let Some(slice) = self.compiled_gateway_fingerprints.get(gateway).map(|v| *v) else {
            return false;
        };
        self.data_plane_applied
            .iter()
            .any(|entry| entry.value().gateway == *gateway && entry.value().fingerprint == slice)
    }

    /// Forget a data plane that disconnected: drop its applied fingerprint and
    /// wake the Programmed trigger (its Gateway may have lost its only current
    /// data plane). Without this, pod churn (one dataplane Deployment per
    /// Gateway, hundreds of Gateways per conformance run) fills the node cap
    /// with dead entries and new pods' ACKs are rejected, leaving Gateways
    /// `Programmed=False/Pending`.
    pub fn forget_data_plane(&self, node_id: &str) {
        if let Some((_, gone)) = self.data_plane_applied.remove(node_id) {
            self.notify_programmed(&gone.gateway);
        }
    }

    /// Whether `node_id` may be (or already is) tracked under the node cap.
    pub fn accepts_data_plane(&self, node_id: &str) -> bool {
        self.data_plane_applied.len() < Self::MAX_DATA_PLANE_NODES
            || self.data_plane_applied.contains_key(node_id)
    }

    /// Record that `node_id` (serving `gateway`) has
    /// applied `fingerprint`. Wakes the Programmed trigger whenever the applied
    /// content of a node changes, so Gateway status can move even if another
    /// node already made the aggregate true. Returns false if the node was
    /// rejected by the cap.
    pub fn record_applied(&self, node_id: &str, gateway: NamespacedName, fingerprint: u64) -> bool {
        if fingerprint == 0 || !self.accepts_data_plane(node_id) {
            return false;
        }
        let state = AppliedState { gateway, fingerprint };
        let previous = self.data_plane_applied.insert(node_id.to_string(), state.clone());
        if previous.as_ref() != Some(&state) {
            if let Some(prev) = previous.filter(|p| p.gateway != state.gateway) {
                self.notify_programmed(&prev.gateway);
            }
            self.notify_programmed(&state.gateway);
        }
        true
    }

    /// Returns true if the given secret (namespace, name) is referenced by any
    /// Gateway (certificateRefs), BasicAuthPolicy, or APIKeyAuthPolicy in the store.
    /// Used by the secret reconciler to avoid storing unreferenced secrets.
    pub fn is_secret_referenced(&self, namespace: &str, name: &str) -> bool {
        // Check Gateway TLS certificate references
        for entry in self.gateways.iter() {
            for listener in &entry.value().listeners {
                for (cert_ns, cert_name) in &listener.tls_cert_refs {
                    if cert_ns == namespace && cert_name == name {
                        return true;
                    }
                }
            }
        }

        // Check Gateway backend client certificate references
        for entry in self.gateway_tls.iter() {
            if entry
                .value()
                .backend_client_cert_ref
                .as_ref()
                .is_some_and(|r| r.namespace == namespace && r.name == name)
            {
                return true;
            }
        }

        // Check BasicAuthPolicy secret references
        for entry in self.basic_auth_policies.iter() {
            let policy = entry.value();
            if policy.secret_namespace == namespace && policy.secret_name == name {
                return true;
            }
        }

        // Check APIKeyAuthPolicy secret references
        for entry in self.api_key_auth_policies.iter() {
            let policy = entry.value();
            if policy.secret_namespace == namespace && policy.secret_name == name {
                return true;
            }
        }

        false
    }
}

// -- State types --

/// What every stored route kind exposes for dependency events.
pub trait RouteState {
    fn parent_refs(&self) -> &[ParentRefState];
    fn backend_refs(&self) -> Vec<&BackendRefState>;

    fn parents(&self) -> Vec<(ParentKind, NamespacedName)> {
        self.parent_refs()
            .iter()
            .map(|p| {
                (p.parent_kind, NamespacedName { namespace: p.gateway_namespace.clone(), name: p.gateway_name.clone() })
            })
            .collect()
    }
    fn backends(&self) -> Vec<NamespacedName> {
        let mut v: Vec<NamespacedName> = self
            .backend_refs()
            .into_iter()
            .map(|b| NamespacedName { namespace: b.namespace.clone(), name: b.name.clone() })
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

impl RouteState for HTTPRouteState {
    fn parent_refs(&self) -> &[ParentRefState] {
        &self.parent_refs
    }
    fn backend_refs(&self) -> Vec<&BackendRefState> {
        self.rules.iter().flat_map(|r| r.backend_refs.iter()).collect()
    }
}

impl RouteState for GRPCRouteState {
    fn parent_refs(&self) -> &[ParentRefState] {
        &self.parent_refs
    }
    fn backend_refs(&self) -> Vec<&BackendRefState> {
        self.rules.iter().flat_map(|r| r.backend_refs.iter()).collect()
    }
}

impl RouteState for TLSRouteState {
    fn parent_refs(&self) -> &[ParentRefState] {
        &self.parent_refs
    }
    fn backend_refs(&self) -> Vec<&BackendRefState> {
        self.backend_refs.iter().collect()
    }
}

impl RouteState for L4RouteState {
    fn parent_refs(&self) -> &[ParentRefState] {
        &self.parent_refs
    }
    fn backend_refs(&self) -> Vec<&BackendRefState> {
        self.backend_refs.iter().collect()
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct NamespacedName {
    pub namespace: String,
    pub name: String,
}

impl fmt::Display for NamespacedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayClassState {
    pub accepted: bool,
    pub generation: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayState {
    pub name: String,
    pub namespace: String,
    pub listeners: Vec<ListenerState>,
    pub generation: i64,
    /// ListenerSet attachment policy. None = ListenerSets not allowed (default per spec).
    pub allowed_listener_namespaces_from: Option<String>,
    /// `matchLabels` from the Gateway's allowedListeners selector (only used
    /// when `allowed_listener_namespaces_from == Some("Selector")`). Each
    /// entry is (label_key, label_value). All must match on the ListenerSet's
    /// namespace for acceptance.
    pub allowed_listener_match_labels: Vec<(String, String)>,
}

/// Validated ListenerSet state. Mirrors the subset of ListenerSetSpec + status
/// the compiler + reconcilers need. Acceptance requires the parent Gateway to
/// exist and its `allowedListeners` to permit this ListenerSet's namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerSetState {
    pub name: String,
    pub namespace: String,
    pub parent_gateway: NamespacedName,
    pub listeners: Vec<ListenerState>,
    /// True when parent Gateway exists and allows this ListenerSet. False
    /// otherwise (routes targeting this set are rejected).
    pub accepted: bool,
    pub generation: i64,
    /// Reason string for Accepted=False conditions, e.g., "NotAllowed",
    /// "ParentNotAccepted", "Invalid".
    pub not_accepted_reason: Option<String>,
    /// Creation timestamp (unix seconds) for listener precedence ordering.
    /// Older ListenerSets win hostname/protocol conflicts.
    pub creation_timestamp: i64,
}

/// Gateway-wide TLS state derived from `Gateway.spec.tls` (mTLS).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayTlsState {
    /// `spec.tls.frontend.default.validation`, when present.
    pub frontend_default: Option<ClientValidationOutcome>,
    /// `spec.tls.frontend.perPort[]`, keyed by port. Overrides the default for
    /// HTTPS listeners on that port.
    pub frontend_per_port: HashMap<u16, ClientValidationOutcome>,
    /// `spec.tls.backend.clientCertificateRef`, resolved to a Secret key when
    /// the reference is valid. The compiler inlines the Secret's PEM data.
    pub backend_client_cert_ref: Option<NamespacedName>,
}

impl GatewayTlsState {
    /// The client validation that applies to an HTTPS listener on `port`:
    /// the per-port override when there is one, otherwise the default.
    pub fn frontend_validation_for_port(&self, port: u16) -> Option<&ClientValidationOutcome> {
        self.frontend_per_port
            .get(&port)
            .or(self.frontend_default.as_ref())
    }

    /// True when any frontend validation runs in `AllowInsecureFallback` mode
    /// (drives the Gateway `InsecureFrontendValidationMode` condition).
    pub fn has_insecure_fallback(&self) -> bool {
        self.frontend_default
            .iter()
            .chain(self.frontend_per_port.values())
            .any(|o| matches!(o, ClientValidationOutcome::Valid(v) if v.mode == CLIENT_VALIDATION_INSECURE_FALLBACK))
    }
}

pub const CLIENT_VALIDATION_ALLOW_VALID_ONLY: &str = "AllowValidOnly";
pub const CLIENT_VALIDATION_INSECURE_FALLBACK: &str = "AllowInsecureFallback";

/// Result of resolving one `FrontendTLSValidation` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientValidationOutcome {
    Valid(ClientValidationRefs),
    /// Listener `ResolvedRefs=False` with this reason/message and
    /// `Accepted=False/NoValidCACertificate`.
    Invalid { reason: String, message: String },
}

/// A valid frontend validation block: CA ConfigMap references (inlined by the
/// compiler from `store.config_maps`, key `ca.crt`) and the enforcement mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientValidationRefs {
    pub ca_config_maps: Vec<NamespacedName>,
    /// `AllowValidOnly` or `AllowInsecureFallback`.
    pub mode: String,
    /// Set when some (not all) caCertificateRefs failed to resolve: the
    /// listener stays accepted with the usable CAs but reports
    /// `ResolvedRefs=False` with this `(reason, message)`.
    pub ref_error: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListenerState {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub hostname: Option<String>,
    pub accepted: bool,
    pub conflicted: bool,
    pub resolved_refs: bool,
    pub allowed_routes: AllowedRoutesState,
    /// TLS certificate references for HTTPS/TLS Terminate listeners.
    /// Each entry is (secret_namespace, secret_name).
    pub tls_cert_refs: Vec<(String, String)>,
    /// TLS mode for TLS protocol listeners: "Passthrough" or "Terminate".
    /// None for non-TLS listeners.
    pub tls_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllowedRoutesState {
    pub namespaces_from: String,
    /// matchLabels for `namespaces.from: Selector`. `None` means no selector
    /// was configured; `Some(vec)` lists the required (key, value) pairs that
    /// the route's namespace labels must all contain. An empty `Some(vec)`
    /// matches all namespaces (per K8s LabelSelector semantics).
    pub namespace_selector: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPRouteState {
    pub namespace: String,
    pub hostnames: Vec<String>,
    pub parent_refs: Vec<ParentRefState>,
    pub rules: Vec<HTTPRouteRuleState>,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParentRefState {
    /// Parent resource kind. "Gateway" (default) or "ListenerSet". Kept as a
    /// String for forward-compat with new parent kinds.
    pub parent_kind: ParentKind,
    /// When parent_kind = Gateway: the Gateway's namespace.
    /// When parent_kind = ListenerSet: the parent ListenerSet's namespace.
    /// (Renamed historically from gateway_namespace — still named gateway_* in
    /// existing code for backward compat.)
    pub gateway_namespace: String,
    pub gateway_name: String,
    pub section_name: Option<String>,
    pub port: Option<u16>,
    pub accepted: bool,
    pub resolved_refs: bool,
    pub reject_reason: Option<String>,
}

/// Parent resource kind for a route's parentRef. Only HTTP-class parents are
/// modeled at the state level; TCP/TLS still go through their own paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ParentKind {
    #[default]
    Gateway,
    ListenerSet,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPRouteRuleState {
    pub matches: Vec<HTTPRouteMatchState>,
    pub filters: Vec<HTTPFilterState>,
    pub backend_refs: Vec<BackendRefState>,
    pub request_timeout_ms: Option<u64>,
    pub backend_request_timeout_ms: Option<u64>,
    /// `rules[].retry`: retry these upstream statuses, `attempts` more times.
    pub retry: Option<RouteRetryState>,
}

/// HTTPRoute rule-level retry (`HTTPRouteRetry`). Takes precedence over a
/// RetryPolicy attached to the route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRetryState {
    pub codes: Vec<u16>,
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPRouteMatchState {
    /// (path_value, match_type) e.g. ("/foo", "Prefix")
    pub path: Option<(String, String)>,
    /// (header_name, header_value, match_type) e.g. ("X-Foo", "bar", "Exact")
    pub headers: Vec<(String, String, String)>,
    pub method: Option<String>,
    /// (param_name, param_value, match_type) e.g. ("version", "v2", "Exact")
    pub query_params: Vec<(String, String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HTTPFilterState {
    RequestHeaderModifier {
        add: Vec<(String, String)>,
        set: Vec<(String, String)>,
        remove: Vec<String>,
    },
    ResponseHeaderModifier {
        add: Vec<(String, String)>,
        set: Vec<(String, String)>,
        remove: Vec<String>,
    },
    RequestRedirect {
        scheme: Option<String>,
        hostname: Option<String>,
        port: Option<u16>,
        path: Option<String>,
        path_type: Option<String>,
        status_code: u16,
    },
    URLRewrite {
        hostname: Option<String>,
        path: Option<String>,
        path_type: Option<String>,
    },
    RequestMirror {
        backend_namespace: String,
        backend_name: String,
        backend_port: u16,
        /// Effective mirror percentage (0 = mirror all, 1-100 = percentage).
        percent: u32,
    },
    CORS {
        allow_origins: Vec<String>,
        allow_methods: Vec<String>,
        allow_headers: Vec<String>,
        expose_headers: Vec<String>,
        allow_credentials: bool,
        max_age: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendRefState {
    pub namespace: String,
    pub name: String,
    pub port: u16,
    pub weight: u32,
    /// Per-backend filters (e.g., RequestHeaderModifier at the backendRef level).
    pub filters: Vec<HTTPFilterState>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GRPCRouteState {
    pub namespace: String,
    pub hostnames: Vec<String>,
    pub parent_refs: Vec<ParentRefState>,
    pub rules: Vec<GRPCRouteRuleState>,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GRPCRouteRuleState {
    pub matches: Vec<GRPCRouteMatchState>,
    pub backend_refs: Vec<BackendRefState>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GRPCRouteMatchState {
    pub service: Option<String>,
    pub method: Option<String>,
    pub match_type: String,
    /// (header_name, header_value, match_type) e.g. ("x-version", "one", "Exact")
    pub headers: Vec<(String, String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TLSRouteState {
    pub namespace: String,
    pub hostnames: Vec<String>,
    pub parent_refs: Vec<ParentRefState>,
    pub backend_refs: Vec<BackendRefState>,
    pub generation: i64,
    /// Reason for ResolvedRefs condition when not resolved (e.g. "InvalidKind", "BackendNotFound", "RefNotPermitted")
    pub resolved_reason: String,
}

/// A TCPRoute or UDPRoute: parentRefs plus the backendRefs of its single rule.
#[derive(Debug, Clone, PartialEq)]
pub struct L4RouteState {
    pub namespace: String,
    pub parent_refs: Vec<ParentRefState>,
    pub backend_refs: Vec<BackendRefState>,
    pub generation: i64,
    /// When several routes bind the same listener, the oldest one is
    /// programmed (Gateway API conflict resolution); ties broken by name.
    pub creation_timestamp: Option<Time>,
    /// Reason for `ResolvedRefs=False`: "BackendNotFound" or "RefNotPermitted".
    pub resolved_refs_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTargetKey {
    pub group: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub section_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitPolicyState {
    pub target: PolicyTargetKey,
    pub requests_per_second: u32,
    pub per_client: bool,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CircuitBreakerPolicyState {
    pub target: PolicyTargetKey,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_secs: u32,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionPolicyState {
    pub target: PolicyTargetKey,
    pub max_connections: u32,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BasicAuthPolicyState {
    pub target: PolicyTargetKey,
    pub secret_namespace: String,
    pub secret_name: String,
    pub realm: String,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiKeyAuthPolicyState {
    pub target: PolicyTargetKey,
    pub secret_namespace: String,
    pub secret_name: String,
    pub header_name: String,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicyState {
    pub target: PolicyTargetKey,
    pub max_retries: u32,
    pub retry_on: Vec<String>,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IPAllowlistPolicyState {
    pub target: PolicyTargetKey,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub trusted_proxy_cidrs: Vec<String>,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestBodySizeLimitPolicyState {
    pub target: PolicyTargetKey,
    pub max_bytes: u64,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthCheckPolicyState {
    pub target: PolicyTargetKey,
    pub path: String,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CORSPolicyState {
    pub target: PolicyTargetKey,
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: u32,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimeoutPolicyState {
    pub target: PolicyTargetKey,
    pub request_timeout_ms: u64,
    pub backend_request_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendTLSPolicyState {
    pub target: PolicyTargetKey,
    pub ca_cert_pem: String,
    pub hostname: String,
    pub subject_alt_names: Vec<SubjectAltNameState>,
    pub generation: i64,
    pub creation_timestamp: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubjectAltNameState {
    pub san_type: String, // "Hostname" or "URI"
    pub value: String,
}

// ---- PolicyState trait implementations ----

use crate::reconcilers::policy_common::PolicyState;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

macro_rules! impl_policy_state {
    ($ty:ty) => {
        impl PolicyState for $ty {
            fn target(&self) -> &PolicyTargetKey {
                &self.target
            }
            fn creation_timestamp(&self) -> &Option<Time> {
                &self.creation_timestamp
            }
            fn accepted(&self) -> bool {
                self.accepted
            }
            fn set_accepted(&mut self, v: bool) {
                self.accepted = v;
            }
        }
    };
}

impl_policy_state!(RateLimitPolicyState);
impl_policy_state!(CircuitBreakerPolicyState);
impl_policy_state!(ConnectionPolicyState);
impl_policy_state!(BasicAuthPolicyState);
impl_policy_state!(ApiKeyAuthPolicyState);
impl_policy_state!(RetryPolicyState);
impl_policy_state!(IPAllowlistPolicyState);
impl_policy_state!(RequestBodySizeLimitPolicyState);
impl_policy_state!(HealthCheckPolicyState);
impl_policy_state!(CORSPolicyState);
impl_policy_state!(TimeoutPolicyState);
impl_policy_state!(BackendTLSPolicyState);

#[derive(Debug, Clone, PartialEq)]
pub struct SecretState {
    /// Key-value data from the Secret (keys are data field names, values are decoded strings)
    pub data: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceGrantState {
    pub namespace: String,
    pub from: Vec<ReferenceGrantFrom>,
    pub to: Vec<ReferenceGrantTo>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceGrantFrom {
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceGrantTo {
    pub group: String,
    pub kind: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ServiceKey {
    pub namespace: String,
    pub name: String,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_notify_only_marks_dirty_on_a_change() {
        let store = ConfigStore::new();
        assert!(store.take_dirty(), "starts dirty so the first compile happens");
        let key = NamespacedName { namespace: "ns".into(), name: "gc".into() };
        let state = GatewayClassState { accepted: true, generation: 1 };
        assert!(store.insert_and_notify(&store.gateway_classes, key.name.clone(), state.clone()));
        assert!(store.take_dirty());
        // Same value again: nothing written, compiler left alone.
        assert!(!store.insert_and_notify(&store.gateway_classes, key.name.clone(), state.clone()));
        assert!(!store.take_dirty());
        // A different value is a change.
        assert!(store.insert_and_notify(&store.gateway_classes, key.name, GatewayClassState { accepted: true, generation: 2 }));
        assert!(store.take_dirty());
    }

    #[test]
    fn publish_reaches_every_subscriber_and_needs_none() {
        let store = ConfigStore::new();
        // No subscriber yet: not an error.
        store.publish(Event::Namespace("a".into()));
        let mut one = store.events.subscribe();
        let mut two = store.events.subscribe();
        let gw = NamespacedName { namespace: "ns".into(), name: "gw".into() };
        store.notify_programmed(&gw);
        assert_eq!(one.try_recv().unwrap(), Event::Programmed(gw.clone()));
        assert_eq!(two.try_recv().unwrap(), Event::Programmed(gw));
    }

    #[test]
    fn record_applied_names_the_gateway_a_node_left_and_the_one_it_joined() {
        let store = ConfigStore::new();
        let mut rx = store.events.subscribe();
        let a = NamespacedName { namespace: "ns".into(), name: "a".into() };
        let b = NamespacedName { namespace: "ns".into(), name: "b".into() };
        assert!(store.record_applied("node", a.clone(), 1));
        assert_eq!(rx.try_recv().unwrap(), Event::Programmed(a.clone()));
        // Same content again: silence.
        assert!(store.record_applied("node", a.clone(), 1));
        assert!(rx.try_recv().is_err());
        // Node moves to another Gateway: both may have changed.
        assert!(store.record_applied("node", b.clone(), 1));
        assert_eq!(rx.try_recv().unwrap(), Event::Programmed(a));
        assert_eq!(rx.try_recv().unwrap(), Event::Programmed(b.clone()));
        store.forget_data_plane("node");
        assert_eq!(rx.try_recv().unwrap(), Event::Programmed(b));
    }

    #[test]
    fn test_new_creates_empty_store() {
        let store = ConfigStore::new();
        assert!(store.gateway_classes.is_empty());
        assert!(store.gateways.is_empty());
        assert!(store.http_routes.is_empty());
        assert!(store.grpc_routes.is_empty());
        assert!(store.tls_routes.is_empty());
        assert!(store.tcp_routes.is_empty());
        assert!(store.udp_routes.is_empty());
        assert!(store.reference_grants.is_empty());
        assert!(store.endpoints.is_empty());
        assert!(store.rate_limit_policies.is_empty());
        assert!(store.circuit_breaker_policies.is_empty());
        assert!(store.connection_policies.is_empty());
        assert!(store.basic_auth_policies.is_empty());
        assert!(store.api_key_auth_policies.is_empty());
        assert!(store.retry_policies.is_empty());
        assert!(store.ip_allowlist_policies.is_empty());
        assert!(store.request_body_size_limit_policies.is_empty());
        assert!(store.health_check_policies.is_empty());
        assert!(store.cors_policies.is_empty());
        assert!(store.timeout_policies.is_empty());
        assert!(store.backend_tls_policies.is_empty());
        assert!(store.secrets.is_empty());
        assert!(store.config_maps.is_empty());
        assert!(store.service_port_map.is_empty());
        assert!(store.service_app_protocols.is_empty());
        assert!(store.service_port_names.is_empty());
        assert_eq!(store.compiled_version.load(Ordering::Relaxed), 0);
        assert_eq!(store.compiled_fingerprint.load(Ordering::Relaxed), 0);
        assert!(store.data_plane_applied.is_empty());
    }

    #[tokio::test]
    async fn test_notify_change_wakes_waiting_task() {
        let store = std::sync::Arc::new(ConfigStore::new());
        let store2 = store.clone();

        let handle = tokio::spawn(async move {
            store2.change_notify.notified().await;
            true
        });

        // Small yield to let the spawned task register its waiter
        tokio::task::yield_now().await;
        store.notify_change();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle,
        )
        .await
        .expect("timeout")
        .expect("join");
        assert!(result);
    }

    #[test]
    fn test_dashmap_insert_remove() {
        let store = ConfigStore::new();
        store.gateway_classes.insert(
            "test".to_string(),
            GatewayClassState {
                accepted: true,
                generation: 1,
            },
        );
        assert_eq!(store.gateway_classes.len(), 1);
        assert!(store.gateway_classes.get("test").unwrap().accepted);

        store.gateway_classes.remove("test");
        assert!(store.gateway_classes.is_empty());
    }

    #[tokio::test]
    async fn test_insert_and_notify_triggers_change() {
        let store = std::sync::Arc::new(ConfigStore::new());
        let store2 = store.clone();

        let handle = tokio::spawn(async move {
            store2.change_notify.notified().await;
            true
        });

        tokio::task::yield_now().await;
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "test-secret".to_string(),
        };
        store.insert_and_notify(&store.secrets, key, SecretState {
            data: std::collections::HashMap::new(),
        });
        assert_eq!(store.secrets.len(), 1);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle,
        )
        .await
        .expect("timeout")
        .expect("join");
        assert!(result, "insert_and_notify should wake the change listener");
    }

    #[tokio::test]
    async fn test_remove_and_notify_triggers_change() {
        let store = std::sync::Arc::new(ConfigStore::new());
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "test-secret".to_string(),
        };
        store.secrets.insert(key.clone(), SecretState {
            data: std::collections::HashMap::new(),
        });

        let store2 = store.clone();
        let handle = tokio::spawn(async move {
            store2.change_notify.notified().await;
            true
        });

        tokio::task::yield_now().await;
        let removed = store.remove_and_notify(&store.secrets, &key);
        assert!(removed.is_some());
        assert!(store.secrets.is_empty());

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle,
        )
        .await
        .expect("timeout")
        .expect("join");
        assert!(result, "remove_and_notify should wake the change listener");
    }

    #[test]
    fn test_remove_and_notify_no_notify_on_missing_key() {
        let store = ConfigStore::new();
        let key = NamespacedName {
            namespace: "default".to_string(),
            name: "nonexistent".to_string(),
        };
        // Should return None and NOT notify (no change)
        let removed = store.remove_and_notify(&store.secrets, &key);
        assert!(removed.is_none());
    }

    #[test]
    fn test_is_programmed_false_with_no_data_planes() {
        let store = ConfigStore::new();
        store.compiled_fingerprint.store(0xabc, Ordering::Release);
        assert!(!store.is_programmed());
    }

    fn dedicated(ns: &str, name: &str, fp: u64) -> AppliedState {
        AppliedState {
            gateway: NamespacedName { namespace: ns.into(), name: name.into() },
            fingerprint: fp,
        }
    }
    fn gw(ns: &str, name: &str) -> NamespacedName {
        NamespacedName { namespace: ns.into(), name: name.into() }
    }

    #[test]
    fn test_is_programmed_false_before_first_compile() {
        let store = ConfigStore::new();
        store.data_plane_applied.insert("node-1".to_string(), dedicated("ns", "gw", 0xabc));
        assert!(!store.is_programmed());
        assert!(!store.is_programmed_for(&gw("ns", "gw")));
    }

    #[test]
    fn test_is_programmed_true_when_a_data_plane_runs_its_current_slice() {
        let store = ConfigStore::new();
        store.compiled_fingerprint.store(0xabc, Ordering::Release);
        store.compiled_gateway_fingerprints.insert(gw("ns", "gw"), 0x111);
        store.data_plane_applied.insert("node-1".to_string(), dedicated("ns", "gw", 0x111));
        assert!(store.is_programmed());
        assert!(store.is_programmed_for(&gw("ns", "gw")));
        assert!(!store.is_programmed_for(&gw("ns", "other")), "a Gateway with no data plane");
    }

    #[test]
    fn test_is_programmed_false_when_every_data_plane_runs_other_content() {
        // Fingerprints are content hashes, not ordered: "newer" has no meaning,
        // only equality with the compiled slice counts.
        let store = ConfigStore::new();
        store.compiled_fingerprint.store(0xabc, Ordering::Release);
        store.compiled_gateway_fingerprints.insert(gw("ns", "gw"), 0x111);
        store.data_plane_applied.insert("node-1".to_string(), dedicated("ns", "gw", 0xdef));
        store.data_plane_applied.insert("node-2".to_string(), dedicated("ns", "gw", 0x123));
        assert!(!store.is_programmed());
    }

    #[test]
    fn test_is_programmed_for_uses_the_gateway_slice_fingerprint() {
        let store = ConfigStore::new();
        store.compiled_fingerprint.store(0xabc, Ordering::Release);
        store.compiled_gateway_fingerprints.insert(gw("ns", "a"), 0xa);
        store.compiled_gateway_fingerprints.insert(gw("ns", "b"), 0xb);
        // Dedicated data plane for `a` on the current slice.
        store.data_plane_applied.insert("dp-a".to_string(), dedicated("ns", "a", 0xa));
        assert!(store.is_programmed_for(&gw("ns", "a")));
        // `b` has no data plane yet.
        assert!(!store.is_programmed_for(&gw("ns", "b")));
        // A dedicated data plane on a stale slice does not count.
        store.data_plane_applied.insert("dp-b".to_string(), dedicated("ns", "b", 0xbad));
        assert!(!store.is_programmed_for(&gw("ns", "b")));
        // The aggregate is true because at least one node is current.
        assert!(store.is_programmed());
        // A data plane dedicated to `a` never programs `b`.
        store.data_plane_applied.insert("dp-a2".to_string(), dedicated("ns", "a", 0xb));
        assert!(!store.is_programmed_for(&gw("ns", "b")));
    }

    #[test]
    fn test_forget_data_plane_frees_the_cap_and_may_unprogram() {
        let store = ConfigStore::new();
        store.compiled_fingerprint.store(9, Ordering::Release);
        store.compiled_gateway_fingerprints.insert(gw("ns", "gw"), 9);
        assert!(store.record_applied("dp-1", gw("ns", "gw"), 9));
        assert!(store.is_programmed());

        store.forget_data_plane("dp-1");
        assert!(!store.is_programmed(), "the only current data plane is gone");
        assert!(store.data_plane_applied.get("dp-1").is_none());
        assert!(store.accepts_data_plane("dp-replacement"));
        // Forgetting an unknown node is a no-op.
        store.forget_data_plane("never-seen");
    }

    #[test]
    fn test_record_applied_ignores_zero_and_enforces_cap() {
        let store = ConfigStore::new();
        assert!(!store.record_applied("node-1", gw("ns", "gw"), 0));
        for i in 0..ConfigStore::MAX_DATA_PLANE_NODES {
            assert!(store.record_applied(&format!("node-{i}"), gw("ns", "gw"), 1));
        }
        assert!(!store.record_applied("one-too-many", gw("ns", "gw"), 1));
        // A known node is still accepted at the cap.
        assert!(store.record_applied("node-0", gw("ns", "gw"), 2));
    }

    #[tokio::test]
    async fn test_record_applied_wakes_programmed_waiters_on_catch_up() {
        let store = std::sync::Arc::new(ConfigStore::new());
        store.compiled_fingerprint.store(7, Ordering::Release);
        let mut events = store.events.subscribe();
        let waiter = tokio::spawn(async move {
            matches!(events.recv().await, Ok(Event::Programmed(g)) if g == gw("ns", "gw"))
        });
        store.compiled_gateway_fingerprints.insert(gw("ns", "gw"), 7);
        tokio::task::yield_now().await;
        // Stale fingerprint: recorded, not programmed (still wakes: content changed).
        assert!(store.record_applied("node-1", gw("ns", "gw"), 6));
        assert!(!store.is_programmed());
        // Current fingerprint: programmed flips and waiters wake.
        assert!(store.record_applied("node-1", gw("ns", "gw"), 7));
        assert!(store.is_programmed());
        let woke = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("waiter must be woken")
            .unwrap();
        assert!(woke);
    }

    #[test]
    fn test_namespaced_name_display() {
        let nn = NamespacedName {
            namespace: "default".to_string(),
            name: "my-gateway".to_string(),
        };
        assert_eq!(nn.to_string(), "default/my-gateway");
    }

    #[test]
    fn test_is_secret_referenced_false_when_empty() {
        let store = ConfigStore::new();
        assert!(!store.is_secret_referenced("default", "my-secret"));
    }

    #[test]
    fn test_is_secret_referenced_by_gateway_tls_cert() {
        let store = ConfigStore::new();
        store.gateways.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "gw".to_string(),
            },
            GatewayState {
                name: "gw".to_string(),
                namespace: "default".to_string(),
                listeners: vec![ListenerState {
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
                    tls_cert_refs: vec![("default".to_string(), "tls-cert".to_string())],
                    tls_mode: Some("Terminate".to_string()),
                }],
                generation: 1,
                allowed_listener_namespaces_from: None,
                allowed_listener_match_labels: Vec::new(),
            },
        );

        assert!(store.is_secret_referenced("default", "tls-cert"));
        assert!(!store.is_secret_referenced("default", "other-secret"));
        assert!(!store.is_secret_referenced("other-ns", "tls-cert"));
    }

    #[test]
    fn test_is_secret_referenced_by_basic_auth_policy() {
        let store = ConfigStore::new();
        store.basic_auth_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ba-pol".to_string(),
            },
            BasicAuthPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                    name: "route".to_string(),
                    section_name: None,
                },
                secret_namespace: "default".to_string(),
                secret_name: "auth-creds".to_string(),
                realm: "Restricted".to_string(),
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        assert!(store.is_secret_referenced("default", "auth-creds"));
        assert!(!store.is_secret_referenced("default", "other-secret"));
    }

    #[test]
    fn test_is_secret_referenced_by_api_key_auth_policy() {
        let store = ConfigStore::new();
        store.api_key_auth_policies.insert(
            NamespacedName {
                namespace: "default".to_string(),
                name: "ak-pol".to_string(),
            },
            ApiKeyAuthPolicyState {
                target: PolicyTargetKey {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    namespace: "default".to_string(),
                    name: "route".to_string(),
                    section_name: None,
                },
                secret_namespace: "default".to_string(),
                secret_name: "api-keys".to_string(),
                header_name: "X-API-Key".to_string(),
                generation: 1,
                creation_timestamp: None,
                accepted: true,
            },
        );

        assert!(store.is_secret_referenced("default", "api-keys"));
        assert!(!store.is_secret_referenced("default", "other-secret"));
    }
}
