//! Per-Gateway dataplane provisioning.
//!
//! Every accepted Gateway gets its own dataplane `Deployment`, a `Service`
//! exposing exactly its listener ports, a `PodDisruptionBudget` and, when the
//! config stream runs over mTLS, a copy of the controller's TLS `Secret` in
//! the Gateway's namespace (a pod can only mount Secrets from its own
//! namespace), all owned by the Gateway (garbage-collected with it). The
//! Service's address is what the Gateway reports in `status.addresses`, so two
//! Gateways never share an
//! address and each dataplane only ever runs its own Gateway's config
//! (`compiler::scope_config`, selected by the `GATEWAY_NAMESPACE`/`GATEWAY_NAME`
//! environment the Deployment sets).
//!
//! The builders here are pure (spec in, object out) so they can be tested
//! without a cluster; `apply` performs the server-side-apply writes.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, HTTPGetAction, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, Secret, SecretVolumeSource, SecurityContext, Service,
    ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, Patch, PatchParams};

use crate::gateway_types::{Gateway, GatewayAddress};
use crate::status::with_write_timeout;

/// Field manager for every object the provisioner writes.
pub const FIELD_MANAGER: &str = "portus-gateway-provisioner";
/// Labels identifying the Gateway an object belongs to.
pub const LABEL_GATEWAY_NAME: &str = "gateway.portus.dev/name";
pub const LABEL_GATEWAY_NAMESPACE: &str = "gateway.portus.dev/namespace";
pub const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
/// Gateway API's standard label for generated infrastructure
/// (`GatewayNameLabelKey`); the conformance suite finds our objects by it.
pub const LABEL_GATEWAY_API_NAME: &str = "gateway.networking.k8s.io/gateway-name";
pub const LABEL_COMPONENT: &str = "app.kubernetes.io/component";

const HEALTH_PORT: i32 = 8081;
const METRICS_PORT: i32 = 9090;

/// Everything the provisioner needs to know that does not come from the
/// Gateway itself. Populated from the controller's environment (rendered by
/// the Helm chart) so a bare `GatewayClass` with no `parametersRef` works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneTemplate {
    pub image: String,
    pub image_pull_policy: String,
    pub replicas: i32,
    /// Kubernetes Service type for the per-Gateway Service.
    pub service_type: String,
    /// Extra annotations for the per-Gateway Service (cloud LB settings).
    pub service_annotations: BTreeMap<String, String>,
    /// `host:port` of the controller's gRPC config stream.
    pub controller_addr: String,
    /// Namespace the controller runs in: where `grpc_tls_secret` lives.
    pub controller_namespace: String,
    /// Secret in `controller_namespace` with `ca.crt`, `tls.crt`, `tls.key`
    /// for the gRPC stream, copied into every Gateway's namespace; None =
    /// plaintext (`GRPC_TLS_INSECURE=true`, dev only).
    pub grpc_tls_secret: Option<String>,
    pub log_level: String,
    /// Emit one access-log line per request (`PORTUS_ACCESS_LOG` on the pods).
    pub access_log: bool,
    /// Pingora worker threads per pod (`DATAPLANE_THREADS`). None lets the
    /// dataplane size itself from its cgroup CPU limit or the node's CPU count.
    pub threads: Option<usize>,
    /// ServiceAccount for dataplane pods. Must exist in every Gateway's
    /// namespace, so it is normally unset (default SA, token automount off).
    pub service_account: Option<String>,
    pub cpu_request: String,
    pub memory_request: String,
    pub memory_limit: String,
}

impl DataplaneTemplate {
    /// Read the template from `PORTUS_DATAPLANE_*` / `PORTUS_*` environment
    /// variables. Missing variables fall back to the chart defaults.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let kv_list = |k: &str| -> BTreeMap<String, String> {
            var(k)
                .map(|v| {
                    v.split(',')
                        .filter_map(|pair| {
                            let (a, b) = pair.split_once('=')?;
                            Some((a.trim().to_string(), b.trim().to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            image: var("PORTUS_DATAPLANE_IMAGE").unwrap_or_else(|| "portus-gateway-dataplane:latest".into()),
            image_pull_policy: var("PORTUS_DATAPLANE_PULL_POLICY").unwrap_or_else(|| "IfNotPresent".into()),
            replicas: var("PORTUS_DATAPLANE_REPLICAS")
                .and_then(|v| v.parse().ok())
                .filter(|r: &i32| *r >= 1)
                .unwrap_or(2),
            service_type: var("PORTUS_DATAPLANE_SERVICE_TYPE").unwrap_or_else(|| "LoadBalancer".into()),
            service_annotations: kv_list("PORTUS_DATAPLANE_SERVICE_ANNOTATIONS"),
            controller_addr: var("PORTUS_CONTROLLER_ADDR").unwrap_or_else(|| "portus-controller:50051".into()),
            controller_namespace: var("PORTUS_NAMESPACE").unwrap_or_else(|| "portus".into()),
            grpc_tls_secret: var("PORTUS_GRPC_TLS_SECRET"),
            log_level: var("PORTUS_DATAPLANE_LOG_LEVEL").unwrap_or_else(|| "info".into()),
            access_log: var("PORTUS_DATAPLANE_ACCESS_LOG").is_some_and(|v| parse_bool(&v)),
            threads: var("PORTUS_DATAPLANE_THREADS").and_then(|v| v.trim().parse().ok()).filter(|n: &usize| *n > 0),
            service_account: var("PORTUS_DATAPLANE_SERVICE_ACCOUNT"),
            cpu_request: var("PORTUS_DATAPLANE_CPU_REQUEST").unwrap_or_else(|| "250m".into()),
            memory_request: var("PORTUS_DATAPLANE_MEMORY_REQUEST").unwrap_or_else(|| "256Mi".into()),
            memory_limit: var("PORTUS_DATAPLANE_MEMORY_LIMIT").unwrap_or_else(|| "512Mi".into()),
        }
    }

    /// Whether the Secret `namespace/name` is the gRPC TLS material every
    /// Gateway's dataplane runs with; a change to it re-provisions them all.
    pub fn is_grpc_tls_source(&self, namespace: &str, name: &str) -> bool {
        self.grpc_tls_secret.as_deref() == Some(name) && self.controller_namespace == namespace
    }
}

/// The TLS Secret keys the config stream needs, copied verbatim per Gateway.
const GRPC_TLS_KEYS: [&str; 3] = ["ca.crt", "tls.crt", "tls.key"];

/// Why a Gateway could not be provisioned.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("{0}")]
    Kube(#[from] kube::Error),
    #[error("gRPC TLS Secret {namespace}/{name} has no `{key}` key")]
    TlsSecretKeyMissing { namespace: String, name: String, key: &'static str },
}

/// The Gateway-owned copy of the controller's gRPC TLS Secret: only the three
/// keys the dataplane mounts, so unrelated data in the source never spreads.
pub fn desired_tls_secret(gw: &GatewayRef, source: &Secret) -> Result<Secret, ProvisionError> {
    let data = source.data.as_ref();
    let mut copied = BTreeMap::new();
    for key in GRPC_TLS_KEYS {
        let value = data.and_then(|d| d.get(key)).ok_or_else(|| ProvisionError::TlsSecretKeyMissing {
            namespace: source.metadata.namespace.clone().unwrap_or_default(),
            name: source.metadata.name.clone().unwrap_or_default(),
            key,
        })?;
        copied.insert(key.to_string(), value.clone());
    }
    Ok(Secret {
        metadata: metadata(gw, BTreeMap::new()),
        type_: Some("kubernetes.io/tls".into()),
        data: Some(copied),
        ..Default::default()
    })
}

/// Transport of a listener port on the Service and the pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum L4Protocol {
    Tcp,
    Udp,
}

impl L4Protocol {
    /// Kubernetes `protocol` value.
    pub fn as_str(self) -> &'static str {
        match self {
            L4Protocol::Tcp => "TCP",
            L4Protocol::Udp => "UDP",
        }
    }

    /// From a Gateway listener protocol: UDP listeners are UDP, everything
    /// else (HTTP, HTTPS, TLS, TCP) is a TCP port.
    pub fn of_listener(protocol: &str) -> Self {
        if protocol == "UDP" { L4Protocol::Udp } else { L4Protocol::Tcp }
    }
}

/// One port a Gateway listens on. The same number may appear once per
/// transport (a UDP and a TCP listener on 5300 are two Service ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListenerPort {
    pub port: u16,
    pub protocol: L4Protocol,
}

/// The Gateway facts the builders need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRef {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    /// Listener ports (Gateway listeners plus attached ListenerSets).
    pub ports: Vec<ListenerPort>,
    /// `spec.infrastructure.labels` / `annotations` to propagate.
    pub infra_labels: BTreeMap<String, String>,
    pub infra_annotations: BTreeMap<String, String>,
}

/// Name of the generated objects for a Gateway: `portus-<name>-<uid prefix>`.
///
/// The UID suffix makes a deleted-and-recreated Gateway get fresh object
/// names. Without it the new Service reuses the old name while the previous
/// Endpoints/EndpointSlice objects are still being garbage-collected, and the
/// endpoints controller stalls on `endpoints "..." already exists` - seen as
/// `connection refused` to the new ClusterIP under the conformance suite's
/// rapid delete/recreate cycles. Bounded to a DNS label (63 chars).
pub fn object_name(gateway_name: &str, uid: &str) -> String {
    let suffix: String = uid.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    let suffix = if suffix.is_empty() { "nouid".to_string() } else { suffix.to_ascii_lowercase() };
    let max_base = 63 - suffix.len() - 1;
    let mut base = format!("portus-{gateway_name}");
    if base.len() > max_base {
        base.truncate(max_base);
    }
    format!("{}-{}", base.trim_end_matches('-'), suffix)
}

fn owner_reference(gw: &GatewayRef) -> OwnerReference {
    OwnerReference {
        api_version: "gateway.networking.k8s.io/v1".into(),
        kind: "Gateway".into(),
        name: gw.name.clone(),
        uid: gw.uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Labels on every generated object. `infra_labels` first so the Gateway
/// cannot override the identity labels.
pub fn common_labels(gw: &GatewayRef) -> BTreeMap<String, String> {
    let mut labels = gw.infra_labels.clone();
    labels.insert(LABEL_MANAGED_BY.into(), "portus-gateway".into());
    labels.insert(LABEL_COMPONENT.into(), "dataplane".into());
    labels.insert(LABEL_GATEWAY_NAME.into(), gw.name.clone());
    labels.insert(LABEL_GATEWAY_NAMESPACE.into(), gw.namespace.clone());
    labels.insert(LABEL_GATEWAY_API_NAME.into(), gw.name.clone());
    labels
}

/// The pod selector: the dedicated dataplane pods of this Gateway.
pub fn pod_selector(gw: &GatewayRef) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED_BY.to_string(), "portus-gateway".to_string()),
        (LABEL_COMPONENT.to_string(), "dataplane".to_string()),
        (LABEL_GATEWAY_NAME.to_string(), gw.name.clone()),
        (LABEL_GATEWAY_NAMESPACE.to_string(), gw.namespace.clone()),
    ])
}

fn metadata(gw: &GatewayRef, annotations: BTreeMap<String, String>) -> ObjectMeta {
    ObjectMeta {
        name: Some(object_name(&gw.name, &gw.uid)),
        namespace: Some(gw.namespace.clone()),
        labels: Some(common_labels(gw)),
        annotations: if annotations.is_empty() { None } else { Some(annotations) },
        owner_references: Some(vec![owner_reference(gw)]),
        ..Default::default()
    }
}

/// Sorted, de-duplicated listener ports; health/metrics are never exposed.
fn service_ports(gw: &GatewayRef) -> Vec<ListenerPort> {
    let mut ports: Vec<ListenerPort> = gw
        .ports
        .iter()
        .copied()
        .filter(|p| p.port != 0 && i32::from(p.port) != HEALTH_PORT && i32::from(p.port) != METRICS_PORT)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Service/container port name: `tcp-80`, `udp-5300`.
fn port_name(p: ListenerPort) -> String {
    format!("{}-{}", p.protocol.as_str().to_ascii_lowercase(), p.port)
}

/// The per-Gateway Service: one port per listener port, selecting the
/// Gateway's dataplane pods.
pub fn desired_service(gw: &GatewayRef, tpl: &DataplaneTemplate) -> Service {
    let mut annotations = gw.infra_annotations.clone();
    annotations.extend(tpl.service_annotations.clone());
    let ports = service_ports(gw)
        .into_iter()
        .map(|p| ServicePort {
            name: Some(port_name(p)),
            port: i32::from(p.port),
            target_port: Some(IntOrString::Int(i32::from(p.port))),
            protocol: Some(p.protocol.as_str().into()),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    Service {
        metadata: metadata(gw, annotations),
        spec: Some(ServiceSpec {
            type_: Some(tpl.service_type.clone()),
            selector: Some(pod_selector(gw)),
            // A Service with no ports is invalid; a Gateway with no accepted
            // listeners still gets an address via a placeholder port so status
            // can be reported. Nothing listens on it.
            ports: Some(if ports.is_empty() {
                vec![ServicePort {
                    name: Some("placeholder".into()),
                    port: 65535,
                    target_port: Some(IntOrString::Int(65535)),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]
            } else {
                ports
            }),
            ..Default::default()
        }),
        status: None,
    }
}

/// Kubernetes-style boolean from the chart (`"true"`, `"1"`, `"yes"`, `"on"`).
pub fn parse_bool(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

fn env(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value.into()),
        value_from: None,
    }
}

fn http_probe(path: &str, initial: i32, period: i32) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.into()),
            port: IntOrString::Int(HEALTH_PORT),
            ..Default::default()
        }),
        initial_delay_seconds: Some(initial),
        period_seconds: Some(period),
        timeout_seconds: Some(1),
        ..Default::default()
    }
}

/// The dedicated dataplane Deployment for a Gateway.
pub fn desired_deployment(gw: &GatewayRef, tpl: &DataplaneTemplate) -> Deployment {
    let selector = pod_selector(gw);
    let mut pod_labels = common_labels(gw);
    pod_labels.extend(selector.clone());

    let mut envs = vec![
        env("RUST_LOG", &tpl.log_level),
        env("PORTUS_ACCESS_LOG", if tpl.access_log { "true" } else { "false" }),
        env("CONTROLLER_ADDR", &tpl.controller_addr),
        env("GATEWAY_NAMESPACE", &gw.namespace),
        env("GATEWAY_NAME", &gw.name),
    ];
    if let Some(threads) = tpl.threads {
        envs.push(env("DATAPLANE_THREADS", &threads.to_string()));
    }
    let mut volumes = Vec::new();
    let mut mounts = Vec::new();
    if tpl.grpc_tls_secret.is_some() {
        envs.push(env("GRPC_TLS_CA", "/etc/grpc-tls/ca.crt"));
        envs.push(env("GRPC_TLS_CERT", "/etc/grpc-tls/tls.crt"));
        envs.push(env("GRPC_TLS_KEY", "/etc/grpc-tls/tls.key"));
        // The Gateway-owned copy `apply` writes next to the Deployment.
        volumes.push(Volume {
            name: "grpc-tls".into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(object_name(&gw.name, &gw.uid)),
                ..Default::default()
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: "grpc-tls".into(),
            mount_path: "/etc/grpc-tls".into(),
            read_only: Some(true),
            ..Default::default()
        });
    } else {
        envs.push(env("GRPC_TLS_INSECURE", "true"));
    }

    let mut container_ports: Vec<ContainerPort> = service_ports(gw)
        .into_iter()
        .map(|p| ContainerPort {
            name: Some(port_name(p)),
            container_port: i32::from(p.port),
            protocol: Some(p.protocol.as_str().into()),
            ..Default::default()
        })
        .collect();
    container_ports.push(ContainerPort {
        name: Some("health".into()),
        container_port: HEALTH_PORT,
        protocol: Some("TCP".into()),
        ..Default::default()
    });
    container_ports.push(ContainerPort {
        name: Some("metrics".into()),
        container_port: METRICS_PORT,
        protocol: Some("TCP".into()),
        ..Default::default()
    });

    let container = Container {
        name: "dataplane".into(),
        image: Some(tpl.image.clone()),
        image_pull_policy: Some(tpl.image_pull_policy.clone()),
        ports: Some(container_ports),
        env: Some(envs),
        volume_mounts: if mounts.is_empty() { None } else { Some(mounts) },
        // Poll readiness once a second from one second in. A dataplane serves
        // traffic within ~1 s of its first config, and the conformance suite
        // gates every test on *all* pods in the Gateway's namespace being
        // Ready, so a slow probe on one Gateway's pod stalls every other test
        // in that namespace. Fast probes also shorten rollouts in production.
        readiness_probe: Some(http_probe("/readyz", 1, 1)),
        liveness_probe: Some(http_probe("/healthz", 10, 10)),
        resources: Some(ResourceRequirements {
            requests: Some(BTreeMap::from([
                ("cpu".to_string(), Quantity(tpl.cpu_request.clone())),
                ("memory".to_string(), Quantity(tpl.memory_request.clone())),
            ])),
            limits: Some(BTreeMap::from([("memory".to_string(), Quantity(tpl.memory_limit.clone()))])),
            ..Default::default()
        }),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                // Binding 80/443 as UID 1000 needs the capability on kernels
                // without unprivileged-port sysctls.
                add: Some(vec!["NET_BIND_SERVICE".into()]),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut pod_annotations = gw.infra_annotations.clone();
    pod_annotations.insert("prometheus.io/scrape".into(), "true".into());
    pod_annotations.insert("prometheus.io/port".into(), METRICS_PORT.to_string());

    Deployment {
        metadata: metadata(gw, gw.infra_annotations.clone()),
        spec: Some(DeploymentSpec {
            replicas: Some(tpl.replicas),
            selector: LabelSelector {
                match_labels: Some(selector),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy {
                type_: Some("RollingUpdate".into()),
                rolling_update: Some(RollingUpdateDeployment {
                    max_surge: Some(IntOrString::Int(1)),
                    max_unavailable: Some(IntOrString::Int(0)),
                }),
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    annotations: Some(pod_annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    // The dataplane has no long-lived work to flush; a short
                    // grace period gets terminating pods out of the way fast.
                    termination_grace_period_seconds: Some(5),
                    service_account_name: tpl.service_account.clone(),
                    automount_service_account_token: Some(false),
                    security_context: Some(PodSecurityContext {
                        run_as_non_root: Some(true),
                        run_as_user: Some(1000),
                        fs_group: Some(1000),
                        ..Default::default()
                    }),
                    containers: vec![container],
                    volumes: if volumes.is_empty() { None } else { Some(volumes) },
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        status: None,
    }
}

/// Keep at least one dataplane pod up during voluntary disruption.
pub fn desired_pdb(gw: &GatewayRef, tpl: &DataplaneTemplate) -> PodDisruptionBudget {
    PodDisruptionBudget {
        metadata: metadata(gw, BTreeMap::new()),
        spec: Some(PodDisruptionBudgetSpec {
            min_available: Some(IntOrString::Int(if tpl.replicas > 1 { 1 } else { 0 })),
            selector: Some(LabelSelector {
                match_labels: Some(pod_selector(gw)),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    }
}

/// Addresses to report for a Gateway from its Service: LoadBalancer ingress
/// entries when present, otherwise the ClusterIP. Empty while neither exists.
pub fn addresses_from_service(svc: &Service) -> Vec<GatewayAddress> {
    let mut out = Vec::new();
    if let Some(ingress) = svc
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
    {
        for entry in ingress {
            if let Some(ip) = entry.ip.as_deref().filter(|s| !s.is_empty()) {
                out.push(GatewayAddress { type_: Some("IPAddress".into()), value: ip.to_string() });
            } else if let Some(host) = entry.hostname.as_deref().filter(|s| !s.is_empty()) {
                out.push(GatewayAddress { type_: Some("Hostname".into()), value: host.to_string() });
            }
        }
    }
    if out.is_empty()
        && let Some(ip) = svc
            .spec
            .as_ref()
            .and_then(|s| s.cluster_ip.as_deref())
            .filter(|ip| !ip.is_empty() && *ip != "None")
    {
        out.push(GatewayAddress { type_: Some("IPAddress".into()), value: ip.to_string() });
    }
    out
}

/// Whether the Service is still waiting for a LoadBalancer address.
/// True once the store has seen at least one ready endpoint for `svc` (from
/// its EndpointSlices). Until then the Service's ClusterIP is not yet a usable
/// address: kube-proxy programs a new Service asynchronously, and a client
/// whose first SYN arrives before that pins a conntrack entry that is never
/// DNAT'd, so its connect blackholes for its whole timeout. The conformance
/// suite dials the instant `status.addresses` appears, which is how this
/// showed up as 30 s TCP/TLS connect hangs on freshly created Gateways.
pub fn service_has_ready_endpoints(store: &crate::store::ConfigStore, svc: &Service) -> bool {
    let (Some(ns), Some(name)) = (svc.metadata.namespace.as_deref(), svc.metadata.name.as_deref()) else {
        return false;
    };
    store
        .endpoints
        .iter()
        .any(|e| e.key().namespace == ns && e.key().name == name && !e.value().is_empty())
}

/// The ClusterIP and first TCP port a reachability probe should target, or
/// None when there is nothing to connect to: no usable ClusterIP (headless,
/// not yet allocated) or only UDP ports, which cannot be probed by connecting.
pub fn probe_target(svc: &Service) -> Option<std::net::SocketAddr> {
    let spec = svc.spec.as_ref()?;
    let ip = spec.cluster_ip.as_deref().filter(|ip| !ip.is_empty() && *ip != "None")?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let port = spec
        .ports
        .as_ref()?
        .iter()
        .find(|p| p.protocol.as_deref().unwrap_or("TCP") == "TCP")?
        .port;
    let port = u16::try_from(port).ok().filter(|p| *p > 0)?;
    Some(std::net::SocketAddr::new(ip, port))
}

/// True once a TCP connection to `addr` succeeds within `timeout`.
///
/// A ready endpoint in the API is not the same as a routable Service: kube-proxy
/// programs the ClusterIP asynchronously, and a client whose first SYN arrives
/// before that pins a conntrack entry that is never DNAT'd, so its connect hangs
/// for its whole timeout. Connecting from the controller before publishing the
/// address is the only signal that covers the dataplane, the endpoints *and*
/// the node's packet path. Refused (REJECT rule, endpoint gone) and timeouts
/// (blackhole) both count as unreachable.
pub async fn tcp_reachable(addr: std::net::SocketAddr, timeout: std::time::Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// True when `status.addresses` must be rewritten: a different set of
/// (type, value) pairs than the Gateway currently reports.
pub fn addresses_changed(current: &[GatewayAddress], desired: &[(String, String)]) -> bool {
    if current.len() != desired.len() {
        return true;
    }
    let mut cur: Vec<(String, String)> = current
        .iter()
        .map(|a| (a.type_.clone().unwrap_or_else(|| "IPAddress".into()), a.value.clone()))
        .collect();
    let mut want: Vec<(String, String)> = desired.to_vec();
    cur.sort();
    want.sort();
    cur != want
}

pub fn load_balancer_pending(svc: &Service) -> bool {
    let is_lb = svc
        .spec
        .as_ref()
        .and_then(|s| s.type_.as_deref())
        .is_some_and(|t| t == "LoadBalancer");
    is_lb
        && svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .is_none_or(|i| i.is_empty())
}

/// Server-side-apply the generated objects for a Gateway and return the
/// Service as the API server now has it (for address reporting). The TLS
/// Secret copy is written before the Deployment so the pods never start
/// against a missing volume.
pub async fn apply(client: &kube::Client, gw: &GatewayRef, tpl: &DataplaneTemplate) -> Result<Service, ProvisionError> {
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    let ns = gw.namespace.as_str();
    let name = object_name(&gw.name, &gw.uid);

    if let Some(source_name) = &tpl.grpc_tls_secret {
        let source: Api<Secret> = Api::namespaced(client.clone(), &tpl.controller_namespace);
        let source = with_write_timeout("gRPC TLS Secret get", source.get(source_name)).await?;
        let copy = desired_tls_secret(gw, &source)?;
        let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
        with_write_timeout("gRPC TLS Secret apply", secrets.patch(&name, &pp, &Patch::Apply(copy))).await?;
    }

    let deployments: Api<Deployment> = Api::namespaced(client.clone(), ns);
    with_write_timeout(
        "dataplane Deployment apply",
        deployments.patch(&name, &pp, &Patch::Apply(desired_deployment(gw, tpl))),
    )
    .await?;
    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), ns);
    with_write_timeout("dataplane PDB apply", pdbs.patch(&name, &pp, &Patch::Apply(desired_pdb(gw, tpl)))).await?;

    let services: Api<Service> = Api::namespaced(client.clone(), ns);
    Ok(with_write_timeout(
        "Gateway Service apply",
        services.patch(&name, &pp, &Patch::Apply(desired_service(gw, tpl))),
    )
    .await?)
}

/// `GatewayRef` from a live Gateway object plus the ports the store knows
/// about (Gateway listeners and attached ListenerSets).
pub fn gateway_ref(gw: &Gateway, ports: Vec<ListenerPort>) -> Option<GatewayRef> {
    let infra = gw.spec.infrastructure.as_ref();
    Some(GatewayRef {
        namespace: gw.metadata.namespace.clone()?,
        name: gw.metadata.name.clone()?,
        uid: gw.metadata.uid.clone()?,
        ports,
        infra_labels: infra.and_then(|i| i.labels.clone()).unwrap_or_default(),
        infra_annotations: infra.and_then(|i| i.annotations.clone()).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpl() -> DataplaneTemplate {
        DataplaneTemplate {
            image: "portus-gateway/dataplane:test".into(),
            image_pull_policy: "Never".into(),
            replicas: 2,
            service_type: "LoadBalancer".into(),
            service_annotations: BTreeMap::from([("lb/type".to_string(), "nlb".to_string())]),
            controller_addr: "portus-controller.portus:50051".into(),
            controller_namespace: "portus".into(),
            grpc_tls_secret: Some("portus-grpc-tls".into()),
            log_level: "info".into(),
            access_log: false,
            threads: None,
            service_account: Some("portus-dataplane".into()),
            cpu_request: "250m".into(),
            memory_request: "256Mi".into(),
            memory_limit: "512Mi".into(),
        }
    }

    fn tcp(port: u16) -> ListenerPort {
        ListenerPort { port, protocol: L4Protocol::Tcp }
    }

    fn udp(port: u16) -> ListenerPort {
        ListenerPort { port, protocol: L4Protocol::Udp }
    }

    fn gw() -> GatewayRef {
        GatewayRef {
            namespace: "infra".into(),
            name: "same-namespace".into(),
            uid: "uid-123".into(),
            ports: [443, 80, 443, 8080, 0, 9090].into_iter().map(tcp).collect(),
            infra_labels: BTreeMap::from([("team".to_string(), "edge".to_string())]),
            infra_annotations: BTreeMap::from([("note".to_string(), "x".to_string())]),
        }
    }

    #[test]
    fn service_exposes_each_listener_port_once_and_is_owned_by_the_gateway() {
        let svc = desired_service(&gw(), &tpl());
        let spec = svc.spec.unwrap();
        let ports: Vec<i32> = spec.ports.unwrap().iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![80, 443, 8080], "sorted, deduplicated, no port 0, metrics port excluded");
        assert_eq!(spec.type_.as_deref(), Some("LoadBalancer"));
        let sel = spec.selector.unwrap();
        assert_eq!(sel.get(LABEL_GATEWAY_NAME).map(String::as_str), Some("same-namespace"));
        assert_eq!(sel.get(LABEL_GATEWAY_NAMESPACE).map(String::as_str), Some("infra"));
        let meta = svc.metadata;
        assert_eq!(meta.name.as_deref(), Some("portus-same-namespace-uid123"));
        let owner = &meta.owner_references.unwrap()[0];
        assert_eq!(owner.kind, "Gateway");
        assert_eq!(owner.uid, "uid-123");
        assert_eq!(owner.controller, Some(true));
        let ann = meta.annotations.unwrap();
        assert_eq!(ann.get("lb/type").map(String::as_str), Some("nlb"));
        assert_eq!(ann.get("note").map(String::as_str), Some("x"), "infrastructure annotations propagate");
        let labels = meta.labels.unwrap();
        assert_eq!(labels.get("team").map(String::as_str), Some("edge"));
        assert_eq!(
            labels.get(LABEL_GATEWAY_API_NAME).map(String::as_str),
            Some("same-namespace"),
            "Gateway API standard gateway-name label (GatewayInfrastructure conformance)"
        );
    }

    #[test]
    fn udp_listeners_become_udp_ports_next_to_tcp_ports_with_the_same_number() {
        // udproute-simple (UDP 5300) next to a TCP listener on 5300: two Service
        // ports, two container ports, distinct names.
        let mut g = gw();
        g.ports = vec![udp(5300), tcp(5300), udp(5300), udp(53)];
        let svc = desired_service(&g, &tpl());
        let ports: Vec<(String, i32, String)> = svc
            .spec
            .unwrap()
            .ports
            .unwrap()
            .into_iter()
            .map(|p| (p.name.unwrap(), p.port, p.protocol.unwrap()))
            .collect();
        assert_eq!(
            ports,
            vec![
                ("udp-53".to_string(), 53, "UDP".to_string()),
                ("tcp-5300".to_string(), 5300, "TCP".to_string()),
                ("udp-5300".to_string(), 5300, "UDP".to_string()),
            ]
        );
        let dep = desired_deployment(&g, &tpl());
        let c = &dep.spec.unwrap().template.spec.unwrap().containers[0];
        let cports: Vec<(String, String)> = c.ports.clone().unwrap().into_iter().map(|p| (p.name.unwrap(), p.protocol.unwrap())).collect();
        assert!(cports.contains(&("udp-5300".to_string(), "UDP".to_string())));
        assert!(cports.contains(&("tcp-5300".to_string(), "TCP".to_string())));
        assert_eq!(L4Protocol::of_listener("UDP"), L4Protocol::Udp);
        for proto in ["HTTP", "HTTPS", "TLS", "TCP"] {
            assert_eq!(L4Protocol::of_listener(proto), L4Protocol::Tcp, "{proto}");
        }
    }

    #[test]
    fn probe_target_uses_the_first_tcp_port_and_skips_udp_only_services() {
        let mut g = gw();
        g.ports = vec![udp(5300), tcp(8080)];
        let mut svc = desired_service(&g, &tpl());
        svc.spec.as_mut().unwrap().cluster_ip = Some("10.43.0.9".into());
        assert_eq!(probe_target(&svc), Some("10.43.0.9:8080".parse().unwrap()), "a UDP port cannot be connected to");
        g.ports = vec![udp(5300)];
        let mut svc = desired_service(&g, &tpl());
        svc.spec.as_mut().unwrap().cluster_ip = Some("10.43.0.9".into());
        assert_eq!(probe_target(&svc), None, "UDP-only Gateways publish on ready endpoints alone");
    }

    #[test]
    fn service_with_no_listeners_still_has_a_valid_port() {
        let mut g = gw();
        g.ports.clear();
        let svc = desired_service(&g, &tpl());
        let ports = svc.spec.unwrap().ports.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 65535);
    }

    #[test]
    fn deployment_pins_the_gateway_and_talks_tls_to_the_controller() {
        let dep = desired_deployment(&gw(), &tpl());
        let spec = dep.spec.unwrap();
        assert_eq!(spec.replicas, Some(2));
        let ru = spec.strategy.unwrap().rolling_update.unwrap();
        assert_eq!(ru.max_unavailable, Some(IntOrString::Int(0)));
        let pod = spec.template.spec.unwrap();
        assert_eq!(pod.automount_service_account_token, Some(false));
        assert_eq!(pod.termination_grace_period_seconds, Some(5));
        assert_eq!(pod.service_account_name.as_deref(), Some("portus-dataplane"));
        let c = &pod.containers[0];
        let readiness = c.readiness_probe.as_ref().unwrap();
        assert_eq!(readiness.initial_delay_seconds, Some(1));
        assert_eq!(readiness.period_seconds, Some(1), "the suite gates on all pods in the namespace being Ready");
        let envs: BTreeMap<String, String> = c
            .env
            .clone()
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.value.unwrap_or_default()))
            .collect();
        assert_eq!(envs["GATEWAY_NAMESPACE"], "infra");
        assert_eq!(envs["GATEWAY_NAME"], "same-namespace");
        assert_eq!(envs["CONTROLLER_ADDR"], "portus-controller.portus:50051");
        assert!(!envs.contains_key("BOUND_PORTS"), "listener ports come from the config stream, not env");
        assert!(!envs.contains_key("DATAPLANE_THREADS"), "threads are sized by the dataplane unless the chart sets them");
        assert_eq!(envs["PORTUS_ACCESS_LOG"], "false", "access log off by default");
        assert_eq!(envs["GRPC_TLS_CA"], "/etc/grpc-tls/ca.crt");
        assert!(!envs.contains_key("GRPC_TLS_INSECURE"));
        assert_eq!(
            pod.volumes.unwrap()[0].secret.as_ref().unwrap().secret_name.as_deref(),
            Some("portus-same-namespace-uid123"),
            "mounts the Gateway-owned copy in its own namespace, not the controller's Secret"
        );
        let names: Vec<String> = c.ports.clone().unwrap().into_iter().filter_map(|p| p.name).collect();
        assert_eq!(names, vec!["tcp-80", "tcp-443", "tcp-8080", "health", "metrics"]);
        let sc = c.security_context.as_ref().unwrap();
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(sc.capabilities.as_ref().unwrap().add.as_ref().unwrap(), &vec!["NET_BIND_SERVICE".to_string()]);
        // Selector labels are a subset of pod labels.
        let pod_labels = spec.template.metadata.unwrap().labels.unwrap();
        for (k, v) in spec.selector.match_labels.unwrap() {
            assert_eq!(pod_labels.get(&k), Some(&v));
        }
    }

    #[test]
    fn deployment_without_tls_secret_opts_into_plaintext_explicitly() {
        let mut t = tpl();
        t.grpc_tls_secret = None;
        let dep = desired_deployment(&gw(), &t);
        let pod = dep.spec.unwrap().template.spec.unwrap();
        let envs: Vec<String> = pod.containers[0].env.clone().unwrap().into_iter().map(|e| e.name).collect();
        assert!(envs.contains(&"GRPC_TLS_INSECURE".to_string()));
        assert!(!envs.contains(&"GRPC_TLS_CA".to_string()));
        assert!(pod.volumes.is_none());
    }

    fn source_secret(data: &[(&str, &str)]) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some("portus-grpc-tls".into()),
                namespace: Some("portus".into()),
                ..Default::default()
            },
            type_: Some("Opaque".into()),
            data: Some(
                data.iter()
                    .map(|(k, v)| (k.to_string(), k8s_openapi::ByteString(v.as_bytes().to_vec())))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn tls_secret_copy_carries_only_the_stream_material_and_is_owned_by_the_gateway() {
        let src = source_secret(&[("ca.crt", "CA"), ("tls.crt", "CERT"), ("tls.key", "KEY"), ("unrelated", "x")]);
        let copy = desired_tls_secret(&gw(), &src).unwrap();
        assert_eq!(copy.metadata.name.as_deref(), Some("portus-same-namespace-uid123"), "same name as the Deployment it feeds");
        assert_eq!(copy.metadata.namespace.as_deref(), Some("infra"), "lives where the dataplane pods run");
        assert_eq!(copy.metadata.owner_references.unwrap()[0].uid, "uid-123");
        assert_eq!(copy.type_.as_deref(), Some("kubernetes.io/tls"));
        let data = copy.data.unwrap();
        assert_eq!(data.len(), 3, "unrelated keys are not spread into other namespaces");
        assert_eq!(data["tls.key"].0, b"KEY");
        assert_eq!(copy.metadata.labels.unwrap()[LABEL_COMPONENT], "dataplane");
    }

    #[test]
    fn tls_secret_copy_refuses_a_source_missing_a_key() {
        let src = source_secret(&[("ca.crt", "CA"), ("tls.crt", "CERT")]);
        let err = desired_tls_secret(&gw(), &src).unwrap_err().to_string();
        assert_eq!(err, "gRPC TLS Secret portus/portus-grpc-tls has no `tls.key` key");
    }

    #[test]
    fn only_the_configured_secret_in_the_controller_namespace_is_the_tls_source() {
        let t = tpl();
        assert!(t.is_grpc_tls_source("portus", "portus-grpc-tls"));
        assert!(!t.is_grpc_tls_source("infra", "portus-grpc-tls"), "a same-named Secret elsewhere is not ours");
        assert!(!t.is_grpc_tls_source("portus", "other"));
        let mut plain = tpl();
        plain.grpc_tls_secret = None;
        assert!(!plain.is_grpc_tls_source("portus", "portus-grpc-tls"));
    }

    #[test]
    fn pdb_keeps_one_pod_when_replicated() {
        let pdb = desired_pdb(&gw(), &tpl());
        assert_eq!(pdb.spec.unwrap().min_available, Some(IntOrString::Int(1)));
        let mut t = tpl();
        t.replicas = 1;
        let pdb = desired_pdb(&gw(), &t);
        assert_eq!(pdb.spec.unwrap().min_available, Some(IntOrString::Int(0)));
    }

    #[test]
    fn explicit_threads_and_access_log_reach_the_pod_env() {
        let mut t = tpl();
        t.threads = Some(8);
        t.access_log = true;
        let dep = desired_deployment(&gw(), &t);
        let envs: BTreeMap<String, String> = dep.spec.unwrap().template.spec.unwrap().containers[0]
            .env
            .clone()
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.value.unwrap_or_default()))
            .collect();
        assert_eq!(envs["DATAPLANE_THREADS"], "8");
        assert_eq!(envs["PORTUS_ACCESS_LOG"], "true");
    }

    #[test]
    fn chart_booleans_parse_like_kubernetes() {
        for v in ["true", "True", "1", "yes", "on", " true "] {
            assert!(parse_bool(v), "{v}");
        }
        for v in ["false", "0", "no", "off", "", "nonsense"] {
            assert!(!parse_bool(v), "{v}");
        }
    }

    #[test]
    fn address_is_withheld_until_the_service_has_a_ready_endpoint() {
        use crate::store::{ConfigStore, ServiceKey};
        let store = ConfigStore::new();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("portus-gw-abcdef12".into()),
                namespace: Some("infra".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!service_has_ready_endpoints(&store, &svc), "no EndpointSlice seen yet");
        // A slice with zero ready addresses (pod still starting) is not enough.
        store.endpoints.insert(
            ServiceKey { namespace: "infra".into(), name: "portus-gw-abcdef12".into(), port: 443 },
            vec![],
        );
        assert!(!service_has_ready_endpoints(&store, &svc));
        store.endpoints.insert(
            ServiceKey { namespace: "infra".into(), name: "portus-gw-abcdef12".into(), port: 443 },
            vec![portus_types::BackendEndpoint { address: "10.42.0.9".into(), port: 443 }],
        );
        assert!(service_has_ready_endpoints(&store, &svc));
        // Another Service's endpoints do not count.
        let other = Service {
            metadata: ObjectMeta { name: Some("portus-other-00000000".into()), namespace: Some("infra".into()), ..Default::default() },
            ..Default::default()
        };
        assert!(!service_has_ready_endpoints(&store, &other));
    }

    #[test]
    fn probe_target_uses_cluster_ip_and_first_port() {
        use k8s_openapi::api::core::v1::ServiceSpec;
        let mut svc = Service {
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.43.0.5".into()),
                ports: Some(vec![
                    ServicePort { port: 8883, ..Default::default() },
                    ServicePort { port: 443, ..Default::default() },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(probe_target(&svc), Some("10.43.0.5:8883".parse().unwrap()));
        svc.spec.as_mut().unwrap().cluster_ip = Some("None".into());
        assert_eq!(probe_target(&svc), None, "headless Services are not probed");
        svc.spec.as_mut().unwrap().cluster_ip = None;
        assert_eq!(probe_target(&svc), None, "no ClusterIP allocated yet");
        svc.spec = None;
        assert_eq!(probe_target(&svc), None);
    }

    #[tokio::test]
    async fn tcp_reachable_distinguishes_listening_refused_and_blackholed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let t = std::time::Duration::from_millis(500);
        assert!(tcp_reachable(open, t).await);
        drop(listener);
        // Nothing listening → refused → not reachable.
        assert!(!tcp_reachable(open, t).await);
        // A non-routable address behaves like a not-yet-programmed ClusterIP:
        // the SYN is never answered and the probe times out.
        let blackhole: std::net::SocketAddr = "10.255.255.1:9".parse().unwrap();
        let started = std::time::Instant::now();
        assert!(!tcp_reachable(blackhole, std::time::Duration::from_millis(300)).await);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn addresses_changed_detects_appearance_and_value_changes() {
        let none: Vec<GatewayAddress> = vec![];
        assert!(!addresses_changed(&none, &[]));
        assert!(addresses_changed(&none, &[("IPAddress".into(), "10.43.0.5".into())]));
        let current = vec![GatewayAddress { type_: Some("IPAddress".into()), value: "10.43.0.5".into() }];
        assert!(!addresses_changed(&current, &[("IPAddress".into(), "10.43.0.5".into())]));
        assert!(addresses_changed(&current, &[("IPAddress".into(), "10.43.0.6".into())]));
        assert!(addresses_changed(&current, &[]));
        // Untyped current addresses default to IPAddress.
        let untyped = vec![GatewayAddress { type_: None, value: "10.43.0.5".into() }];
        assert!(!addresses_changed(&untyped, &[("IPAddress".into(), "10.43.0.5".into())]));
    }

    #[test]
    fn object_names_stay_dns_labels_and_change_with_the_gateway_uid() {
        assert_eq!(object_name("gw", "3f9c2d1e-aaaa-bbbb-cccc-000000000000"), "portus-gw-3f9c2d1e");
        // A recreated Gateway (new UID) gets new object names: no clash with
        // stale Endpoints of the previous incarnation.
        assert_ne!(object_name("gw", "uid-one"), object_name("gw", "uid-two"));
        let long = "a".repeat(80);
        let n = object_name(&long, "0123456789abcdef");
        assert!(n.len() <= 63, "{n}");
        assert!(n.starts_with("portus-aaaa"));
        assert!(n.ends_with("-01234567"));
        assert_eq!(n, object_name(&long, "0123456789abcdef"), "stable");
        assert_eq!(object_name("gw", ""), "portus-gw-nouid");
    }

    #[test]
    fn addresses_prefer_load_balancer_ingress_then_cluster_ip() {
        use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};
        let mut svc = desired_service(&gw(), &tpl());
        svc.spec.as_mut().unwrap().cluster_ip = Some("10.43.0.7".into());
        assert!(load_balancer_pending(&svc));
        let addrs = addresses_from_service(&svc);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].value, "10.43.0.7");
        assert_eq!(addrs[0].type_.as_deref(), Some("IPAddress"));

        svc.status = Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(vec![
                    LoadBalancerIngress { ip: Some("203.0.113.9".into()), ..Default::default() },
                    LoadBalancerIngress { hostname: Some("lb.example.net".into()), ..Default::default() },
                ]),
            }),
            ..Default::default()
        });
        assert!(!load_balancer_pending(&svc));
        let addrs = addresses_from_service(&svc);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].value, "203.0.113.9");
        assert_eq!(addrs[1].type_.as_deref(), Some("Hostname"));

        // ClusterIP services are never "pending".
        svc.spec.as_mut().unwrap().type_ = Some("ClusterIP".into());
        assert!(!load_balancer_pending(&svc));
    }

}
