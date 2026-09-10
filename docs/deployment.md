# Portus Deployment and Operations Guide

Portus is a Kubernetes Gateway API implementation built on Pingora. It deploys as a controller (a Kubernetes operator) that watches Gateway API resources, compiles routing config and streams it over mTLS gRPC to the dataplanes (Pingora proxies) it provisions: one Deployment, Service and PodDisruptionBudget per Gateway.

## Prerequisites

- Kubernetes 1.32+ (the Gateway API v1.6 CRDs use CEL helpers older API servers lack)
- Helm 3.8+ (OCI registry support)
- `kubectl` with cluster-admin access (the controller needs a ClusterRole for Gateway API resources, Secrets, Services, Deployments and EndpointSlices)

## Installing

### Gateway API CRDs

Portus uses the experimental channel of the Gateway API CRDs because it depends on GRPCRoute, TLSRoute, TCPRoute, UDPRoute and ListenerSet, which are not in the standard channel:

```bash
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/experimental-install.yaml
```

### Helm chart

The chart is published to GHCR as an OCI artifact with every release, and its images (`ghcr.io/portus-gateway/controller`, `ghcr.io/portus-gateway/dataplane`, `linux/amd64` and `linux/arm64`) are tagged with the same version, which the chart pins as its `appVersion`:

```bash
helm install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.1 \
  --namespace portus --create-namespace
```

The chart creates:

- the controller **Deployment** (leader-elected singleton, `strategy: Recreate`) and its ClusterIP **Service** for the gRPC config stream;
- the **GatewayClass** `controller.gatewayClassName` (default `portus-gateway`);
- the **ServiceAccount**, **ClusterRole** and **ClusterRoleBinding** for the controller, plus a Role for its leader-election Lease;
- the mTLS **Secret** for the config stream (see below);
- Portus's own policy **CRDs** from `crds/` (RateLimitPolicy, CircuitBreakerPolicy, ConnectionPolicy, BasicAuthPolicy, APIKeyAuthPolicy, RetryPolicy, IPAllowlistPolicy, RequestBodySizeLimitPolicy, HealthCheckPolicy, CORSPolicy, TimeoutPolicy). Helm installs these on first install only; after an upgrade re-apply them with `kubectl apply --server-side --force-conflicts -f deploy/helm/crds/` from the matching tag.

Dataplanes are not chart objects. For every accepted Gateway the controller provisions a dataplane **Deployment** (`dataplane.replicasPerGateway` pods), a **Service** (`dataplane.service.type`, one port per listener) and a **PodDisruptionBudget** in the Gateway's namespace, all owned by the Gateway and garbage-collected with it. The `dataplane.*` values are the template for those objects. Generated objects are named `portus-<gateway>-<uid prefix>`, labelled `gateway.portus.dev/name` / `gateway.portus.dev/namespace` and `gateway.networking.k8s.io/gateway-name`, and carry the Gateway's `spec.infrastructure.labels` / `.annotations`. Each dataplane receives only its Gateway's config over the gRPC stream and has no Kubernetes API access. The Gateway's `status.addresses` is the Service's address (the LoadBalancer ingress once assigned, the ClusterIP otherwise), published once the controller can reach a ready dataplane through it.

### mTLS on the config stream

The stream between controller and dataplanes carries the compiled routing config, the Gateways' TLS private keys and auth credentials, so it is encrypted and mutually authenticated by default (`grpcTls.enabled: true`):

- With `grpcTls.secretName` empty, the chart generates a CA and a certificate for the controller Service (SANs `<release>-portus-gateway-controller`, `.<namespace>`, `.<namespace>.svc`, `.<namespace>.svc.cluster.local`; ten years) into the Secret `<release>-portus-gateway-grpc-tls`, and keeps the existing material on every upgrade.
- To bring your own, set `grpcTls.secretName` to a Secret in the release namespace with `ca.crt`, `tls.crt` and `tls.key`. The certificate must be valid for the host the dataplanes dial: the controller Service name, or `dataplane.controllerUrl` when set. The dataplanes present the same certificate as their client identity, so it needs the `clientAuth` extended key usage as well as `serverAuth`.
- A pod can only mount Secrets from its own namespace, so the controller copies the three keys into a Gateway-owned Secret (named like the Deployment) in each Gateway's namespace and mounts that. Changing the source Secret re-provisions every Gateway; the controller itself reads its certificate at start, so restart it after rotating.
- `grpcTls.enabled: false` sends the stream in plaintext. Local development only.

### Cloud LoadBalancers

`dataplane.service.type` defaults to `LoadBalancer`, so every Gateway gets its own external address from the cloud provider. `dataplane.service.annotations` (rendered onto every generated Service) carries provider settings such as the load balancer type or scheme. Node security groups must allow every Gateway listener port from the VPC CIDR: ClusterIP traffic between nodes uses the node network, and a group that only allows the NodePort range shows up as intermittent 502s (same-node requests work, cross-node ones do not). The controller talks only to the Kubernetes API and needs no cloud IAM permissions; `serviceAccount.annotations` is there for clusters that require an identity on every pod.

### Helm values reference

| Value | Default | Description |
|-------|---------|-------------|
| `controller.image.repository` | `ghcr.io/portus-gateway/controller` | Controller image |
| `controller.image.tag` | `""` (the chart's `appVersion`) | Image tag |
| `controller.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `controller.replicas` | `1` | Only the leader reconciles; extra replicas stand by. `strategy: Recreate` so an upgrade never leaves a new pod waiting on a Lease the old pod still holds |
| `controller.resources` | 100m / 256Mi requests, 512Mi memory limit | No CPU limit |
| `controller.grpcPort` | `50051` | Port the controller exposes for the config stream |
| `controller.logLevel` | `info` | `RUST_LOG` (`env_logger` syntax, e.g. `portus_controller=debug`) |
| `controller.gatewayClassName` | `portus-gateway` | GatewayClass the chart creates and the controller accepts |
| `controller.controllerName` | `github.com/Portus-Gateway/Portus` | `controllerName` on the GatewayClass |
| `controller.securityContext` / `.containerSecurityContext` | non-root UID 1000, read-only root, no capabilities | Pod and container security contexts |
| `dataplane.image.repository` | `ghcr.io/portus-gateway/dataplane` | Dataplane image the controller provisions |
| `dataplane.image.tag` | `""` (the chart's `appVersion`) | Image tag |
| `dataplane.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `dataplane.replicasPerGateway` | `2` | Pods per Gateway; the PDB keeps one available |
| `dataplane.resources` | 250m / 256Mi requests, 512Mi memory limit | The CPU request also sizes the Pingora worker pool (`DATAPLANE_THREADS`, at least 2) |
| `dataplane.logLevel` | `info` | `RUST_LOG` |
| `dataplane.controllerUrl` | `""` | `host:port` the dataplanes dial; empty means the controller Service (`<release>-portus-gateway-controller.<namespace>:<grpcPort>`) |
| `dataplane.service.type` | `LoadBalancer` | Type of every per-Gateway Service; `ClusterIP` on k3d and for in-cluster clients |
| `dataplane.service.annotations` | `{}` | Annotations on every per-Gateway Service |
| `grpcTls.enabled` | `true` | mTLS on the config stream |
| `grpcTls.secretName` | `""` | Your own Secret (`ca.crt`, `tls.crt`, `tls.key`); empty generates one |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / `""` / `{}` | Controller ServiceAccount |
| `nameOverride` / `fullnameOverride` | `""` | Resource naming |

## Building Images

Both images build from `rust:1.98-alpine` with musl into a `FROM scratch` final stage: no shell, no libc, just the binary, running as UID 1000. `deploy/docker/Dockerfile.controller` and `Dockerfile.dataplane` are the release builds; the `.dev` variants build the debug profile for fast iteration. BuildKit cache mounts keep the cargo registry and target directory between builds.

```bash
make build                # both release images, tagged portus-gateway/{controller,dataplane}:dev
docker buildx build --platform linux/amd64 -t my-registry/portus-controller:x -f deploy/docker/Dockerfile.controller .
```

Cross-architecture builds go through QEMU and are slow (the release workflow avoids this by building each architecture on a native runner). To run your own images, override `controller.image.*` and `dataplane.image.*`.

### Releasing

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`: native `linux/amd64` and `linux/arm64` image builds pushed by digest and joined into one manifest list (`X.Y.Z` and `latest`), the chart pushed to `oci://ghcr.io/portus-gateway/charts/portus-gateway`, and a GitHub release with the install commands. The workflow refuses a tag whose version differs from the chart's `version` and `appVersion` in `deploy/helm/Chart.yaml`.

## k3d Local Development

### Cluster Creation

The Makefile handles cluster creation with the correct port mappings:

```bash
make k3d-up
```

This creates a k3d cluster named `portus-local` with ports 80, 443, 8080, 8090, 8443, and 8883 forwarded from the host to the k3d load balancer. It also disables Traefik (k3s's default ingress controller) since Portus replaces it.

To create the cluster manually:

```bash
k3d cluster create portus-local \
  -p "80:80@loadbalancer" \
  -p "443:443@loadbalancer" \
  -p "8080:8080@loadbalancer" \
  -p "8090:8090@loadbalancer" \
  -p "8443:8443@loadbalancer" \
  -p "8883:8883@loadbalancer" \
  --k3s-arg "--disable=traefik@server:0" \
  --wait
```

### Dev Loop

The typical development cycle is build, import, deploy:

```bash
# Build images
make build

# Deploy (imports images into k3d, installs CRDs, runs helm upgrade)
make deploy
```

If you want unique tags to force image pulls (useful when debugging caching issues):

```bash
TAG="dev-$(date +%s)"
docker build -t portus-gateway/controller:$TAG -f deploy/docker/Dockerfile.controller .
docker build -t portus-gateway/dataplane:$TAG -f deploy/docker/Dockerfile.dataplane .
k3d image import portus-gateway/controller:$TAG portus-gateway/dataplane:$TAG -c portus-local
helm upgrade --install portus deploy/helm --namespace portus \
  --set controller.image.repository=portus-gateway/controller --set controller.image.tag=$TAG --set controller.image.pullPolicy=Never \
  --set dataplane.image.repository=portus-gateway/dataplane --set dataplane.image.tag=$TAG --set dataplane.image.pullPolicy=Never \
  --set dataplane.service.type=ClusterIP --set dataplane.replicasPerGateway=1 \
  --wait
```

`pullPolicy=Never` keeps Kubernetes from pulling the chart's default `ghcr.io` images instead of the ones imported into k3d. The default mTLS path runs locally too; nothing needs to be disabled.

### Teardown

```bash
make k3d-down    # deletes the k3d cluster
make clean       # alias for k3d-down
```

## Environment Variables

### Controller

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level. Supports `env_logger` filter syntax. |
| `GATEWAY_CLASS_NAME` | `portus-gateway` | Name of the GatewayClass this controller manages. Only Gateways referencing this class are reconciled. |
| `CONTROLLER_NAME` | `github.com/Portus-Gateway/Portus` | Controller name string set in the GatewayClass spec. |

The dataplane template the provisioner uses comes from `PORTUS_DATAPLANE_*` variables plus `PORTUS_CONTROLLER_ADDR`, `PORTUS_GRPC_TLS_SECRET` and `PORTUS_NAMESPACE` (downward API), all rendered by the chart from the `dataplane.*` and `grpcTls.*` values; they are not meant to be set by hand.

The controller hardcodes the gRPC listen address to `[::]:50051`. This is not configurable via environment variable -- change `controller.grpcPort` in the Helm values if you need a different port (though you'd also need to update the Dockerfile `EXPOSE` directive and the source).

### Dataplane

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level. |
| `CONTROLLER_ADDR` | `portus-controller:50051` | gRPC address of the controller. The Helm chart auto-generates this from the controller Service name and port. |
| `L4_IDLE_TIMEOUT_SECS` | `3600` | Idle timeout for L4 sessions (SNI mux passthrough/terminate, TCPRoute). A session is closed only when neither direction has carried bytes for this long, so long-lived protocols such as MQTT stay up as long as they exchange keepalives. |
| `UDP_IDLE_TIMEOUT_SECS` | `60` | Idle timeout for UDPRoute client sessions (one per client source address per listener port). A client that stays quiet this long gets a fresh backend choice on its next datagram. |

## Health Checks

The dataplane exposes health and readiness endpoints on port 8081:

- **`/healthz`** -- always returns 200. The process is alive.
- **`/readyz`** -- returns 200 if the dataplane has received at least one config from the controller AND either the gRPC stream is connected or the last config was received within the last 120 seconds (stale grace period). Returns 503 otherwise.

The readiness probe has a 120-second grace period for gRPC disconnects. This means a brief controller restart or network blip won't cause the dataplane to go unready and stop receiving traffic -- it will keep serving with its last known config. If the stream stays down for more than 2 minutes, the pod goes unready.

On cold start, the dataplane waits up to 60 seconds for the first config from the controller. If no config arrives within that deadline, the process exits with an error. This prevents the dataplane from starting with an empty route table.

## Monitoring

### Prometheus Metrics

The dataplane exposes Prometheus metrics on port 9090 (configurable via `dataplane.metricsPort`). The dataplane pods are annotated with `prometheus.io/scrape: "true"` and `prometheus.io/port` for automatic discovery.

#### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_requests_total` | Counter | `host`, `status`, `protocol` | Total proxied requests |
| `proxy_request_duration_seconds` | Histogram | `host`, `protocol` | Request latency. Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 5s, 30s |
| `proxy_routes_loaded` | Gauge | -- | Number of routes in the current route map |
| `proxy_endpoints_loaded` | Gauge | `service` | Number of endpoints per backend service |
| `proxy_watcher_errors_total` | Counter | `watcher` | Config-path errors: `grpc_config_stream` (stream dropped), `config_validation` (config applied with validation warnings) |
| `proxy_tls_cert_expiry_seconds` | Gauge | -- | TLS certificate expiry as unix timestamp |
| `proxy_upstream_connect_errors_total` | Counter | `service` | Upstream connection failures per service |
| `proxy_rate_limit_rejected_total` | Counter | `host` | Rate limit rejections; the `host` label carries the route's backend service, matching `proxy_requests_total` |
| `proxy_circuit_breaker_state` | Gauge | `service` | Circuit breaker state per service: 0=closed, 1=open, 2=half-open |
| `config_last_update_timestamp` | Gauge | -- | Unix timestamp of the last config update from the controller |
| `grpc_stream_connected` | Gauge | -- | 1 if the gRPC stream to the controller is connected, 0 if disconnected |

#### Key Metrics to Alert On

The two most important operational metrics are `grpc_stream_connected` and `config_last_update_timestamp`. If `grpc_stream_connected` drops to 0 and stays there, the dataplane is running on stale config. If `config_last_update_timestamp` stops advancing, the compilation loop in the controller may have stalled (see Troubleshooting below).

`proxy_tls_cert_expiry_seconds` is useful for certificate rotation monitoring. The dataplane hot-reloads TLS certs without restart -- the controller pushes new certs over the gRPC stream and the dataplane swaps them atomically via `ArcSwap`. But if the controller isn't sending updated certs, this metric will tell you how much time you have.

## Troubleshooting

### Compilation Loop Stalled

**Symptom**: `config_last_update_timestamp` stops advancing. Routes created or modified in Kubernetes don't take effect.

**What to check**: Look at the controller logs for `PANIC` or `BUG` messages. The compilation loop runs on a dedicated thread with its own tokio runtime. If it panics, the controller logs `BUG: compilation_loop exited -- no more configs will be sent to data planes`. The controller process stays alive (reconcilers still run), but no new compiled config is produced.

```bash
kubectl logs -n portus deploy/portus-controller | grep -E 'PANIC|BUG|compilation_loop'
```

If you see the BUG message, the controller needs a restart. File a bug with the preceding panic backtrace.

### gRPC Stream Disconnects

**Symptom**: `grpc_stream_connected` flapping between 0 and 1, or stuck at 0. Dataplane logs show stream errors.

**What to check**: The dataplane reconnects automatically with backoff, so brief disconnects during controller restarts are normal. Persistent disconnects usually mean the controller Service is unreachable or the controller pod is crash-looping.

```bash
kubectl logs -n portus -l app.kubernetes.io/component=dataplane --tail=50 | grep -i stream
kubectl get pods -n portus -l app.kubernetes.io/component=controller
```

The gRPC connection uses HTTP/2 keepalives (15s interval, 60s timeout) and adaptive flow control. If you're seeing disconnects across a service mesh or network policy boundary, make sure port 50051 TCP is allowed between dataplane and controller pods.

### TLS Certificate Not Loading

**Symptom**: HTTPS requests fail with TLS errors. The dataplane starts with a self-signed bootstrap cert instead of the real one.

**What to check**: Look for `tls_updated` in the dataplane's applied config logs. When the controller pushes a config that includes TLS certificate data, the dataplane logs whether it applied the cert successfully.

```bash
kubectl logs -n portus -l app.kubernetes.io/component=dataplane --tail=100 | grep -i tls
```

Common causes:
- The TLS Secret referenced by the Gateway listener doesn't exist or is in a different namespace without a ReferenceGrant.
- The Secret data is malformed (not valid PEM, or the cert and key don't match).
- The controller doesn't have permission to read Secrets (check the ClusterRole).

### Routes Not Compiling

**Symptom**: HTTPRoutes or GRPCRoutes exist in Kubernetes but traffic returns 404 or doesn't route as expected.

**What to check**: The controller logs the compiled config summary each time it recompiles. Look for the route count:

```bash
kubectl logs -n portus deploy/portus-controller | grep -i 'compiled'
```

If the route count is 0 or lower than expected:
- Check that the route's `parentRefs` reference a Gateway with the correct `gatewayClassName` (`portus-gateway` by default).
- Check that the Gateway's listeners match the route's hostnames and ports.
- Check the route's status conditions for `Accepted` and `ResolvedRefs`.
- If using cross-namespace references, ensure a ReferenceGrant exists in the target namespace.

Deletions are evicted from the ConfigStore as the watch reports them; a pruning task (every 120 seconds) is the safety net. If you see routes disappearing, check whether the underlying Kubernetes resources actually exist:

```bash
kubectl get httproutes -A
kubectl get gateways -A
```

### Dataplane Exits on Startup

**Symptom**: Dataplane pod is in CrashLoopBackOff. Logs show `timed out waiting for first config after 60s`.

**Cause**: The dataplane waits 60 seconds for the first config from the controller on startup. If the controller is not reachable, the dataplane exits.

**What to check**:
- Is the controller pod running? `kubectl get pods -n portus`
- Can the dataplane resolve the controller Service? The default address is `<release>-controller:50051`.
- Is there a NetworkPolicy blocking port 50051 between the components?

## Running Conformance Tests

Conformance tests live in `tests/conformance/` and use the official Gateway API conformance test suite. They run **inside the cluster**: Gateway addresses are per-Gateway Service ClusterIPs that only pods can reach, so the Go suite is compiled into an image (`deploy/conformance/Dockerfile.runner`) and run as a Job with cluster-admin.

```bash
make conformance-image            # build + import the runner image
make conformance-run              # HTTP, GRPC, TLS, TCP and UDP profiles; ~7 min
make conformance-run CONFORMANCE_RUN='TestConformance/HTTPRouteSimpleSameNamespace$$'
```

The report is extracted to `tests/conformance/conformance-report.yaml` and the full log to `/tmp/conformance-incluster.txt`. `make conformance-run` waits for a previous run's namespaces to be gone first; never run two suites against one cluster at once.

