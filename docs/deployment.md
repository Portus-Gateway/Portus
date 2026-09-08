# Portus Deployment and Operations Guide

Portus is a Kubernetes Gateway API implementation built on Pingora. It deploys as two components: a controller (Kubernetes operator) and a dataplane (Pingora proxy). The controller watches Gateway API CRDs, compiles routing config, and streams it to dataplanes over gRPC. The dataplane runs as a DaemonSet and handles live traffic.

## Prerequisites

- Kubernetes 1.28+
- Helm 3
- Gateway API CRDs v1.4.0+ (experimental channel)
- `kubectl` with cluster-admin access (the controller needs a ClusterRole for Gateway API resources, Secrets, Services, and EndpointSlices)

## Installing Gateway API CRDs

Portus uses the experimental channel of the Gateway API CRDs because it depends on GRPCRoute, TLSRoute, TCPRoute and UDPRoute, which are not in the standard channel. Install them before deploying the chart:

```bash
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/experimental-install.yaml
```

Portus also ships custom policy CRDs for rate limiting, circuit breaking, connection policies, and auth. These live in `deploy/helm/crds/` and must be applied separately -- Helm does not upgrade CRDs after initial install:

```bash
kubectl apply --server-side --force-conflicts -f deploy/helm/crds/
```

The custom CRDs are:
- `ratelimitpolicies.portus-gateway.dev`
- `circuitbreakerpolicies.portus-gateway.dev`
- `connectionpolicies.portus-gateway.dev`
- `basicauthpolicies.portus-gateway.dev`
- `apikeyauthpolicies.portus-gateway.dev`

## Helm Installation

The chart is at `deploy/helm/` (chart name: `portus-gateway`, version 0.2.0).

```bash
helm upgrade --install portus deploy/helm \
  --namespace portus \
  --create-namespace \
  --wait
```

### Helm Values Reference

#### Controller

| Value | Default | Description |
|-------|---------|-------------|
| `controller.image.repository` | `portus-gateway-controller` | Container image repository |
| `controller.image.tag` | `latest` | Image tag |
| `controller.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `controller.replicas` | `1` | Number of controller replicas. Only one actively reconciles; additional replicas are standby. The Deployment uses `strategy: Recreate` so an upgrade never leaves a new pod waiting on a Lease the old pod still holds; the outgoing pod releases the Lease on SIGTERM. |
| `controller.resources.requests.cpu` | `100m` | CPU request |
| `controller.resources.requests.memory` | `128Mi` | Memory request |
| `controller.resources.limits.cpu` | `500m` | CPU limit |
| `controller.resources.limits.memory` | `256Mi` | Memory limit |
| `controller.grpcPort` | `50051` | Port the controller exposes for gRPC config streaming |
| `controller.logLevel` | `info` | Sets `RUST_LOG` env var. Accepts standard `env_logger` syntax (`debug`, `info`, `portus_controller=debug`, etc.) |
| `controller.gatewayClassName` | `portus-gateway` | Name of the GatewayClass resource the chart creates |
| `controller.controllerName` | `github.com/Portus-Gateway/Portus` | Controller name string in the GatewayClass spec |

#### Dataplane

| Value | Default | Description |
|-------|---------|-------------|
| `dataplane.image.repository` | `portus-gateway-dataplane` | Container image repository |
| `dataplane.image.tag` | `latest` | Image tag |
| `dataplane.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `dataplane.resources.requests.cpu` | `250m` | CPU request |
| `dataplane.resources.requests.memory` | `256Mi` | Memory request |
| `dataplane.resources.limits.cpu` | `2` | CPU limit |
| `dataplane.resources.limits.memory` | `512Mi` | Memory limit |
| `dataplane.logLevel` | `info` | Sets `RUST_LOG` env var |
| `dataplane.controllerUrl` | `""` (auto-generated) | gRPC address of the controller. If empty, the chart generates `<release>-controller:<grpcPort>`. |
| `dataplane.service.type` | `LoadBalancer` | Service type for the dataplane. Use `NodePort` for bare-metal, `LoadBalancer` for cloud. |
| `dataplane.service.annotations` | `{}` | Annotations on the dataplane Service (e.g., for cloud LB configuration) |

#### Global

| Value | Default | Description |
|-------|---------|-------------|
| `nameOverride` | `""` | Override chart name in resource names |
| `fullnameOverride` | `""` | Override full resource name prefix |
| `serviceAccount.create` | `true` | Create a ServiceAccount |
| `serviceAccount.name` | `""` | Override ServiceAccount name (auto-generated if empty) |
| `serviceAccount.annotations` | `{}` | ServiceAccount annotations (useful for IAM role binding on EKS) |

### What the Chart Creates

The Helm chart creates:
- **Deployment** for the controller (1 replica by default)
- **Service** (ClusterIP) for the controller gRPC endpoint
- **GatewayClass** resource matching `controller.gatewayClassName`
- **ServiceAccount**, **ClusterRole**, and **ClusterRoleBinding** for the controller

Dataplanes are not chart objects. For every accepted Gateway the controller provisions a dataplane **Deployment** (`dataplane.replicasPerGateway`), a **Service** (`dataplane.service.type`, one port per listener) and a **PodDisruptionBudget** in the Gateway's namespace, all owned by the Gateway and garbage-collected with it. The `dataplane.*` values are the template for those objects. Generated objects are named `portus-<gateway>-<uid prefix>`, labelled `gateway.portus.dev/name` / `gateway.portus.dev/namespace`, and carry the Gateway's `spec.infrastructure.labels` / `.annotations`. Each dataplane receives only its Gateway's config over the gRPC stream and has no Kubernetes API access. The Gateway's `status.addresses` is the Service's address, published once the controller can reach it.

## Building Container Images

Both images build from `rust:1.98-alpine` using musl, producing statically-linked binaries. The final stage is `FROM scratch` -- no shell, no libc, just the binary. They run as UID 1000 (non-root).

### Local Builds (Native Architecture)

```bash
docker build -t portus-gateway/controller:dev -f deploy/docker/Dockerfile.controller .
docker build -t portus-gateway/dataplane:dev -f deploy/docker/Dockerfile.dataplane .
```

Or use the Makefile:

```bash
make build-controller
make build-dataplane
make build          # builds the controller and dataplane images
```

### Cross-Compilation (ARM64 / AMD64)

The Dockerfiles use Alpine's musl toolchain, so cross-compilation requires `docker buildx`. If you're building on Apple Silicon for an AMD64 cluster (or vice versa):

```bash
docker buildx build --platform linux/amd64 \
  -t portus-gateway/controller:dev \
  -f deploy/docker/Dockerfile.controller .

docker buildx build --platform linux/amd64 \
  -t portus-gateway/dataplane:dev \
  -f deploy/docker/Dockerfile.dataplane .
```

This is slow because QEMU emulates the Rust compiler. Expect 10-15 minute build times for cross-arch builds versus 2-3 minutes for native. There is currently no cross-compilation setup that avoids QEMU (e.g., using `xx` or Zig as a cross-linker) -- that would be a worthwhile optimization if cross-arch builds happen frequently.

### Image Repositories

For local development with k3d, images are imported directly into the cluster (no registry needed). For production, push to your container registry of choice:

```bash
TAG="v0.2.0"
docker tag portus-gateway/controller:dev your-registry/gateway-controller:$TAG
docker push your-registry/gateway-controller:$TAG
```

Then override the image values in Helm:

```bash
helm upgrade --install portus deploy/helm \
  --namespace portus \
  --set controller.image.repository=your-registry/gateway-controller \
  --set controller.image.tag=$TAG \
  --set dataplane.image.repository=your-registry/gateway-dataplane \
  --set dataplane.image.tag=$TAG
```

## EKS Deployment

### ECR Setup

Create repositories and push images:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-west-2
ECR_PREFIX="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

aws ecr create-repository --repository-name portus-gateway/controller
aws ecr create-repository --repository-name portus-gateway/dataplane

aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ECR_PREFIX

docker tag portus-gateway/controller:dev $ECR_PREFIX/portus-gateway/controller:latest
docker tag portus-gateway/dataplane:dev $ECR_PREFIX/portus-gateway/dataplane:latest
docker push $ECR_PREFIX/portus-gateway/controller:latest
docker push $ECR_PREFIX/portus-gateway/dataplane:latest
```

### Helm Install on EKS

```bash
helm upgrade --install portus deploy/helm \
  --namespace portus --create-namespace \
  --set controller.image.repository=$ECR_PREFIX/portus-gateway/controller \
  --set controller.image.tag=latest \
  --set dataplane.image.repository=$ECR_PREFIX/portus-gateway/dataplane \
  --set dataplane.image.tag=latest \
  --set dataplane.service.type=LoadBalancer \
  --wait
```

Each Gateway's `status.addresses` reflects the LoadBalancer ingress address AWS assigns to that Gateway's Service (its ClusterIP until then).

### Security Group Requirements

Every Gateway's dataplane Deployment sits behind its own LoadBalancer Service. For cross-node traffic to work, the EKS node security group needs:

- **Every Gateway listener port (TCP) ingress from the VPC CIDR** -- ClusterIP traffic between nodes uses the node network, not the pod network. If your security group only allows traffic on the NodePort range (30000-32767), cross-node ClusterIP routing will silently fail. This manifests as intermittent 502s where some requests work (same-node) and others don't (cross-node).

### IAM Considerations

The controller needs Kubernetes API access (provided by the ClusterRole), but does not need any AWS IAM permissions. If you use IRSA (IAM Roles for Service Accounts), you can annotate the ServiceAccount:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/portus-controller
```

In practice, the controller only talks to the Kubernetes API server and streams config to dataplanes. It does not interact with AWS services directly, so IRSA is only needed if your cluster enforces it for all pods.

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
  --wait
```

The `pullPolicy=Never` is important for k3d -- without it, Kubernetes will try to pull from a registry that doesn't have your locally-built image.

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

