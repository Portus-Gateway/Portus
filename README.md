# Portus

Kubernetes Gateway API implementation built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) proxy framework. Written in Rust.

<!-- badges -->
[![Gateway API Conformance](https://img.shields.io/badge/Gateway%20API-v1.6.2-blue)](https://gateway-api.sigs.k8s.io/)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](#license)

## Why Portus

Most Gateway API implementations are wrappers around general-purpose proxies (Envoy, Nginx, HAProxy) that translate Gateway API resources into the proxy's native configuration format. Portus skips the translation layer entirely — the controller compiles Gateway API CRDs directly into a protobuf config that the Pingora-based dataplane consumes over gRPC. There's no intermediate config language, no sidecar injection, and no control plane restart on config changes. Config updates are applied atomically via `ArcSwap`, so the dataplane never drops connections during reconfiguration.

## Conformance

Gateway API **v1.6.2** (`experimental` channel): **130 of 130 conformance tests pass, 0 failures, 0 skips**, across all five profiles (GATEWAY-HTTP, GATEWAY-GRPC, GATEWAY-TLS, GATEWAY-TCP, GATEWAY-UDP), run in-cluster against the per-Gateway deployment (one dataplane Deployment and Service per Gateway).

| Profile | Core | Extended |
|---------|------|----------|
| HTTP    | 37/37 | 56/56 |
| GRPC    | 15/15 | 9/9 |
| TLS     | 20/20 | 14/14 |
| TCP     | 19/19 | 9/9 |
| UDP     | 20/20 | 9/9 |

Supported extended features include: HTTPRoute method matching, query param matching, request mirroring (including multiple mirrors and percentage-based), path/host rewrite, backend request header modification, response header modification, backend protocol H2C, WebSocket, destination port matching, request/backend timeouts, redirect status codes (303/307/308), CORS, ListenerSet, HTTP listener isolation, misdirected-request detection, BackendTLSPolicy with SAN validation, TLS Terminate and mixed mode, HTTPRoute retry, TCPRoute and UDPRoute.

See the full [conformance report](tests/conformance/conformance-report.yaml).

## Performance

Measured with the [howardjohn/gateway-api-bench](https://github.com/howardjohn/gateway-api-bench) method on a
10-vCPU Linux VM on an Apple M4 (apple/container machine, k3s, pods at MTU 65485; see
[`deploy/machine/`](deploy/machine/README.md)): **Portus 0.2.3** and agentgateway v1.5.0, the fastest gateway in that
benchmark's own ranking, three interleaved rounds each against the same backend pods, fortio in-cluster with one pod
per rung, `kubectl top` sampled every 5 s. Medians of the three rounds; per-round values, spread and method are in
[`benchmarks/`](benchmarks/README.md). Numbers from one machine are only comparable with each other.

**Traffic** (bare `GET /`; 3 proxy pods each, agentgateway unlimited):

| Connections | Portus QPS | agentgateway QPS | |
|---|---|---|---|
| 64 | **116,429** | 96,003 | +21 % |
| 128 | **123,105** | 101,067 | +22 % |
| 256 | **126,070** | 89,827 | +40 % |

p99 at a fixed 30,000 QPS (benchtool, same machine, same day): **Portus 0.35 ms**, agentgateway 0.82 ms.

**Payloads** (fortio echo backend, 64 connections, 10 s per rung, all requests `200`; QPS, Portus / agentgateway):

| Response size | Download | Upload (POST, echoed) | HTTPS download | HTTP/2 download |
|---|---|---|---|---|
| 1 KB | **87,722** / 67,598 | **66,089** / 58,495 | **76,997** / 60,088 | **64,172** / 49,453 |
| 16 KB | **59,257** / 51,562 | **29,578** / 27,940 | **56,831** / 48,295 | **49,448** / 40,279 |
| 128 KB | **29,954** / 27,136 | 8,160 / 7,922 | **25,357** / 22,294 | **22,431** / 19,641 |
| 1 MiB | 5,206 / 5,633 | 4,380 / 4,249 | 4,200 / 4,110 | **4,173** / 3,538 |

Portus leads on 18 of 19 rungs, by 20–40 % on the request path and 13–30 % at 1 KB; the two are level at 1 MiB over
plain HTTP and TLS, where the shared 10 vCPUs are the limit. Proxy CPU on the payload ladders: Portus 2.0–2.3 cores at
131 Mi peak, agentgateway 2.3–2.6 cores at 383–456 Mi peak.

**Control plane and availability** (gateway-api-bench suite, Portus 0.2.2 vs agentgateway on Docker Desktop, 2026-09-10;
the bench catch-all route removed before the attached-routes and propagation tests):

| Test | Portus | agentgateway |
|---|---|---|
| Route propagation, 200 routes | 23 ms per route, controller 107 m CPU / 12 Mi | **14 ms per route**, controller 34 m / 136 Mi |
| Route changes, 60 flips under load | 0 errors in 85,218 requests | 0 errors in 78,562 requests |
| Route scale, 500 pods + routes over 10 min | controller 44 m mean, **21 Mi** | controller **16 m** mean, 172 Mi |
| Backend failover, 1 of 4 endpoints blackholed, no policy | **0.025 % errors** (passive outlier ejection) | 2.0 % errors |
| Backend failover with a Gateway `RetryPolicy` | **0 errors** | not applicable |

Details: [`benchmarks/head-to-head-machine-2026-09-11.md`](benchmarks/head-to-head-machine-2026-09-11.md) and
[`benchmarks/head-to-head-0.2.2-2026-09-10-k3d.md`](benchmarks/head-to-head-0.2.2-2026-09-10-k3d.md). Reproduce with
`make bench-backend bench-portus bench-traffic-fortio bench-latency bench-download bench-upload bench-https bench-h2` and
the `bench-*` control-plane targets.

## Quick Start

Prerequisites: a Kubernetes 1.32+ cluster, `kubectl`, Helm 3.8+.

```bash
# Gateway API CRDs (experimental channel: GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ListenerSet)
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/experimental-install.yaml

# Portus: controller, GatewayClass `portus-gateway`, policy CRDs, mTLS material for the config stream
helm install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.3 \
  --namespace portus --create-namespace
```

Images are published to `ghcr.io/portus-gateway/controller` and `ghcr.io/portus-gateway/dataplane`
for `linux/amd64` and `linux/arm64`; the chart pins the tag matching its version.

Once deployed, create a Gateway and HTTPRoute:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: portus
spec:
  gatewayClassName: portus-gateway
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: portus
spec:
  parentRefs:
  - name: my-gateway
  hostnames:
  - "app.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: my-service
      port: 8080
```

Each Gateway gets its own dataplane Deployment and Service; the Service's address appears in
`status.addresses`:

```bash
ADDR=$(kubectl get gateway my-gateway -n portus -o jsonpath='{.status.addresses[0].value}')
curl -H "Host: app.example.com" http://$ADDR/
```

## Architecture

```
                    ┌──────────────────────────────────┐
                    │         Kubernetes API            │
                    │  Gateway  HTTPRoute  GRPCRoute    │
                    │  TLSRoute  TCPRoute  UDPRoute     │
                    └──────────┬───────────────────────┘
                               │ watch
                    ┌──────────▼───────────────────────┐
                    │       portus-controller             │
                    │                                   │
                    │  Reconcilers → ConfigStore         │
                    │       → compile_config()           │
                    │       → CompiledConfig (proto)     │
                    └──────────┬───────────────────────┘
                               │ gRPC stream
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
     ┌────────────┐   ┌────────────┐   ┌────────────┐
     │  dataplane  │   │  dataplane  │   │  dataplane  │
     │  (Pingora)  │   │  (Pingora)  │   │  (Pingora)  │
     └────────────┘   └────────────┘   └────────────┘
```

The **controller** watches Gateway API CRDs via the kube-rs runtime and provisions a dataplane Deployment, Service and PodDisruptionBudget per Gateway. Each resource type has a dedicated reconciler that updates a shared `ConfigStore`. Reconcilers publish store events to each other instead of polling, so nothing is requeued on a timer. On any change the store is compiled into a `CompiledConfig` protobuf message; each dataplane receives only its own Gateway's slice over gRPC and acknowledges the content fingerprint it applied, which is what drives the Gateway's `Programmed` condition.

The **dataplane** receives the compiled config, builds route maps keyed by `listener_port:hostname`, binds every listener port from the config, and serves traffic through Pingora's proxy framework. Failing endpoints are ejected from load balancing passively (a connect failure or five consecutive 5xx) and readmitted after a growing back-off. Route matching follows Gateway API precedence rules — exact paths before prefix paths, longest prefix first, with header/method/query matches as tiebreakers. Config updates are swapped atomically via `ArcSwap`, so in-flight requests always see a consistent snapshot and no connections are dropped.

The **proto schema** (`proto/portus/v1/config.proto`) defines the contract between controller and dataplane. It carries listeners, route configs, backend refs, filters, TLS certificates, and all the routing metadata needed to reconstruct full Gateway API semantics on the dataplane side.

## Configuration

### Helm Values

```bash
helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.3 \
  --namespace portus --create-namespace \
  --set dataplane.replicasPerGateway=3
```

| Key | Default | Description |
|-----|---------|-------------|
| `controller.image.repository` / `.tag` | `ghcr.io/portus-gateway/controller` / chart `appVersion` | Controller image |
| `controller.replicas` | `1` | Leader election via a Lease; extra replicas stand by |
| `controller.grpcPort` | `50051` | Config stream gRPC port |
| `controller.logLevel` | `info` | `RUST_LOG` |
| `controller.gatewayClassName` | `portus-gateway` | GatewayClass this controller accepts |
| `controller.controllerName` | `github.com/Portus-Gateway/Portus` | `controllerName` on the GatewayClass |
| `controller.resources` | 100m / 256Mi requests, 512Mi limit | No CPU limit |
| `dataplane.image.repository` / `.tag` | `ghcr.io/portus-gateway/dataplane` / chart `appVersion` | Dataplane image (the controller provisions the Deployments) |
| `dataplane.replicasPerGateway` | `2` | Pods per Gateway |
| `dataplane.resources` | 250m / 256Mi requests, 512Mi limit | No CPU limit |
| `dataplane.threads` | `""` | Pingora worker threads per pod; empty sizes from the cgroup CPU limit, else the node's CPU count |
| `dataplane.accessLog` | `false` | One log line per request (`portus_dataplane::access`) |
| `dataplane.service.type` | `LoadBalancer` | Per-Gateway Service type; use `ClusterIP` on k3d |
| `dataplane.logLevel` | `info` | `RUST_LOG` |
| `grpcTls.enabled` | `true` | mTLS on the config stream. The chart generates a CA and controller certificate on first install and keeps them across upgrades; the controller copies the Secret into each Gateway's namespace |
| `grpcTls.secretName` | `""` | Bring your own Secret (`ca.crt`, `tls.crt`, `tls.key`) instead of the generated one |

Full reference: [`docs/deployment.md`](docs/deployment.md).

## Building from Source

Requires Rust 1.98+ and protoc.

```bash
# Build all workspace crates
cargo build --workspace --release

# Run unit tests
cargo test --workspace -- --test-threads=1 -q

# Build container images
make build
```

Local cluster with [mise](https://mise.jdx.dev/) managing k3d, helm, kubectl, go and protoc:

```bash
make k3d-up     # k3d cluster `portus-local`
make build      # controller + dataplane images
make deploy     # Gateway API CRDs, image import, helm install (ClusterIP Services, one pod per Gateway)
```

The workspace contains three crates:

| Crate | Path | Description |
|-------|------|-------------|
| `portus-controller` | `crates/portus-controller` | Kubernetes controller — reconcilers, config store, compiler, gRPC server |
| `portus-dataplane` | `crates/portus-dataplane` | Pingora-based proxy — config receiver, router, TLS, health/metrics |
| `portus-types` | `crates/portus-types` | Protobuf-generated types shared between controller and dataplane |

Release builds use `opt-level = 3`, fat LTO, single codegen unit, and `panic = abort` for minimal binary size.

### Running Conformance Tests

Conformance runs in-cluster: every Gateway gets its own dataplane and a ClusterIP address that only pods can reach, so the suite is built into an image and run as a Job.

```bash
make k3d-up build deploy          # cluster, images, chart
make conformance-image            # build + import the runner
make conformance-run              # all five profiles; report -> tests/conformance/conformance-report.yaml
make conformance-run CONFORMANCE_RUN='TestConformance/HTTPRouteSimpleSameNamespace$$'
```

## License

Apache-2.0
