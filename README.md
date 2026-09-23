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
helm install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.4 \
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

### Network stacks

Everything the data plane decides — routing, policies, TLS material, endpoint pools, the SNI mux, the L4 and UDP proxies — lives in `portus-dataplane-core` and knows nothing about the proxy framework underneath. The framework is an adapter that extracts a request's facts, asks the core for a plan, and carries it out. Two adapters exist:

| Stack | Status | Select with |
|---|---|---|
| [Rama](https://github.com/plabayo/rama) 0.4 | The release stack since 0.2.4: default in every published image, conformance 130/130, the AI gateway runs on it | `dataplane.networkStack: rama` (default) |
| [Pingora](https://github.com/cloudflare/pingora) 0.9 | The stack behind every release up to 0.2.3 and every number in the tables above; still in the release image | `dataplane.networkStack: pingora` |

Both stacks share the core, benchmarks and conformance suite; a value the image was not built with fails the pod at start with a log line naming it.

Rama against Pingora, one round on the same 10 vCPU machine as the tables above, Pingora then Rama on the same 3 pods × 2 CPU (fortio, 10 s per rung, all requests 200). Rama ran with other load on the box (load average 7.4 against 2.7 for the Pingora pass), so its numbers are if anything understated; a single round still means differences under 5 % are noise.

| Ladder | Rung | Pingora | Rama | Δ |
|---|---|---|---|---|
| Traffic (bare `GET /`, by connections) | 64 | 135,987 | 149,683 | +10 % |
| | 128 | 149,926 | 169,209 | +13 % |
| | 256 | 148,653 | 163,788 | +10 % |
| Download (64 connections, by response size) | 1 KiB | 88,970 | 91,627 | +3 % |
| | 16 KiB | 69,336 | 75,649 | +9 % |
| | 128 KiB | 38,578 | 40,449 | +5 % |
| | 1 MiB | 6,496 | 7,317 | +13 % |
| Upload (POST, echoed) | 1 KiB | 75,840 | 84,721 | +12 % |
| | 16 KiB | 32,335 | 36,934 | +14 % |
| | 128 KiB | 9,819 | 9,778 | 0 % |
| | 1 MiB | 5,142 | 5,374 | +5 % |
| HTTPS download | 1 KiB | 81,094 | 86,925 | +7 % |
| | 16 KiB | 59,729 | 67,483 | +13 % |
| | 128 KiB | 25,914 | 28,960 | +12 % |
| | 1 MiB | 4,154 | 5,427 | +31 % |
| HTTP/2 download | 1 KiB | 60,484 | 66,619 | +10 % |
| | 16 KiB | 45,696 | 52,156 | +14 % |
| | 128 KiB | 21,276 | 23,329 | +10 % |
| | 1 MiB | 3,781 | 4,602 | +22 % |

Resources over the same round, summed across the three dataplane pods (CPU in millicores, memory in MiB):

| Ladder | Pingora CPU mean / peak | Rama CPU mean / peak | Pingora memory mean / peak | Rama memory mean / peak |
|---|---|---|---|---|
| Traffic | 1,323 / 2,691 | 1,257 / 3,208 | 41 / 68 | 31 / 85 |
| Download | 3,246 / 3,563 | 3,036 / 3,273 | 136 / 282 | 120 / 138 |
| Upload | 2,600 / 3,237 | 2,436 / 3,184 | 184 / 282 | 123 / 152 |
| HTTPS | 2,213 / 2,973 | 2,264 / 3,035 | 235 / 331 | 140 / 152 |
| HTTP/2 | 3,063 / 3,499 | 2,716 / 3,236 | 369 / 432 | 126 / 167 |

The Rama adapter uses Rama 0.4 unpatched for TCP, TLS, the HTTP/1 and HTTP/2 client connections and the server. The upstream connection pool is Portus's own: one shard of idle HTTP/1 connections per backend, TLS policy and protocol, a rotating set of HTTP/2 connections per gRPC or h2c backend, the client read buffer capped at 64 KiB, and TCP_NODELAY on every socket. Its decisions are exported as `proxy_upstream_pool_events_total{event}` on the metrics port.

## AI gateway

Portus can front LLM providers as well as ordinary backends. Three CRDs turn a Gateway into an AI gateway; clients keep speaking the provider's native API (Anthropic Messages, OpenAI chat) and the gateway routes on the request body, swaps the client's key for the provider's, meters tokens and enforces budgets. It needs the Rama network stack (`dataplane.networkStack: rama`) and `aiGateway.enabled: true`, which also deploys the ledger, the small companion service that keeps everything with state so the data plane never calls out on the request path.

| Resource | What it does |
|---|---|
| `AIProvider` | An LLM API: `kind` (`anthropic`, `openai`, `openai-compatible`), `url` (scheme and host), the provider credential from a Secret. Resolved to endpoints by the controller. |
| `AIRoute` | An HTTPRoute-shaped route whose matches include the body's `model` (exact, prefix or regex) and `stream`. `requireApiKey: true` demands a Portus API key. |
| `AIUsagePolicy` | A token budget on an AIRoute per key, tenant or route, per UTC hour, day or month, with a fail-open or fail-closed choice when the ledger is unreachable. |

The ordinary policies (TimeoutPolicy, RateLimitPolicy, RetryPolicy and the rest) target an AIRoute the same way they target an HTTPRoute.

MCP servers are providers too (`kind: mcp`, Streamable HTTP): an AIRoute matches on the JSON-RPC `method` and on the tool a `tools/call` names, keys carry a tool allow list, budgets can count calls instead of tokens, and a session stays on the server pod that created it (rendezvous hashing on `Mcp-Session-Id`, nothing shared between gateway pods). Refusals inside a session are JSON-RPC errors on 200 so clients keep their session. Routes can also accept OAuth bearer tokens from an issuer such as dex (`auth.jwt`): the ledger fetches the JWKS, the data plane verifies tokens locally and caches them, and the host publishes the RFC 9728 metadata MCP clients use to find the login. Field reference: [`docs/ai-gateway.md`](docs/ai-gateway.md).

How it stays fast: the body is scanned as it streams with a memchr-driven JSON field scanner that stops at the first sight of `model` and `stream`, and the held bytes are replayed to the provider unchanged; keys are one SHA-256 and a hash-map lookup against a snapshot the ledger pushes; budgets are a local counter per subject that reserves an estimate before the request and settles to the provider's real token count after, syncing with the ledger once a second; usage records go into a lock-free ring drained by a background task. Every budgeted response carries `x-portus-tokens-remaining`; refusals are 401, 403 or 429 in the provider's own error shape with `Retry-After`.

The ledger issues and revokes keys (`POST`/`GET`/`DELETE /v1/keys`, bearer token in the generated `<release>-portus-gateway-ledger-admin` Secret), answers `GET /v1/summary?hours=24` with requests, refusals and tokens per key, exports every record as JSON lines (`GET /export.jsonl`) and exposes `/metrics`. Example manifests and a walk-through, including pointing Claude Code at the gateway with `ANTHROPIC_BASE_URL`, are in [`deploy/examples/ai-gateway/`](deploy/examples/ai-gateway/).

## Configuration

### Helm Values

```bash
helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.4 \
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
| `dataplane.threads` | `""` | Proxy worker threads per pod; empty sizes from the cgroup CPU limit, else the node's CPU count |
| `dataplane.networkStack` | `rama` | Network stack the dataplane pods serve on: `rama` (default) or `pingora`, both in the release image |
| `dataplane.accessLog` | `false` | One log line per request (`portus_dataplane::access`) |
| `dataplane.service.type` | `LoadBalancer` | Per-Gateway Service type; use `ClusterIP` on k3d |
| `dataplane.logLevel` | `info` | `RUST_LOG` |
| `grpcTls.enabled` | `true` | mTLS on the config stream. The chart generates a CA and controller certificate on first install and keeps them across upgrades; the controller copies the Secret into each Gateway's namespace |
| `grpcTls.secretName` | `""` | Bring your own Secret (`ca.crt`, `tls.crt`, `tls.key`) instead of the generated one |
| `aiGateway.enabled` | `false` | Deploy the ledger and enable AI routes; needs `dataplane.networkStack: rama`. On an existing install upgrade with `--reset-then-reuse-values` and delete the generated grpc-tls Secret once so it is regenerated with the ledger's names |
| `aiGateway.ledger.storage.size` | `1Gi` | PersistentVolumeClaim for the ledger's SQLite file |
| `aiGateway.ledger.adminTokenSecretName` | `""` | Bring your own admin token Secret (key `token`) for the key API |
| `aiGateway.jwt.issuers` | `[]` | OAuth issuers whose tokens `AIRoute.auth.jwt` may accept; the ledger fetches their JWKS every 5 minutes |

Full reference: [`docs/deployment.md`](docs/deployment.md). Policies (timeouts, retries, rate limits, circuit breakers, CORS, IP allow lists, body limits, auth): [`docs/policies.md`](docs/policies.md). AI gateway and MCP: [`docs/ai-gateway.md`](docs/ai-gateway.md). What is supported, planned and not planned: [`docs/compliance-matrix.md`](docs/compliance-matrix.md).

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

The workspace contains four crates plus the patched `pingora-core`:

| Crate | Path | Description |
|-------|------|-------------|
| `portus-controller` | `crates/portus-controller` | Kubernetes controller — reconcilers, config store, compiler, gRPC server |
| `portus-dataplane-core` | `crates/portus-dataplane-core` | Network-stack-independent data plane — config receiver, route matching, policies, endpoint pools, TLS material, SNI mux, L4/UDP proxies, metrics |
| `portus-dataplane` | `crates/portus-dataplane` | The data plane binary: network-stack adapters over the core (Pingora; Rama behind the `rama` feature), selected with `PORTUS_NETWORK_STACK` |
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
