# Portus

A Kubernetes gateway in Rust: the Gateway API, an AI gateway for LLM providers and an MCP gateway
for tool servers, on one data plane with a swappable network stack.

<!-- badges -->
[![Gateway API Conformance](https://img.shields.io/badge/Gateway%20API-v1.6.2%20%C2%B7%20130%2F130-blue)](https://gateway-api.sigs.k8s.io/)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](#license)

## What Portus is

- **A Gateway API implementation.** Gateway API v1.6.2, experimental channel: HTTPRoute, GRPCRoute,
  TLSRoute, TCPRoute, UDPRoute, ListenerSet, BackendTLSPolicy. 130 of 130 conformance tests across
  all five profiles, no skips. The controller compiles the CRDs straight into a protobuf config and
  streams it to the data planes over mTLS gRPC; there is no intermediate proxy config language.
- **An AI gateway.** Point clients that speak the Anthropic Messages or OpenAI chat API at Portus.
  It routes on the request body (`model`, `stream`), swaps the client's key for the provider's,
  meters tokens from JSON and streamed responses, enforces token budgets and issues its own API keys.
- **An MCP gateway.** Model Context Protocol servers over Streamable HTTP sit behind the same
  gateway: routing on the JSON-RPC method and tool, sessions pinned to the server pod that created
  them, per-key tool allow lists, call budgets, and OAuth bearer tokens verified against an issuer
  such as dex.

Three rules shape the design. The data plane never calls anything on the request path: keys,
budgets and token verification are local lookups against state the ledger pushes in. Config
changes swap atomically (`ArcSwap`), so a reload never drops a connection. And the network stack
is an adapter: everything Portus decides lives in a stack-independent core, and the release image
carries both [Rama](https://github.com/plabayo/rama) (default) and
[Pingora](https://github.com/cloudflare/pingora).

## Quick Start

Prerequisites: a Kubernetes 1.32+ cluster, `kubectl`, Helm 3.8+.

```bash
# Gateway API CRDs (experimental channel: GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ListenerSet)
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/experimental-install.yaml

# Portus: controller, GatewayClass `portus-gateway`, policy CRDs, mTLS material for the config stream
helm install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.5 \
  --namespace portus --create-namespace
```

Images are published to `ghcr.io/portus-gateway/controller`, `ghcr.io/portus-gateway/dataplane` and
`ghcr.io/portus-gateway/ledger` for `linux/amd64` and `linux/arm64`; the chart pins the tag matching
its version.

A Gateway and an HTTPRoute:

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

## Gateway API

Gateway API **v1.6.2** (`experimental` channel): **130 of 130 conformance tests pass, 0 failures,
0 skips**, run in-cluster against the per-Gateway deployment.

| Profile | Core | Extended |
|---------|------|----------|
| HTTP    | 37/37 | 56/56 |
| GRPC    | 15/15 | 9/9 |
| TLS     | 20/20 | 14/14 |
| TCP     | 19/19 | 9/9 |
| UDP     | 20/20 | 9/9 |


Extended features covered: HTTPRoute method and query matching, request mirroring (multiple and
percentage-based), path and host rewrite, request and response header modification, H2C and
WebSocket backends, destination port matching, request and backend timeouts, redirect status codes,
CORS, ListenerSet, HTTP listener isolation, misdirected-request detection, BackendTLSPolicy with SAN
validation, TLS terminate, passthrough and mixed mode, HTTPRoute retry, TCPRoute and UDPRoute. Full
[conformance report](tests/conformance/conformance-report.yaml).

### Policies

Portus policies are CRDs that attach to a Gateway, route or Service with a `targetRef`; the
controller compiles them into the route config and the data plane enforces them locally.

| Policy | What it does |
|---|---|
| `TimeoutPolicy` | Request, backend-request and connect deadlines |
| `RetryPolicy` | Replay to another endpoint when the connection fails |
| `RateLimitPolicy` | Token bucket per route or per client IP |
| `CircuitBreakerPolicy` | Stop sending to a backend after consecutive 5xx |
| `ConnectionPolicy` | Cap in-flight requests to a backend |
| `HealthCheckPolicy` | Active HTTP health checks on the endpoints |
| `CORSPolicy` | Preflight answers and CORS response headers |
| `IPAllowlistPolicy` | Allow and deny CIDRs, with trusted proxies for `X-Forwarded-For` |
| `RequestBodySizeLimitPolicy` | 413 above `maxBytes`, streamed bodies included |
| `BasicAuthPolicy`, `ApiKeyAuthPolicy` | HTTP Basic against bcrypt hashes; a header against keys in a Secret |
| `AIUsagePolicy` | Token or call budgets on an AIRoute |

Fields, examples and semantics: [`docs/policies.md`](docs/policies.md).

## AI gateway

Three CRDs turn a Gateway into a front for LLM providers. Clients keep speaking the provider's
native API; the gateway routes on the body, swaps credentials, meters and enforces. Opt in with
`aiGateway.enabled: true`, which also deploys the **ledger**, the companion service that holds
keys, budgets and usage so the data plane never calls out on the request path.

```yaml
apiVersion: portus-gateway.dev/v1alpha1
kind: AIProvider
metadata: {name: anthropic, namespace: llm}
spec:
  kind: anthropic
  url: https://api.anthropic.com
  credential: {secretRef: {name: anthropic-key}}
---
apiVersion: portus-gateway.dev/v1alpha1
kind: AIRoute
metadata: {name: claude, namespace: llm}
spec:
  parentRefs: [{name: gateway}]
  hostnames: [llm.example.com]
  requireApiKey: true
  rules:
  - matches:
    - model: {type: Prefix, value: claude-}
    providerRefs: [{name: anthropic}]
---
apiVersion: portus-gateway.dev/v1alpha1
kind: AIUsagePolicy
metadata: {name: daily-cap, namespace: llm}
spec:
  targetRef: {group: portus-gateway.dev, kind: AIRoute, name: claude}
  budget: {tokens: 1000000, window: Daily, per: Key}
```

- **Routing on the body.** A streaming JSON scanner reads `model`, `stream` and `max_tokens` as
  the request arrives and replays the bytes to the provider unchanged; Anthropic and OpenAI SDKs
  put `model` after the prompt, so this matters.
- **Keys.** The ledger issues `portus_sk_…` keys or imports external ones and stores only hashes;
  the data plane checks a key with one hash and one lookup against a pushed snapshot. Keys carry
  `allowed_models` and `allowed_tools`.
- **Metering and budgets.** Input, output and cache tokens are read from JSON and SSE responses of
  both dialects. Budgets are local counters per key, tenant or route, reserved before the request
  and settled after, synced with the ledger once a second; every response carries
  `x-portus-tokens-remaining`.
- **Refusals in the provider's shape**: 401 `authentication_error`, 403 `permission_error`, 429
  with `Retry-After`. Every refusal is recorded with its reason.
- **Ordinary policies apply**: `TimeoutPolicy`, `RateLimitPolicy`, `RetryPolicy` and the rest
  target an AIRoute like an HTTPRoute.
- **Claude Code** works unchanged: `ANTHROPIC_BASE_URL=https://llm.example.com ANTHROPIC_API_KEY=portus_sk_… claude`.

## MCP gateway

An MCP server is a provider of `kind: mcp`; the transport is Streamable HTTP.

```yaml
apiVersion: portus-gateway.dev/v1alpha1
kind: AIProvider
metadata: {name: github-mcp, namespace: tools}
spec:
  kind: mcp
  url: http://github-mcp.tools.svc.cluster.local:3001
---
apiVersion: portus-gateway.dev/v1alpha1
kind: AIRoute
metadata: {name: mcp, namespace: tools}
spec:
  parentRefs: [{name: gateway}]
  hostnames: [mcp.example.com]
  requireApiKey: true
  auth:
    jwt: {issuer: https://dex.example.com, audience: portus}
  rules:
  - matches:
    - method: {type: Exact, value: tools/call}
      tool: {type: Prefix, value: github.}
    providerRefs: [{name: github-mcp}]
  - matches:
    - path: {type: PathPrefix, value: /mcp}
    providerRefs: [{name: github-mcp}]
```

- **Routing** on the JSON-RPC `method` and on the tool a `tools/call` names, so one namespace of
  tools can live on one server and the rest elsewhere.
- **Sessions stay on the server pod that created them.** The `Mcp-Session-Id` a client receives
  carries the gateway's tag for that endpoint in front of the server's id; nothing is shared between
  gateway pods and the server never sees the tag. A provider that names a cluster Service follows
  its pod endpoints, not the ClusterIP.
- **Per-key tool allow lists** (`allowed_tools`, exact or `prefix.*`) and **call budgets**
  (`budget.calls`), with refusals as JSON-RPC errors on 200 so clients keep their session.
- **OAuth.** With `auth.jwt`, bearer tokens from an issuer such as dex are accepted in place of a
  Portus key: the ledger fetches the issuer's JWKS, the data plane verifies tokens locally and caches
  them by hash, the subject's groups become the tenant and a scope claim can gate tools. The host
  publishes `/.well-known/oauth-protected-resource`, which is how MCP clients find the login.
- **Claude Code**: `claude mcp add --transport http github https://mcp.example.com/mcp --header "Authorization: Bearer …"`.

Field reference for the three CRDs, the key API and the refusal shapes:
[`docs/ai-gateway.md`](docs/ai-gateway.md). Examples: [`deploy/examples/ai-gateway/`](deploy/examples/ai-gateway/).

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


### Network stacks

Everything the data plane decides (routing, policies, TLS material, endpoint pools, the SNI mux, the
L4 and UDP proxies, the AI and MCP logic) lives in `portus-dataplane-core` and knows nothing about
the proxy framework underneath. The framework is an adapter that extracts a request's facts, asks
the core for a plan and carries it out. The release image carries two:

| Stack | Status | Select with |
|---|---|---|
| [Rama](https://github.com/plabayo/rama) 0.4 | Default since 0.2.4: conformance 130/130, the AI and MCP gateways run on it. Rama is used unpatched; the upstream connection pool is Portus's own | `dataplane.networkStack: rama` (default) |
| [Pingora](https://github.com/cloudflare/pingora) 0.9 | The stack behind releases up to 0.2.3 and the numbers above; a small patch to `pingora-core` is vendored | `dataplane.networkStack: pingora` |

On the same machine Rama measured 3–31 % more throughput than Pingora on every payload rung and used
2–2.6× less memory in a single round
([`benchmarks/rama-vs-pingora-2026-09-15.md`](benchmarks/rama-vs-pingora-2026-09-15.md)); a
three-round comparison is due with the next release's numbers.

## Architecture

```
                    ┌──────────────────────────────────┐
                    │         Kubernetes API            │
                    │  Gateway  HTTPRoute  GRPCRoute    │
                    │  TLSRoute TCPRoute UDPRoute       │
                    │  AIProvider AIRoute AIUsagePolicy │
                    └──────────┬───────────────────────┘
                               │ watch
                    ┌──────────▼───────────────────────┐        ┌──────────────────┐
                    │       portus-controller           │        │  portus-ledger   │
                    │  Reconcilers → ConfigStore        │        │  keys · budgets  │
                    │       → compile_config()          │        │  usage · JWKS    │
                    │       → CompiledConfig (proto)    │        └───────┬──────────┘
                    └──────────┬───────────────────────┘                │ snapshots, syncs,
                               │ gRPC stream (mTLS)                     │ usage batches (mTLS)
              ┌────────────────┼────────────────┐                       │
              ▼                ▼                 ▼                       │
     ┌────────────┐   ┌────────────┐   ┌────────────┐                    │
     │  dataplane  │   │  dataplane  │   │  dataplane  │ ◀─────────────────┘
     │   (rama)    │   │   (rama)    │   │   (rama)    │
     └────────────┘   └────────────┘   └────────────┘
```

The **controller** watches Gateway API and Portus CRDs via the kube-rs runtime and provisions a
dataplane Deployment, Service and PodDisruptionBudget per Gateway. Each resource type has a
dedicated reconciler that updates a shared `ConfigStore`; reconcilers publish store events to each
other instead of polling. On any change the store is compiled into a `CompiledConfig` protobuf
message; each dataplane receives only its own Gateway's slice over gRPC and acknowledges the
content fingerprint it applied, which drives the Gateway's `Programmed` condition.

The **dataplane** builds route maps keyed by `listener_port:hostname`, binds every listener port
and serves traffic through the selected network stack. Failing endpoints are ejected from load
balancing passively (a connect failure or five consecutive 5xx) and readmitted after a growing
back-off. Route matching follows Gateway API precedence: exact paths before prefix paths, longest
prefix first, header, method and query matches as tiebreakers. Config updates swap atomically via
`ArcSwap`. On SIGTERM a pod stops accepting, reports not ready, lets requests in flight finish and
exits.

The **ledger** (opt-in with the AI gateway) issues keys, keeps budgets as a shared counter the data
planes sync every second, stores usage in SQLite and fetches OAuth issuers' JWKS. It pushes
snapshots down and receives usage batches up; it is never on the request path.

The **proto schema** (`proto/portus/v1/`) is the contract between the three: listeners, routes,
backends, filters, TLS material, AI backends and budgets on the config stream; key snapshots,
budget syncs and usage records on the ledger stream.

## Configuration

### Helm Values

```bash
helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.5 \
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

Full reference: [`docs/deployment.md`](docs/deployment.md). Policies: [`docs/policies.md`](docs/policies.md).
AI gateway and MCP: [`docs/ai-gateway.md`](docs/ai-gateway.md). What is supported, planned and not
planned: [`docs/compliance-matrix.md`](docs/compliance-matrix.md).

## Building from Source

Requires Rust 1.98+ and protoc.

```bash
cargo build --workspace --release
cargo test --workspace -- --test-threads=1 -q
make build      # controller, dataplane and ledger images
```

Local cluster with [mise](https://mise.jdx.dev/) managing k3d, helm, kubectl, go and protoc:

```bash
make k3d-up     # k3d cluster `portus-local`
make build      # images
make deploy     # Gateway API CRDs, image import, helm install (ClusterIP Services, one pod per Gateway)
```

The workspace contains five crates plus the patched `pingora-core`:

| Crate | Path | Description |
|-------|------|-------------|
| `portus-controller` | `crates/portus-controller` | Kubernetes controller: reconcilers, config store, compiler, gRPC server |
| `portus-dataplane-core` | `crates/portus-dataplane-core` | Network-stack-independent data plane: config receiver, route matching, policies, endpoint pools, TLS material, SNI mux, L4/UDP proxies, AI and MCP logic, metrics |
| `portus-dataplane` | `crates/portus-dataplane` | The data plane binary: network-stack adapters over the core (Rama by default, Pingora), selected with `PORTUS_NETWORK_STACK` |
| `portus-ledger` | `crates/portus-ledger` | The AI gateway's companion: keys, budgets, usage store, JWKS refresh |
| `portus-types` | `crates/portus-types` | Protobuf-generated types shared by all three |

Release builds use `opt-level = 3`, fat LTO, single codegen unit, and `panic = abort`.

### Running Conformance Tests

Conformance runs in-cluster: every Gateway gets its own dataplane and a ClusterIP address that only
pods can reach, so the suite is built into an image and run as a Job.

```bash
make k3d-up build deploy          # cluster, images, chart
make conformance-image            # build + import the runner
make conformance-run              # all five profiles; report -> tests/conformance/conformance-report.yaml
make conformance-run CONFORMANCE_RUN='TestConformance/HTTPRouteSimpleSameNamespace$$'
```

## License

Apache-2.0
