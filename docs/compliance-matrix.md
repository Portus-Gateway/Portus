# Portus Compliance and Feature Matrix

**Living document.** Last verified against conformance suite: 2026-09-06 (Gateway API v1.6.2 experimental channel; 130/130 tests, 0 failures, 0 skips, in-cluster run, one dataplane per Gateway).

This document captures what Portus supports today, what we plan to build, and what we've decided not to build. If something is marked "Supported" here, it means we have both an implementation and passing conformance tests (where applicable). If it's marked "Planned," there's a realistic path to implementation but no code yet.

---

## 1. Gateway API Conformance

Portus passes **130 of 130** Gateway API v1.6.2 conformance tests across the HTTP, GRPC, TLS, TCP and UDP profiles with **0 failures and 0 skips**, including mTLS (GatewayFrontendClientCertificateValidation, ...InsecureFallback, GatewayBackendClientCertificate), ListenerSet, GatewayHTTPListenerIsolation, HTTPRouteHTTPSListenerDetectMisdirectedRequests, BackendTLSPolicy, BackendTLSPolicySANValidation, TCPRoute, UDPRoute and HTTPRouteMultipleGateways (each Gateway gets its own dataplane and address). The conformance report lives at `tests/conformance/conformance-report.yaml`; it is produced by the in-cluster runner (`make conformance-run`).

### Core HTTP Features (37/37 core, 47/47 extended)

These are the request routing and traffic management features defined in the Gateway API HTTPRoute spec. Every core feature is required for conformance; extended features are opt-in declarations.

| Feature | Status | Notes |
|---------|--------|-------|
| Path matching (Exact) | Supported | Core. Case-sensitive exact string match. |
| Path matching (PathPrefix) | Supported | Core. Longest-prefix-wins with proper `/` boundary handling. |
| Path matching (RegularExpression) | Supported | Regex compiled once at config time, not per-request. |
| Header matching (Exact) | Supported | Core. Case-insensitive header name, exact value. |
| Header matching (RegularExpression) | Supported | Extended. Compiled regex, same as path regex. |
| Method matching | Supported | Extended (`HTTPRouteMethodMatching`). Matches HTTP method (GET, POST, etc.). |
| Query parameter matching (Exact) | Supported | Extended (`HTTPRouteQueryParamMatching`). |
| Query parameter matching (RegularExpression) | Supported | Extended. |
| HTTP redirects (301, 302) | Supported | Core. Scheme, hostname, port, path, status code all configurable. |
| HTTP redirects (303, 307, 308) | Supported | Extended (`HTTPRoute303RedirectStatusCode`, `HTTPRoute307RedirectStatusCode`, `HTTPRoute308RedirectStatusCode`). |
| Path redirect (ReplaceFullPath) | Supported | Extended (`HTTPRoutePathRedirect`). |
| Path redirect (ReplacePrefixMatch) | Supported | Extended (`HTTPRoutePathRedirect`). Handles double-slash and trailing-slash edge cases. |
| Scheme redirect | Supported | Extended (`HTTPRouteSchemeRedirect`). |
| Port redirect | Supported | Extended (`HTTPRoutePortRedirect`). |
| URL rewrite (path) | Supported | Extended (`HTTPRoutePathRewrite`). Both ReplaceFullPath and ReplacePrefixMatch. |
| URL rewrite (hostname) | Supported | Extended (`HTTPRouteHostRewrite`). Rewrites Host header before proxying. |
| Request header modification (add/set/remove) | Supported | Core. Applied before proxying to backend. |
| Response header modification (add/set/remove) | Supported | Extended (`HTTPRouteResponseHeaderModification`). Applied on the response path. |
| Backend request header modification | Supported | Extended (`HTTPRouteBackendRequestHeaderModification`). Per-backend header mutations in weighted splits. |
| Request mirroring (single) | Supported | Extended (`HTTPRouteRequestMirror`). Fire-and-forget async mirror. |
| Request mirroring (multiple) | Supported | Extended (`HTTPRouteRequestMultipleMirrors`). Multiple mirror backends per rule. |
| Request mirroring (percentage) | Supported | Extended (`HTTPRouteRequestPercentageMirror`). Percentage-based sampling. |
| Weighted backend traffic splitting | Supported | Core. Weighted round-robin across multiple backendRefs. Per-backend header mutations supported. |
| Request timeout | Supported | Extended (`HTTPRouteRequestTimeout`). Per-rule timeout on the full request lifecycle. |
| Backend request timeout | Supported | Extended (`HTTPRouteBackendTimeout`). Timeout on the backend connection specifically. |
| Backend protocol H2C | Supported | Extended (`HTTPRouteBackendProtocolH2C`). Forces HTTP/2 cleartext to backend via `appProtocol: kubernetes.io/h2c`. |
| Backend protocol WebSocket | Supported | Extended (`HTTPRouteBackendProtocolWebSocket`). Native Pingora WebSocket handling via `appProtocol: kubernetes.io/ws`. |
| CORS | Supported | Extended (`HTTPRouteCORS`). Preflight and simple request handling. Configurable origins, methods, headers, credentials, max-age. |
| Retry (`rules[].retry`) | Supported | Extended (`HTTPRouteRetry`). Upstream responses with a listed status are retried up to `attempts` more times before the last response is passed through; `backoff` is accepted but not applied (`HTTPRouteRetryBackoff` / `HTTPRouteRetryConnectionError` not claimed). Takes precedence over a `RetryPolicy` on the same route. |
| Named route rules | Supported | Extended (`HTTPRouteNamedRouteRule`). |
| Destination port matching | Supported | Extended (`HTTPRouteDestinationPortMatching`). Routes keyed by `host:listener_port` for port-specific routing. |
| ParentRef port binding | Supported | Extended (`HTTPRouteParentRefPort`). Routes bound to specific listener ports via parentRef. |
| Gateway on port 8080 | Supported | Extended (`GatewayPort8080`). Non-standard listener ports. |
| Cross-namespace references (ReferenceGrant) | Supported | Core. Full ReferenceGrant validation for cross-namespace Service and Secret refs. |
| Route precedence | Supported | Core. Exact > Prefix (longest first) > catch-all, with header/method/query as tiebreakers. |

### Core Gateway Features

| Feature | Status | Notes |
|---------|--------|-------|
| GatewayClass | Supported | Controller watches GatewayClass, sets Accepted condition. |
| Gateway (create, update, delete) | Supported | Full reconciliation with status conditions. |
| Listener protocol HTTP | Supported | |
| Listener protocol HTTPS | Supported | TLS termination with cert from Secret. |
| Listener protocol TLS | Supported | Both Passthrough and Terminate modes. |
| Listener protocol TCP | Supported | Raw bidirectional byte proxy. |
| Listener hostname restriction | Supported | Hostname intersection between listener and route hostnames. |
| Gateway status Accepted | Supported | |
| Gateway status Programmed | Supported | |
| Listener status attachedRoutes | Supported | Accurate count per listener. |
| Multiple listeners per Gateway | Supported | Including mixed protocols on different ports. |
| ReferenceGrant | Supported | Dedicated reconciler, enforced on cross-namespace backend and Secret refs. |
| Secret (TLS certificates) | Supported | Reconciler watches Secrets, feeds cert PEM to dataplane. |
| EndpointSlice resolution | Supported | Watches EndpointSlices for backend IP resolution. |
| Gateway address assignment (`GatewayAddressEmpty`) | Supported | Extended. A `spec.addresses` entry with type `IPAddress`/`Hostname` and no value is assigned by the per-Gateway Service. Unsupported types → `Accepted=False/UnsupportedAddress`. |
| Gateway static addresses | Not supported | A fixed `spec.addresses` value → `Accepted=False/AddressNotUsable`. Would need `loadBalancerIP`/cloud annotation plumbing on the per-Gateway Service. |
| Gateway infrastructure propagation | Supported | Extended. `spec.infrastructure.labels/annotations` land on the generated Deployment, Service, PDB and pods, which also carry `gateway.networking.k8s.io/gateway-name`. |
| ListenerSet | Supported | Extended (`ListenerSet`). Listeners contributed by ListenerSet resources, with allowedListeners namespace policy, sibling precedence and ReferenceGrant for cross-namespace cert refs. |
| Listener isolation | Supported | Extended (`GatewayHTTPListenerIsolation`). Per-listener route tables; the most-specific listener claims a request with no cross-listener fallback. |
| HTTPS misdirected request detection | Supported | Extended (`GatewayHTTPSListenerDetectMisdirectedRequests`). 421 when the SNI-selected listener differs from the Host-selected listener. |
| Frontend client cert validation | Supported | Extended (`GatewayFrontendClientCertificateValidation`, `...InsecureFallback`). `spec.tls.frontend.default` / `perPort` CA ConfigMaps; per-port rustls client verifier, strict or insecure-fallback mode. |
| Backend client certificate | Not supported | Extended. Client cert presented to backends. |

### GRPC Features (13/13 core)

| Feature | Status | Notes |
|---------|--------|-------|
| GRPCRoute (service + method matching) | Supported | Core. Exact match on gRPC service and method names. |
| GRPCRoute header matching | Supported | Core. Same header match semantics as HTTPRoute. |
| GRPCRoute request header modification | Supported | Core. |
| GRPCRoute response header modification | Supported | Core. |
| GRPCRoute named rules | Supported | Provisional (`GRPCRouteNamedRule`), passing. |
| GRPCRoute backend protocol | Supported | Forces HTTP/2 for gRPC backends automatically. |

### TLS Features (18/18 core, 4/4 extended)

| Feature | Status | Notes |
|---------|--------|-------|
| TLSRoute Passthrough | Supported | Core. SNI-based routing, raw TLS forwarded to backend. |
| TLSRoute Terminate | Supported | Extended (`TLSRouteModeTerminate`). TLS decrypted at proxy, TCP proxied to backend. |
| TLSRoute mixed mode | Supported | Extended (`TLSRouteModeMixed`). Passthrough and Terminate listeners on same Gateway. |
| SNI extraction (ClientHello peek) | Supported | Uses rustls Acceptor to parse SNI from ClientHello. |
| SNI multiplexer | Supported | Routes to Passthrough backend, Terminate (Pingora HTTPS), or TlsTerminate (decrypt + TCP proxy). |
| Wildcard hostname matching | Supported | Both listener hostname and route hostname wildcards. |
| Per-listener scoped routing | Supported | Most-specific listener match first, then route lookup within that listener's scope. |
| Certificate from Secret | Supported | TLS certs loaded from Kubernetes Secrets, updated on reconciliation. |

### TCP Features

| Feature | Status | Notes |
|---------|--------|-------|
| TCPRoute | Supported | Raw bidirectional byte copying; weighted backendRefs; oldest route wins per listener. |
| TCP proxy (L4) | Supported | Runs as separate async task alongside Pingora HTTP proxy. |

### UDP Features

| Feature | Status | Notes |
|---------|--------|-------|
| Listener protocol UDP | Supported | One socket per UDP listener port on the per-Gateway Service (`protocol: UDP`). |
| UDPRoute | Supported | GATEWAY-UDP profile. Per-client sessions (source address) to weighted backendRefs, replies returned from the Gateway address, idle timeout `UDP_IDLE_TIMEOUT_SECS` (60 s). |

### Mesh Features

| Feature | Status | Notes |
|---------|--------|-------|
| Service mesh (GAMMA) | Not supported | Portus is a north-south gateway, not a service mesh. No sidecar injection, no mesh routing. |

---

## 2. Policy Support Matrix

Policies are CRDs that attach to Gateways, routes and Services with a `targetRef`; the controller compiles them into the route config and the data plane enforces them on the request path. Field reference and examples: [`policies.md`](policies.md); the AI gateway policies: [`ai-gateway.md`](ai-gateway.md).

### Implemented

| Policy | Targets | Notes |
|--------|---------|-------|
| TimeoutPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Request, backend-request and connect deadlines |
| RetryPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Connection-time replay (`connect-failure`); response-code retries via the rule's `retry.codes` |
| RateLimitPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Token bucket, per route or per client IP; limiters survive reloads |
| CircuitBreakerPolicy | HTTPRoute, GRPCRoute, Service | Closed/Open/HalfOpen on consecutive 5xx |
| ConnectionPolicy | Service, HTTPRoute | Max in-flight requests |
| HealthCheckPolicy | Service | Active `GET` probes with thresholds |
| CORSPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Preflight and response headers |
| IPAllowlistPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Allow/deny CIDRs, trusted proxies for `X-Forwarded-For` |
| RequestBodySizeLimitPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | 413 on `Content-Length` and on streamed bodies |
| BasicAuthPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | bcrypt hashes in a Secret, cost ≥ 10 |
| ApiKeyAuthPolicy | HTTPRoute, GRPCRoute, AIRoute, Gateway | Header against Secret values |
| AIUsagePolicy | AIRoute | Token or call budgets per key, tenant or route (0.2.4) |
| BackendTLSPolicy | Service | Gateway API v1: CA bundle, hostname and SAN validation; client certificate from `Gateway.spec.tls.backend` |

### Planned

| Policy | Notes |
|--------|-------|
| JWTAuthPolicy | Local verification against a JWKS the ledger refreshes (in design for 0.2.5 alongside OAuth for MCP clients) |
| LoadBalancerPolicy | Round-robin is the default; keyed selection exists for MCP session affinity and will be exposed as a policy |
| ExtAuthPolicy | External authorization callout |

### Not Planned

| Policy | Notes |
|--------|-------|
| Fault injection | Use a service mesh for chaos testing |
| Request body transformation | An API-gateway pattern outside a Gateway API implementation's role |

---

## 3. Dataplane Capabilities

These are proxy-level features in the Pingora-based dataplane, independent of Gateway API spec compliance.

### Protocol Support

| Capability | Status | Notes |
|------------|--------|-------|
| HTTP/1.1 proxying | Supported | Default upstream protocol. |
| HTTP/2 cleartext (h2c) | Supported | Via `appProtocol: kubernetes.io/h2c` on the backend Service. |
| gRPC proxying | Supported | Forces HTTP/2 with appropriate stream concurrency and keepalive. |
| WebSocket | Supported | Native Pingora handling via `appProtocol: kubernetes.io/ws`. |
| TLS termination | Supported | Certificates from Kubernetes Secrets, loaded via SNI multiplexer. |
| TLS passthrough (SNI routing) | Supported | SNI extracted from ClientHello via rustls Acceptor. |
| mTLS to backends | Supported | `Gateway.spec.tls.backend.clientCertificateRef` (TLS Secret) is presented on every TLS connection the Gateway's routes make (`CompiledConfig.gateway_backend_tls` → `HttpPeer.client_cert_key`, part of the connection-reuse hash). |

### Traffic Management

| Capability | Status | Notes |
|------------|--------|-------|
| Weighted traffic splitting | Supported | Weighted round-robin across multiple backendRefs. |
| Request mirroring | Supported | Single, multiple, and percentage-based. Fire-and-forget async. |
| URL rewrite (path + hostname) | Supported | ReplaceFullPath, ReplacePrefixMatch, and hostname rewrite. |
| Request/response header modification | Supported | Add, set, remove operations on both request and response headers. |
| HTTP redirects | Supported | Full control over scheme, host, port, path, status code (301/302/303/307/308). |
| Request timeout | Supported | Per-rule request lifecycle timeout. |
| Backend request timeout | Supported | Per-rule backend connection timeout. |
| Max retries | Supported | `RetryPolicy` (connection-time) and the HTTPRoute rule's `retry` (response codes). |

### Resilience and Security

| Capability | Status | Notes |
|------------|--------|-------|
| Rate limiting (token bucket) | Supported | Per-route, configurable RPS. Limiters preserved across config reloads. |
| Circuit breaker | Supported | Three-state (Closed/Open/HalfOpen). Configurable thresholds and timeout. |
| Connection limiting | Supported | Per-service max concurrent connections. |
| CORS | Supported | Preflight and simple requests. Configurable origins, methods, headers, credentials, max-age. |
| Basic auth | Supported | Bcrypt credential validation, configurable realm. |
| API key auth | Supported | Header-based key validation, O(1) lookup. |
| JWT auth | Planned | Token validation, JWKS fetching, claim extraction. |
| External auth (ExtAuth) | Planned | Callout to external authorization service. |
| IP allowlist/denylist | Supported | `IPAllowlistPolicy`: allow and deny CIDRs, trusted proxy CIDRs for `X-Forwarded-For`. |
| Request body size limit | Supported | `RequestBodySizeLimitPolicy`: `Content-Length` and streamed bodies. |

### Infrastructure

| Capability | Status | Notes |
|------------|--------|-------|
| Zero-downtime config reload | Supported | `ArcSwap` for lock-free atomic config swap. In-flight requests always see a consistent snapshot. |
| Connection pooling (upstream keepalive) | Supported | 1024-connection upstream pool. |
| Load balancing (round-robin) | Supported | Default. |
| Load balancing (keyed / consistent) | Supported for MCP | Rendezvous hashing on `Mcp-Session-Id` for `AIProvider kind: mcp`; a general LoadBalancerPolicy is planned. |
| Prometheus metrics | Supported | Exposed on configurable metrics port (default 9090). |
| Health/readiness probes | Supported | Dedicated health port (default 8081). |
| PodDisruptionBudget | Supported | Helm chart creates PDB with configurable minAvailable. |

---

## 4. Performance

See the benchmarks in `benchmarks/` and the Performance section of the README: on one 10-CPU k3d node,
119k QPS peak and p99 0.62 ms at 30k QPS against agentgateway's 76k / 1.90 ms, controller under route
churn 50–64 m CPU, single-endpoint outage 0.03 % errors with no policy. Numbers are only comparable with
runs on the same machine.

