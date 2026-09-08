# Portus Architecture

Portus is a Kubernetes Gateway API implementation built on Cloudflare's Pingora proxy framework. It ships as two binaries — a controller that watches Gateway API CRDs and compiles them into a protobuf config, and a dataplane that receives that config over gRPC and routes live traffic.

## System Overview

```
                         Kubernetes API Server
                                 |
                    watches (kube-rs controllers)
                                 |
                                 v
  +----------------------------------------------------------+
  |                     portus-controller                      |
  |                                                          |
  |  +-------------------+    +---------------------------+  |
  |  | Main Tokio Runtime|    | Compilation Thread        |  |
  |  |                   |    | (dedicated OS thread,     |  |
  |  | GatewayClass  ----+--->| single-thread tokio RT)   |  |
  |  | Gateway       ----|    |                           |  |
  |  | HTTPRoute     ----|    | change_notify.notified()  |  |
  |  | GRPCRoute     ----|    | 100ms debounce            |  |
  |  | TLSRoute      ----|    | compile_config()          |  |
  |  | TCPRoute      ----|    | fingerprint check         |  |
  |  | EndpointSlice ----|    | watch::Sender::send()     |  |
  |  | Service       ----|    +---------------------------+  |
  |  | Secret        ----|                                   |
  |  | ReferenceGrant---|    +---------------------------+   |
  |  | Policy CRDs  ----|    | gRPC Server Thread        |   |
  |  +-------------------+    | (dedicated OS thread,    |   |
  |           |               |  multi-thread(2) tokio)  |   |
  |           v               |                          |   |
  |    +-------------+        | WatchStream -> proto     |   |
  |    | ConfigStore |------->| StreamConfig RPC         |   |
  |    | (DashMap)   |        +---------------------------+   |
  +----------------------------------------------------------+
                                 |
                          gRPC stream (proto)
                                 |
                                 v
  +----------------------------------------------------------+
  |                      portus-dataplane                      |
  |                                                          |
  |  +----------------------------+                          |
  |  | Config Receiver Thread     |                          |
  |  | (dedicated OS thread,      |                          |
  |  |  single-thread tokio RT)   |                          |
  |  |                            |                          |
  |  | connect_and_stream()       |                          |
  |  | build_route_map_from_proto |                          |
  |  | build_lb_map_from_proto    |                          |
  |  | ArcSwap::store()  ---------+---> RouteMap             |
  |  +----------------------------+     ServiceLbMap         |
  |                                     L4Config             |
  |                                     TlsCertSlot          |
  |                                         |                |
  |          +------------------------------+--------+       |
  |          |              |               |        |       |
  |          v              v               v        v       |
  |    +-----------+  +-----------+  +----------+ +------+   |
  |    | Pingora   |  | Pingora   |  | SNI Mux  | | L4   |   |
  |    | HTTP :80  |  | HTTPS     |<-| :443 TCP | | Proxy|   |
  |    | (h2c)     |  | (hand-off)|  | (peek)   | | :NNN |   |
  |    +-----------+  +-----------+  +----------+ +------+   |
  +----------------------------------------------------------+
```

The system has three distinct runtime boundaries in each binary, all isolated by OS threads with their own single-threaded tokio runtimes. This isolation is deliberate — it guarantees that reconciler storms can't starve the compilation loop, and that neither can starve the gRPC server.

## Data Pipeline

Here's what happens from the moment a user `kubectl apply`s an HTTPRoute to the moment that route handles its first request.

### 1. Reconciler writes to ConfigStore

The kube-rs controller framework detects the new HTTPRoute and calls `reconcile_http_route`. The reconciler validates the resource — checks that parentRefs point to an existing Gateway with an accepted GatewayClass, that backendRefs resolve to valid Services (with ReferenceGrant checks for cross-namespace refs), and so on. It then writes an `HTTPRouteState` into `store.http_routes` (a `DashMap<NamespacedName, HTTPRouteState>`); if that differs from what the store held, the compiler is woken (`notify_change`) and an `Event::Route` is published naming the route's parents and backend Services. A route none of whose parents is a Gateway or ListenerSet we manage is not stored at all: it is another implementation's (or not yet created), and the parent's own event re-runs the route when it appears.

The reconciler also updates the HTTPRoute's status conditions via the Kubernetes API (Accepted, ResolvedRefs) using server-side apply with the `portus-gateway` field manager.

### 2. Compilation loop wakes

The compilation loop (`compiler::compilation_loop`) runs on its own OS thread. It blocks on `store.change_notify.notified()`; `Notify::notify_one` stores a permit when nobody is waiting, so a notification sent between two iterations is never lost and there is no timer. When woken, it sleeps `COMPILE_DEBOUNCE` (100 ms) — writes landing in that window coalesce into a single compilation — and compiles only if the store is still marked dirty.

### 3. compile_config reads ConfigStore

`compile_config()` iterates every DashMap in the ConfigStore and produces a `CompiledConfig` protobuf message. For routes, this involves:

- Resolving effective hostnames by intersecting route hostnames with listener hostnames (the `compute_effective_hostnames` function). A route with hostnames `[foo.example.com]` bound to a listener with hostname `*.example.com` produces an effective hostname of `foo.example.com`. A route with no hostnames on a listener with no hostname produces `*`.
- Resolving listener ports from parentRef sectionName/port fields.
- Compiling each rule's matches (path, headers, method, query params), filters (redirect, rewrite, header modification, mirrors), and backend references into `RouteConfig` proto messages.
- Re-checking ReferenceGrants at compile time for cross-namespace backends, not just at reconcile time. This ensures that a deleted grant takes effect on the next compilation cycle.
- Resolving backend endpoints through the service port map (service port -> target port translation populated by the Service reconciler), then looking up actual pod IPs from the EndpointSlice reconciler's data.
- Inlining policy configurations (rate limits, circuit breakers, auth) from policy CRDs into the routes they target.

### 4. Fingerprint-based change detection

After compilation, `config_fingerprint()` computes a `u64` hash of the entire config. It proto-encodes each element (route, backend, listener, etc.) and hashes the bytes, then combines them using `wrapping_add`. The wrapping-add is the key property: it's commutative, so DashMap iteration order doesn't affect the result. Two configs with the same set of routes/backends/listeners in any order produce the same fingerprint.

If the fingerprint matches the previous compilation's fingerprint, the config is silently dropped — no version bump, no broadcast. This matters because reconcilers fire frequently (endpoint churn, status updates) and many of those firings produce identical compiled output.

The previous approach cloned the entire config, sorted all fields, and compared. Fingerprinting replaced that with zero clones and O(n) hashing during the compilation pass.

### 5. Watch channel broadcast

When the fingerprint differs, the compilation loop increments a generation counter (`store.compiled_version`, informational: it restarts with the controller), publishes the fingerprint itself in `store.compiled_fingerprint`, sets both `config.version` and `config.fingerprint`, and sends the config through a `tokio::sync::watch::Sender<CompiledConfig>`. The fingerprint is the config's identity everywhere else: identical content produced by any controller instance has the same fingerprint.

We chose `watch` over `broadcast` for a specific reason: `watch` always delivers the latest value. If the dataplane falls behind by multiple config versions (say it was slow applying a previous config), it skips straight to the current one. `broadcast` would queue every intermediate version, wasting bandwidth and causing lag. The tradeoff is that `watch` can only hold one value — there's no history — but that's exactly what we want for config distribution. The dataplane only ever needs the latest config.

### 6. gRPC streaming to the dataplane

The gRPC server (`ConfigServer`) runs on its own dedicated OS thread. When a dataplane connects via `StreamConfig`, the server subscribes to the watch channel and wraps it in a `WatchStream`, which yields the current value immediately (so the dataplane always gets a config on connect) and then yields on each subsequent change.

The dataplane's config receiver (`config_stream_loop`) runs in its own OS thread too, with a reconnecting loop. On connect, it sends a `ConfigRequest` with its node ID, bound ports, schema version, and the fingerprint of the config it is currently running. For every message it decides with `apply_decision`: a fingerprint different from what it runs is applied; the same fingerprint is a heartbeat (redundant push, or a restarted controller recompiling identical content); only a controller that predates fingerprints falls back to the old generation-order rule. After `apply_config` the dataplane calls the `ReportApplied` RPC with the fingerprint it applied. The controller records bound ports (used by the Gateway reconciler for listener programming) and per-node applied fingerprints; `ConfigStore::is_programmed()` is true when at least one dataplane runs the currently compiled fingerprint, which drives the `Programmed` condition on Gateways and policies. A change in programmed state wakes `programmed_notify`, which feeds the Gateway controller's `reconcile_all_on` trigger stream, so no user object is written to requeue.

### 7. Route map building and ArcSwap

When the dataplane receives a new `CompiledConfig`, `apply_config()` builds new internal data structures from the proto:

- `build_route_map_from_proto` groups routes by host (or `host:port` for port-specific routes), builds `HostRoutes` with sorted `PathRoute` vectors (exact matches first, then prefix longest-first), and preserves existing rate limiter instances when the service/path/rps matches (so token bucket state isn't reset on config reload).
- `build_lb_map_from_proto` creates per-(service, port) `LoadBalancer<RoundRobin>` instances from backend endpoints.
- `build_l4_config_from_proto` constructs the `L4Config` with TLS listener routing tables and TCP/UDP proxy mappings (UDPRoute datagrams are served by `udp_proxy.rs`: one socket per UDP listener port, per-client sessions to weighted backends).

All of this happens in the config receiver thread. Once the new maps are built, they're swapped into the shared `ArcSwap` slots in a single batch:

```rust
state.routes.store(Arc::new(new_routes));
state.wildcard_routes.store(Arc::new(wildcard));
state.domain_wildcards.store(Arc::new(new_domain_wildcards));
state.lbs.store(Arc::new(new_lbs));
state.circuit_breakers.store(Arc::new(new_cbs));
state.connection_limiters.store(Arc::new(new_cls));
state.l4_config.store(Arc::new(new_l4));
```

Pingora worker threads calling `routes.load()` get a snapshot — either entirely the old config or entirely the new one. There's no lock, no mutex, no blocking. Readers on the old config drain naturally as the `Arc` refcount drops to zero.

### 8. Request routing

A request arrives at Pingora on the original client socket (the listener manager hands it over in-process, so the local port is the real listener port). The `Router::request_filter` implementation extracts the Host header and the socket's local port, and looks up the route:

1. Try `host:port` key in the route map (for port-specific listeners)
2. Fall back to plain `host`
3. Try domain wildcard map (e.g., `foo.example.com` -> `*.example.com`)
4. Fall back to global wildcard `*`

Once a `HostRoutes` is found, `match_request` does multi-dimensional matching: path (exact > prefix longest-first > regex), then method, headers, and query parameters — all with AND logic per the Gateway API spec. The first matching `PathRoute` wins.

## Controller Architecture

### Three Isolated Runtimes

The controller runs three OS threads, each with its own single-threaded tokio runtime:

**Main runtime** (`#[tokio::main]`): Runs all kube-rs controllers (one per CRD type) as spawned tasks. Each controller watches its CRD via the Kubernetes API and runs a reconcile function that validates the resource and writes state to the ConfigStore. The controllers also set up cross-resource watches — for example, the HTTPRoute controller watches Gateway and ReferenceGrant resources so that routes are re-reconciled when their parent Gateway is created or a grant is revoked.

**Compilation thread** (`std::thread::spawn` with `tokio::runtime::Builder::new_current_thread`): Runs the compilation loop exclusively. The isolation guarantees that even if the main runtime is saturated with reconciler tasks (common during initial cluster sync or mass resource updates), compilation still runs promptly. The 100ms debounce is deliberately short — we'd rather compile a few extra times than delay config propagation.

**gRPC server thread** (`std::thread::spawn` with `tokio::runtime::Builder::new_multi_thread` and 2 worker threads): Runs the tonic gRPC server. Isolated so that a slow dataplane or network issue can't block reconcilers or compilation.

### ConfigStore and DashMap

The `ConfigStore` (`crates/portus-controller/src/store.rs`) is the central shared state between reconcilers and the compiler. Every resource type gets its own `DashMap` — `gateway_classes`, `gateways`, `http_routes`, `grpc_routes`, `tls_routes`, `tcp_routes`, `reference_grants`, `endpoints`, `secrets`, and several policy types.

DashMap was chosen over `RwLock<HashMap>` because reconcilers run concurrently (they're independent tokio tasks on the main runtime) and frequently write to different maps simultaneously. DashMap uses sharded internal locks, so a write to `http_routes` doesn't block a write to `endpoints`. The compiler reads all maps during `compile_config()` — it iterates each DashMap, which acquires per-shard read locks that are released immediately per iteration step.

There's also auxiliary state: `service_port_map` (maps service ports to target ports, populated by the Service reconciler), `service_app_protocols` (appProtocol annotations for H2C/WebSocket detection), `bound_ports` (ports the dataplane has pre-bound, reported over gRPC), and `compiled_version` / `data_plane_versions` (for the Programmed status condition flow).

### Change Signaling

Two signals leave the store, both only when something actually changed (`insert_and_notify` compares before writing; every publisher compares first):

- `notify_change()` wakes the compilation loop (`change_notify: Notify`, one waiter, `notify_one`).
- `publish(Event)` puts a dependency event on a `tokio::sync::broadcast` bus (`store.events`). Every controller whose objects derive status from someone else's state subscribes through `triggers::on_events`, mapping each event to the objects to re-reconcile from its own reflector: routes follow their parents (`Event::Gateway`, `Event::ListenerSet`), backend Services, ReferenceGrants in namespaces they reach into and their Namespace's labels; Gateways follow their class, attached routes and ListenerSets, data plane acks (`Event::Programmed(gateway)`), and grants/labels their TLS refs and selectors depend on; ListenerSets follow their parent, siblings and routes; policies follow acks and same-kind siblings on the same target (`Event::Policy`). A subscriber that lagged behind the bus re-reconciles everything it owns.

Because the event is published after the store write, the dependent reconcile always sees the new state, which is what the old `watches` on other Kubernetes kinds could not guarantee (the watched object's reconciler runs on its own schedule). And because unchanged reconciles publish nothing, two controllers cannot re-trigger each other indefinitely. Together these replace every timed requeue: reconcilers return `Action::await_change()`, with one exception, a Gateway whose dataplane Service is not yet reachable re-probes every second (`ADDRESS_PROBE_INTERVAL`) because kube-proxy programming a ClusterIP produces no event.

Deletions come from the watch itself: `registry::controller` builds every controller from a `touched_objects` reflector stream (`Controller::for_stream`), so a delete triggers a reconcile request that the runtime reports as `ObjectNotFound` and the kind's `Gone` hook evicts the object and publishes its event. (`Controller::new` only reconciles applied objects; with timed requeues gone, a deleted route would otherwise have stayed compiled until the prune task ran.)

`watches` on other kinds remain only where the dependency is a Kubernetes object we do not reconcile in dependency order (ConfigMap, Secret, the dataplane's own EndpointSlice), and they go through `registry::cache_then`, which writes the cache before naming the dependents.

### Store Pruning

There's a subtle problem with kube-rs: when an object is deleted and no requeue was pending for it, the controller may never learn it's gone. Deletions normally arrive through the `touched_objects` watch (see Change Signaling); as a safety net a pruning task runs every 120 seconds on the main runtime, compares every ConfigStore map against the controllers' own reflector caches (no API LISTs) and removes entries that no longer exist. If it prunes anything, it calls `notify_change()` to trigger recompilation.

The pruning covers HTTPRoutes, Gateways, ReferenceGrants, GRPCRoutes, TLSRoutes, TCPRoutes and UDPRoutes. ObjectNotFound errors from reconciler callbacks also trigger cleanup.

## Dataplane Architecture

### Startup Sequence

The dataplane `main()` starts by spawning the config receiver thread, then blocks the main thread waiting for the first config with a 60-second deadline. This ensures Pingora doesn't start accepting connections until routes are loaded. If the controller is unreachable for 60 seconds, the process exits (the pod restarts via Kubernetes).

Once the first config arrives:

1. The listener manager (`l4_proxy::run_l4_proxy`) spawns on its own OS thread. It binds every listener port in the compiled config (HTTP, HTTPS, TLS, TCP as TCP sockets; UDP as UDP sockets) and follows config changes: a new listener port is bound within a second, a removed one released.
2. Pingora's HTTP and HTTPS services have no sockets of their own: they accept connections the listener manager hands over in-process (`HandoffSource` channels in the patched pingora-core) on the original client socket. HTTP ports go straight to the HTTP service (h2c enabled for gRPC); HTTPS/TLS ports go through the SNI decision first.
3. UDP ports are served by `udp_proxy.rs` (per-client sessions to UDPRoute backends).
4. Health check endpoint binds `0.0.0.0:8081`
5. Prometheus metrics endpoint binds `0.0.0.0:9090`

The dataplane uses mimalloc as the global allocator for better multi-threaded allocation performance.

### Pingora Worker Threads

Pingora spawns `available_parallelism()` worker threads with work stealing enabled and a 1024-connection upstream keepalive pool. Each worker runs the `ProxyHttp` trait implementation on the `Router` struct.

### ProxyHttp Request Flow

The request lifecycle through Pingora follows this path:

**`request_filter`** — Route matching and early returns. This is where the route lookup, redirect handling, CORS preflight, rate limiting, circuit breaker checks, and authentication all happen. For redirect routes, a 3xx response is sent directly and the function returns `Ok(true)` to short-circuit proxying. For normal routes, the matched `PathRoute`'s settings (timeouts, headers, TLS config, backend info) are cached into the per-request `RouterCtx`.

**`upstream_peer`** — Backend selection. Loads the `ServiceLbMap` from ArcSwap, builds the LB key from the service name and port stored in `RouterCtx`, selects a backend via round-robin, and constructs an `HttpPeer`. For weighted backends, `select_weighted_backend` uses a global atomic counter with modular arithmetic for deterministic proportional distribution. If the backend requires TLS (upstream_tls), the peer is configured with SNI and cert verification settings.

**`upstream_request_filter`** — Header mutation. Applies request header add/set/remove operations from the route's `HeaderMutation` config. Also applies URL rewrites (path and hostname) and sets the `:authority` header for H2C/gRPC backends.

**`response_filter`** — Response header mutation and CORS. Applies response header add/set/remove, then adds CORS response headers (Access-Control-Allow-Origin, etc.) if the request matched a CORS-configured route.

**`fail_to_proxy`** — Error handling. Maps Pingora errors to HTTP status codes per Gateway API semantics. When timeouts are configured, `ReadTimedout` and `ConnectTimedout` become 504 Gateway Timeout. Connection limiter permits are released here.

### ArcSwap for Zero-Lock Config Reads

Every shared config structure in the dataplane is wrapped in `Arc<ArcSwap<T>>`:

```rust
type RouteMap = Arc<ArcSwap<HashMap<String, HostRoutes>>>;
type ServiceLbMap = Arc<ArcSwap<HashMap<(Arc<str>, u16), Arc<LoadBalancer<RoundRobin>>>>>;
type DomainWildcardMap = Arc<ArcSwap<HashMap<String, HostRoutes>>>;
type WildcardRouteSlot = Arc<ArcSwap<Option<HostRoutes>>>;
type CircuitBreakerMap = Arc<ArcSwap<HashMap<(Arc<str>, u16), Arc<CircuitBreaker>>>>;
type L4ConfigSlot = Arc<ArcSwap<L4Config>>;
type TlsCertSlot = Arc<ArcSwap<Option<TlsCertData>>>;
```

`ArcSwap::load()` returns a guard that holds an `Arc` pointing to the current value. This is wait-free on the read path (no CAS loop, no spinlock). The writer calls `store(Arc::new(new_value))`, which atomically swaps the pointer. Old values are deallocated when all readers drop their guards.

We considered `RwLock` and rejected it because Pingora worker threads would contend on the read lock during high-throughput traffic. With ArcSwap, every `request_filter` call loads a snapshot independently — there's zero contention between workers.

### Mirror Requests

Mirror backends are fire-and-forget. The router spawns a tokio task per mirror that sends a minimal HTTP/1.1 request to the mirror backend. Concurrency is bounded by a semaphore (128 permits); if the semaphore is full, the mirror is silently skipped. This is per the Gateway API spec — mirrors are best-effort and must not affect latency on the primary request path.

## TLS Architecture

### HTTPS/TLS ports: The SNI Multiplexer

An HTTPS or TLS listener port is shared between three modes of traffic, and the SNI decision (`l4_proxy::handle_l4_connection`, `sni_mux_decision_for_port`) sorts them out per port. The listener manager accepts the raw TCP connection and peeks the ClientHello to extract the SNI extension without consuming bytes from the socket. `:443` below stands for any such port.

```
  Client
    |
    |  TLS ClientHello (SNI: foo.example.com)
    v
+-------------------------------------------+
|           SNI Multiplexer (:443)          |
|                                           |
|   peek 4KB -> extract SNI via rustls      |
|   sni_mux_decision():                     |
|                                           |
|   1. Find best matching TLS listener      |
|      (exact > *.subdomain > *.tld > any)  |
|   2. Look up route within that listener   |
|                                           |
|   Decision:                               |
|   +-- Passthrough: copy_bidirectional     |
|   |   to backend (TLS untouched)          |
|   |                                       |
|   +-- TlsTerminate: accept TLS handshake, |
|   |   then copy_bidirectional plaintext   |
|   |   to backend (TLSRoute Terminate)     |
|   |                                       |
|   +-- Terminate: hand the socket to       |
|   |   Pingora HTTPS (in-process channel)  |
|   |                                       |
|   +-- Reject: drop connection             |
|       (SNI matches listener but no route) |
+-------------------------------------------+
```

The decision logic in `sni_mux_decision()`:

1. If no SNI is present, hand the connection to Pingora's HTTPS service (Terminate).
2. Find the most specific TLS listener whose hostname matches the SNI. Specificity scoring: exact hostname = 1000, wildcard = (number of dots + 2), empty (match-all) = 1.
3. If a listener matches, look up a route within that listener's scope (exact hostname first, then wildcard).
4. If route found on a Passthrough listener: proxy bidirectionally to the backend. The TLS is never decrypted.
5. If route found on a Terminate listener: perform TLS termination using the listener's certificate (from the Gateway's Secret reference), then proxy plaintext to the backend. This is for TLSRoute with mode=Terminate.
6. If a listener matches but no route exists: reject (drop the connection). This prevents TLS passthrough listeners from leaking traffic to the HTTPS handler.
7. If no listener matches at all: hand the connection to Pingora's HTTPS service. This handles HTTPS traffic for HTTPRoutes and GRPCRoutes.

### HTTPS hand-off (no loopback hop)

The SNI mux owns the `:443` socket. When a connection is to be terminated as HTTPS, the mux converts the accepted `tokio::net::TcpStream` to a `std::net::TcpStream` and sends it over an in-process channel; Pingora's HTTPS service is registered with `add_tls_handoff(...)` (a `ServerAddress::Handoff` endpoint added to the patched pingora-core) and accepts from that channel on its own runtime. The peeked ClientHello is still in the kernel buffer, so the TLS handshake proceeds normally, and the socket digest carries the real client address and the real local port (443). Consequences: no second TCP connection or extra copy per HTTPS byte, per-IP rate limiting / IP allowlists / `X-Forwarded-For` see the client rather than `127.0.0.1`, and the router needs no internal-port remapping (`listener_scheme_and_port()` only picks the scheme). Before 2026-09-05 the mux proxied to `127.0.0.1:18443`, which made every HTTPS client look like loopback.

### TLS Certificate Hot-Reload

HTTPS certificates come from Kubernetes Secrets referenced by Gateway listeners. The controller resolves Secret data at compile time and inlines the PEM-encoded cert/key into the `CompiledConfig` proto. On the dataplane side:

1. At startup, the dataplane waits up to 5 seconds for a cert from the controller. If none arrives, it generates a self-signed bootstrap cert.
2. A `ReloadableCertResolver` backed by ArcSwap serves as the rustls `ResolvesServerCert` implementation. Every TLS handshake calls `resolve()`, which loads the current cert atomically.
3. A background thread polls the `TlsCertSlot` and calls `resolver.swap()` when new certs arrive from the controller.

The result is zero-downtime certificate rotation with no restarts and no disk I/O on the hot path.

### mTLS

**Frontend (client certificates).** `Gateway.spec.tls.frontend` gives every HTTPS listener a client-validation policy: `default.validation` unless a `perPort[]` entry matches the listener port. The Gateway reconciler resolves each `caCertificateRefs` entry (core ConfigMap, key `ca.crt`, same namespace or granted by a ReferenceGrant) into `store.gateway_tls`; the compiler inlines the PEM bundles as `Listener.client_validation` (`ca_cert_pems`, `mode`). On the dataplane `client_validation_from_listeners` collapses that to one policy per port and the cert hot-reload thread builds one rustls `ServerConfig` per port (`tls::build_port_configs`: shared `ReloadableCertResolver`, plus a `WebPkiClientVerifier`, wrapped in `InsecureFallbackVerifier` for `AllowInsecureFallback`, or a fail-closed verifier when the bundle is unusable). Every HTTPS port shares Pingora's one hand-off endpoint, so the choice is made per connection: the patched `TlsSettings::from_config_chooser` reads the ClientHello with tokio-rustls's `LazyConfigAcceptor` and asks `PortServerConfigs` for the config matching the socket's local port, falling back to the default (no client auth) config. Status: unresolvable CA → listener `ResolvedRefs=False` (`InvalidCACertificateRef`, `InvalidCACertificateKind`, `RefNotPermitted`); no usable CA at all → `Accepted=False/NoValidCACertificate`, and the listener is not compiled (its port is not bound). Any insecure-fallback block → Gateway `InsecureFrontendValidationMode=True`.

**Backend (client certificate).** `spec.tls.backend.clientCertificateRef` names a TLS Secret; the compiler emits one `CompiledConfig.gateway_backend_tls` entry per Gateway (scoped per Gateway by `scope_config`, part of the fingerprint). The dataplane parses it once into Pingora's `CertKey` and indexes it by the `(service, port)` backends of that Gateway's routes (`build_backend_client_certs_from_proto`); `request_filter` caches it in `RouterCtx` and `upstream_peer` sets `HttpPeer.client_cert_key` on TLS peers, where the patched rustls connector presents it. The Gateway reports `ResolvedRefs` for the reference (`InvalidClientCertificateRef` / `RefNotPermitted`).

## Config Change Detection

The fingerprinting approach (`config_fingerprint` in `compiler.rs`) deserves its own section because it solves a real problem with DashMap-based stores.

DashMap doesn't guarantee iteration order. If you iterate `store.http_routes` twice, you might get the entries in a different order. The previous change detection approach cloned the entire `CompiledConfig`, sorted all fields, and compared with the previous clone. This worked but was expensive — it allocated a full copy of every route, backend, and listener on every compilation cycle.

The fingerprint replaces this with a `u64` computed during compilation:

```rust
fn config_fingerprint(config: &CompiledConfig) -> u64 {
    let mut fp: u64 = 0;
    for r in &config.routes { fp = fp.wrapping_add(hash_msg(r)); }
    for b in &config.backends { fp = fp.wrapping_add(hash_msg(b)); }
    for l in &config.listeners { fp = fp.wrapping_add(hash_msg(l)); }
    // ... same for tls_passthrough_routes, tcp_proxy_routes, etc.
    fp
}
```

Each element is proto-encoded to bytes and hashed with `DefaultHasher`. The per-element hashes are combined with `wrapping_add`, which is commutative — `a + b + c == c + a + b` regardless of iteration order. Zero allocations beyond the per-element encode buffer (which is stack-allocated for small messages).

The tradeoff is that wrapping-add has a theoretical collision risk: two different configs could produce the same fingerprint. In practice, with 64-bit hashes and proto-encoded messages, the probability is negligible; the next real change produces a new fingerprint and is pushed.

## Performance Characteristics

Measured with the howardjohn/gateway-api-bench method on one 10-CPU k3d node, back to back with agentgateway
v1.5.0 (see `benchmarks/`): peak 119k QPS at 256 connections (agentgateway 76k), p99 0.62 ms at a fixed
30k QPS (1.90 ms), 3.2 cores for the three dataplane pods at 30k QPS (3.8). Control plane: 200 routes
propagate at ~0.4 ms each with the controller at 64 m CPU; 500 pods and routes churning for ten minutes
hold it at 50 m mean. A single blackholed endpoint out of four costs 0.03 % of requests with no policy
(passive outlier ejection) and none with a Gateway `RetryPolicy`. Absolute numbers depend on the machine;
the method reproduces with `make bench-*`.

## Key Design Decisions

### Watch over Broadcast for Config Distribution

`tokio::sync::watch` holds exactly one value — the latest. When the sender writes a new config, any receiver that hasn't read the previous one skips directly to the new value. `tokio::sync::broadcast` would queue every intermediate config, and a slow receiver could either lag (wasting bandwidth replaying outdated configs) or overflow (losing messages and requiring reconnection logic).

For config distribution, the latest-wins semantic of watch is correct by definition. There's no value in a dataplane applying config v5 if v6 is already available. The `WatchStream` adapter makes this work with tonic's streaming response type.

### Dedicated OS Threads (not tokio::spawn)

Each isolated component (compilation loop, gRPC server, config receiver, SNI mux, L4 proxy) gets its own `std::thread::spawn` with a `new_current_thread` tokio runtime. We could have used `tokio::spawn` on a shared multi-threaded runtime, but:

- **No starvation**: During initial cluster sync, the main runtime may have hundreds of reconciler tasks queued. A compilation loop running as just another task on that runtime could be delayed by seconds. On its own thread, it runs immediately.
- **Panic isolation**: `catch_unwind` in the compilation loop catches panics without affecting reconcilers. On a shared runtime, a panic in one task can poison the runtime.
- **Predictable scheduling**: The compilation thread does one thing — wake, debounce, compile, fingerprint, maybe send. No competing work.

The cost is a few extra OS threads, which is negligible.

### ArcSwap over RwLock

Covered above, but the core reason: RwLock introduces contention on the read path. Even "uncontended" RwLock has a CAS loop that cache-bounces across cores. With Pingora handling tens of thousands of requests per second across multiple worker threads, each doing a route lookup, even brief contention adds up. ArcSwap's `load()` is a single atomic load — it reads the pointer, increments a refcount, done. The writer path (`store()`) is slightly more expensive, but config updates happen at most a few times per second.

### DashMap over RwLock<HashMap>

Same principle as ArcSwap but for the controller side. Reconcilers for different resource types run concurrently. With `RwLock<HashMap>`, a write to any resource type would block reads to all resource types (since they'd share one lock). DashMap provides per-shard locking, so concurrent writes to different resource types (the common case) don't contend at all.

### Prost (proto) over Serde for Config Wire Format

The config wire format between controller and dataplane is protobuf, compiled with prost. We could have used JSON (serde_json) or bincode, but:

- **Schema evolution**: Protobuf handles field additions gracefully — old dataplanes ignore unknown fields, new dataplanes use defaults for missing fields. The `schema_version` field enables hard breaks when needed.
- **Size**: TLS certificates are inlined in the config. A config with multiple HTTPS listeners can be several MB. Protobuf's binary encoding is significantly smaller than JSON for this data.
- **Streaming**: tonic natively supports protobuf streaming. Using a different format would mean either reimplementing streaming or adding a serialization layer on top of tonic.
- **Type safety**: Prost generates Rust structs with correct types from the `.proto` file. Changes to the wire format are caught at compile time in both controller and dataplane.
