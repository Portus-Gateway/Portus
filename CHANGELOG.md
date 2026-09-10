# Changelog

All notable changes to Portus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.2] - Unreleased

### Changed

- **Pingora 0.9.0.** `pingora-core`, `pingora-proxy`, `pingora-http` and `pingora-load-balancing` move from 0.8.1 to 0.9.0 (reworked connection pooling with a sharded pool and a real global LRU, HTTP/1.1 downstream pipelining, configurable HTTP/2 windows, per-listener socket buffers, hop-by-hop header sanitisation on upstream requests, stricter request-target validation). The vendored `pingora-core` patch was rebased: upstream now honours per-peer CA bundles in the rustls connector and offers `Acceptor::from_server_config`, so those parts of the patch are gone; what remains is the hand-off listener, the per-connection `ServerConfig` chooser for frontend mTLS, the SNI in `SslDigest`, SAN-constrained upstream verification and the stricter HTTP/1.1 request parser (18 files, ~600 changed lines against pristine 0.9.0).
- Prometheus moved out of `pingora-core`; the dataplane's `/metrics` service comes from `pingora-prometheus`.
- Gateway API v1.6.2 conformance on the rebased build: 130/130 across all five profiles (after the connection-reuse fix below).

### Fixed

- **A BackendTLSPolicy cannot borrow another policy's verified connection.** Pingora keys its upstream connection pool by address, scheme, SNI, client cert and the verify flags, but not by the CA bundle or the required SANs. Two routes to the same backend pods and hostname with different `BackendTLSPolicy` CAs therefore shared pooled connections, and a request under the mismatched policy could ride a connection verified by the valid one instead of failing. Found by the rebased build on `BackendTLSPolicy` (mismatched cert) and `BackendTLSPolicySANValidation` (3 mismatched-SAN cases) returning 200; the reuse hash now covers the CA certificates and the required SANs. Tests: `reuse_hash_separates_peers_with_different_ca_bundles`, `reuse_hash_separates_peers_with_different_required_sans`.
- The dataplane's Prometheus endpoint listened on `127.0.0.1:9090`, unreachable from a scraper despite the pods' `prometheus.io/*` annotations. It now listens on the pod address.

## [0.2.1] - 2026-09-10

### Changed

- **Route changes propagate in milliseconds, not 105 ms.** The compile loop's 100 ms debounce was leading-edge: every wake slept the full window before compiling, so a single HTTPRoute took ~105 ms to reach the data plane (the sub-millisecond figures in the 2026-09-06/07 reports were an artifact of a catch-all route attached during the probe). It is now trailing-edge: an idle loop compiles at once and only writes that follow a compile within the window wait for the next one, so a burst still coalesces. Test: `compilation_loop_compiles_at_once_when_idle_and_batches_a_burst`.
- **`Programmed` no longer flaps on every recompile.** A Gateway whose data planes still run the previous slice stays `Programmed=True` for `PROGRAMMED_GRACE` (10 s) after a recompile; it goes False only if no data plane applies the new slice within that window (a check the compile loop schedules) or its data planes leave. `Event::Programmed` is published only when the answer moves, so a route change no longer costs a Gateway status write and a wake of every policy reconciler (the attached-routes bench wrote status 417 times for 100 routes, 146 before the event-driven controller). Tests: `programmed_survives_a_slice_change_while_the_data_plane_catches_up`, `programmed_lapses_when_the_grace_window_passes`, `programmed_events_fire_only_when_the_answer_moves`.

### Fixed

- **A failed status write is retried.** Every route and policy reconciler swallowed a failed status patch with "will retry on next reconcile"; since reconciles are event-driven, nothing scheduled that next reconcile, so an API-server stall left the object without status until something else changed. Seen once in conformance (`TCPRouteParentRefAttachAll`: a 15 s API stall, then 60 s with no `Accepted`). The failure now returns an error and the registry requeues in 30 s, as `BackendTLSPolicy` already did.

## [0.2.0] - 2026-09-08

### Added

- **Installable from GHCR.** A `vX.Y.Z` tag runs `.github/workflows/release.yml`: native `linux/amd64` and `linux/arm64` builds of `ghcr.io/portus-gateway/controller` and `ghcr.io/portus-gateway/dataplane` (pushed by digest, joined into one manifest list under the version tag and `latest`), the Helm chart pushed to `oci://ghcr.io/portus-gateway/charts/portus-gateway`, and a GitHub release with the install commands. The chart defaults to those images with the tag defaulting to its `appVersion`, so `helm install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.0` is the whole install after the Gateway API CRDs.
- **mTLS on the config stream works out of the box.** With `grpcTls.enabled` (the default) and no `grpcTls.secretName`, the chart generates a CA and a controller certificate (SANs for every form of the controller Service name, 10 years) into `<release>-grpc-tls` and reuses it on upgrade via `lookup`; the former `fail` guard is gone. Because a pod can only mount Secrets from its own namespace, the provisioner now copies the three TLS keys into a Gateway-owned Secret next to each dataplane Deployment (`desired_tls_secret`; unrelated keys are not copied) and the Deployment mounts that copy. A change to the source Secret re-provisions every Gateway. `make deploy` runs the mTLS path too; `grpcTls.enabled=false` remains the plaintext opt-out. The controller learns its namespace from `PORTUS_NAMESPACE` (downward API).
- **Event-driven controller, no timed requeues.** Every reconciler now returns `await_change`; the one poll left is a Gateway whose dataplane ClusterIP is not yet reachable (1 s, kube-proxy has no event). The store gained a dependency event bus (`ConfigStore::events`, `Event`): a reconciler publishes after writing the store, and only when the state changed, and `triggers` maps each event to the objects whose status depends on it (routes ← parents/Services/ReferenceGrants/Namespace labels; Gateways ← class/routes/ListenerSets/acks/grants/labels; ListenerSets ← parent/siblings/routes; policies ← acks/siblings). Cross-kind Kubernetes `watches` were the previous mechanism and could run the dependent before the dependency's reconciler had written the cache, which the 5 s requeues papered over. The compile loop lost its 5 s safety tick (`Notify` permits make it unnecessary), `insert_and_notify` writes and wakes only on change, EndpointSlice updates with an unchanged ready set no longer recompile, and routes bound only to other implementations' Gateways are no longer stored or compiled. Programmed acks are per Gateway (`Event::Programmed`).
- **Deletions are watched, not polled.** `Controller::new` only reconciles applied objects; a delete produced no reconcile request, so the runtime never reported `ObjectNotFound` and store eviction relied on the next timed requeue finding the object gone. Every controller is now built by `registry::controller`, which feeds `Controller::for_stream` a `touched_objects` watch (deletes included), so a deleted route, policy or Gateway leaves the store the moment the watch reports it (the 120 s prune remains a safety net, not the mechanism).
- **Deterministic compile.** Effective hostnames were collected in a `HashSet`, so a route with several hostnames produced a different `CompiledConfig` fingerprint on every compile; each "new" config flipped a Gateway's `Programmed`, and because the listener's programmed flag was stored in the Gateway's state, the flip woke the compiler again (one Gateway at ~30 reconciles/s and 4,900 config versions in one conformance run). Hostnames are now ordered and `programmed` is derived when status is written, not stored. Regression test: `compile_is_deterministic_for_multi_hostname_routes`.
- **Disk guard.** `make disk-check` (run by every image build/import target) refuses to start below `DISK_MIN_FREE_GB` (20); `make disk-report` shows host, `Docker.raw`, Docker and k3d-node usage; `make disk-prune` removes our image tags the chart is not configured to run (host and k3d node), dangling images and BuildKit records unused for three days. A full disk had corrupted Docker's store and the k3s datastore four times; the k3d node alone held 26 GB of imported images that nothing ever removed.
- **Passive outlier ejection in the data plane** (`outlier.rs`). A connect failure takes the endpoint out of its pool at once; five 5xx responses in a row do the same. Ejections last 10 s, growing with each repeat up to 5 min, and the count decays after 5 min of good behaviour; the last ready endpoint of a pool is never ejected. Implemented on the load balancer's enable flag, so it composes with `HealthCheckPolicy`. `proxy_upstream_ejections_total{service}` counts ejections. In the gateway-api-bench backend-failover test this took the error rate during a single-endpoint outage from 20 % to 0.03 % (12 of 44,120) with no policy attached.
- **HTTPRoute `rules[].retry`** (`HTTPRouteRetry`, Gateway API v1.6): an upstream response whose status is in `codes` is discarded and the request replayed, up to `attempts` more times (default 1); the last attempt's response is passed through, and statuses not listed are never retried. Implemented in the dataplane's `upstream_response_filter` as a retryable Pingora error, so no client bytes are written before the decision. A rule-level retry takes precedence over a `RetryPolicy` attached to the route. Standalone YAML gains `retries.codes`. Claims `HTTPRouteRetry` (`HTTPRouteRetryBackoff` / `...ConnectionError` are not claimed; `backoff` is accepted and stored).
- **UDPRoute / GATEWAY-UDP profile.** `UDPRoute` (`gateway.networking.k8s.io/v1`) attaches to `UDP` listeners with the TCPRoute semantics (bind by `sectionName`, `port`, both, or every UDP listener; weighted backendRefs with weight 0 receiving nothing; oldest route wins when several bind one listener while all stay `Accepted` and are counted in `attachedRoutes`; `ResolvedRefs` reasons `BackendNotFound` / `RefNotPermitted`; `NotAllowedByListeners` for TCP/TLS listeners). One reconciler (`reconcilers/l4_route.rs`, generic over the `L4Route` trait) and one compiler path (`compile_l4_routes`) serve TCPRoute and UDPRoute. The per-Gateway Service and pod expose UDP listeners as `protocol: UDP` ports. The dataplane gains a UDP path (`udp_proxy.rs`, Pingora has none): the listener manager binds one `UdpSocket` per UDP listener port and each client gets a session to a weighted-round-robin backend whose replies come back from the Gateway address; sessions end after `UDP_IDLE_TIMEOUT_SECS` (default 60 s) idle. Claims `UDPRoute`; all nine upstream UDPRoute tests pass.
- **mTLS.** Frontend: `Gateway.spec.tls.frontend` (`default.validation` and `perPort[].tls.validation`) makes HTTPS listeners request and validate client certificates against CA bundles from ConfigMaps (`ca.crt`), mode `AllowValidOnly` (default) or `AllowInsecureFallback` (certificate requested, connection accepted without a valid one; surfaced as the Gateway condition `InsecureFrontendValidationMode=True/ConfigurationChanged`). An unresolvable CA reference sets the listener `ResolvedRefs=False` (`InvalidCACertificateRef` / `InvalidCACertificateKind` / `RefNotPermitted`) and, when no CA is usable, `Accepted=False/NoValidCACertificate`; HTTP listeners are unaffected. The data plane builds one rustls `ServerConfig` per validating port and the patched Pingora picks it per connection from the accepted socket's local port (`TlsSettings::from_config_chooser`, tokio-rustls `LazyConfigAcceptor`). Backend: `spec.tls.backend.clientCertificateRef` (a `kubernetes.io/tls` Secret) is presented to TLS backends by every route of that Gateway; the Gateway reports `ResolvedRefs` (`InvalidClientCertificateRef` / `RefNotPermitted` on failure). Claims `GatewayFrontendClientCertificateValidation`, `GatewayFrontendClientCertificateValidationInsecureFallback` and `GatewayBackendClientCertificate`.
- Claimed `GatewayInfrastructurePropagation` (generated Deployment/Service/pods carry `gateway.networking.k8s.io/gateway-name` plus the Gateway's `infrastructure.labels/annotations`) and `GatewayAddressEmpty` (a `spec.addresses` entry with a supported type and no value is assigned by the provisioner). Unsupported address types are rejected with `UnsupportedAddress`, fixed values with `AddressNotUsable`. `GatewayAddress.value` is now optional in our types: a Gateway with an empty-value address used to be undeserialisable and would have broken the Gateway watch.
- `dataplane.mode` defaults to `PerGateway`; `make deploy` deploys it on k3d (ClusterIP, one replica per Gateway) and `make deploy-legacy` keeps the shared DaemonSet flow for host-side suite runs. GitHub Actions workflow runs unit tests, clippy and the in-cluster conformance suite on k3d.
- All Dockerfiles (controller/dataplane dev + release, conformance runner) use BuildKit cache mounts for the cargo registry, git checkouts and per-binary `target/` (Go module and build caches for the runner), so a code change rebuilds only the crates that changed instead of the whole dependency graph.
- **Per-Gateway dataplane provisioning** (`dataplane.mode`: `Legacy` | `Shared` | `PerGateway`). In `PerGateway` mode the controller owns a dataplane Deployment, Service and PodDisruptionBudget per Gateway (ownerReferences → garbage-collected with it, `spec.infrastructure.labels/annotations` propagated), each dataplane receives only its Gateway's config, and `status.addresses` reports the Service's LoadBalancer ingress (ClusterIP while pending). `Shared` keeps one fleet but still gives every Gateway its own Service and address. Template from `PORTUS_DATAPLANE_*` controller env (rendered by the chart).
- **In-cluster conformance runner** (`make conformance-image && make conformance-run`): the Go suite compiled into an image and run as a Job with cluster-admin, so Gateway addresses only need to be pod-reachable. Report extracted to `tests/conformance/conformance-report.yaml`. Host-side runs set `CONFORMANCE_SHARED_ADDRESS=true` and skip `HTTPRouteMultipleGateways`; the in-cluster run has no skips.
- Gateway API **v1.6.2** conformance suite and CRDs (from v1.5.1). New `GATEWAY-TCP` profile support: TCPRoute is served as `v1`, parentRefs bind by `sectionName`, `port`, both, or neither (all TCP listeners), weighted backendRefs (weight 0 = no traffic), oldest-route-wins when several TCPRoutes bind one listener (all stay `Accepted`, `attachedRoutes` counts them), and `ResolvedRefs` reasons `BackendNotFound` / `RefNotPermitted`, `Accepted` reasons `NotAllowedByListeners` / `NoMatchingParent`.
- The dataplane L4 proxy binds TCP and TLS listener ports dynamically from the compiled config (and releases them), so Gateways on new ports no longer need a pod restart; `dataplane.extraTcpPorts` opens them on the Service.
- Gateway `Accepted` condition follows the spec: `ListenersNotValid` when any listener is rejected (status False when none is accepted) and `InvalidParameters` for an unknown `infrastructure.parametersRef`.
- Controller handles SIGTERM (what Kubernetes sends) and releases its leader Lease on shutdown, so the successor acquires it immediately instead of waiting up to 15s for expiry.
- Idle-based L4 session timeout (`L4_IDLE_TIMEOUT_SECS`, default 3600s) replacing the fixed one-hour session cap that cut long-lived TLS passthrough / TCPRoute connections (MQTT on 8883, databases) regardless of activity.
- Bounded HTTP/2 server settings (100 concurrent streams, 64 KiB header list) on the h2c and HTTPS listeners.
- `proxy_routes_loaded`, `proxy_endpoints_loaded` and `proxy_watcher_errors_total` are now populated (they were registered but never updated).
- RetryPolicy status discloses that `gateway-error` retries apply to upstream connection failures only.
- SNI-based TLS certificate selection for multiple HTTPS listeners, enabling distinct certificates per hostname on the same port.
- Per-client-IP rate limiting (SEC-10) with configurable burst and sustained request thresholds.
- Trusted proxy CIDR configuration (SEC-11) for accurate client IP extraction from X-Forwarded-For headers.
- Query parameter `RegularExpression` matching support for HTTPRoute.
- Event-driven ConfigStore with `insert_and_notify` / `remove_and_notify` for immediate recompilation on resource changes.
- Controller health probes -- readiness probe returns 503 until the first config is successfully compiled.
- Six new policy CRDs: RateLimitPolicy, CircuitBreakerPolicy, ConnectionPolicy, BasicAuthPolicy, APIKeyAuthPolicy, CORSPolicy. Wired through the full pipeline (reconcilers, compiler, proto, dataplane enforcement).
- Criterion benchmarks for route matching hot paths.
- Benchmark results comparing Portus against Envoy Gateway, Kong, kgateway, Traefik, Istio, Cilium, and Nginx Gateway Fabric.
- Local profiling tooling (flamegraphs, CPU profiles).

### Changed

- Proto `TcpProxyRoute` is `L4ProxyRoute`, used by both `CompiledConfig.tcp_proxy_routes` and the new `udp_proxy_routes`; the dataplane no longer falls back to the singular `backend_service`/`backend_port` fields when `backends` is empty. Generated Service/container port names are `tcp-<port>` / `udp-<port>` (were `port-<port>`) and `BOUND_PORTS` lists `port/PROTOCOL`. The Gateway address reachability probe targets the first TCP port and is skipped for UDP-only Gateways. `CONFORMANCE_TCP` is gone: the runner always claims every profile (HTTP, GRPC, TLS, TCP, UDP).

- Controller wiring is a registry (`crates/portus-controller/src/registry.rs`): every kind goes through one `spawn` that owns the error policy (404 evicts the object from the store, anything else requeues in 30 s), `ObjectNotFound` eviction, per-kind reconcile timing (`/metrics` on the controller's health port: `portus_controller_reconciles_total`, `_errors_total`, `_duration_seconds_{sum,max}` by kind, slow reconciles logged) and returns the reflector store the prune task reads. The 25 per-kind `error_policy_*` functions and the hand-written `for_each` loops are gone; `main.rs` went from 1648 to 810 lines. The ConfigMap reconciler no longer LISTs BackendTLSPolicies to re-trigger them: the policy controller watches ConfigMaps, and the Gateway controller watches the CA ConfigMaps and client-cert Secrets it references, through `registry::cache_then`, which caches the watched object in the store before fanning out so the dependent reconcile never sees stale data (the ConfigMap controller runs on its own schedule).

- The dataplane binds every Gateway listener port dynamically from the compiled config (HTTP, HTTPS, TLS and TCP alike) and hands HTTP/HTTPS connections to Pingora's services in-process on the original socket. Ports 80 and 443 are no longer special-cased, `EXTRA_HTTP_PORTS`/`HTTP_PORT` are gone, and a listener on a new port is serving within a second of the controller programming it. The SNI decision is scoped to the TLS listeners of the port the connection arrived on.
- Every compiled route, listener, TLS passthrough and TCP route carries its owning Gateway (`gateway_namespace`/`gateway_name`; ListenerSet listeners resolve to their parent Gateway). A data plane that names its Gateway in `ConfigRequest` receives only that Gateway's slice (`compiler::scope_config`) with the slice's own fingerprint, and `Programmed` on a Gateway is judged against the slice a dedicated data plane reports (`ConfigStore::is_programmed_for`). Groundwork for one dataplane Deployment per Gateway.
- Config identity is a content fingerprint, not a controller-lifetime counter. `CompiledConfig.fingerprint` (order-independent hash) travels with every push; the data plane applies whenever the fingerprint differs from what it runs and treats an identical fingerprint as a heartbeat, so controller restarts or a second controller instance never wedge a data plane and identical recompiles are not re-applied. `version` remains as an informational generation.
- Real Programmed ACKs: a new `ReportApplied` RPC lets each data plane report the fingerprint it applied; `Gateway`/policy `Programmed` is now true only once a data plane runs the current compiled config (previously it flipped as soon as the controller had compiled anything, and policies could only learn about applied configs on reconnect).
- Programmed changes re-trigger Gateway reconciliation through a kube-runtime trigger stream (`reconcile_all_on`) instead of patching a `portus-gateway/programmed-trigger` annotation onto every Gateway.
- `crates/pingora-core-patch` is a workspace member so `cargo test --workspace` and `cargo clippy` cover the patched Pingora too. Upstream lints that the patch does not touch are allowed in-source; `test_req_header_no_eos_empty_data_with_eos` is ignored (fails identically on pristine 0.8.1 with h2 ≥ 0.4.19).

- Helm: controller Deployment uses `strategy: Recreate` with a 20s termination grace period. RollingUpdate deadlocked a leader-elected singleton (new pod waits for the Lease the old pod holds; the old pod is never terminated because the new one never becomes Ready).
- `make gateway-api-crds` and the deployment guide pin the Gateway API CRD bundle to v1.5.1, matching the conformance suite in `tests/conformance/go.mod` (`latest` had moved to v1.6.x and the suite refused to start).
- L4 sessions ended by a peer hanging up (broken pipe, reset) log at debug instead of warn.
- Toolchain: MSRV 1.98, container base image `rust:1.98-alpine`; crates inherit `rust-version` from the workspace.
- Dependencies: pingora 0.8.1 (patch crate rebased), kube 4.2 / k8s-openapi 0.28, tokio 1.53, rustls 0.23.43, hashbrown 0.17, prometheus 0.14, rand 0.10, rcgen 0.14, `serde_yaml_ng` replaces the unmaintained `serde_yaml`; `x509-parser` unified on 0.18.
- Controller prune task reads each controller's reflector store instead of LISTing ~20 resource kinds from the API server every cycle; ListenerSets and ConfigMaps are now pruned too.
- Compilation loop skips its periodic recompile when nothing changed (dirty flag set by `notify_change`).
- Dataplane `LoadBalancer`s are reused across config applies when the endpoint set and health-check config are unchanged, preserving health-check state and round-robin position.
- TLS certificate hot-reload is notification-driven instead of a 500 ms poll.
- BackendTLSPolicy lookup happens once in `request_filter` (no second snapshot load or allocation in `upstream_peer`); SNI is borrowed rather than cloned per TLS request; weighted-backend counter is thread-local; per-IP rate limiter takes a shard read lock on the hot path.
- `RetryPolicy` CRD `retryOn` enum drops the never-supported `5xx` value.
- Removed dead code: legacy CRD-mirror types and route builders are test-only, unused compiler helpers and duplicate cert-expiry helper deleted; clippy is clean with `--all-targets`.
- Replaced `env_logger` with `tracing-subscriber` to eliminate global mutex contention in the logging path. Measurable throughput improvement under load.
- Switched to `hashbrown::HashMap` in the dataplane for faster route lookups.
- O(1) exact path matching via HashMap -- prefix matching still uses sorted-prefix scan, but exact matches no longer search linearly.
- Upstream idle timeout and TCP keepalive on backend connections for connection reuse across requests.
- DashMap snapshots taken at `compile_config` entry to bound lock hold time during compilation.
- Pre-indexed policies for O(1) route-target lookup in `apply_policies`.
- Eliminated redundant second `http_routes` pass during backend namespace indexing.
- Zero-clone config change detection via order-independent hashing.
- Migrated all reconcilers to `insert_and_notify` / `remove_and_notify` pattern, replacing manual compile triggers.
- Bumped MSRV to 1.93.

### Removed

- `tools/config-server` (served a `CompiledConfig` no dataplane can consume without a Gateway name; excluded from the workspace since the single-model cut) and the dead `cmd/proxy` workspace exclusion. The provisioner no longer sets `BOUND_PORTS` on dataplane pods (nothing read it; ports come from the config stream). Bench targets no longer scale a `component=proxy` Deployment or flip a shared proxy Service that no longer exist.

- The `Legacy` and `Shared` dataplane deployment modes, the dataplane DaemonSet/Service/PDB/ServiceAccount chart templates, `controller.gatewayAddress`, `dataplane.mode`, the static port lists (`httpPort`, `httpsPort`, `extraHttpPorts`, `extraTlsPorts`, `extraTcpPorts`) and the dataplane `BOUND_PORTS` / `L4_PORTS` / `GATEWAY_ADDRESS` environment. There is one deployment model: the controller provisions a dataplane Deployment, Service and PodDisruptionBudget per Gateway, every dataplane names its Gateway (the config stream rejects one that does not), and every listener port is bound from the compiled config.
- The host-side conformance targets (`tests/conformance/Makefile`, `CONFORMANCE_SHARED_ADDRESS`, `make deploy-legacy`, `deploy-tls`) and the k3d host port mappings they needed. The suite runs in-cluster only (`make conformance-image && make conformance-run`).
- Dead plumbing: `CompiledConfig.tls` (certificates live on `Listener.tls_cert_ref`), `ConfigRequest.bound_ports`, the dataplane's `tls_cert_loaded` readiness flag, and the per-backend client-certificate map (a dataplane serves one Gateway, so it has one backend client certificate).

### Known gaps

- UDPRoute (GATEWAY-UDP profile) is not implemented and not claimed. `HTTPRouteMultipleGateways` passes in `PerGateway` mode; `Legacy` deployments report one address for every Gateway and skip it explicitly (`CONFORMANCE_SHARED_ADDRESS=true`).

### Fixed

- Route status no longer fights other implementations. Every route reconciler wrote `status.parents` as only its own entries; the list is atomic under server-side apply, so on a route whose parentRefs span two implementations each controller erased the other's entry and both reconciled forever (~190 reconciles/s on one HTTPRoute, seen with agentgateway on the same cluster). `status::merge_route_parents` keeps other controllers' entries, the diff-before-write compares only ours, and parentRefs to Gateways or ListenerSets this controller does not manage (or that do not exist) get no entry from Portus, as the spec requires.
- No implicit circuit breaker or connection limit. The dataplane gave every backend a 5-failure/30 s breaker and a 128-connection limit even without a CircuitBreakerPolicy or ConnectionPolicy, so a backend that answered 5xx a few times was replaced by a `503 circuit is open` from the Gateway itself (caught by the `HTTPRouteRetry` conformance test). Breakers and limiters now exist only where a policy attaches one.

- The dataplane no longer waits 5 s for a TLS certificate before starting Pingora when the first applied config carries none (HTTP-only and TLS-passthrough Gateways): the health port came up 5 s late, so every such per-Gateway pod was not-Ready for at least that long, and under load the readiness lag stretched to 30 s+ and starved conformance tests of their time budget.
- In `Shared`/`PerGateway` modes a Gateway's `status.addresses` is published only once its dataplane Service has a ready endpoint *and* the controller has opened a TCP connection to the ClusterIP itself (1.5 s probe, 1 s requeue while withheld; EndpointSlice watch re-reconciles the Gateway; addresses now count as a status change). A ready endpoint alone was not enough: kube-proxy programs the Service after the EndpointSlice turns ready, and a client dialing in that window still hung. Publishing the ClusterIP the instant the Service was created let a client that dials immediately send its first SYN before kube-proxy had programmed the Service, pinning a conntrack entry that is never DNAT'd, so the connect blackholed for its whole timeout. Seen as 30 s TCP/TLS connect hangs (`TCPRouteParentRefPortAndSectionName`, `TLSRouteMixedTerminationSameNamespace`) on freshly created Gateways in back-to-back conformance runs.
- BackendTLSPolicy status could never be written when the cluster had more than 16 Gateways and the policy was reconciled before the HTTPRoute that references its Service: the ancestor fallback listed every Gateway in the *store* (all namespaces), the API server rejected the patch (`status.ancestors: Too many: 27: must have at most 16 items`), the failure was only logged, and the next attempt was the 300 s requeue. The fallback is now the policy's own namespace, ancestors are sorted and capped at 16, a failed status write returns an error (30 s requeue), and the policy controller watches HTTPRoutes so the ancestor list updates when the route lands.

- The dataplane sizes its Pingora worker pool from its own CPU allocation (`DATAPLANE_THREADS`, set by the provisioner from the pod's CPU request, else the cgroup v2 quota) instead of the node's CPU count. Twelve per-Gateway dataplanes on a 10-CPU node previously asked for 120 worker threads between them.
- Per-Gateway dataplane pods use a 1 s readiness probe (was 2 s delay / 5 s period) and a 5 s termination grace period. The conformance suite gates every test on all pods in the Gateway's namespace being Ready, so a slow probe on one Gateway's pod stalled unrelated parallel tests; production rollouts are quicker for the same reason.
- L4 backend connects (TLS passthrough, TLSRoute terminate, TCPRoute) are bounded to 5 s. An endpoint that had just gone away left the client waiting on kernel SYN retries with nothing sent, which a TLS client sees as a handshake that never completes.
- In `Shared`/`PerGateway` modes a Gateway that is not Accepted reports no address (it has no dataplane) instead of the Legacy static address.
- TLS certificate rotation was silently ignored by the dataplane when the new PEM had the same length as the old one (the hot-reload compared lengths); it now compares a content hash. Found by the conformance suite recreating same-named Secrets between runs: the dataplane kept serving the previous run's certificate.
- TLS and TCP Gateway listeners bind their ports as soon as the listener is programmed, not only once a route attaches, so a TLSRoute/TCPRoute created a moment after its Gateway does not see connection refusals.
- Data planes are forgotten when their config stream ends, so pod churn (one Deployment per Gateway) can no longer exhaust the node cap and reject new pods' Programmed ACKs.
- Per-Gateway objects are named `portus-<gateway>-<uid prefix>`: a Gateway deleted and recreated under the same name no longer collides with the previous Service's Endpoints (`endpoints "..." already exists` left the new ClusterIP with no endpoints).
- A ConfigMap created or changed after the BackendTLSPolicy that references it now re-reconciles that policy immediately (ConfigMap watch mapped to referencing policies) instead of waiting for the 300 s requeue.
- HTTPS connections no longer lose the client address. The SNI mux used to proxy terminate-mode connections over a second TCP connection to Pingora on `127.0.0.1:18443`, so per-IP rate limiting, IP allowlists, `X-Forwarded-For` and access logs saw `127.0.0.1` for every TLS client. The mux now hands the accepted socket to Pingora's HTTPS service in-process (`ServerAddress::Handoff` / `add_tls_handoff` in the patched pingora-core); no loopback hop, no extra copy, and the router's internal-port remapping is gone.
- Every API-server write (status patches, Lease renew/acquire/release, the programmed-trigger annotation) runs under a 15 s deadline (`status::with_write_timeout`), and the kube client restores the 295 s read timeout that kube-client 4 dropped. Without either, one stalled HTTP/2 request wedged the owning reconciler forever: seen live when a Gateway status patch never returned and the Gateway stayed `Accepted=Unknown` for the rest of the run. A stalled Lease renewal would have silently lost leadership the same way.
- Request mirrors now carry the full request target (path and query); the mirror previously dropped the query string.
- `allowedRoutes.namespaces.from: Same` on a ListenerSet listener is evaluated against the ListenerSet's namespace (not its Gateway's) at compile time, matching the reconcilers.
- SNI extraction waits for the whole TLS ClientHello instead of trusting a single `peek()`. Large ClientHellos (post-quantum key shares) split across TCP segments were classified as "no SNI" and misrouted to the HTTPS handler instead of their TLS passthrough / terminate route.
- Health-check state and round-robin position no longer reset on every config apply.
- `rustls-webpki` 0.103.15 (RUSTSEC-2026-0098, -0099 name-constraint bypasses; -0104 CRL parse panic).
- Hostname intersection now allows multi-level subdomain wildcards per Gateway API spec (e.g., `*.bar.example.com` matching `foo.bar.example.com`).
- Case-insensitive hostname matching and single-level wildcard semantics aligned to spec.
- CORS preflight requests returning 403 when they should have been handled by the CORS filter.
- Vary header append logic (was overwriting instead of appending).
- Mirror request headers were missing host and content-length.
- Weighted backend counter was not resetting across recompilations.
- Health endpoint moved back to main Tokio runtime to avoid blocking the proxy event loop.
- Stale Secrets and GatewayClasses are now pruned from the ConfigStore.
- Selector namespace safety -- cross-namespace selectors no longer leak resources.
- `observedGeneration` now correctly tracks the most recent generation seen by the reconciler.
- Controller no longer reports ready before first config compilation completes.
- Conformance race condition caused by per-resource `get_opt` in the prune loop.

### Security

- Wave 1: Constant-time comparison for auth tokens, input injection guards on header values, panic safety for all request handlers.
- Wave 2: gRPC TLS enabled by default between controller and dataplane. Dataplane ServiceAccount isolated from controller permissions.
- Wave 4: Removed all `unwrap()` calls from production code paths. Added mutex poison recovery.
- Comprehensive security review covering timing attacks, input validation, resource exhaustion, and privilege boundaries.
- Dependency update to address known CVEs in transitive dependencies.

## [0.1.0] - 2026-03-21

Initial release with full Gateway API conformance.

### Added

- 425/425 Gateway API conformance tests passing (experimental channel, v1.5.1): HTTP 61/61, GRPC 13/13, TLS 22/22.
- Kubernetes controller watching Gateway, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, ReferenceGrant, and Secret resources.
- Protobuf-based config pipeline: reconcilers populate a ConfigStore, `compile_config` produces a CompiledConfig proto, streamed to dataplanes over gRPC.
- Pingora-based dataplane with atomic config swap via ArcSwap -- no dropped connections during reconfiguration.
- Full Gateway API route matching: exact/prefix/regex paths, header matching, method matching, query parameter matching, hostname matching with wildcard intersection.
- HTTPRoute filters: RequestHeaderModifier, ResponseHeaderModifier, RequestRedirect, URLRewrite, RequestMirror (including multiple mirrors and percentage-based), ExtensionRef.
- Backend request header modification and backend protocol selection (H2C, WebSocket).
- Redirect status codes: 301, 302, 303, 307, 308.
- TLS Terminate mode with dynamic certificate hot-reload from Kubernetes Secrets.
- TLS Passthrough mode with SNI-based routing.
- TCP proxy routing (TCPRoute).
- Cross-namespace backend references via ReferenceGrant.
- Weighted backend traffic splitting.
- Request and backend timeouts.
- Prometheus metrics endpoint.
- Health and readiness probes.
- Helm chart for deployment with configurable controller and dataplane parameters.
- Gateway API conformance test suite (Go, runs against live k3d cluster).

[0.2.0]: https://github.com/Portus-Gateway/Portus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Portus-Gateway/Portus/releases/tag/v0.1.0
