# Project Instructions

## Project Memory (Grimoire)

Prior context lives in Grimoire under the root doc **Portus** (architecture, config pipeline, controller, dataplane, TLS/SNI mux, policies, conformance process, dev workflow, deployment, security, performance, Pingora patch, backlog, decision history). Use `mcp__grimoire__search` and `read_doc` before re-deriving anything from the repo, and update the relevant doc when a feature lands or a decision is locked.

## What This Project Is

Portus is a **Kubernetes Gateway API implementation** built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) proxy framework. It consists of:

- **portus-controller** — Kubernetes controller that watches Gateway API CRDs (Gateways, HTTPRoutes, GRPCRoutes, TCPRoutes, TLSRoutes, etc.), reconciles them into a `ConfigStore`, and compiles that state into a `CompiledConfig` proto message.
- **portus-dataplane** — Pingora-based proxy that receives `CompiledConfig` from the controller, builds route maps, and handles live traffic with full Gateway API routing semantics.
- **portus-types** — Shared protobuf-generated types (`CompiledConfig`, `RouteConfig`, `Listener`, etc.) used by both controller and dataplane.

The data pipeline is: **Gateway API CRDs → Reconcilers → ConfigStore → compile_config → proto → config_receiver → router (Pingora)**.

## Goal: Full Gateway API Conformance

We are targeting **100% conformance** with the Kubernetes Gateway API specification — both Core and Extended conformance profiles (HTTP, GRPC, TLS). Every conformance test must pass. When implementing features or fixing bugs, always consider how the change affects conformance test coverage.

## Rust Standards

Write **pure, clean, safe, and performant** Rust:

- **Safe by default** — no `unsafe` unless absolutely necessary and thoroughly justified. No `unwrap()` in production paths; use proper error handling (`?`, `Result`, `Option` combinators).
- **Clean and idiomatic** — follow standard Rust conventions. Use iterators over manual loops. Prefer `impl` over `dyn` when the type is known. Keep functions focused and small.
- **Performant** — use `Arc<str>` over `String` for shared immutable data. Minimize allocations in hot paths. Use `ArcSwap` for lock-free config updates. Profile before optimizing — don't add complexity for hypothetical performance gains.
- **No dead code** — remove unused imports, functions, and variables. Don't leave commented-out code.
- **Consistent error messages** — error messages should describe what failed and include relevant context (host, port, service name, etc.).

## Zero Regressions Policy

**Every bug found and every fix made MUST have a corresponding unit test.** We do not break things that were previously working. Before merging any change:

1. **Run the full test suite** (`cargo test --workspace -- --test-threads=1 -q`) and verify zero failures.
2. **For every bug fix**, write a test that reproduces the bug FIRST, then fix it. The test must fail before the fix and pass after.
3. **For every new feature**, write tests that cover the happy path, edge cases, and interaction with existing features.
4. **Before deploying to the cluster**, all unit tests must pass. Conformance tests confirm what unit tests already verified — they should never be the place where you discover regressions.
5. **If a security hardening change could affect routing, compilation, or config application**, write a regression test that exercises the conformance-critical path with that change active.

## Test-Driven Development (TDD)

**Always write tests before or alongside implementation.** Never submit code without tests.

### The Process for Every Conformance Feature

Before writing ANY implementation code:

1. **Read the upstream conformance test YAML** — understand exactly what Gateway, Routes, and backends the test creates, and what request/response expectations it checks. The conformance suite IS the spec.
2. **Think through the full pipeline impact** — trace the data from CRD → reconciler → ConfigStore → compiler → proto → config_receiver → router. Ask: "what else could this change affect?" Look for shared code paths, keying logic, wildcard handling, fallback chains.
3. **Write unit tests at each pipeline stage FIRST** — before fixing or implementing anything. These tests should encode the conformance test's expectations at the compiler, config_receiver, router, and E2E levels.
4. **Run the tests** — let failures pinpoint which stage has the bug or missing feature.
5. **Fix what the tests reveal**, then re-run the full suite.
6. **Think about regressions** — after fixing, ask: "what existing behavior depends on the code I just changed?" Write additional tests for those cases. The wildcard+port regression taught us this lesson.
7. **Only deploy to the cluster once all unit tests pass** — conformance tests should be confirmation, not discovery. We should be confident before deploying.

### Pipeline-Stage Testing

For any feature or bug that touches the data pipeline, write tests at **each stage** the data flows through:

1. **Compiler tests** (`compiler.rs`) — Verify that `compile_config` produces correct `RouteConfig` fields from `ConfigStore` state. Test hostname intersection, listener port resolution, filter compilation, etc.
2. **Config receiver tests** (`config_receiver.rs`) — Verify that `build_route_map_from_proto` correctly groups, keys, and sorts routes. Test port-specific keying, wildcard handling, protocol parsing, etc.
3. **Router tests** (`router.rs`) — Verify that `HostRoutes::match_request` correctly matches requests against compiled routes. Test path matching, header matching, method matching, fallback behavior, etc.
4. **Conformance E2E tests** (`conformance_tests.rs`) — Full pipeline tests that populate a `ConfigStore` with the same state the reconcilers would produce from conformance test YAML, compile it, and verify matching using the inline dataplane-equivalent helpers (`match_request` / `match_request_on_port`).

### Test Patterns

- **Use existing test helpers** — `make_listener`, `make_listener_on_port`, `make_parent_ref`, `make_parent_ref_with_port`, `make_http_route`, `empty_store`, `setup_gateway_with_listeners`, etc. Add new helpers when a pattern repeats.
- **Test positive AND negative cases** — every test should verify what matches AND what should NOT match.
- **Name tests descriptively** — `test_compile_listener_port_matching_no_cross_contamination` is better than `test_port_matching_3`.
- **Use `..Default::default()`** for proto/struct fields you don't care about in a test, but be aware this is also where bugs hide (missing field = silent default).
- **Always push coverage higher** — unit tests are faster than conformance tests. Every round of work should leave more pipeline stages covered.

### Debugging with Tests

When a test failure is surprising:

1. Add targeted `#[cfg(test)] eprintln!("DBG ...")` output to trace values through the pipeline.
2. Run the single failing test with `--nocapture` to see the output.
3. Narrow down which stage corrupts/drops the value.
4. Fix the bug, remove all debug output, re-run the full suite.

## Running Tests

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --workspace -- --test-threads=1 -q
```

The workspace includes `crates/pingora-core-patch` (our patched pingora-core), so the full run also executes upstream Pingora's ~330 unit tests (~45 s). One upstream h2 test is `#[ignore]`d with the reason inline; do not "fix" it by loosening the patch.

Run a single test with output:
```bash
cargo test -p portus-controller -- test_name --nocapture
```

## Build & Deploy (Conformance Testing)

**Disk first.** A full disk has corrupted Docker's store and the k3s datastore four times (each time the k3d cluster had to be recreated). Every image build/import target runs `make disk-check` and refuses below 20 GiB free; when it refuses, run `make disk-prune` (drops our stale image tags on the host and inside the k3d node, dangling images, BuildKit records unused for 3 days; keeps the cargo/go cache mounts and every image the chart is configured to run) and `make disk-report` to see the rest. `rm -rf target` frees ~13 GB of debug artefacts at the cost of one rebuild. Never `docker builder prune` without a filter: it deletes the cache mounts and the next build is ~30 min cold.

**IMPORTANT: Use `.dev` Dockerfiles for fast iteration (debug profile). `helm upgrade` works (controller uses Recreate + Lease release); uninstall+install remains the clean-slate path. Delete the lease first on a fresh install.**

The k3d cluster is `portus-local`. The helm release is `portus` in namespace `portus`. gRPC TLS must be disabled for local dev. There is one deployment model: the controller provisions a dataplane Deployment + Service + PDB per Gateway (`make deploy` uses ClusterIP Services and one replica per Gateway).

```bash
TAG="dev-$(date +%s)"

# Build dev images. BuildKit cache mounts keep the cargo registry and target dir
# between builds: a code change rebuilds only the changed crates (seconds to a few
# minutes warm; ~30 min cold). Never pass --no-cache unless the cache is suspect.
docker build -t portus-gateway/controller:$TAG -f deploy/docker/Dockerfile.controller.dev .
docker build -t portus-gateway/dataplane:$TAG -f deploy/docker/Dockerfile.dataplane.dev .

# Import to k3d
mise exec -- k3d image import portus-gateway/controller:$TAG portus-gateway/dataplane:$TAG -c portus-local

# CRITICAL: Delete stale lease and uninstall before installing.
# Stale leases cause controller crash-loops. helm upgrade hits stale state.
mise exec -- kubectl delete lease portus-gateway-controller -n portus 2>/dev/null
mise exec -- helm uninstall portus -n portus 2>/dev/null
sleep 3

# Fresh install with gRPC TLS disabled
mise exec -- helm install portus deploy/helm --namespace portus --create-namespace \
  --set controller.image.repository=portus-gateway/controller --set controller.image.tag=$TAG --set controller.image.pullPolicy=Never \
  --set dataplane.image.repository=portus-gateway/dataplane --set dataplane.image.tag=$TAG --set dataplane.image.pullPolicy=Never \
  --set dataplane.service.type=ClusterIP --set dataplane.replicasPerGateway=1 \
  --set grpcTls.enabled=false \
  --wait

# Verify: the controller pod 1/1 Running with ZERO restarts (dataplanes appear per Gateway)
mise exec -- kubectl get pods -n portus
```

Conformance runs in-cluster (Gateway addresses are per-Gateway ClusterIPs the host cannot reach):
```bash
make conformance-image     # build + import the runner (rebuild after editing tests/conformance/conformance_test.go)
make conformance-run       # all five profiles (HTTP, GRPC, TLS, TCP, UDP), ~7 min (4 min of it is the suite's fixed setup); report -> tests/conformance/conformance-report.yaml
make conformance-run CONFORMANCE_RUN='TestConformance/(GatewayFrontendClientCertificateValidation|TCPRouteWeightedRouting)$$'
```
Iterate on a subset, run the full suite once at the end. Never pipe `make conformance-run` through `head`: it kills the log stream but not the Job.

The suite is pinned to Gateway API **v1.6.2** (experimental CRD bundle, `make gateway-api-crds`). The Go module needs Go 1.26: prefix with `GOTOOLCHAIN=auto` if `mise exec -- go version` is older.

Upstream conformance test Go code and YAML manifests are at:
`~/go/pkg/mod/sigs.k8s.io/gateway-api/conformance@v1.6.2/tests/`

