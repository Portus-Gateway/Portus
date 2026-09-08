# Contributing to Portus

Portus is a Kubernetes Gateway API implementation built on Cloudflare's Pingora proxy framework, written in Rust. Contributions are welcome -- bug fixes, new features, conformance improvements, documentation, and performance work.

## Getting Started

### Prerequisites

- **Rust** (edition 2024, MSRV 1.98) -- install via [rustup](https://rustup.rs/)
- **protoc** -- protobuf compiler, needed by the `portus-types` build script
- **Docker** -- for building container images
- **k3d** -- for running conformance tests against a local cluster
- **mise** -- manages k3d, helm, kubectl, go, and protoc versions (`mise install` from the repo root)

### Clone and Build

```bash
git clone https://github.com/Portus-Gateway/Portus.git
cd portus
cargo build --workspace
```

The workspace contains three crates:

| Crate | Path | What it does |
|-------|------|--------------|
| `portus-controller` | `crates/portus-controller` | Kubernetes controller -- reconcilers, config store, compiler, gRPC server |
| `portus-dataplane` | `crates/portus-dataplane` | Pingora-based proxy -- config receiver, router, TLS, health/metrics |
| `portus-types` | `crates/portus-types` | Protobuf-generated types shared between controller and dataplane |

## Development Workflow

### Running Tests

Unit tests are the primary feedback loop. Run the full suite with:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --workspace -- --test-threads=1 -q
```

The `--test-threads=1` flag is required because some tests share state via `ConfigStore` and need sequential execution to avoid races.

To run a single test with output (useful for debugging with `eprintln!`):

```bash
cargo test -p portus-controller -- test_name --nocapture
```

### Building Container Images

The controller and dataplane each have their own Dockerfile. Tag images with a unique identifier to avoid caching issues:

```bash
TAG="dev-$(date +%s)"
docker build -t portus-gateway/controller:$TAG -f deploy/docker/Dockerfile.controller .
docker build -t portus-gateway/dataplane:$TAG -f deploy/docker/Dockerfile.dataplane .
```

### Running Conformance Tests

The suite runs inside the cluster: every Gateway gets its own dataplane and a ClusterIP address only pods can reach, so the Go suite is built into an image and run as a Job.

```bash
make k3d-up build deploy          # cluster, images, chart
make conformance-image            # build + import the runner (rebuild after editing tests/conformance)
make conformance-run              # all five profiles; report -> tests/conformance/conformance-report.yaml
make conformance-run CONFORMANCE_RUN='TestConformance/HTTPRouteSimpleSameNamespace$$'
```

Iterate on a subset, run the full suite once at the end.

All unit tests should pass before you deploy to the cluster. Conformance tests should confirm what unit tests already verified, not be the place where you discover problems.

## Code Standards

### Safe Rust

Write safe, idiomatic Rust. No `unsafe` blocks unless absolutely necessary and thoroughly justified in comments. No `unwrap()` in production code paths -- use `?`, `Result`, and `Option` combinators for error handling. If an `unwrap()` is truly unreachable, use `expect()` with an explanation of why it cannot fail.

### No Dead Code

Remove unused imports, functions, and variables. Don't leave commented-out code in the tree. `cargo clippy` should be clean.

### Error Messages

Error messages should describe what failed and include enough context to debug without a stack trace. Include the relevant identifiers -- hostnames, port numbers, service names, namespace -- not just "operation failed."

### Performance

Use `Arc<str>` over `String` for shared immutable data. Minimize allocations in hot paths. Profile before optimizing -- don't add complexity for hypothetical gains.

## Testing Approach

Portus follows a test-driven development process, and we take it seriously because the data pipeline has multiple stages where subtle bugs can hide. If you're fixing a bug or adding a feature, we expect tests at each pipeline stage the change touches.

### Pipeline Stages

Data flows through the system as: Gateway API CRDs -> Reconcilers -> ConfigStore -> `compile_config` -> proto -> `config_receiver` -> router. A change to hostname matching logic, for example, might need tests at the compiler, config_receiver, and router levels.

The four test levels:

1. **Compiler tests** (`compiler.rs`) -- verify that `compile_config` produces correct `RouteConfig` fields from `ConfigStore` state.
2. **Config receiver tests** (`config_receiver.rs`) -- verify that `build_route_map_from_proto` correctly groups, keys, and sorts routes.
3. **Router tests** (`router.rs`) -- verify that `HostRoutes::match_request` correctly matches requests against compiled routes.
4. **Conformance E2E tests** (`conformance_tests.rs`) -- full pipeline tests that populate a `ConfigStore` with the same state the reconcilers would produce from conformance test YAML, compile it, and verify matching.

### Test Helpers

The test modules include helpers that reduce boilerplate: `make_listener`, `make_listener_on_port`, `make_parent_ref`, `make_parent_ref_with_port`, `make_http_route`, `empty_store`, `setup_gateway_with_listeners`, and others. Use them. If you find yourself repeating a setup pattern, add a new helper.

### What Good Tests Look Like

- Test both positive and negative cases. Every test should verify what matches AND what should not match.
- Use descriptive names: `test_compile_listener_port_matching_no_cross_contamination` tells the reader what's being tested. `test_port_3` does not.
- Use `..Default::default()` for fields you don't care about, but be aware this can mask bugs where a missing field silently defaults to something wrong.

## Pull Request Process

1. **Fork the repo** and create a feature branch from `main`.
2. **Write tests first** (or alongside your implementation). PRs without tests will be asked for them.
3. **Run the full test suite** and ensure it passes: `cargo test --workspace -- --test-threads=1 -q`.
4. **Write clear commit messages.** One logical change per commit. Use conventional commit prefixes (`feat:`, `fix:`, `perf:`, `refactor:`, `test:`, `docs:`, `chore:`).
5. **Keep PRs focused.** One logical change per PR. If your feature requires a refactor, consider splitting that into a separate PR that lands first.
6. **Describe what and why** in the PR description. If the change affects conformance test coverage, mention which tests are impacted.
7. **Security-sensitive changes** (auth, TLS, input validation, rate limiting) should say which controls in [SECURITY.md](SECURITY.md) are affected.

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. Include:

- What you expected to happen
- What actually happened
- Steps to reproduce (Gateway/Route YAML, curl commands, etc.)
- Portus version and Kubernetes version

For security vulnerabilities, do not open a public issue. Follow the process described in [SECURITY.md](SECURITY.md).

## License

By contributing to Portus, you agree that your contributions will be licensed under the Apache-2.0 license.
