# Benchmarks

Traffic benchmarks follow the method of [howardjohn/gateway-api-bench](https://github.com/howardjohn/gateway-api-bench)
(the "v2" report's traffic section): the `howardjohn/hyper-server` backend behind one
Gateway + HTTPRoute per implementation, load from `howardjohn/benchtool` (fortio) running
**inside the cluster**, a connection ladder at unlimited QPS, then a fixed-QPS run for p99.

Everything lives in `deploy/bench/` and the `bench-*` Makefile targets:

```bash
make bench-backend                            # namespace `bench`, hyper-server x5, Service backend:80
make bench-portus                             # Portus Gateway; dataplane template -> BENCH_REPLICAS pods, BENCH_CPU cores each
make bench-traffic GATEWAYS=bench/portus      # ladder 1..256 connections, 10 s each, unlimited QPS
make bench-latency GATEWAYS=bench/portus      # 30k QPS on 64 connections for 30 s -> p50/p90/p99
make bench-download GATEWAYS=bench/portus     # 1 KB..1 MiB responses from the fortio echo backend, 64 conns
make bench-upload GATEWAYS=bench/portus       # POST bodies of the same sizes, echoed back
make bench-https GATEWAYS=bench/portus        # download ladder over the HTTPS listener
make bench-h2 GATEWAYS=bench/portus           # download ladder over h2c
kubectl delete -f deploy/bench/portus.yaml    # one implementation at a time keeps the box to itself
make bench-agentgateway                       # agentgateway chart v1.5.0, scaled to BENCH_REPLICAS
make bench-traffic GATEWAYS=bench/agentgateway
make bench-latency GATEWAYS=bench/agentgateway
make bench-teardown                           # everything above, dataplane template back to defaults
```

`bench-backend` also deploys fortio's echo server (`echo-backend.yaml`) behind a `/echo` rule
and an HTTPS listener (self-signed `bench-tls` Secret) on each bench Gateway; the payload
targets run one fortio pod per size with `-httpbufferkb 2048`, because benchtool cannot raise
fortio's 128 KiB response buffer and above it the client closes every connection.

Raw benchtool output is saved under `benchmarks/results/<timestamp>-<traffic|latency>-<gateways>.txt`,
followed by a resource summary: `deploy/bench/sample-top.py` samples `kubectl top pods` every 5 s
during the run (data planes in `bench`, control planes in their own namespaces) and appends mean
and peak CPU (millicores) and memory (Mi) per workload; the raw samples are next to it as `.top.tsv`.
`bench-envoy-gateway` and `bench-nginx` install the other two v2 implementations with the same
pinned versions as the upstream harness.

## Control-plane and availability tests

The rest of the v2 report (attached routes, route propagation, route changes, backend failover,
route scale) uses the upstream tools themselves, built at a pinned commit into one image and run
as an in-cluster Job with cluster-admin (`deploy/bench/Dockerfile.tools`, `tools-job.yaml`):

```bash
make bench-tools-image                                  # build + import portus/bench-tools:dev
make bench-attached-routes GATEWAYS=bench/portus        # BENCH_ROUTES=100: attachedRoutes up and down, status writes
make bench-probe GATEWAYS=bench/portus                  # BENCH_ROUTES=100: per-route propagation time
make bench-route-change GATEWAYS=bench/portus           # BENCH_ITERATIONS=10: traffic while the route flips; any non-200 fails
make bench-backend-failover GATEWAYS=bench/portus BENCH_TOOL_FLAGS='--log_output_level default:debug'
make bench-route-scale GATEWAYS=bench/portus            # pilot-load: BENCH_SCALE_NAMESPACES x BENCH_SCALE_ROUTES apps for BENCH_SCALE_SECONDS
```

Each run saves the tool log and the same `kubectl top` summary under `results/`. Things the tools
assume that the targets take care of: `attachedroutes` needs `attachedRoutes: 0` on the Gateway
before it starts; `backendfailover` applies Istio and Envoy Gateway policies whatever the
implementation (stub CRDs in `deploy/bench/stub-crds.yaml`, namespace `envoy`) and only reports
per-request results at debug level; `routechange` reuses the `app=backend` selector and must not
see the failover test's single-port pods (the target deletes them). ListenerSet scale is not
wired: the tool drives `XListenerSet`, Portus implements `ListenerSet` v1. Results: the
current head-to-head is `head-to-head-machine-2026-09-11.md` (Portus 0.2.3 vs agentgateway v1.5.0, three interleaved rounds on an apple/container machine, fortio for every ladder); `head-to-head-0.2.2-2026-09-10-k3d.md` (Portus 0.2.2 vs agentgateway v1.5.0 on Docker Desktop, evening, gated on a quiet host) and `head-to-head-2026-09-10-k3d.md` is the 0.2.1 record (Portus 0.2.1 vs agentgateway v1.5.0 on a
clean box, every table above). Older files: `portus-0.2.0-clean-box-2026-09-09.md` (Portus only),
`gateway-comparison-2026-09-06-k3d.md` and `gateway-api-bench-v2-2026-09-06.md` (superseded; their
propagation figures were measured with the catch-all route attached).

Rules that keep the comparison honest:

- **Release images only.** The `.dev` images are debug builds and run several times slower.
  Build with `make build` (or `deploy/docker/Dockerfile.*` directly) before benchmarking.
- **Same thread budget.** Portus sizes its Pingora worker pool from the pod's CPU request
  (`BENCH_CPU`); the other implementations run unlimited. Report the budget with the numbers.
- **One implementation at a time**, same node, same backend pods, back to back.
- `bench-portus` changes the chart's dataplane template for *every* Gateway (replicas and CPU
  request). Run `make bench-teardown` before a conformance run, or the suite's base Gateways
  will not schedule on a small node.
- **Remove the bench catch-all HTTPRoute before `probe` and `attachedroutes`**: with it attached
  the probe's requests succeed before its own route exists and "propagation" measures nothing
  (the 2026-09-06/07 propagation figures have this flaw).
- Numbers are only comparable with runs on the same machine. Raw tool output under
  `benchmarks/results/` is git-ignored; the reports in this directory carry the figures.
