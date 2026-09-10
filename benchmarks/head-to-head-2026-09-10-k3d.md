# Portus 0.2.1 vs agentgateway v1.5.0, clean box (2026-09-10)

> Superseded for the README by `head-to-head-0.2.2-2026-09-10-k3d.md` (Portus 0.2.2, same day, quieter box).

Both implementations on the same fresh k3d cluster in one session, one implementation at a time,
same backend pods, `kubectl top` sampled every 5 s. Docker Desktop 4.83 (Apple silicon, 10 CPUs,
VM 12 GiB, Resource Saver off), no other cluster or heavy process on the host. Portus **0.2.1 as
released** (public OCI chart, GHCR images), 3 dataplane pods with a 2-CPU request each (2 Pingora
worker threads per pod); agentgateway v1.5.0 from its own chart, 3 pods, no CPU limit. Raw logs
under `results/` (git-ignored); every figure is copied from them.

Supersedes `gateway-comparison-2026-09-06-k3d.md` and `gateway-api-bench-v2-2026-09-06.md`
(busier box, and their route-propagation figures were an artifact of the bench catch-all route
being attached during the probe; both are withdrawn). Portus-only clean-box numbers for 0.2.0 are
in `portus-0.2.0-clean-box-2026-09-09.md`.

## Traffic (empty responses, `howardjohn/hyper-server`, benchtool/fortio)

| Connections | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 | 10,923 | 0.16 ms | 8,811 | 0.26 ms |
| 8 | 42,779 | 0.45 ms | 35,485 | 0.60 ms |
| 32 | 84,078 | 1.71 ms | 66,939 | 2.45 ms |
| 64 | 111,092 | 1.98 ms | 88,259 | 3.61 ms |
| 128 | 120,080 | 3.77 ms | **94,730** | 6.29 ms |
| 256 | **125,535** | 7.23 ms | 87,924 | 15.4 ms |

Portus ahead at every rung, 1.24× at 1 connection and 1.33× at its peak. Proxy CPU across the
ladder: Portus 1,710 m mean / 3,225 m peak (3 pods), agentgateway 1,848 m / 4,068 m.

**Fixed 30,000 QPS on 64 connections for 30 s**:

| | p50 | p90 | p99 | Proxy CPU (3 pods) | Proxy memory |
|---|---|---|---|---|---|
| Portus | 0.17 ms | 0.35 ms | **1.94 ms** | 2,892 m | 128 Mi |
| agentgateway | 0.23 ms | 0.54 ms | 2.65 ms | 3,087 m | 105 Mi |

(Portus measured 0.62 ms p99 at 30k the night before on the same box; daytime runs are noisier.
Compare within this file only.)

### Two load generators at once (same day, fresh cluster, 20 s, both pods verified to run concurrently)

| Load | Portus 0.2.1 QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 2 × 128 connections | **115,981** | 8.8 ms | 81,039 | 17.4 ms |
| 2 × 256 connections | **99,214** | 20.0 ms | 60,240 | 35.7 ms |

A second generator does not raise Portus's aggregate above the single-generator ladder (the 10-CPU
node is saturated by clients, proxies and backends together; Portus pods sat at 3.4 of their 6
cores), but it shows the shape under more clients: Portus keeps its throughput, agentgateway loses a
quarter of it. Method trap: with the generator Job requesting 2 CPUs the second one could not be
scheduled next to Portus's three 2-CPU pods and ran *after* the first, which summed to a bogus 211k;
the request is now 1 CPU and the run records pod start/end times.

## Payloads (fortio echo backend, `/echo`, 64 connections, 10 s per rung)

One fortio pod per rung (`make bench-download|upload|https|h2`, `-httpbufferkb 2048`). Every rung
for both implementations returned 100 % `200` with all 64 connections kept alive.

**Download** (`GET /echo?size=N`):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **79,526** | 3.8 ms | 63,455 | 4.7 ms |
| 16 KB | **56,378** | 4.7 ms | 47,467 | 6.3 ms |
| 128 KB | **29,462** (3.9 GB/s) | 9.0 ms | 23,375 | 12.8 ms |
| 1 MiB | **5,496** (5.8 GB/s) | 41 ms | 4,597 (4.8 GB/s) | 57 ms |

**Upload** (`POST /echo`, body echoed back):

| Body | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **66,422** | 4.4 ms | 44,787 | 7.1 ms |
| 16 KB | **28,840** | 10.1 ms | 24,237 | 11.9 ms |
| 128 KB | 8,657 | 40 ms | 8,356 | 32 ms |
| 1 MiB | 4,650 | 76 ms | 4,484 | 60 ms |

**HTTPS** (TLS terminated at the Gateway, self-signed certificate, download ladder):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **73,694** | 3.7 ms | 56,696 | 5.2 ms |
| 16 KB | **48,957** | 5.5 ms | 43,960 | 6.5 ms |
| 128 KB | **24,454** | 9.7 ms | 18,329 | 15.5 ms |
| 1 MiB | **4,506** | 48 ms | 3,237 | 70 ms |

**HTTP/2** (h2c to the plain listener, download ladder):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **53,979** | 5.1 ms | 46,045 | 5.7 ms |
| 16 KB | **39,953** | 5.9 ms | 29,980 | 8.3 ms |
| 128 KB | **20,056** | 11.6 ms | 13,656 | 18.9 ms |
| 1 MiB | **4,051** | 52 ms | 2,082 | 117 ms |

At the largest rungs the client, proxies and backends share the box's 10 cores and the VM's
loopback network, so those rows say which proxy costs less per byte, not what a NIC would carry.

## Control plane and availability (gateway-api-bench tools)

The bench catch-all HTTPRoute was removed before `attachedroutes` and `probe` for both
implementations (with it attached, the probe measures nothing).

| Test | Portus 0.2.1 | agentgateway v1.5.0 |
|---|---|---|
| Attached routes, 100 routes | correct; 207 status writes; `attachedRoutes` reached 100 before the tool finished applying; controller 22 m mean / 51 m peak, 9 Mi | correct; 200 writes; add-all 39.4 s; controller 21 m / 33 m, 49 Mi |
| Route propagation, 200 routes | **29 ms mean / 76 ms max** per route after the first (first route 1.7 s while its new backend's endpoints came up: 290 non-200 polls, all on that route); controller 112 m / 179 m, 12 Mi; proxies 36 m | **14 ms mean / 21 ms max**, 0 non-200 polls; controller 38 m / 46 m, 57 Mi; proxies 12 m |
| Route changes, 60 flips under traffic | 86,583 requests, **0 errors** | 76,682 requests, **0 errors** |
| Backend failover, 1 of 4 endpoints blackholed × 5, no policy | **14 of 44,109 (0.03 %)** | 912 of 44,164 (2.1 %) |
| Backend failover with a Gateway `RetryPolicy` | **0 of 44,092** | not applicable |
| Route scale, 500 pods + routes over 10 min | controller **43 m mean / 94 m peak, 21 Mi** (26 Mi peak); proxies 24 m, 268 Mi | controller 18 m / 30 m, 88 Mi (110 Mi peak); proxies 7 m, 102 Mi |

agentgateway propagates a single route change about twice as fast: Portus spends a 10 ms quiet
period coalescing writes before it compiles, then streams the slice and waits for the data plane
to apply it (`COMPILE_QUIET` in `compiler.rs` is the knob). Portus uses a quarter of the
controller memory and, without any policy, loses 70× fewer requests when a backend disappears
(passive outlier ejection); agentgateway's controller burns less CPU under route churn.

## Method notes

- `howardjohn/hyper-server` returns `content-length: 0`; the payload ladders use fortio's echo
  server behind a `/echo` rule on the same Gateway (`deploy/bench/echo-backend.yaml`).
- benchtool cannot raise fortio's 128 KiB response buffer; the payload targets run fortio directly.
  The standalone fortio client is slower than benchtool's at small sizes, so the traffic and payload
  tables are not comparable with each other, only across the two columns.
- `bench-portus` retunes the dataplane template (3 replicas, 2-CPU request) for every Gateway.
  `make bench-teardown` restores the defaults.
