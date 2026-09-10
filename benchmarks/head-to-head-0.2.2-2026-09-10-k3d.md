# Portus 0.2.2 vs agentgateway v1.5.0, quiet box (2026-09-10, evening)

Both implementations on the same k3d cluster in one session, one implementation at a time, same
backend pods, `kubectl top` sampled every 5 s. Docker Desktop 4.83 (Apple silicon, 10 CPUs, VM
12 GiB, Resource Saver off), only this cluster on the box. Portus **0.2.2 as released** (public OCI
chart, GHCR images; Pingora 0.9.0), 3 dataplane pods with a 2-CPU request each (2 Pingora worker
threads per pod); agentgateway v1.5.0 from its own chart, 3 pods, no CPU limit. Raw logs under
`results/` (git-ignored); every figure is copied from them.

The run was gated: it started only with the host 1-minute load under 3 and after a fortio smoke
test through Portus cleared 100k QPS (119,243 measured), and the load average was written to the
log before every ladder. An earlier attempt the same evening, while other builds were running on
the host, put Portus at 20–33k QPS with its pods below one core each; that run was discarded and is
the reason for the gate.

Supersedes `head-to-head-2026-09-10-k3d.md` (Portus 0.2.1, daytime, same method). Both files are
kept: the earlier one is the record for 0.2.1 and its agentgateway column was measured on a busier
box (agentgateway peaked at 94,730 there and 117,529 here; Portus moved from 125,535 to 132,997).
Compare only within one file.

## Traffic (empty responses, `howardjohn/hyper-server`, benchtool/fortio)

| Connections | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 | 10,950 | 0.17 ms | 9,007 | 0.19 ms |
| 8 | 42,051 | 0.45 ms | 37,224 | 0.54 ms |
| 32 | 90,551 | 1.29 ms | 83,028 | 1.83 ms |
| 64 | 114,208 | 1.96 ms | 103,704 | 2.82 ms |
| 128 | 127,435 | 3.21 ms | 113,305 | 4.52 ms |
| 256 | **132,997** | 6.34 ms | **117,529** | 7.42 ms |

Portus ahead at every rung, 1.22× at 1 connection and 1.13× at the peak, with a lower p99
throughout. Proxy CPU across the ladder: Portus 1,850 m mean / 3,779 m peak (3 pods), agentgateway
2,394 m / 4,357 m.

**Fixed 30,000 QPS on 64 connections for 30 s**:

| | p50 | p90 | p99 | Proxy CPU (3 pods) | Proxy memory |
|---|---|---|---|---|---|
| Portus | 0.16 ms | 0.28 ms | **0.58 ms** | 2,739 m | 137 Mi |
| agentgateway | 0.19 ms | 0.34 ms | 0.70 ms | 3,112 m | 143 Mi |

### Two load generators at once (both generator pods verified to run concurrently)

| Load | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 2 × 64 connections | **103,920** | 2.03 ms | 87,040 | 3.71 ms |
| 2 × 128 connections | **119,235** | 3.48 ms | 101,928 | 5.26 ms |
| 2 × 256 connections | **124,810** | 6.80 ms | 104,911 | 9.30 ms |
| 2 × 512 connections | **120,575** | 15.9 ms | 101,006 | 19.5 ms |

Proxy CPU: Portus 2,259 m mean / 4,192 m peak; agentgateway 2,717 m / 4,921 m. A second generator
does not lift either implementation above its single-generator ladder: the 10-CPU node is
saturated by clients, proxies and backends together.

## Payloads (fortio echo backend, `/echo`, 64 connections, 10 s per rung)

One fortio pod per rung (`make bench-download|upload|https|h2`, `-httpbufferkb 2048`). Every rung
returned 100 % `200` with all 64 connections kept alive, except one `503` in agentgateway's HTTPS
1 KB rung (1 of 713,036).

**Download** (`GET /echo?size=N`):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **80,293** | 3.6 ms | 74,666 | 3.9 ms |
| 16 KB | 58,138 | 4.5 ms | 58,509 | 4.7 ms |
| 128 KB | 33,717 (4.4 GB/s) | 6.8 ms | 33,973 | 7.4 ms |
| 1 MiB | 5,565 (5.8 GB/s) | 38 ms | **6,985** (7.3 GB/s) | 30 ms |

Proxy CPU over the ladder: Portus 3,206 m mean, agentgateway 3,874 m; memory 178 Mi vs 233 Mi mean
(501 Mi peak for agentgateway).

**Upload** (`POST /echo`, body echoed back):

| Body | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | 68,510 | 4.3 ms | 69,993 | 4.1 ms |
| 16 KB | 29,220 | 10.2 ms | **33,119** | 8.3 ms |
| 128 KB | 9,270 | 38 ms | **10,000** | 28 ms |
| 1 MiB | 5,199 | 66 ms | 5,343 | 49 ms |

**HTTPS** (TLS terminated at the Gateway, self-signed certificate, download ladder):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | **76,524** | 3.6 ms | 71,293 | 4.1 ms |
| 16 KB | 52,487 | 4.8 ms | 53,138 | 5.2 ms |
| 128 KB | 23,461 | 9.9 ms | **26,043** | 9.8 ms |
| 1 MiB | 3,848 | 62 ms | **5,318** | 39 ms |

**HTTP/2** (h2c to the plain listener, download ladder):

| Response | Portus QPS | Portus p99 | agentgateway QPS | agentgateway p99 |
|---|---|---|---|---|
| 1 KB | 60,749 | 4.0 ms | 59,199 | 4.4 ms |
| 16 KB | 39,813 | 5.8 ms | **45,186** | 5.5 ms |
| 128 KB | 19,210 | 11.6 ms | **22,224** | 10.7 ms |
| 1 MiB | 3,465 | 64 ms | **4,031** | 48 ms |

Reading the payload tables honestly: Portus leads on 1 KB, the two are level from 16 KB to 128 KB on
plain HTTP, and agentgateway leads on the 1 MiB rungs and on the mid-size upload and TLS/h2 rungs,
while using 15–25 % more CPU and about twice the memory (up to 536 Mi against 296 Mi). At those
rungs the client, three proxies and five backends share the box's 10 cores and the VM's loopback
network; Portus's pods are capped by their 2-thread worker pools (2-CPU request), agentgateway's
are not, and the gap closes when the box is otherwise idle: a standalone 1 MiB HTTPS run (six
alternating runs, `BENCH_SIZES=1048576`) gave Portus 5,409 QPS median the same evening. The
in-ladder 1 MiB row inherits a hot echo backend from the three smaller rungs before it. The rows
say which proxy costs less per byte under contention, not what a NIC would carry.

## Control plane and availability (gateway-api-bench tools)

The bench catch-all HTTPRoute was removed before `attachedroutes` and `probe` for both
implementations (with it attached, the probe measures nothing).

| Test | Portus 0.2.2 | agentgateway v1.5.0 |
|---|---|---|
| Attached routes, 100 routes | correct; 208 status writes; add-all 39.4 s; controller 23 m mean / 49 m peak, 9 Mi | correct; 200 writes; add-all 39.4 s; controller 19 m / 28 m, 129 Mi |
| Route propagation, 200 routes | **23.3 ms mean / 41 ms max** per route after the first (first route 1.7 s while its new backend's endpoints came up: 291 non-200 polls, all on that route); controller 107 m / 192 m, 12 Mi; proxies 35 m | **14.0 ms mean / 19.6 ms max**, 0 non-200 polls; controller 34 m / 42 m, 136 Mi; proxies 9 m |
| Route changes, 60 flips under traffic | 85,218 requests, **0 errors** | 78,562 requests, **0 errors** |
| Backend failover, 1 of 4 endpoints blackholed × 5, no policy | **11 of 44,112 (0.025 %)** | 887 of 44,116 (2.0 %) |
| Backend failover with a Gateway `RetryPolicy` | **0 of 44,114** | not applicable |
| Route scale, 500 pods + routes over 10 min | controller **44 m mean / 95 m peak, 21 Mi** (28 Mi peak); proxies 20 m, 254 Mi | controller 16 m / 27 m, 172 Mi (191 Mi peak); proxies 7 m, 147 Mi |

agentgateway still propagates a single route change faster: Portus 0.2.2 spends a 2 ms quiet period
coalescing writes (10 ms in 0.2.1, which measured 29 ms here), then compiles, streams the slice and
waits for the data plane to apply it; the remaining 9 ms is that pipeline, not the quiet period.
Portus uses an eighth of the controller memory and, without any policy, loses 80× fewer requests
when a backend disappears (passive outlier ejection); agentgateway's controller burns less CPU under
route churn.

## Method notes

- `howardjohn/hyper-server` returns `content-length: 0`; the payload ladders use fortio's echo
  server behind a `/echo` rule on the same Gateway (`deploy/bench/echo-backend.yaml`).
- benchtool cannot raise fortio's 128 KiB response buffer; the payload targets run fortio directly.
  The standalone fortio client is slower than benchtool's at small sizes, so the traffic and payload
  tables are not comparable with each other, only across the two columns.
- `bench-portus` retunes the dataplane template (3 replicas, 2-CPU request) for every Gateway.
  `make bench-teardown` restores the defaults.
- Never quote a run without checking the host first: `k3d cluster list` must show only this cluster
  and the host load must be low. Version comparisons need interleaving on the same box within
  minutes; a single 10 s rung cannot resolve a 10 % difference here.
