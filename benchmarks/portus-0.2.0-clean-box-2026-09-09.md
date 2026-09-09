# Portus 0.2.0 on a clean box (2026-09-09)

Portus **0.2.0 as released**: the public OCI chart and GHCR images, nothing built locally.
Fresh k3d cluster (`rancher/k3s:v1.36.4-k3s1`) on Docker Desktop 4.83 (Apple silicon, 10 CPUs,
VM memory 12 GiB, Resource Saver off), no other cluster or heavy process on the host. Bench
Gateway with 3 dataplane pods, each with a 2-CPU request (2 Pingora worker threads); load
generator and backends in-cluster as in the other reports. Raw logs under `results/`
(git-ignored); every figure below is copied from them.

Only Portus was measured in this run. The 2026-09-06 head-to-head with agentgateway
(`gateway-comparison-2026-09-06-k3d.md`, `gateway-api-bench-v2-2026-09-06.md`) was taken on a
busier box, so the numbers here are **not** directly comparable to that table; agentgateway
gets the same clean-box run before the comparison is refreshed as a set.

## Traffic (empty responses, `howardjohn/hyper-server`, benchtool/fortio)

Connection ladder, unlimited QPS, 10 s per rung:

| Connections | QPS | p50 | p90 | p99 |
|---|---|---|---|---|
| 1 | 11,087 | 0.09 ms | 0.10 ms | 0.13 ms |
| 8 | 42,078 | 0.18 ms | 0.30 ms | 0.46 ms |
| 32 | 90,431 | 0.30 ms | 0.61 ms | 1.34 ms |
| 64 | 118,597 | 0.46 ms | 0.96 ms | 1.94 ms |
| **128** | **134,638** | 0.84 ms | 1.84 ms | 2.99 ms |
| 256 | 134,462 | 1.71 ms | 3.37 ms | 6.46 ms |

Proxy pods 1,683 m mean / 3,408 m peak across the ladder. Fixed **30,000 QPS on 64 connections
for 30 s**: p50 0.15 ms, p90 0.27 ms, **p99 0.62 ms**, proxy 3,126 m mean (3 pods), 126 Mi.

## Payloads (fortio echo backend, `/echo`)

64 connections, unlimited QPS, 10 s per rung, one fortio pod per rung
(`make bench-download|upload|https|h2`; `-httpbufferkb 2048`, perfect keepalive and 100 %
`200` on every rung). The standalone fortio client is itself slower than benchtool's at small
sizes (1 KB: 62.7k vs 87.2k QPS against the same proxy), so compare rows within this section,
not against the traffic table.

**Download** (`GET /echo?size=N`):

| Response | QPS | p50 | p99 | Payload throughput |
|---|---|---|---|---|
| 1 KB | 62,699 | 0.77 ms | 5.3 ms | 64 MB/s |
| 16 KB | 59,991 | 0.84 ms | 4.4 ms | 983 MB/s |
| 128 KB | 34,074 | 1.6 ms | 7.1 ms | 4.5 GB/s |
| 1 MiB | 6,279 | 9.0 ms | 33.6 ms | 6.6 GB/s |

**Upload** (`POST /echo`, body echoed back, so bytes cross the proxy twice):

| Body | QPS | p50 | p99 |
|---|---|---|---|
| 1 KB | 69,388 | 0.74 ms | 4.0 ms |
| 16 KB | 29,830 | 1.6 ms | 9.8 ms |
| 128 KB | 8,982 | 4.3 ms | 39 ms |
| 1 MiB | 5,076 | 7.8 ms | 66 ms |

**HTTPS** (TLS terminated on the Gateway's 443 listener, self-signed certificate, download ladder):

| Response | QPS | p50 | p99 |
|---|---|---|---|
| 1 KB | 78,724 | 0.69 ms | 3.4 ms |
| 16 KB | 55,881 | 0.91 ms | 4.5 ms |
| 128 KB | 26,978 | 2.0 ms | 8.4 ms |
| 1 MiB | 4,898 | 11.5 ms | 42 ms |

**HTTP/2** (h2c to the plain listener, download ladder):

| Response | QPS | p50 | p99 |
|---|---|---|---|
| 1 KB | 63,974 | 0.80 ms | 3.9 ms |
| 16 KB | 44,015 | 1.2 ms | 5.3 ms |
| 128 KB | 22,304 | 2.4 ms | 9.8 ms |
| 1 MiB | 4,103 | 13.5 ms | 51 ms |

Proxy CPU during the payload ladders sat at 2.0–2.4 cores mean across the 3 pods (2.7–2.9
peak); the echo backends used about the same. At 1 MiB the client, proxy and backends share the
box's 10 cores and the VM's loopback network, so the large rungs say "the proxy is not the
bottleneck", not what a NIC would deliver.

## Control plane and availability (gateway-api-bench tools)

| Test | Result | Controller CPU mean / peak |
|---|---|---|
| Attached routes, 100 | correct up and down; add-all 39 s, remove-all 20 s, **417 status writes** | 19 m / 56 m, 8 Mi |
| Route propagation, 200 routes | **104–109 ms per route**, first 1.8 s, 287 non-200 polls | 102 m / 157 m, 11 Mi |
| Route changes, 60 flips | 86,856 requests, 0 errors | 75 m; proxies 17 m |
| Backend failover, no policy | 44,091 requests, 12 × 502 (0.027 %) over 5 blackhole cycles | 3 m / 18 m; proxies 82 m / 288 m |
| Backend failover, Gateway `RetryPolicy` | 44,107 requests, 0 errors | — |
| Route scale, 500 pods + routes, 10 min | pilot-load exit 0 | 49 m / 95 m, 19 Mi mean / 25 Mi peak; proxies 19 m, 279 Mi |

Two findings, fixed on `main` the same night (re-measured below):

- **The 0.4 ms propagation figure in the 2026-09-06/07 reports was an artifact.** Those runs
  left the bench catch-all HTTPRoute (`bench/portus`, no hostname) attached, so the probe's
  requests were answered before its own route existed. This run removed that route first; real
  propagation is ~105 ms per route, almost all of it the controller's 100 ms compile debounce.
  agentgateway's 1.2 ms in the same table has the same flaw.
- **Status writes tripled** (417 vs 146 on 2026-09-06): `Programmed` flips to False on every
  recompile until the data planes ack the new fingerprint, and the Gateway reconciled 1,051
  times for 200 routes. Correct, but noisy.

### After the fixes (same box, controller built from `main`, dataplanes still 0.2.0)

| Test | 0.2.0 | `main` |
|---|---|---|
| Route propagation, 200 routes | 104–109 ms per route, first 1.8 s, 287 non-200 polls | **15–42 ms per route (mean 27 ms), first 20 ms, 0 non-200 polls** |
| Attached routes, 100 | 417 status writes | **212 status writes** (one per `attachedRoutes` change, up and down) |
| `Programmed` condition flips during both tests | one per recompile | **0** (3 total in the run: initial provisioning and Gateway re-creation) |

The compile loop now waits for writes to go quiet for 10 ms (capped at 100 ms under continuous churn)
instead of sleeping 100 ms after every wake, and a Gateway whose data planes still run the previous
slice stays `Programmed=True` for 10 s while the new one streams to them, with `Programmed` events
published only when the answer moves.

## Harness notes

- `howardjohn/hyper-server` returns `content-length: 0` for everything; the payload ladders use
  fortio's echo server (`deploy/bench/echo-backend.yaml`, `-maxpayloadsizekb 2048`) behind a
  `/echo` rule on the same Gateway.
- benchtool cannot raise fortio's 128 KiB response buffer; above it the fast client closes every
  connection, exhausts client ports and aborts, so the 128 KB / 1 MB rows of any benchtool run
  are invalid. The `bench-download|upload|https|h2` targets run fortio directly with
  `-httpbufferkb 2048` and record `Sockets used` per rung as the keepalive check.
- Remove the bench catch-all HTTPRoute before `probe` and `attachedroutes`, or both measure the
  catch-all.
