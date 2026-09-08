# Portus vs agentgateway — 2026-09-06, local k3d

Method: [howardjohn/gateway-api-bench](https://github.com/howardjohn/gateway-api-bench) traffic tests
(see `README.md` in this directory). Numbers here are **only comparable with each other**: a different machine gives different
absolute numbers.

## Environment

- k3d `portus-local`, one node: Docker Desktop VM on Apple silicon, **10 CPU / 16 GB**, k3s v1.36.4.
- Backend: `howardjohn/hyper-server` × 5 (100m CPU request each).
- Load generator: `howardjohn/benchtool` (fortio) as a Job on the same node, 10 s per connection
  level at unlimited QPS, then 30 s at a fixed 30,000 QPS on 64 connections.
- One implementation at a time, back to back, same backend pods. Resources sampled with
  `kubectl top` every 5 s during each run (mean and peak over the run).
- **Portus** `d4e4334`, release image, 3 dataplane pods × **2 Pingora worker threads** (CPU request
  `2`, which is what sizes the thread pool; no CPU limit).
- **agentgateway** v1.5.0 (`cr.agentgateway.dev/charts/agentgateway`), 3 pods, no requests/limits,
  so each pod may use every core.

## Throughput ladder (unlimited QPS, 10 s per level)

| Conns | Portus QPS | Portus p50 | Portus p99 | agentgateway QPS | agentgateway p50 | agentgateway p99 |
|---|---|---|---|---|---|---|
| 1 | 10,950 | 0.088 ms | 0.163 ms | 9,155 | 0.107 ms | 0.195 ms |
| 2 | 19,852 | 0.098 ms | 0.192 ms | 14,852 | 0.129 ms | 0.254 ms |
| 4 | 27,258 | 0.139 ms | 0.299 ms | 21,545 | 0.175 ms | 0.404 ms |
| 8 | 41,659 | 0.179 ms | 0.451 ms | 32,740 | 0.226 ms | 0.600 ms |
| 16 | 61,048 | 0.236 ms | 0.727 ms | 48,253 | 0.286 ms | 1.299 ms |
| 32 | 87,239 | 0.317 ms | 1.450 ms | 59,113 | 0.399 ms | 2.887 ms |
| 64 | 109,179 | 0.495 ms | 1.991 ms | 71,994 | 0.681 ms | 4.378 ms |
| 128 | 112,173 | 0.940 ms | 4.800 ms | 76,206 | 1.466 ms | 7.038 ms |
| 256 | **119,372** | 1.907 ms | 7.154 ms | **76,462** | 2.889 ms | 12.878 ms |

Resources during the ladder (3 data-plane pods summed; control plane separately):

| | CPU mean | CPU peak | Mem mean | Mem peak |
|---|---|---|---|---|
| Portus dataplanes | 1,285 m | 3,576 m | 69.5 Mi | 116 Mi |
| agentgateway proxies | 2,119 m | 4,453 m | 45.2 Mi | 87 Mi |
| Portus controller | 3 m | 15 m | 9 Mi | 9 Mi |
| agentgateway controller | 4 m | 15 m | 67 Mi | 68 Mi |

## Fixed 30,000 QPS, 64 connections, 30 s

| | achieved QPS | p50 | p90 | p99 | data-plane CPU mean / peak | data-plane mem mean / peak |
|---|---|---|---|---|---|---|
| Portus | 29,997 | 0.169 ms | 0.297 ms | **0.622 ms** | 3,198 m / 3,917 m | 130 Mi / 136 Mi |
| agentgateway | 29,998 | 0.297 ms | 0.632 ms | 1.901 ms | 3,804 m / 4,453 m | 98 Mi / 102 Mi |

## Findings

- Portus is ahead at every connection level: 1.2× at 1 connection, **1.56× at peak** (119k vs
  76k QPS), with lower p50 and p99 throughout (p99 at 256 connections 7.2 ms vs 12.9 ms).
- At a fixed 30k QPS Portus's p99 is 3× tighter (0.62 ms vs 1.90 ms) while using ~16% less CPU
  (3.2 vs 3.8 cores). Memory is the one place agentgateway is leaner: ~30% less at 30k QPS.
- Portus did this on 6 worker threads total; agentgateway could use all 10 cores per pod. The
  CPU-per-request gap is therefore understated in Portus's favour, not overstated.
- Control planes were flat during traffic (a few millicores each). Portus's controller uses ~7×
  less memory (9 Mi vs 67 Mi).

## What the first attempt got wrong (kept for the record)

The first pass measured Portus at 34.6k QPS peak and looked like a 1.7× *deficit*. Two causes,
both ours:

1. The **debug-profile dev image** (the conformance build) was benchmarked. Release is ~3.5× faster.
2. The idle Portus controller showed 165–328 millicores against agentgateway's 100–187. `/metrics`
   traced it to one HTTPRoute reconciled ~190 times a second: both controllers rewrote
   `status.parents` on a route bound to the other's Gateway (SSA replaces the atomic list), a real
   bug fixed in `d4e4334`. After the fix both controllers idle at a few millicores.

A third bug fell out of the same session: a 5-failure circuit breaker and a 128-connection limit
existed on every backend with no policy attached (also fixed in `d4e4334`).

## Raw output

The benchtool and `kubectl top` logs behind these tables are kept locally under `benchmarks/results/`
(git-ignored); every figure above is copied from them.
