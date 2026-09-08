# gateway-api-bench "Part 2" suite: Portus vs agentgateway — 2026-09-06, local k3d

Method: the six control-plane and availability tests from
[howardjohn/gateway-api-bench Part 2](https://github.com/howardjohn/gateway-api-bench/blob/main/README-v2.md)
(`attachedroutes`, `probe`, `routechange`, `backendfailover`, pilot-load route scale), run
with the upstream tool sources (`deploy/bench/Dockerfile.tools`, `BENCH_REF=141add64d254`) as an
in-cluster Job. Traffic results are in `gateway-comparison-2026-09-06-k3d.md`. Numbers are only
comparable with each other, not with the published report (16-core bare metal there; a Docker VM
here).

## Environment

- k3d `portus-local`, one node: Docker Desktop VM on Apple silicon, 10 CPU / 16 GB, k3s v1.36.4.
- **Portus** `d4e4334` release image: 1 controller, 3 dataplane pods × 2 Pingora worker threads.
- **agentgateway** v1.5.0 (`cr.agentgateway.dev/charts/agentgateway`): 1 controller
  (`agentgateway-system`), 3 proxy pods (1 pod in the attached-routes/probe/route-scale runs, which
  do not depend on proxy count).
- One implementation's Gateway at a time (`bench/portus`, `bench/agentgateway`). The Portus
  controller stayed installed while agentgateway was measured (and vice versa), so a controller's
  CPU under another implementation's run shows what it spends reacting to routes it does not own.
- Resources are `kubectl top` samples every 5 s: mean and peak over the run.
- ListenerSet scale was **not run**: the tool drives `XListenerSet`; Portus implements `ListenerSet`
  (v1, Gateway API 1.6). Both agentgateway and Portus would need a different tool.

## Summary

| Test | Portus | agentgateway |
|---|---|---|
| Attached routes (100 routes) | ✅ status correct, 146 writes; controller 115 m mean / 333 m peak, 8 Mi | ✅ 200 writes; controller 35 m / 52 m, 46 Mi |
| Route propagation (200 routes) | ✅ 0 errors, sum 130 ms, worst 23.9 ms; ⚠️ controller 548 m mean / **2.5 cores** peak | ✅ 0 errors, sum 235 ms, worst 5.1 ms; controller 29 m / 39 m |
| Route changes | ✅ 0 errors in 13,938 + 69,526 requests (10 and 50 flips) | ✅ 0 errors in 12,436 + 63,262 requests |
| Route scale (500 pods, 10 min) | ⚠️ controller 475 m mean / 1.18 cores peak, 22 Mi; dataplane 16 m, 108 Mi | ✅ controller 18 m / 45 m, 72 Mi; proxy 4 m, 12 Mi |
| Backend failover, no retries | ⚠️ 20.0 % errors while one of four endpoints is down (plain round robin) | ✅ 4.0 % errors (healthy-first load balancing) |
| Backend failover, retries on | ✅ **0 / 44,201** with a `RetryPolicy` | not run (tool disables retries; upstream report shows near zero) |

Read: on 2026-09-06 agentgateway's control plane was the more efficient one under route churn by
a wide margin, and Portus's round robin kept sending to a dead endpoint. Both were fixed the next
day; see the rerun section below (controller 64 m / 50 m, failover 0.03 %).

## Attached routes

`attachedroutes --routes=100`: creates 100 HTTPRoutes, waits for `attachedRoutes` on the Gateway
listener to reach 100, deletes them, waits for 0. Both implementations converge; the "ready" and
"teardown" times (39.8 s / 39.4 s for both) are the tool's own client-side rate limiting, not the
controllers. `writes` is how many status writes the controller made.

| | writes | ready | teardown | controller CPU mean / peak | controller mem |
|---|---|---|---|---|---|
| Portus | 146 | 39.8 s | 39.4 s | 115 m / 333 m | 8 Mi |
| agentgateway | 200 | 39.8 s | 39.4 s | 35 m / 52 m | 46 Mi |

Portus batches (fewer writes than routes) because the Gateway reconciler recomputes the listener
counter once per debounce window. During the agentgateway run the Portus controller still used
46 m mean / 88 m peak reacting to routes bound to a Gateway it does not own.


## Route propagation

`probe --routes=200`: applies one HTTPRoute at a time and measures how long until it answers 200
through the Gateway. `runtime` is the sum of those waits, `max` the worst single route.

| | errors | sum of waits | worst route | controller CPU mean / peak | dataplane CPU mean / peak |
|---|---|---|---|---|---|
| Portus | 0 | 130 ms | 23.9 ms | 548 m / **2,498 m** | 24 m / 39 m |
| agentgateway | 0 | 235 ms | 5.1 ms | 29 m / 39 m | 11 m / 12 m |

Portus propagates a route in about 0.65 ms on average (the tool's polling floor), agentgateway in
1.2 ms; agentgateway's worst case is tighter. The cost is on the Portus controller: every HTTPRoute
event recompiles the whole config for every Gateway and every route reconcile requeues on a 5 s
timer, so 200 routes arriving in 40 s drove it to 2.5 cores. The Portus controller also burned
540 m mean during the agentgateway probe run for routes it does not serve.


## Route changes

`routechange --iterations=N`: continuous single-connection traffic through the Gateway while the
HTTPRoute flips every 200 ms between two backend ports (one with a response-header filter). Any
non-200 fails the run.

| | 10 flips | 50 flips | data plane CPU during 50 flips |
|---|---|---|---|
| Portus | 13,938 requests, 0 errors | 69,526 requests, 0 errors | 71 m (3 pods) |
| agentgateway | 12,436 requests, 0 errors | 63,262 requests, 0 errors | 108 m / 213 m peak (3 pods) |

Both implementations swap the route without a single failed request; Portus pushed ~10 % more
requests through the same single-connection client in the same wall time (its per-request latency
is lower, see the traffic report). Portus applies each change as a new config version about 100 ms
after the HTTPRoute write (dataplane log: `applied config v8`).


## Route scale

pilot-load `cluster` simulation: 10 namespaces × 50 applications, each a pod, Service and
HTTPRoute attached to the Gateway under test, ramped at ~1 pod/s for 10 minutes (600 s timeout;
the tool then churns the cluster). ~580 pods started in each run.

| | controller CPU mean / peak | controller mem mean / peak | data plane CPU mean / peak | data plane mem mean / peak |
|---|---|---|---|---|
| Portus | 475 m / 1,180 m | 22 Mi / 29 Mi | 16 m / 25 m | 108 Mi / 131 Mi |
| agentgateway | 18 m / 45 m | 72 Mi / 88 Mi | 4 m / 104 m | 12 Mi / 13 Mi |

Same story as propagation: the Portus controller spends ~26× the CPU of agentgateway's under
sustained route and endpoint churn, while using a third of the memory. The Portus data plane is
idle (no traffic in this test); its memory is the compiled route table for 500 routes × 3 pods.
Portus controller during the agentgateway run: 149 m mean / 367 m peak.


## Backend failover

`backendfailover`: a `backend` Service with three always-healthy pods and one that is blackholed
(iptables) and restored every ~22 s for five cycles, ~200 requests/s across varying paths, `retry:
attempts: 0` on the route (the tool's YAML is invalid against Gateway API 1.6 and is patched to
omit the block; both implementations therefore ran with their defaults, which is no retry for
both). Per-request status codes via `--log_output_level default:debug`.

| | requests | errors while one endpoint down | errors while all healthy | p50 / p99 |
|---|---|---|---|---|
| Portus (no policy) | 44,208 | 4,413 (20.0 %, all 502) | 0 | 0.35 ms / 1.3 ms |
| agentgateway | 44,177 | 881 (4.0 %, all 503) | 1 | 0.38 ms / 1.7 ms |
| Portus + `RetryPolicy` (maxRetries 3, connect-failure + gateway-error, on the Gateway) | 44,201 | **0** | 0 | 0.26 ms / 1.0 ms |

Portus's default is plain round robin with no passive health tracking, so a quarter of requests
hit the dead endpoint while it is down (20 % after phase boundaries). agentgateway's default load
balancer prefers endpoints that have recently succeeded and gets to 4 %. A Gateway-scoped
`RetryPolicy` takes Portus to zero errors with lower latency than the no-retry run (the retry
lands on a warm connection to a healthy pod). Neither implementation returned errors when all
four endpoints were healthy.

Data-plane resources during the test (3 pods): Portus 41 m / 119 Mi, agentgateway 45 m / 27 Mi.


## Rerun after the 2026-09-07 fixes (commit `c3ca58a`, release image `rel-1788781167`)

Same box, same shapes. The two backlog items below were fixed the next day: the controller is
now event-driven with no timed requeues and a deterministic compile, and the data plane ejects
failing endpoints passively (`outlier.rs`). Only the three tests those changes target were rerun.

| Test | 2026-09-06 | 2026-09-07 |
|---|---|---|
| Route propagation (200 routes), controller CPU mean / peak | 548 m / 2,498 m | **64 m / 116 m** |
| Route propagation, sum of waits / worst route | 130 ms / 23.9 ms | 76 ms / 1.7 ms |
| Route scale (500 pods, 10 min), controller CPU mean / peak | 475 m / 1,180 m | **50 m / 71 m** |
| Route scale, controller memory | 22 Mi | 21 Mi |
| Backend failover, no policy, errors while 1 of 4 endpoints down | 4,413 / 44,208 (20.0 %) | **12 / 44,120 (0.03 %)** |
| Backend failover, p50 / p99 | 0.35 ms / 1.3 ms | 0.45 ms / 1.5 ms |

Failover: 15 ejections over the five outages (one per data-plane pod per outage, each
lasting longer than the last: 10 s, 20 s, 30 s), so the per-phase error count fell 4 → 3 → 1 →
1 → 3. agentgateway's default was 4.0 %; a Gateway `RetryPolicy` still gives 0. The controller
under route churn is now in agentgateway's range (its controller: 29 m probe, 18 m route
scale) rather than 20–90× above it.

Two caveats. The route-scale sampler restarted seven minutes in (the host ran out of memory and
killed the driver, not the test), so its numbers cover the last seven of ten minutes. The first
failover run of the day recorded 0 errors with **no** connect attempt to the blackholed pod in
any data plane log, which cannot be right; it was discarded and the run above, watched live
(endpoint set, data plane failures, tool phases), is the figure.


Raw tool logs and `kubectl top` samples for every run are kept locally under `benchmarks/results/`
(git-ignored); the tables above are copied from them.

## Harness notes (things that produced wrong results first)

- **Failover leftovers break route-change.** `backendfailover` leaves `backend-healthy` (Deployment)
  and `backend-unhealthy` (Pod) in `default`, all labelled `app=backend`, listening on 8080 only.
  `routechange` reuses a `backend` Service selecting `app=backend` and flips its target port to
  8081, so both proxies get connection refused on those pods: Portus 502, agentgateway 503. Every
  route-change run before 23:00 failed for this reason.
  Delete the failover pods before route-change.
- `attachedroutes` needs the Gateway to report `attachedRoutes: 0` before it starts
  (`bench-attached-routes` waits for it).
- `backendfailover` applies an Istio `DestinationRule` and an Envoy Gateway `BackendTrafficPolicy`
  unconditionally: stub CRDs (`deploy/bench/stub-crds.yaml`) and an `envoy` namespace are created.
- pilot-load ramps about one pod per second on this node; 500 pods need the full 10 minutes.
- The tools report to VictoriaLogs only; the debug log level is the only way to get per-request
  results out of `backendfailover`.

## Backlog items raised (both closed 2026-09-07, see the rerun section)

1. **Controller CPU under route churn** (probe 2.5 cores peak, route scale 1.2 cores): HTTPRoute
   reconciles requeue every 5 s regardless of change; every route or EndpointSlice event recompiles
   all Gateways. Fix: `await_change` requeue, Service/EndpointSlice → route trigger instead of
   timers, per-Gateway compile scope. Also skip HTTPRoutes whose parents are all foreign Gateways.
2. **Passive endpoint health in the load balancer**: prefer endpoints without a recent connect
   failure (agentgateway's default) or eject for a short window; today only a `RetryPolicy` or
   `CircuitBreakerPolicy` changes behaviour.
