# Rama vs Pingora on the same core (2026-09-15, one round)

The two network-stack adapters of Portus 0.2.3+ compared on the same data plane core, the same
10 vCPU apple/container machine, the same 3 pods × 2 CPU and the same fortio ladders, Pingora then
Rama. One round: differences under 5 % are noise.

Rama against Pingora, one round on the same 10 vCPU machine as the tables above, Pingora then Rama on the same 3 pods × 2 CPU (fortio, 10 s per rung, all requests 200). Rama ran with other load on the box (load average 7.4 against 2.7 for the Pingora pass), so its numbers are if anything understated; a single round still means differences under 5 % are noise.

| Ladder | Rung | Pingora | Rama | Δ |
|---|---|---|---|---|
| Traffic (bare `GET /`, by connections) | 64 | 135,987 | 149,683 | +10 % |
| | 128 | 149,926 | 169,209 | +13 % |
| | 256 | 148,653 | 163,788 | +10 % |
| Download (64 connections, by response size) | 1 KiB | 88,970 | 91,627 | +3 % |
| | 16 KiB | 69,336 | 75,649 | +9 % |
| | 128 KiB | 38,578 | 40,449 | +5 % |
| | 1 MiB | 6,496 | 7,317 | +13 % |
| Upload (POST, echoed) | 1 KiB | 75,840 | 84,721 | +12 % |
| | 16 KiB | 32,335 | 36,934 | +14 % |
| | 128 KiB | 9,819 | 9,778 | 0 % |
| | 1 MiB | 5,142 | 5,374 | +5 % |
| HTTPS download | 1 KiB | 81,094 | 86,925 | +7 % |
| | 16 KiB | 59,729 | 67,483 | +13 % |
| | 128 KiB | 25,914 | 28,960 | +12 % |
| | 1 MiB | 4,154 | 5,427 | +31 % |
| HTTP/2 download | 1 KiB | 60,484 | 66,619 | +10 % |
| | 16 KiB | 45,696 | 52,156 | +14 % |
| | 128 KiB | 21,276 | 23,329 | +10 % |
| | 1 MiB | 3,781 | 4,602 | +22 % |

Resources over the same round, summed across the three dataplane pods (CPU in millicores, memory in MiB):

| Ladder | Pingora CPU mean / peak | Rama CPU mean / peak | Pingora memory mean / peak | Rama memory mean / peak |
|---|---|---|---|---|
| Traffic | 1,323 / 2,691 | 1,257 / 3,208 | 41 / 68 | 31 / 85 |
| Download | 3,246 / 3,563 | 3,036 / 3,273 | 136 / 282 | 120 / 138 |
| Upload | 2,600 / 3,237 | 2,436 / 3,184 | 184 / 282 | 123 / 152 |
| HTTPS | 2,213 / 2,973 | 2,264 / 3,035 | 235 / 331 | 140 / 152 |
| HTTP/2 | 3,063 / 3,499 | 2,716 / 3,236 | 369 / 432 | 126 / 167 |

The Rama adapter uses Rama 0.4 unpatched for TCP, TLS, the HTTP/1 and HTTP/2 client connections and the server. The upstream connection pool is Portus's own: one shard of idle HTTP/1 connections per backend, TLS policy and protocol, a rotating set of HTTP/2 connections per gRPC or h2c backend, the client read buffer capped at 64 KiB, and TCP_NODELAY on every socket. Its decisions are exported as `proxy_upstream_pool_events_total{event}` on the metrics port.

