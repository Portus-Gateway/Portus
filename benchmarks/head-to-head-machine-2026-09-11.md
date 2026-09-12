# Portus 0.2.3 vs agentgateway v1.5.0 on an apple/container machine (2026-09-11, three rounds)

**Current README numbers.** Portus is the 0.2.3 build (0.2.2 plus: worker threads sized from the
node instead of the CPU request, access log off, 1 MiB / 4 MiB h2 windows, constant keepalive pool
cap), measured from a local build of the release commit minus the keepalive-pool-cap change, which
landed after the run and only lowers how many idle upstream connections a pod keeps (the bench
never exceeds 256); agentgateway is v1.5.0 from its chart.
The previous record, 0.2.2 vs agentgateway on Docker Desktop, is `head-to-head-0.2.2-2026-09-10-k3d.md`.

Box: `container machine` (Virtualization.framework), 10 vCPUs, 12 GiB, custom Kata 6.18 kernel
with the Kubernetes networking options, Ubuntu 24.04 + systemd rootfs, k3s v1.35 on containerd,
pods at MTU 65485 (flannel on the `node0` dummy). See `deploy/machine/README.md`. Same backend
pods for both, one implementation at a time, three interleaved rounds (Portus, agentgateway,
repeat), fortio for every ladder including bare traffic (`make bench-traffic-fortio`), one fortio
pod per rung. Portus 3 pods × 2-CPU request (10 worker threads each); agentgateway 3 pods, no
limit. Raw logs under `results/` (git-ignored). Medians over the three rounds; per-round values
shown so the spread is visible.

## Traffic (bare `GET /`, hyper-server backend, fortio, 10 s per rung)

| Connections | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead |
|---|---|---|---|---|---|
| 64 | 121,122 / 116,429 / 111,956 | **116,429** | 96,003 / 76,554 / 99,600 | 96,003 | +21 % |
| 128 | 144,170 / 122,086 / 123,105 | **123,105** | 101,067 / 65,371 / 106,457 | 101,067 | +22 % |
| 256 | 147,130 / 123,230 / 126,070 | **126,070** | 89,827 / 75,739 / 108,590 | 89,827 | +40 % |

Proxy CPU over the ladder (3 pods): Portus 1.81–1.87 cores mean / 3.3–3.5 peak, 38–43 Mi;
agentgateway 0.95–2.06 cores mean / 3.4–3.8 peak, 36–50 Mi.

Fixed 30,000 QPS on 64 connections for 30 s: fortio's default histogram resolution is 1 ms, so it
reports p99 as 0.99 ms for Portus in all three rounds and 1.00 / 1.76 / 1.00 ms for agentgateway;
use benchtool's run (or fortio `-r 0.0001`) for the sub-millisecond tail. Earlier the same day, on
this machine, benchtool measured Portus at 0.35–0.37 ms and agentgateway at 0.82 ms.

## Payloads (fortio echo backend, 64 connections, 10 s per rung; QPS)

| Rung | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead |
|---|---|---|---|---|---|
| Download 1 KB | 91,702 / 86,774 / 87,722 | **87,722** | 68,367 / 63,892 / 67,598 | 67,598 | +30 % |
| Download 16 KB | 69,617 / 59,257 / 58,706 | **59,257** | 51,562 / 47,911 / 55,320 | 51,562 | +15 % |
| Download 128 KB | 39,060 / 29,954 / 29,420 | **29,954** | 27,136 / 26,314 / 30,708 | 27,136 | +10 % |
| Download 1 MiB | 6,501 / 5,206 / 5,019 | 5,206 | 5,633 / 5,003 / 5,749 | **5,633** | −8 % |
| Upload 1 KB | 76,212 / 66,089 / 64,562 | **66,089** | 59,212 / 55,682 / 58,495 | 58,495 | +13 % |
| Upload 16 KB | 33,217 / 29,578 / 28,371 | **29,578** | 29,062 / 27,618 / 27,940 | 27,940 | +6 % |
| Upload 128 KB | 9,885 / 8,160 / 8,132 | 8,160 | 8,164 / 7,922 / 7,884 | 7,922 | +3 % |
| Upload 1 MiB | 5,158 / 4,380 / 4,330 | 4,380 | 4,395 / 4,249 / 4,180 | 4,249 | +3 % |
| HTTPS 1 KB | 78,197 / 76,997 / 74,861 | **76,997** | 60,560 / 60,088 / 59,545 | 60,088 | +28 % |
| HTTPS 16 KB | 58,578 / 56,831 / 52,866 | **56,831** | 49,802 / 47,844 / 48,295 | 48,295 | +18 % |
| HTTPS 128 KB | 26,045 / 25,357 / 19,890 | **25,357** | 22,549 / 22,294 / 16,528 | 22,294 | +14 % |
| HTTPS 1 MiB | 4,319 / 4,200 / 3,530 | 4,200 | 4,182 / 4,110 / 4,103 | 4,110 | +2 % |
| h2c 1 KB | 65,953 / 64,172 / 56,747 | **64,172** | 49,453 / 50,186 / 48,084 | 49,453 | +30 % |
| h2c 16 KB | 51,370 / 49,448 / 43,315 | **49,448** | 38,666 / 41,032 / 40,279 | 40,279 | +23 % |
| h2c 128 KB | 23,715 / 22,431 / 20,282 | **22,431** | 19,292 / 19,691 / 19,641 | 19,641 | +14 % |
| h2c 1 MiB | 4,400 / 4,173 / 3,700 | **4,173** | 3,539 / 3,538 / 3,398 | 3,538 | +18 % |

Proxy resources on the download ladders (3 pods): Portus 1.97–2.26 cores mean, 105–114 Mi mean /
131 Mi peak; agentgateway 2.33–2.63 cores mean, 142–188 Mi mean / 383–456 Mi peak.

## Reading

- Portus leads on 18 of 19 rungs: 20–40 % on the request path, 13–30 % at 1 KB, 14–23 % across
  h2c, single digits on large plain uploads; the two are level at 1 MiB over plain HTTP and TLS
  (agentgateway +8 % on 1 MiB download, Portus +2 % on 1 MiB HTTPS), with Portus using less CPU
  and a quarter of the peak memory.
- Round-to-round drift remains on both implementations even with fortio and one pod per rung
  (Portus traffic @256 147k → 123k → 126k; agentgateway 90k → 76k → 109k): the box slows and
  recovers on a scale of tens of minutes. Medians over interleaved rounds are the comparison to
  quote; single rounds are not.
- Portus round 1 is consistently its best and round 3 its worst on the payload ladders (HTTPS
  128 KB 26.0k → 19.9k), while agentgateway's rounds are flatter. Not explained yet; proxy memory
  is flat (105–114 Mi), so it is not growth. Open item; the medians are quoted as measured.
- Pod MTU matters on this box: at the vz default (pods at 1230) Portus's body rungs were 15–30 %
  lower; agentgateway barely moved with MTU. Docker Desktop's k3d pods run at 1450.

## Method notes

- `make bench-traffic-fortio` / `bench-latency-fortio` (this run) drive bare traffic with fortio;
  `bench-traffic` / `bench-latency` (benchtool) remain for the sub-millisecond tail.
- `BENCH_CPU` sets the dataplane pods' CPU request only; threads are sized by the dataplane.
- Portus upload rungs were run at MTU 65485 in this set (an earlier single round had them at 1230).
