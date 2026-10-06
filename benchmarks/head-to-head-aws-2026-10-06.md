# Portus 0.2.12 vs agentgateway v1.5.0 on an AWS c7a.8xlarge (2026-10-06, three rounds)

**Current README and site numbers.** Portus is the released 0.2.12 chart and image (Rama network
stack, the default); agentgateway is v1.5.0 from its chart. The previous record, 0.2.3 on a
10-vCPU apple/container VM on an Apple M4, is `head-to-head-machine-2026-09-11.md`; the M4 VM ran
out of CPU before either gateway did, which is why this box replaced it.

Box: AWS `c7a.8xlarge` spot in eu-west-1: 32 vCPUs (AMD EPYC 9R14, Zen 4, one thread per core),
64 GiB, Ubuntu 24.04, Docker CE, a single-node k3d cluster (k3s v1.36.4) on a Docker network with
MTU 65000. Steal stayed at ~0 and the spread between rounds is mostly under 1 %. Same backend pods
for both gateways, one gateway at a time, three interleaved rounds (Portus, agentgateway, then the
order reversed), fortio for every ladder with one fortio pod per rung (`-httpbufferkb 2048`,
2-CPU request), 10 s per rung. Portus: 3 pods × 2-CPU request, no limit (32 worker threads each,
sized from the node); agentgateway: 3 pods, no limit. CPU and memory come from `kubectl top`
sampled every 5 s (`deploy/bench/sample-top.py`); memory is per pod, the 3-pod total divided by 3.
Raw logs under `results/` (git-ignored). Medians over the three rounds; per-round values shown so
the spread is visible.

**Summary.** Portus leads every request-path rung (+31–71 %) and 15 of 16 payload rungs, by
16–26 % at 1 KB and 16 KB and 4–11 % at 128 KiB. At 1 MiB the two are level over upload, TLS and
HTTP/2 (+1 to +4 %), and agentgateway is 8 % ahead on plain-HTTP downloads. Portus used less proxy
CPU on every suite while serving more requests; agentgateway used less memory (51–145 Mi per pod
against Portus's 155–181 Mi).

## Traffic (bare `GET /`, connections ladder)

| Connections | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead | p99 ms Portus / agentgateway |
|---|---|---|---|---|---|---|
| 1 | 14,218 / 13,900 / 14,307 | **14,218** | 9,663 / 8,942 / 9,103 | 9,103 | +56 % | 0.99 / 0.75 |
| 2 | 28,914 / 28,493 / 25,890 | **28,493** | 16,628 / 17,482 / 16,537 | 16,628 | +71 % | 0.61 / 0.99 |
| 4 | 44,634 / 49,145 / 45,450 | **45,450** | 32,889 / 32,501 / 30,628 | 32,501 | +40 % | 0.99 / 0.99 |
| 8 | 60,470 / 60,529 / 62,509 | **60,529** | 45,476 / 44,806 / 43,508 | 44,806 | +35 % | 0.99 / 0.99 |
| 16 | 98,400 / 98,535 / 98,539 | **98,535** | 71,144 / 71,516 / 71,937 | 71,516 | +38 % | 0.99 / 0.99 |
| 32 | 143,135 / 138,034 / 143,764 | **143,135** | 102,034 / 102,446 / 101,898 | 102,034 | +40 % | 0.99 / 0.99 |
| 64 | 168,502 / 169,317 / 169,455 | **169,317** | 127,501 / 127,988 / 128,151 | 127,988 | +32 % | 1.00 / 1.76 |
| 128 | 195,738 / 196,390 / 197,027 | **196,390** | 150,218 / 149,827 / 150,414 | 150,218 | +31 % | 1.96 / 2.54 |
| 256 | 224,173 / 223,805 / 224,883 | **224,173** | 168,586 / 166,688 / 168,099 | 168,099 | +33 % | 2.98 / 3.94 |

Proxy CPU, mean over the suite (3 pods, median of rounds): Portus 3.2 cores, agentgateway 4.1 cores. Peak memory per proxy pod (median of rounds): Portus 155 Mi, agentgateway 51 Mi.

## Download (fortio echo, 64 connections)

| Size | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead | p99 ms Portus / agentgateway |
|---|---|---|---|---|---|---|
| 1 KB | 133,842 / 132,981 / 133,077 | **133,077** | 105,345 / 105,639 / 104,967 | 105,345 | +26 % | 1.92 / 1.96 |
| 16 KB | 107,755 / 107,546 / 107,185 | **107,546** | 87,835 / 87,685 / 87,697 | 87,697 | +23 % | 2.17 / 2.28 |
| 128 KiB | 59,230 / 59,289 / 59,288 | **59,288** | 55,560 / 55,698 / 55,645 | 55,645 | +7 % | 3.58 / 3.37 |
| 1 MiB | 12,874 / 13,025 / 12,110 | 12,874 | 13,937 / 13,923 / 13,961 | **13,937** | -8 % | 13.25 / 11.83 |

Proxy CPU, mean over the suite (3 pods, median of rounds): Portus 4.1 cores, agentgateway 5.7 cores. Peak memory per proxy pod (median of rounds): Portus 161 Mi, agentgateway 82 Mi.

## Upload (POST echoed, 64 connections)

| Size | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead | p99 ms Portus / agentgateway |
|---|---|---|---|---|---|---|
| 1 KB | 123,596 / 124,170 / 123,366 | **123,596** | 98,902 / 98,722 / 98,966 | 98,902 | +25 % | 1.99 / 2.03 |
| 16 KB | 69,246 / 67,989 / 67,837 | **67,989** | 58,283 / 57,427 / 57,557 | 57,557 | +18 % | 3.79 / 3.91 |
| 128 KiB | 26,027 / 25,830 / 25,823 | **25,830** | 24,868 / 24,639 / 24,791 | 24,791 | +4 % | 10.20 / 8.62 |
| 1 MiB | 16,144 / 16,228 / 16,240 | **16,228** | 16,027 / 15,902 / 15,999 | 15,999 | +1 % | 15.34 / 12.88 |

Proxy CPU, mean over the suite (3 pods, median of rounds): Portus 7.6 cores, agentgateway 7.8 cores. Peak memory per proxy pod (median of rounds): Portus 162 Mi, agentgateway 122 Mi.

## HTTPS download (64 connections)

| Size | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead | p99 ms Portus / agentgateway |
|---|---|---|---|---|---|---|
| 1 KB | 127,695 / 128,165 / 127,918 | **127,918** | 101,266 / 101,157 / 100,687 | 101,157 | +26 % | 1.93 / 1.97 |
| 16 KB | 101,856 / 101,416 / 101,225 | **101,416** | 82,952 / 83,001 / 82,979 | 82,979 | +22 % | 2.25 / 2.44 |
| 128 KiB | 50,882 / 50,848 / 50,948 | **50,882** | 45,446 / 45,646 / 45,702 | 45,646 | +11 % | 3.81 / 3.87 |
| 1 MiB | 11,208 / 11,221 / 11,286 | **11,221** | 11,126 / 10,375 / 11,110 | 11,110 | +1 % | 14.65 / 14.28 |

Proxy CPU, mean over the suite (3 pods, median of rounds): Portus 7.0 cores, agentgateway 7.3 cores. Peak memory per proxy pod (median of rounds): Portus 181 Mi, agentgateway 145 Mi.

## HTTP/2 (h2c) download (64 connections)

| Size | Portus r1 / r2 / r3 | median | agentgateway r1 / r2 / r3 | median | Portus lead | p99 ms Portus / agentgateway |
|---|---|---|---|---|---|---|
| 1 KB | 90,868 / 90,857 / 90,604 | **90,857** | 75,676 / 67,782 / 75,825 | 75,676 | +20 % | 2.85 / 2.92 |
| 16 KB | 74,831 / 74,714 / 74,824 | **74,824** | 64,895 / 64,374 / 64,439 | 64,439 | +16 % | 3.05 / 3.23 |
| 128 KiB | 32,319 / 32,095 / 32,028 | **32,095** | 30,867 / 31,053 / 30,949 | 30,949 | +4 % | 6.01 / 5.99 |
| 1 MiB | 6,842 / 6,844 / 6,840 | **6,842** | 6,602 / 6,598 / 6,593 | 6,598 | +4 % | 27.33 / 24.62 |

Proxy CPU, mean over the suite (3 pods, median of rounds): Portus 7.7 cores, agentgateway 8.3 cores. Peak memory per proxy pod (median of rounds): Portus 181 Mi, agentgateway 129 Mi.

## Fixed 30,000 QPS on 64 connections, 30 s

Achieved: Portus 29,998 / 29,998 / 29,998, agentgateway 29,997 / 29,998 / 29,998. p99 Portus 0.99 ms, agentgateway 0.99 ms: both inside fortio's 1 ms histogram bucket, so this run does not separate them. Proxy CPU: Portus 5.9 cores, agentgateway 7.0 cores.

## Not changed by this run

- The control-plane and availability numbers (route propagation, route changes, route scale,
  backend failover) are still the 0.2.2 run on Docker Desktop in
  `head-to-head-0.2.2-2026-09-10-k3d.md`.
- A larger HTTP/1 read buffer closes most of the 1 MiB download gap (upstream 128 KiB: +3 %,
  256 KiB: +6 %; 400 KiB on both sides: +10 %) but costs ~95–200 Mi per pod, because an idle
  pooled connection keeps the buffer it grew. Portus keeps 64 KiB.
