#!/usr/bin/env python3
"""Sample `kubectl top pods` while a benchmark runs and summarise per workload.

Usage: sample-top.py <out.tsv> [interval-seconds]   (run in the background; SIGTERM ends it)
       sample-top.py --summarise <out.tsv>

Pods in the bench, portus, agentgateway-system, envoy-gateway-system and
nginx-system namespaces are sampled; the backend and the load generator are
excluded. Pods are grouped by workload (pod name minus the ReplicaSet/pod
hashes) so `portus-portus-4c969822-7f4969487f-hz9pq` x3 becomes one row.
"""
import os, re, signal, subprocess, sys, time

NAMESPACES = ["bench", "portus", "agentgateway-system", "envoy-gateway-system", "nginx-system"]
SKIP = re.compile(r"^(backend-|benchtool-)")
HASH = re.compile(r"(-[0-9a-f]{8,10})?-[0-9a-z]{5}$")


def workload(pod: str) -> str:
    return HASH.sub("", pod)


def cpu_m(s: str) -> int:
    return int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)


def mem_mi(s: str) -> float:
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}
    for u, f in units.items():
        if s.endswith(u):
            return float(s[: -len(u)]) * f
    return float(s) / 1024 / 1024


def sample(out, interval):
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    kubectl = os.environ.get("KUBECTL", "kubectl").split()
    with open(out, "a") as f:
        while not stop:
            t = time.time()
            for ns in NAMESPACES:
                try:
                    res = subprocess.run(kubectl + ["top", "pods", "-n", ns, "--no-headers"], capture_output=True, text=True, timeout=20)
                except Exception:
                    continue
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 3 or SKIP.match(parts[0]):
                        continue
                    f.write(f"{t:.0f}\t{ns}\t{parts[0]}\t{cpu_m(parts[1])}\t{mem_mi(parts[2]):.1f}\n")
            f.flush()
            time.sleep(interval)


def summarise(path):
    rows = {}
    for line in open(path):
        t, ns, pod, cpu, mem = line.rstrip("\n").split("\t")
        key = (ns, workload(pod))
        rows.setdefault(key, {}).setdefault(t, []).append((int(cpu), float(mem)))
    print(f"{'NAMESPACE':<22}{'WORKLOAD':<40}{'PODS':>5}{'CPU mean(m)':>13}{'CPU peak(m)':>13}{'MEM mean(Mi)':>14}{'MEM peak(Mi)':>14}")
    for (ns, wl), samples in sorted(rows.items()):
        totals = [(sum(c for c, _ in v), sum(m for _, m in v), len(v)) for v in samples.values()]
        pods = max(n for _, _, n in totals)
        cpu_mean = sum(c for c, _, _ in totals) / len(totals)
        cpu_peak = max(c for c, _, _ in totals)
        mem_mean = sum(m for _, m, _ in totals) / len(totals)
        mem_peak = max(m for _, m, _ in totals)
        print(f"{ns:<22}{wl:<40}{pods:>5}{cpu_mean:>13.0f}{cpu_peak:>13}{mem_mean:>14.1f}{mem_peak:>14.1f}")


if __name__ == "__main__":
    if sys.argv[1] == "--summarise":
        summarise(sys.argv[2])
    else:
        sample(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 5.0)
