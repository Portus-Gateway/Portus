#!/usr/bin/env python3
"""Combine the benchtool logs of several load generators that ran the same
ladder at the same time: QPS is summed per rung, latency percentiles are the
worst generator's, so the table reads like one bigger client.

Usage: sum-generators.py <log> [<log> ...]
"""
import re, sys

ROW = re.compile(r"^(\S+)\s+fortio\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)qps\s+([\d.]+)ms\s+([\d.]+)ms\s+([\d.]+)ms")

rungs = {}
order = []
for path in sys.argv[1:]:
    for line in open(path):
        m = ROW.match(line.strip())
        if not m:
            continue
        dest, qps_target, conns, dur, payload, success, qps, p50, p90, p99 = m.groups()
        key = (dest, int(conns), payload)
        if key not in rungs:
            rungs[key] = {"n": 0, "success": 0, "qps": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "dur": dur}
            order.append(key)
        r = rungs[key]
        r["n"] += 1
        r["success"] += int(success)
        r["qps"] += float(qps)
        for k, v in (("p50", p50), ("p90", p90), ("p99", p99)):
            r[k] = max(r[k], float(v))

cols = ("DEST", "GENERATORS", "CONS", "DUR", "SUCCESS", "THROUGHPUT", "P50", "P90", "P99")
rows = [cols]
for key in order:
    dest, conns, _ = key
    r = rungs[key]
    rows.append((dest, str(r["n"]), str(conns * r["n"]), r["dur"], str(r["success"]), f"{r['qps']:.2f}qps",
                 f"{r['p50']:.3f}ms", f"{r['p90']:.3f}ms", f"{r['p99']:.3f}ms"))
widths = [max(len(row[i]) for row in rows) + 2 for i in range(len(cols))]
for row in rows:
    print("".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
