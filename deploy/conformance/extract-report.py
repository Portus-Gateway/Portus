#!/usr/bin/env python3
"""Extract the conformance report and exit status from an in-cluster run log."""
import re
import sys

log_path, report_path = sys.argv[1], sys.argv[2]
text = open(log_path, encoding="utf-8", errors="replace").read()
m = re.search(r"=====CONFORMANCE-REPORT-BEGIN=====\n(.*?)=====CONFORMANCE-REPORT-END=====", text, re.S)
if m and not m.group(1).startswith("# no report"):
    open(report_path, "w").write(m.group(1))
    print(f"report written to {report_path}")
else:
    print("no conformance report in log")
passed = len(re.findall(r"^    --- PASS", text, re.M))
failed = re.findall(r"^\s*--- FAIL: (\S+)", text, re.M)
status = re.search(r"=====CONFORMANCE-EXIT=(\d+)=====", text)
code = int(status.group(1)) if status else 1
print(f"PASS={passed} FAIL={len(failed)} exit={code}")
for name in failed:
    print(f"  FAIL {name}")
sys.exit(code)
