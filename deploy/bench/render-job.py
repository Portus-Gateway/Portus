#!/usr/bin/env python3
"""Render a deploy/bench Job template with environment substitutions.

Usage: render-job.py [benchtool-job.yaml|tools-job.yaml]   (default benchtool-job.yaml)

BENCH_ARGS: shell-style argument string, rendered as a JSON array into ${BENCH_ARGS_JSON}.
BENCH_TARGETS, BENCH_TOOLS_IMAGE: substituted verbatim.
"""
import json, os, shlex, sys

template = sys.argv[1] if len(sys.argv) > 1 else "benchtool-job.yaml"
args = shlex.split(os.environ.get("BENCH_ARGS", ""))
text = open(os.path.join(os.path.dirname(__file__), template)).read()
text = text.replace("${BENCH_ARGS_JSON}", ", ".join(json.dumps(a) for a in args))
for key in ("BENCH_TARGETS", "BENCH_TOOLS_IMAGE"):
    text = text.replace("${%s}" % key, os.environ.get(key, ""))
sys.stdout.write(text)
