#!/usr/bin/env python3
"""Render deploy/conformance/job.yaml with CONFORMANCE_* environment variables."""
import os
import sys

text = open(os.path.join(os.path.dirname(__file__), "job.yaml"), encoding="utf-8").read()
for key in ("CONFORMANCE_IMAGE", "CONFORMANCE_RUN", "CONFORMANCE_TIMEOUT"):
    text = text.replace("${%s}" % key, os.environ.get(key, ""))
sys.stdout.write(text)
