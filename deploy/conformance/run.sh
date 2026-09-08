#!/bin/sh
# Runs the compiled conformance suite and prints the report between markers so
# `make conformance-run` can extract it from the Job log.
set -u
cd /tmp || exit 1
RUN_FILTER="${CONFORMANCE_RUN:-TestConformance}"
TIMEOUT="${CONFORMANCE_TIMEOUT:-40m}"
/conformance.test -test.v -test.run "$RUN_FILTER" -test.timeout "$TIMEOUT" -test.count=1
status=$?
echo "=====CONFORMANCE-REPORT-BEGIN====="
cat conformance-report.yaml 2>/dev/null || echo "# no report written"
echo "=====CONFORMANCE-REPORT-END====="
echo "=====CONFORMANCE-EXIT=$status====="
exit $status
