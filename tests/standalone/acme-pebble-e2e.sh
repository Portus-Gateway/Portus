#!/usr/bin/env bash
# End-to-end check of standalone ACME against Pebble (Let's Encrypt's test CA).
#
# Runs Pebble, its DNS test server (every name -> 127.0.0.1), a plain backend
# and a standalone dataplane, then checks that:
#   1. http-01: a certificate is issued and served for portus.test, the
#      backend is reached by DNS name, and HTTP redirects to HTTPS;
#   2. tls-alpn-01: switching the challenge in the YAML (hot reload, no
#      restart) issues a certificate for alpn.test over the HTTPS listener;
#   3. a restart re-issues nothing (the cache is reused).
# The whole scenario runs once per network stack (STACKS, default both).
#
# Needs: go (installs pebble + pebble-challtestsrv), curl, python3.
# Usage: [STACKS="rama pingora"] [KEEP=1] tests/standalone/acme-pebble-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/portus-acme-e2e.XXXXXX")"
STACKS="${STACKS:-rama pingora}"
STACK=setup
RUN="$WORK"
PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ "${KEEP:-}" == 1 ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL ($STACK): $*" >&2; echo "--- dataplane log tail:" >&2; tail -40 "$RUN/dataplane.log" >&2; exit 1; }
orders() { awk '/ordering a certificate/{n++} END{print n+0}' "$RUN/dataplane.log"; }

export GOBIN="$WORK/bin"
echo "installing pebble into $GOBIN"
GOTOOLCHAIN=auto go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1 \
  github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
PEBBLE_SRC="$(GOTOOLCHAIN=auto go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.10.1"

echo "building the dataplane (pingora + rama, as the image does)"
(cd "$ROOT" && cargo build -q -p portus-dataplane --features rama)
DATAPLANE="$ROOT/target/debug/portus-dataplane"

# Pebble validates http-01 on :5002 and tls-alpn-01 on :5001 (its config);
# the dataplane listens there instead of 80/443.
"$GOBIN/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver :8053 \
  -http01 "" -https01 "" -tlsalpn01 "" -doh "" >"$WORK/challtestsrv.log" 2>&1 &
PIDS+=($!)
(cd "$PEBBLE_SRC" && PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
  exec "$GOBIN/pebble" -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053) >"$WORK/pebble.log" 2>&1 &
PIDS+=($!)

mkdir -p "$WORK/www"
echo "hello from the backend" >"$WORK/www/hello.txt"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$WORK/www" >"$WORK/backend.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 50); do curl -sk https://localhost:14000/dir >/dev/null && break; sleep 0.2; done
curl -sk https://localhost:14000/dir >/dev/null || fail "pebble did not start"

write_config() { # $1 = challenge, $2 = domain
  cat >"$RUN/portus.yaml.tmp" <<EOF
acme:
  directory: https://localhost:14000/dir
  ca_file: $PEBBLE_SRC/test/certs/pebble.minica.pem
  cache_dir: $RUN/acme
  challenge: $1
listeners:
  - port: 5002
    protocol: HTTP
    routes:
      - hosts: ["*"]
        redirect: {scheme: https, port: 5001, status_code: 301}
  - port: 5001
    protocol: HTTPS
    tls:
      acme:
        domains: [$2]
    routes:
      - hosts: [$2]
        backends:
          - address: "localhost:18080"
EOF
  mv "$RUN/portus.yaml.tmp" "$RUN/portus.yaml"
}

start_dataplane() {
  PORTUS_NETWORK_STACK="$STACK" PORTUS_CONFIG_FILE="$RUN/portus.yaml" RUST_LOG=info \
    "$DATAPLANE" >>"$RUN/dataplane.log" 2>&1 &
  DP_PID=$!
  PIDS+=("$DP_PID")
}

wait_for_cert() { # $1 = domain
  for _ in $(seq 150); do
    compgen -G "$RUN/acme/*/$1/certificate.pem" >/dev/null && return 0
    sleep 0.2
  done
  fail "no certificate issued for $1"
}

pebble_roots() {
  { curl -sk https://localhost:15000/roots/0; curl -sk https://localhost:15000/intermediates/0; } >"$WORK/pebble-roots.pem"
}

check_https() { # $1 = domain
  local body
  for _ in $(seq 50); do
    body="$(curl -s --cacert "$WORK/pebble-roots.pem" --resolve "$1:5001:127.0.0.1" "https://$1:5001/hello.txt" || true)"
    [[ "$body" == "hello from the backend" ]] && return 0
    sleep 0.2
  done
  fail "https://$1:5001 did not serve the backend with a Pebble-issued certificate (got: '$body')"
}

scenario() {
  RUN="$WORK/$STACK"
  mkdir -p "$RUN"
  echo "== $STACK"
  echo "1. http-01 for portus.test"
  write_config http-01 portus.test
  start_dataplane
  wait_for_cert portus.test
  pebble_roots
  check_https portus.test
  local redirect
  redirect="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: portus.test' http://127.0.0.1:5002/x)"
  [[ "$redirect" == "301 https://portus.test:5001/x" ]] || fail "HTTP redirect: $redirect"
  echo "   ok: issued, served, backend reached by DNS name, HTTP redirects"

  echo "2. tls-alpn-01 for alpn.test (hot reload)"
  write_config tls-alpn-01 alpn.test
  wait_for_cert alpn.test
  check_https alpn.test
  echo "   ok: issued over TLS-ALPN-01 on the HTTPS listener"

  echo "3. restart reuses the cache"
  kill -INT "$DP_PID"; wait "$DP_PID" 2>/dev/null || true
  local before after
  before="$(orders)"
  start_dataplane
  check_https alpn.test
  sleep 2
  after="$(orders)"
  [[ "$before" == "$after" ]] || fail "restart ordered again ($before -> $after)"
  echo "   ok: no new order after restart"
  kill -INT "$DP_PID"; wait "$DP_PID" 2>/dev/null || true
}

for STACK in $STACKS; do scenario; done
echo "PASS"
