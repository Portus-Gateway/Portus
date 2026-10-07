# Standalone mode

The Portus dataplane runs as a plain reverse proxy, with no Kubernetes and no
controller, when `PORTUS_CONFIG_FILE` names a YAML file:

```bash
PORTUS_CONFIG_FILE=/etc/portus/portus.yaml portus-dataplane
```

The YAML compiles into the same `CompiledConfig` the controller would send, so
routing, policies and TLS behave exactly as in a cluster. A complete example
with every field is [`examples/standalone.yaml`](../examples/standalone.yaml).

Standalone mode covers HTTP and HTTPS reverse proxying. L4 routes (TCP, UDP,
TLS passthrough), client certificate validation and the AI/MCP gateway are
Kubernetes-only.

## Hot reload

Edits apply without a restart and without dropping connections:

- **The YAML and every `cert_file` / `key_file` it names are watched**, each by
  file and by directory. In-place writes, editor renames, certbot's
  `live/<domain>/` symlink swaps and a ConfigMap's `..data` swap are all seen.
- A burst of writes is applied once, 200 ms after the last one (2 s at most
  after the first), so the final state of the files is what gets applied.
- Events from unrelated files in the same directories (a log file, the ACME
  cache) are ignored: a reload runs only if a watched file's contents changed.
- A config that fails to parse, compile or validate is logged and skipped; the
  previous config keeps serving.

## Backends

```yaml
backends:
  - address: "10.0.1.1:8080"     # IP literal
  - address: "[fd00::1]:8080"    # IPv6
  - address: "app:8080"          # DNS name (docker compose service, VM hostname)
```

- **DNS names** resolve through the system resolver (`/etc/hosts`, then DNS).
  Every address a name returns becomes an endpoint of the pool.
  `dns_refresh_secs` (top level, default 30, 0 disables) re-resolves
  periodically, and a changed address set is applied like an edit. A lookup
  that fails keeps the last addresses. A name that has never resolved gets no
  endpoints: its routes return 502 until it does, and the rest of the config
  still applies.
- **Weights.** Backends with equal weights (or none) share one pool, balanced
  per endpoint with health and outlier state. Unequal weights (`weight: 3` and
  `weight: 1`) split traffic in that ratio, one pool per backend.

## TLS

An HTTPS listener takes certificate files:

```yaml
- port: 443
  protocol: HTTPS
  tls:
    cert_file: /etc/tls/fullchain.pem
    key_file: /etc/tls/privkey.pem
```

Or certificates issued over ACME (Let's Encrypt by default):

```yaml
acme:
  email: ops@example.com            # optional contact
  directory: letsencrypt            # letsencrypt | letsencrypt-staging | an ACME directory URL
  cache_dir: /var/lib/portus/acme   # account key and certificates; keep it on a volume
  challenge: http-01                # or tls-alpn-01
  # ca_file: /path/ca.pem           # trust for a private ACME CA (step-ca, Pebble)

listeners:
  - port: 80
    protocol: HTTP
    routes:
      - hosts: ["*"]
        redirect: { scheme: https, status_code: 301 }
  - port: 443
    protocol: HTTPS
    tls:
      acme:
        domains: [app.example.com, api.example.com]
    routes:
      - hosts: [app.example.com, api.example.com]
        backends:
          - address: "app:8080"
```

- **Domains.** `tls.acme.domains`, else the listener's `hostname`, else every
  exact host the listener's routes name. Wildcards and IP addresses are
  refused: HTTP-01 and TLS-ALPN-01 cannot validate them.
- **One certificate per domain**, selected by SNI. One failing domain does not
  hold up the others.
- **Challenges.**
  - `http-01`: the CA fetches `/.well-known/acme-challenge/<token>` over
    plain HTTP. Every HTTP listener answers it before routing, so an
    HTTP-to-HTTPS redirect is fine. The config must have an HTTP listener,
    on port 80 for a public CA.
  - `tls-alpn-01`: the CA makes a TLS handshake with ALPN `acme-tls/1`, which
    every HTTPS listener answers. No HTTP listener is needed; it must be on
    port 443 for a public CA.
- **Startup.** Until a domain's first certificate arrives it serves a
  self-signed placeholder, so the listener starts at once. Issuance usually
  takes a few seconds and the certificate is swapped in without a restart.
- **Renewal** runs two thirds of the way through a certificate's lifetime
  (day 60 of 90). A failed order is retried after 5 minutes, then at doubling
  intervals capped at 4 hours, which stays inside Let's Encrypt's
  failed-validation limit.
- **Cache.** `<cache_dir>/<directory>/account.json` and
  `<cache_dir>/<directory>/<domain>/certificate.pem` (key and chain in one
  file, mode 0600). A restart reuses both and orders nothing. Switching
  `directory` (staging to production) uses a separate subdirectory, so
  staging certificates are never served against production.
- **Staging first.** Try `directory: letsencrypt-staging` until issuance
  works; production rate limits are strict.

In Kubernetes, use cert-manager: the controller serves the Secrets it writes.
None of the above runs there. The HTTP-01 path routes to cert-manager's solver
as an ordinary HTTPRoute, and HTTPS listeners do not offer `acme-tls/1`.

### Testing ACME locally

`tests/standalone/acme-pebble-e2e.sh` runs the whole flow against
[Pebble](https://github.com/letsencrypt/pebble):
issuance over HTTP-01, a hot switch to TLS-ALPN-01, backends by DNS name, and
a restart that orders nothing. It needs Go, curl and python3.

## Ports

Besides the listeners in the YAML, the dataplane binds health on `:8081`
(`/healthz`, `/readyz`) and metrics on `:9090`.

## Running the image

The release image runs as uid 1000 on an empty filesystem (it carries only the
binary and a CA bundle for reaching the ACME CA), so mount the config and give
ACME a writable cache:

```bash
docker run -d --name portus \
  -p 80:80 -p 443:443 \
  -v $PWD/portus.yaml:/etc/portus/portus.yaml:ro \
  -v portus-acme:/var/lib/portus/acme \
  -e PORTUS_CONFIG_FILE=/etc/portus/portus.yaml \
  ghcr.io/portus-gateway/dataplane:<version>
```

Mount the config's directory rather than the file when it is edited by
replacement (most editors, `kubectl` ConfigMaps). A bind-mounted single file
keeps the old inode and never sees the edit. A named volume
(`portus-acme` above) starts out owned by root; if the first issuance logs a
permission error, `chown 1000` the volume once.
