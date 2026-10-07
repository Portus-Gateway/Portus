# Policies

Portus policies are CRDs in the `portus-gateway.dev/v1beta1` group that attach to a
Gateway API object with a `targetRef` (GEP-713 style). The controller compiles them into
the route config; the data plane enforces them on the request path. The only call-out on
the request path is the one an ExtAuthPolicy asks for.

Common rules:

- `targetRef` is `{group, kind, name, sectionName}` in the policy's own namespace. Route
  kinds accepted per policy are listed below; `Gateway` applies the policy to every route
  attached to it, `sectionName` narrows a Gateway target to one listener.
- Two policies of one kind on the same target conflict; the oldest (by
  `creationTimestamp`) wins and the other gets `Accepted: False`, reason `Conflicted`.
- A route-level policy overrides a Gateway-level one of the same kind for that route.
- Every policy reports `status.conditions[type=Accepted]` with a reason (`Accepted`,
  `Invalid`, `Conflicted`, `TargetNotFound`).

The chart installs all CRDs; `kubectl get <plural> -A` lists each kind with its
printer columns.

| Policy | Targets | What it does |
|---|---|---|
| [TimeoutPolicy](#timeoutpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | Request, backend-request and connect deadlines |
| [RetryPolicy](#retrypolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | Replay to another endpoint when the connection fails |
| [RateLimitPolicy](#ratelimitpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | Token bucket, per route or per client IP |
| [CircuitBreakerPolicy](#circuitbreakerpolicy) | HTTPRoute, GRPCRoute, Service | Stop sending to a backend after consecutive 5xx |
| [ConnectionPolicy](#connectionpolicy) | Service, HTTPRoute | Cap concurrent in-flight requests to a backend |
| [HealthCheckPolicy](#healthcheckpolicy) | Service | Active HTTP health checks on the endpoints |
| [CORSPolicy](#corspolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | Preflight answers and CORS response headers |
| [IPAllowlistPolicy](#ipallowlistpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | Allow and deny CIDRs, with trusted proxies |
| [RequestBodySizeLimitPolicy](#requestbodysizelimitpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | 413 above `maxBytes`, streamed bodies included |
| [BasicAuthPolicy](#basicauthpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | HTTP Basic against bcrypt hashes in a Secret |
| [ApiKeyAuthPolicy](#apikeyauthpolicy) | HTTPRoute, GRPCRoute, AIRoute, Gateway | A header checked against keys in a Secret |
| [JWTAuthPolicy](#jwtauthpolicy) | HTTPRoute, GRPCRoute, Gateway | Bearer JWTs verified against an issuer's published keys; claims to headers |
| [ExtAuthPolicy](#extauthpolicy) | HTTPRoute, GRPCRoute, Gateway | Ask an authorization service (forward-auth: oauth2-proxy, Authelia, Authentik) |
| [AIUsagePolicy](ai-gateway.md#aiusagepolicy) | AIRoute | Token or call budgets per key, tenant or route |
| BackendTLSPolicy | Service | Gateway API v1: CA bundle and SANs for TLS to a backend |

## TimeoutPolicy

```yaml
apiVersion: portus-gateway.dev/v1beta1
kind: TimeoutPolicy
metadata: {name: slow-backend, namespace: apps}
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: reports}
  timeout:
    requestTimeoutMs: 30000        # whole exchange, client-facing
    backendRequestTimeoutMs: 10000 # read timeout on the backend response
    connectTimeoutMs: 2000
```

All three are optional; `0` or absent means no deadline of that kind. A rule's own
`timeouts` in the HTTPRoute takes precedence over the policy.

## RetryPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api}
  retry:
    maxRetries: 2                  # 0–10
    retryOn: [connect-failure]     # connect-failure | gateway-error (alias)
```

Retries happen at connection time only: when the connection to an endpoint fails the
request is replayed to another one. A response already received is never retried by
this policy; use the HTTPRoute rule's `retry.codes` for that (bodies up to 64 KiB are
buffered for replay, larger bodies get one attempt). Ignored on rules that carry their
own `retry`.

## RateLimitPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api}
  rateLimit:
    requestsPerSecond: 100
    perClient: true                # default false: one bucket for the route
```

Token bucket with a burst of one second's worth. `perClient` keys the bucket by client
IP (after `IPAllowlistPolicy.trustedProxyCIDRs`, if set). Over the limit answers `429`.
Limiters survive config reloads when path and rate are unchanged.

## CircuitBreakerPolicy

```yaml
spec:
  targetRef: {group: "", kind: Service, name: payments}
  circuitBreaker:
    failureThreshold: 5            # consecutive 5xx to open
    successThreshold: 2            # consecutive 2xx in half-open to close
    timeoutSecs: 30                # open → half-open
```

Closed, Open (answers `503` without forwarding), HalfOpen (lets requests through and
watches). Without a policy, backend 5xx pass through untouched; passive outlier
ejection of single endpoints is always on and separate from this.

## ConnectionPolicy

```yaml
spec:
  targetRef: {group: "", kind: Service, name: legacy}
  maxConnections: 200
```

Caps in-flight requests to the target; the excess is answered `503`.

## HealthCheckPolicy

```yaml
spec:
  targetRef: {group: "", kind: Service, name: api}
  healthCheck:
    path: /healthz
    intervalSecs: 10
    timeoutSecs: 5
    healthyThreshold: 1
    unhealthyThreshold: 3
```

Each data plane probes every endpoint of the Service with `GET path` on a fresh
connection; `200` is healthy. An endpoint flips after a run of `healthyThreshold` or
`unhealthyThreshold` consecutive results, and only ready endpoints are load-balanced to.
Endpoints start healthy.

## CORSPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api}
  cors:
    allowOrigins: ["https://app.example.com"]   # or ["*"]
    allowMethods: [GET, POST]
    allowHeaders: [content-type, authorization]
    exposeHeaders: [x-request-id]
    allowCredentials: true
    maxAge: 600
```

Preflight (`OPTIONS` with `Access-Control-Request-Method`) is answered by the gateway;
other requests get the CORS response headers added. An origin not in the list gets no
CORS headers.

## IPAllowlistPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: Gateway, name: edge}
  allowCIDRs: ["10.0.0.0/8", "2001:db8::/32"]
  denyCIDRs: ["10.9.0.0/16"]
  trustedProxyCIDRs: ["10.0.0.0/8"]
```

Deny is checked first, then allow (an empty `allowCIDRs` allows everything not denied).
Refused requests get `403`. With `trustedProxyCIDRs` the client IP is the last
`X-Forwarded-For` hop that is not a trusted proxy; without it, the peer address.

## RequestBodySizeLimitPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: upload}
  maxBytes: 10485760
```

A `Content-Length` above the limit is refused with `413` before the body is read; a
chunked or streamed body that crosses it is cut with `413` and the connection closed.

## BasicAuthPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: admin}
  basicAuth:
    secretRef: {name: admin-users}   # namespace: defaults to the policy's
    realm: Admin                     # default Restricted
```

The Secret's data is `username: bcrypt-hash`, one entry per user (cost ≥ 10; hashes
with a lower cost are rejected). A missing or wrong credential gets `401` with
`WWW-Authenticate: Basic realm="…"`. Verification is constant-time and bounded to half
the CPUs so a flood of bad passwords cannot starve the proxy.

## ApiKeyAuthPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api}
  apiKey:
    secretRef: {name: api-keys}
    headerName: X-API-Key            # default
```

Every value in the Secret's data is a valid key (the data keys are labels). A missing or
unknown key gets `401`. This is the plain header check for ordinary routes; AI routes
use the ledger-issued keys described in [ai-gateway.md](ai-gateway.md#keys).

## JWTAuthPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api}
  jwt:
    providers:
      - issuer: https://dex.example.com      # the tokens' iss claim
        audiences: [api]                     # any one; omit to accept any audience
        # jwksUri: https://dex.example.com/keys   # default: OpenID discovery, then <issuer>/keys
        claimToHeaders:
          - {claim: sub, header: X-User}
          - {claim: groups, header: X-Groups}  # arrays are comma-joined
```

Requests need `Authorization: Bearer <token>`. The token must be signed by one of the
issuer's published keys, name that issuer, carry `sub` and an unexpired `exp` (60 s
leeway), not be before its `nbf`, and carry one of `audiences` when set. A missing token
gets `401` with `WWW-Authenticate: Bearer realm="portus"`; a rejected one adds
`error="invalid_token"`. The token is forwarded to the backend unchanged.

`claimToHeaders` copies verified claims into request headers. Any copy of those headers
the client sent is removed first, so a backend can trust them. Strings are copied as
they are, numbers and booleans as text, arrays of those comma-joined; objects are skipped.
`Authorization`, `Host` and framing headers cannot be targets.

The controller fetches each issuer's keys (JWKS) and ships them to the data planes in the
config, so data planes never call the issuer. Keys are refreshed every five minutes; a
rotation reaches the data planes as a config update. While an issuer's keys cannot be
fetched, every token from it is refused (the route stays closed) and the policy reports
`ResolvedRefs: False`, reason `JWKSUnavailable`, with the error. A failed refresh keeps
the keys already fetched. The controller therefore needs network access to each issuer.

A route has one authentication policy: when several target it, BasicAuthPolicy wins over
ApiKeyAuthPolicy, which wins over JWTAuthPolicy. AIRoutes take OAuth tokens through their
own `auth.jwt` ([ai-gateway.md](ai-gateway.md)).

## ExtAuthPolicy

```yaml
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: dashboard}
  extAuth:
    backendRef: {name: oauth2-proxy, namespace: auth, port: 4180}
    path: /oauth2/auth                 # default /
    timeoutMs: 1000                    # default
    failOpen: false                    # default: 503 when the service cannot answer
    # requestHeaders: [cookie, authorization]   # default: every client header
    responseHeaders: [X-Auth-Request-User, X-Auth-Request-Email]
```

Before forwarding, the data plane sends `GET <path>` to the Service with the client's
headers (all of them, or `requestHeaders`) and `X-Forwarded-Method`, `X-Forwarded-Proto`,
`X-Forwarded-Host`, `X-Forwarded-Uri` and `X-Forwarded-For`, and no body. This is the
forward-auth contract of Traefik's ForwardAuth and nginx's `auth_request`, so oauth2-proxy
(`/oauth2/auth`), Authelia (`/api/authz/forward-auth`) and Authentik's outposts work
unchanged.

- **2xx**: the request is forwarded. The `responseHeaders` the service set are copied into
  the backend request; client copies of them are removed first.
- **Anything else** goes back to the client as it is (status, headers, up to 64 KiB of
  body), so a `302` to a login page or a `401` with its challenge reaches the browser.
- **No answer** (no ready endpoint, connection error, `timeoutMs` passed): `503`, or the
  request is forwarded when `failOpen` is true.

The check runs after the route's own authentication policy (Basic, API key or JWT), so a
route can require a JWT and also ask a service. A Service in another namespace needs a
ReferenceGrant in that namespace with `from: {group: portus-gateway.dev, kind:
ExtAuthPolicy, namespace: <policy namespace>}` and `to: {group: "", kind: Service}`.
Without one the route refuses every request with `500` (it is never left open) and the
policy reports `ResolvedRefs: False`, reason `RefNotPermitted`. Connections to the service
are plain HTTP and kept alive.
