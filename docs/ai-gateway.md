# AI gateway

Portus fronts LLM providers and MCP servers the way it fronts any backend, with three
CRDs: `AIProvider` (an upstream API), `AIRoute` (a route that can match on the request
body) and `AIUsagePolicy` (a budget). Clients keep speaking the provider's native API;
the gateway routes on the body, swaps the client's key for the provider's, meters what
each request cost and refuses what a key may not do. State (keys, budgets, usage) lives
in the ledger, a companion service the chart deploys; the data plane never calls it on
the request path.

## Install

```bash
helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.11 \
  --namespace portus --create-namespace --set aiGateway.enabled=true
```

A fresh install carries the AI CRDs. On an existing install, `helm upgrade` does not
touch CRDs: apply `deploy/helm/crds/aiprovider.yaml`, `airoute.yaml` and
`aiusagepolicy.yaml` by hand. Pass your values with `-f` on every upgrade rather than
`--reuse-values` or `--reset-then-reuse-values`: the reuse flags ignore new chart defaults,
and after a failed revision they can drop values you had set (an install came up without
its ledger that way). An install first created before 0.2.6 must also delete the generated
`<release>-portus-gateway-grpc-tls` Secret once so it is regenerated with the ledger's
names; from 0.2.6 the names are always in it. The AI gateway runs on the Rama network
stack, the default since 0.2.4.

If every key is refused with 401 right after enabling the AI gateway, the data planes
have no key snapshot: their log says `cannot watch API keys at …` with the reason, and
the most common one is that certificate.

## AIProvider

An upstream the gateway forwards to. The controller resolves `url`'s host every 30 s
into the provider's endpoints.

| Field | Values | Notes |
|---|---|---|
| `kind` | `anthropic`, `openai`, `openai-compatible`, `mcp` | Decides how usage is read from responses, the default credential header and the refusal shape |
| `url` | `https://host[:port]` | Scheme and host only; the request path passes through unchanged. A host that names a Service in the cluster (`name`, `name.ns.svc`, `name.ns.svc.cluster.local`) resolves to the Service's ready pods, not its ClusterIP, so affinity, health checks and outlier ejection work per pod; any other host is resolved by DNS every 30 s |
| `credential.secretRef.name` / `.key` | Secret in the provider's namespace; key defaults to `api-key` | Injected on every forwarded request; the client's own credential is stripped |
| `credential.header` | default `x-api-key` for anthropic, `authorization` otherwise | |
| `credential.prefix` | default empty for anthropic, `Bearer ` otherwise | |
| `sessionAffinity` | `header`, `none`; default `header` for `mcp`, `none` otherwise | `header` pins requests carrying `Mcp-Session-Id` to the endpoint the session hashes to |

Without a `credential`, the client's `Authorization` header passes through when
`requireApiKey` is false (OAuth end to end); with `requireApiKey` true the Portus key is
stripped and nothing is injected.

## AIRoute

HTTPRoute-shaped: `parentRefs`, `hostnames`, rules with matches and one `providerRef`
per rule. Rules are ordered by the usual Gateway API precedence, so a rule with a body
match wins over a catch-all path rule.

| Match field | Values | Applies to |
|---|---|---|
| `path` | `Exact`, `PathPrefix`, `RegularExpression` | all |
| `headers[]` | `Exact`, `RegularExpression` | all |
| `model` | `Exact`, `Prefix`, `RegularExpression` on the body's top-level `model` | LLM requests |
| `stream` | `true` / `false`, the body's top-level `stream` | LLM requests |
| `method` | `Exact`, `Prefix`, `RegularExpression` on the JSON-RPC `method` | MCP requests |
| `tool` | `Exact`, `Prefix`, `RegularExpression` on `params.name` of a `tools/call` | MCP requests |

A match combines its fields with AND; several matches in a rule are OR. A body field
match on a request that has no body (`GET`, `DELETE`) or lacks the field does not match,
so a rule with only a `path` match is what carries those requests. `model`/`stream` and
`method`/`tool` cannot appear in the same match.

`requireApiKey: true` demands a Portus API key (`x-api-key` or `Authorization: Bearer`)
on every request; the key is checked against the ledger's snapshot on the data plane and
stripped before forwarding.

`auth.jwt` lets the route accept OAuth bearer tokens from one issuer in place of a Portus
key (see [OAuth clients](#oauth-clients)).

| `auth.jwt` field | Values | Notes |
|---|---|---|
| `issuer` | `https://…` | The token's `iss`; must be listed in the chart's `aiGateway.jwt.issuers` |
| `audience` | string | Required `aud` when set |
| `tenantClaim` | claim name, default `groups` | A string claim, or the first entry of an array claim |
| `toolsClaim` | claim name, default `scope` | The MCP tools the subject may call: an array of strings or a space-separated string |
| `scopes` | list, default `[openid, profile, email, groups]` | What clients are told to request: `scopes_supported` in the metadata document and `scope` in the 401 challenge. Dex behind an upstream connector needs `federated:id` added when the token's `federated_claims` matter |
| `groupsClaim` | claim name, default `groups` | The subject's groups, for `toolsByGroup` |
| `toolsByGroup` | `{group: [tools]}` | MCP tools per group, exact or `prefix.*`. A subject may call the union of what its groups grant and what `toolsClaim` lists. With a map in force, a subject granted nothing may call no tool (`tools/list` and `initialize` still work), so dex users are restricted per tool without a key |

`auth.onBehalfOf` is for a caller that holds one key for many users (a hub, an
orchestrator): it names the user it acts for in a header, the gateway records that user as
the row's `subject` (the key stays on the row as the one that vouched, and `on_behalf_of`
repeats the name), an `AIUsagePolicy` with `budget.per: Subject` limits each user
separately, and the header never reaches the provider. Only keys matching `trustedKeys`
are believed: `name`, `tenant/name`, `tenant/*` (every key of the tenant, including keys a
hub issues later) or `label:key=value` (every key with that label; see
[Keys](#keys)). A bare `*` is refused. From any other key the header is dropped, so an
agent cannot claim to be someone else.

```yaml
auth:
  onBehalfOf:
    header: x-portus-on-behalf-of   # default
    trustedKeys: [team-a/hub]
```

A rule may carry `urlRewrite` with the shape of HTTPRoute's URLRewrite filter
(`path.type: ReplaceFullPath | ReplacePrefixMatch`), for a server that lives at `/mcp`
behind a route matched on `/tools/deepwiki`:

```yaml
rules:
  - matches: [{ path: { type: PathPrefix, value: /tools/deepwiki } }]
    urlRewrite: { path: { type: ReplaceFullPath, replaceFullPath: /mcp } }
    providerRefs: [{ name: deepwiki }]
```

Every response on an AI route carries `x-portus-request-id`, the id of the ledger row
(16 hex characters). A client may send its own id in the same header; it is stored as the
row's `client_request_id`, so a turn's tokens can be tied to the gateway's bill.

The body is scanned as it streams for `model`, `stream`, `max_tokens`, `method`, `id`
and `params` (`params` kept up to 64 KiB to read the tool name). Bodies over 8 MiB are
refused with 413; the bytes read are replayed to the provider unchanged.

## AIUsagePolicy

A budget on an AIRoute (`targetRef.kind: AIRoute`, same namespace, one policy per
route; the oldest wins a conflict).

| Field | Values | Notes |
|---|---|---|
| `budget.tokens` | integer ≥ 1 | Input + output + cache read + cache creation tokens per window (LLM routes) |
| `budget.calls` | integer ≥ 1 | JSON-RPC requests that reached the server per window (MCP routes) |
| `budget.window` | `Hourly`, `Daily`, `Monthly` | Fixed windows in UTC |
| `budget.per` | `Key` (default), `Subject`, `Tenant`, `Route` | Whose counter the request spends from. `Subject`: the user behind the call, the `auth.onBehalfOf` name under its key, else the key or OAuth subject itself |

| `onLedgerUnavailable` | `Open` (default), `Closed` | Before the first sync of a window with the ledger unreachable |
| `onExhausted.fallbackModel` | model name | Token budgets only: a spent budget sends the request to this model (same provider) instead of a 429 |
| `onExhausted.overflowTokens` | integer ≥ 1, default a tenth of `budget.tokens` | What the fallback may spend per subject and window; when it is spent too, requests are refused |

A key with its own `token_limit` or `call_limit` (see [Keys](#keys)) is held to that on
policies of that unit instead of `budget.tokens` / `budget.calls`, on `per: Key` and
`per: Subject` counters (each user under the key gets the key's limit). A token limit
never touches a call budget and the other way round. Tenant and route counters are shared
and a key cannot resize them. `GET /v1/limits` on the ledger shows the effective figures.

With `onExhausted`, the request whose budget is spent is rewritten to the fallback model
and forwarded; its response carries `x-portus-fallback-model`, its row keeps the model the
client asked for in `requested_model` and records `rule: <policy>#fallback`. The overflow
spends from its own counter (`<policy>#overflow` in `/v1/limits`), so the cap is still a
cap: budget plus overflow.

Exactly one of `tokens` and `calls` is set. The gateway forwards `Accept-Encoding: identity`
to providers on AI routes so it can read usage from the response; clients may still request
compression, it just does not reach the provider. Each data plane keeps a counter per subject,
reserves an estimate before forwarding (`max_tokens` plus a quarter of the request
bytes, or one call), settles to the provider's reported usage when the response ends and
syncs the delta with the ledger about once a second, so overrun is bounded by one sync
interval. A pod whose view of a subject is older than that asks the ledger before deciding
(one in-cluster round trip, at most 250 ms), so slow traffic spread across pods sees the
true total. A fallback's overflow can run over by what one request's estimate missed. Every budgeted response carries `x-portus-tokens-remaining` or
`x-portus-calls-remaining`.

## Keys

The ledger issues and imports keys; only SHA-256 hashes are stored and pushed to the
data planes. Every call below except `/metrics` needs the bearer token in the
`<release>-portus-gateway-ledger-admin` Secret (key `token`): the usage reads name keys,
tenants and subjects. `aiGateway.ledger.openReads: true` serves `/export.jsonl` and
`/v1/summary` without it, for a ledger nothing but operators can reach.

| Call | Body / result |
|---|---|
| `POST /v1/keys` | `{"tenant","name","allowed_models":[…],"allowed_tools":[…],"key","expires_in_secs","token_limit","call_limit","labels":{…}}`; `key` imports an external key (≥ 16 characters), omitted generates `portus_sk_` + 40 hex; `expires_in_secs` sets an expiry (omitted: never); `token_limit` and `call_limit` give the key its own budget per window on token and call policies, replacing the policy's limit for this key (omitted or 0: the policy's); `labels` (up to 32, keys of letters, digits, `-_./`) are returned on the key, its usage rows and events, and match `label:key=value` in `trustedKeys`. The plaintext is returned once |
| `PATCH /v1/keys/{id}` | Change `tenant`, `name`, `allowed_models`, `allowed_tools`, `expires_in_secs`, `token_limit`, `call_limit` (0 clears each) or `labels` (replaces the map; `{}` clears) in place; the plaintext keeps working and the data planes get the change within a second, so a policy change needs no new key and no restart. Rotation grace: issue the new key, give the old one `expires_in_secs` |
| `GET /v1/keys` | Every key, revoked ones included, without plaintext or hash; `expires_unix_secs` when set. Expired keys are revoked by the ledger within a minute and refused by the data planes at the second |
| `DELETE /v1/keys/{id}` | Revoke; data planes drop the key within a second |
| `GET /v1/summary?hours=N&by=` | Totals per group: `by=key` (default: a key's tenant and name, or an OAuth token's tenant claim and `sub`), `subject` (the user behind each key), `model` (per key and model; MCP: method), `tool` (per key, method and tool), `tenant`, `route` (host and provider). Each row: requests, refusals broken down by reason (`refused_unauthenticated`, `refused_model_not_allowed`, `refused_tool_not_allowed`, `refused_budget_exhausted`), `upstream_errors` (5xx from the provider), tokens, `duration_micros_total` and `first_byte_micros_total`/`first_byte_samples` for averages, `last_seen_unix_micros` |
| `GET /v1/series?hours=N&bucket_secs=S&by=` | The same rows per time bucket (`bucket_start_unix_micros`; default 3600 s, 60 s to 7 d, epoch-aligned) for charts and spike detection |
| `GET /v1/limits` | The effective limits: every AIUsagePolicy the data planes hold (`limit`, `unit`, `window`, `per`, `fail_open`, `window_end_unix_micros`), listed from the moment it is configured (data planes declare their policies within seconds of a config change and every minute; one no data plane holds for ten minutes drops out), with the current window's `spent`, `limit` and `remaining` per subject (a key override shows as that subject's limit), plus `key_budgets`: the live keys with a `token_limit` or `call_limit`, and their labels |
| `GET /export.jsonl?after_id=&limit=` (or `?since_us=`) | Page with `after_id`: the rows stored after that row id, in id order, never repeated or skipped; `x-portus-next-after-id` on the response is the cursor for the next page (start at `0`). One JSON row per request: status, dialect, provider, model or method, tool, tokens, bytes, key id, tenant, subject, `on_behalf_of`, refusal and `rule` (the AIUsagePolicy that refused, or `key`/`jwt` for an allow list), `request_id`, `client_request_id`, `duration_micros`, `first_byte_micros`, and `key_labels` when the key has labels |
| `GET /metrics` | Prometheus; no token |

`allowed_models` applies to LLM requests (empty: any model). `allowed_tools` applies to
MCP `tools/call` requests, exact names or `prefix.*` (empty: any tool); other MCP
methods only need a valid key.

## OAuth clients

Routes with `auth.jwt` accept bearer JWTs without any call-out on the request path:

- The ledger fetches each issuer in `aiGateway.jwt.issuers` (`/.well-known/openid-configuration`
  → `jwks_uri`, or `<issuer>/keys` for dex-style issuers) every five minutes and ships the
  JWKS to the data planes in the key snapshot.
- The data plane verifies signature, `exp`, `iss` and `aud` against those keys (RS*, PS*,
  ES*, EdDSA), then caches the verified token by hash until it expires; a cached token costs
  the same hash lookup as a Portus key.
- The subject's id, used in usage rows and per-key budgets, is derived from `(issuer, sub)`;
  its display name is `email`, `preferred_username` or `name` when the token has one, else
  `sub`; tenant and tool list come from `tenantClaim` and `toolsClaim`. A Portus key on the
  same route keeps working.
- The login flow starts from the gateway itself. A request without a valid token on such a
  route gets 401 with `WWW-Authenticate: Bearer realm="portus",
  resource_metadata="https://host/.well-known/oauth-protected-resource/<path>", scope="…"`
  (`error="invalid_token"` when a token was presented). That document (RFC 9728) names the
  route's resource, the issuer as its authorization server and `scopes_supported`; the
  host-level `/.well-known/oauth-protected-resource` answers too. From there the client reads
  the issuer's OpenID configuration and runs the authorization-code flow with PKCE. This is the
  chain claude.ai connectors and Claude Code follow.

```yaml
spec:
  requireApiKey: true
  auth:
    jwt:
      issuer: https://dex.example.com
      audience: portus
      toolsClaim: scope
```

## Refusals

Refusals are shaped like the provider's own errors so SDKs handle them without special
cases.

| Situation | Anthropic / OpenAI | MCP |
|---|---|---|
| No key or unknown key | 401 `authentication_error` | 401, JSON-RPC error `-32001` |
| Model not in `allowed_models` | 403 `permission_error` | n/a |
| Tool not in `allowed_tools` | n/a | 200, JSON-RPC error `-32002` with the request's `id` |
| Budget spent or too small for the request | 429 `rate_limit_error` / `insufficient_quota`, `Retry-After` | 200, JSON-RPC error `-32003` with the request's `id`, `Retry-After` |

MCP policy refusals are 200s on purpose: a non-2xx inside a session makes clients tear
the session down. Every refusal is recorded in the ledger with its reason
(`unauthenticated`, `model_not_allowed`, `tool_not_allowed`, `budget_exhausted`) and the
rule behind it (`rule`: the AIUsagePolicy's `namespace/name`, or `key`/`jwt` for an
allow list); `/v1/summary` counts them per reason. Refusals carry `x-portus-request-id`
too.

## Events

With `aiGateway.ledger.webhook.url` set, the ledger POSTs one JSON event per request to it:

| `type` | When | Fields |
|---|---|---|
| `budget.threshold` | A subject's spend crosses a threshold (`webhook.thresholds`, default `[80, 100]` percent of its limit); each fires once per subject and window, whichever pod's sync crossed it | `policy`, `subject`, `window`, `window_end_unix_micros`, `unit`, `threshold_pct`, `spent`, `limit`, and for key subjects `key_id`, `tenant`, `key_name`, `key_labels`, `user` (the on-behalf-of user under `per: Subject`) |
| `refusal` | The gateway refused a request of a kind in `webhook.refusals` (default `model_not_allowed`, `tool_not_allowed`, `budget_exhausted`) | `refusal`, `rule`, `status`, `key_id`, `tenant`, `subject`, `on_behalf_of`, `route_host`, `provider`, `model` or `method` and `tool`, `request_id`, `client_request_id`, `key_labels` |

Every event carries `id` and `ts_unix_micros`; `x-portus-event-id` repeats the id. Delivery
is at least once: events are written to an outbox in the same transaction as the spend or
usage row that caused them and deleted only after a 2xx, so a ledger restart can resend one
but never loses one. Deduplicate on `id`. A failed delivery is retried with backoff (2 s
doubling to 5 min) in order; after 20 attempts the event is dropped and logged. With
`webhook.secretName` set, `x-portus-signature: sha256=<hex>` is the HMAC-SHA256 of the
exact body with that Secret's key. `/metrics` has `ledger_events_pending` and delivered,
failed and dropped counters.

## MCP

Streamable HTTP (spec revision 2025-06-18) is the transport: the client `POST`s one
JSON-RPC message per request to the server's endpoint (`/mcp` by convention), `GET`
opens the server-to-client event stream, `DELETE` ends the session. The gateway:

- routes on `method` and `tool`, so `tools/call` for one namespace can go to one server
  and everything else to another;
- keeps a session on the server pod that created it. The `Mcp-Session-Id` the client
  receives is the gateway's tag for that endpoint (16 hex characters) followed by a dot
  and the server's own id; on every later request the tag picks the endpoint and the
  server sees only its id. Nothing is shared between gateway pods. When the endpoint is
  gone the request goes to another server, which answers 404 as the spec requires and the
  client re-initialises; `proxy_mcp_session_rehomed_total{provider}` counts those;
- passes `Mcp-Session-Id`, `MCP-Protocol-Version`, `Last-Event-ID` and `Accept` through
  untouched, rewrites `Host` to the provider;
- records one usage row per request with the method in the model column and the tool in
  the served-model column, no tokens; a `calls` budget counts them.

The older HTTP+SSE transport (2024-11-05) flows through an ordinary path rule: its
`POST`s route and are recorded like any other, but sessions are not pinned.

### Federation

Several MCP servers behind one endpoint, with namespaced tool names, is an `AIProvider`
of kind `mcp-federation` whose members are other `mcp` providers in the same namespace:

```yaml
apiVersion: portus-gateway.dev/v1alpha1
kind: AIProvider
metadata: {name: tools, namespace: agents}
spec:
  kind: mcp-federation
  members:
  - {name: github, provider: github-mcp}          # path defaults to /mcp
  - {name: wiki, provider: deepwiki, path: /mcp}
  - {name: aws, provider: aws-knowledge, path: /}
```

An `AIRoute` rule points at it like any provider. The gateway then:

- answers `initialize` itself after initialising every member (the first member's
  protocol version, a `tools` capability only, every member's `instructions` under its
  name); a member that fails to initialise fails the whole `initialize` with JSON-RPC
  `-32004`, so a session never starts half-formed;
- answers `tools/list` by asking every member and prefixing each tool with `<member>.`
  (`github.search`, `wiki.read_wiki_structure`); a member that fails is left out and
  logged;
- routes `tools/call` by the prefix, strips it from `params.name` and streams the member's
  reply back; an unknown prefix is `-32602`;
- fans `notifications/*` and `DELETE` out to every member; answers `ping`, `prompts/list`,
  `resources/list` and `resources/templates/list` itself (empty); other methods are
  `-32601`; `GET` streams are `405`;
- keeps every member's session inside the client's `Mcp-Session-Id`
  (`fed.github=<tag>.<id>;wiki=<tag>.<id>`), each pinned to the member endpoint that
  created it, so any gateway pod serves any request and nothing is stored anywhere.

Allow lists, budgets and usage rows see the namespaced name: a key with
`allowed_tools: ["github.*", "wiki.read_wiki_structure"]` may call exactly those, and
rows carry `github.search` in the tool column. Members keep their own credentials, TLS and
Host. Two members that both offer `echo` no longer clash.

A server-to-client stream is a request in flight: on a pod drain it is cut after
`PORTUS_DRAIN_SECONDS` (25) and the client resumes with `Last-Event-ID` on the new pod,
which the affinity hash sends to the same server.

Claude Code against a Portus MCP endpoint:

```bash
claude mcp add --transport http tools https://mcp.example.com/mcp \
  --header "Authorization: Bearer portus_sk_…"
```

Examples: [`deploy/examples/ai-gateway/`](../deploy/examples/ai-gateway/).
