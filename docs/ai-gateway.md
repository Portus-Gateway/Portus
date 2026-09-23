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
helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.4 \
  --namespace portus --create-namespace --set aiGateway.enabled=true
```

A fresh install carries the AI CRDs. On an existing install, `helm upgrade` does not
touch CRDs: apply `deploy/helm/crds/aiprovider.yaml`, `airoute.yaml` and
`aiusagepolicy.yaml` by hand, upgrade with `--reset-then-reuse-values`, and delete the
generated `<release>-portus-gateway-grpc-tls` Secret once so it is regenerated with the
ledger's names. The AI gateway runs on the Rama network stack, the default since 0.2.4.

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
| `budget.per` | `Key` (default), `Tenant`, `Route` | Whose counter the request spends from |
| `onLedgerUnavailable` | `Open` (default), `Closed` | Before the first sync of a window with the ledger unreachable |

Exactly one of `tokens` and `calls` is set. Each data plane keeps a counter per subject,
reserves an estimate before forwarding (`max_tokens` plus a quarter of the request
bytes, or one call), settles to the provider's reported usage when the response ends and
syncs the delta with the ledger about once a second, so overrun is bounded by one sync
interval. Every budgeted response carries `x-portus-tokens-remaining` or
`x-portus-calls-remaining`.

## Keys

The ledger issues and imports keys; only SHA-256 hashes are stored and pushed to the
data planes. Admin calls need the bearer token in the `<release>-portus-gateway-ledger-admin`
Secret (key `token`).

| Call | Body / result |
|---|---|
| `POST /v1/keys` | `{"tenant","name","allowed_models":[…],"allowed_tools":[…],"key"}`; `key` imports an external key (≥ 16 characters), omitted generates `portus_sk_` + 40 hex. The plaintext is returned once |
| `GET /v1/keys` | Every key, revoked ones included, without plaintext or hash |
| `DELETE /v1/keys/{id}` | Revoke; data planes drop the key within a second |
| `GET /v1/summary?hours=N` | Requests, refusals and tokens per key |
| `GET /export.jsonl?since_us=&limit=` | One JSON row per request: status, dialect, provider, model or method, tool, tokens, bytes, key, refusal |
| `GET /metrics` | Prometheus |

`allowed_models` applies to LLM requests (empty: any model). `allowed_tools` applies to
MCP `tools/call` requests, exact names or `prefix.*` (empty: any tool); other MCP
methods only need a valid key.

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
(`unauthenticated`, `model_not_allowed`, `tool_not_allowed`, `budget_exhausted`).

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

A server-to-client stream is a request in flight: on a pod drain it is cut after
`PORTUS_DRAIN_SECONDS` (25) and the client resumes with `Last-Event-ID` on the new pod,
which the affinity hash sends to the same server.

Claude Code against a Portus MCP endpoint:

```bash
claude mcp add --transport http tools https://mcp.example.com/mcp \
  --header "Authorization: Bearer portus_sk_…"
```

Examples: [`deploy/examples/ai-gateway/`](../deploy/examples/ai-gateway/).
