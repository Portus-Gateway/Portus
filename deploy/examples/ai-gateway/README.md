# AI gateway examples

The AI gateway routes LLM requests on fields of their JSON body, checks
Portus API keys, enforces token budgets and records usage in the ledger.
Clients keep speaking the provider's native API.

1. Install with the ledger:
   `helm upgrade --install portus oci://ghcr.io/portus-gateway/charts/portus-gateway --version 0.2.7 -n portus --create-namespace --set aiGateway.enabled=true`.
   A fresh install carries the AI CRDs. An existing install: apply
   `deploy/helm/crds/aiprovider.yaml`, `airoute.yaml` and `aiusagepolicy.yaml`
   by hand (Helm does not upgrade CRDs) and pass your values with `-f`, not
   a reuse flag. Installs first created before 0.2.6 also delete the
   generated `portus-portus-gateway-grpc-tls` Secret once so it is
   regenerated with the ledger's names.
2. Put your provider key in the Secret and apply `provider-and-route.yaml`,
   then `budget.yaml`.
3. Issue a client key through the ledger's admin API:
   ```sh
   TOKEN=$(kubectl get secret -n portus portus-portus-gateway-ledger-admin -o jsonpath='{.data.token}' | base64 -d)
   kubectl port-forward -n portus deploy/portus-portus-gateway-ledger 8083:8083 &
   curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"tenant":"team-a","name":"laptop","allowed_models":["claude-opus-5","claude-haiku-4-5"]}' \
     localhost:8083/v1/keys
   ```
   The response shows the key once (`portus_sk_…`). `GET /v1/keys` lists
   keys without plaintext; `DELETE /v1/keys/{id}` revokes within a second.
4. Point a client at the gateway. Claude Code:
   `ANTHROPIC_BASE_URL=https://llm.example.com ANTHROPIC_API_KEY=portus_sk_… claude`
5. Read usage: `curl -H "Authorization: Bearer $TOKEN" 'localhost:8083/export.jsonl?limit=100'` (one JSON row
   per request: model, tokens, key id, status, latency) and `/metrics`.

6. MCP: `mcp.yaml` puts an MCP server behind the same gateway. Issue a key
   with `"allowed_tools":["github.*"]`, then in Claude Code:
   `claude mcp add --transport http github https://mcp.example.com/mcp --header "Authorization: Bearer portus_sk_…"`.
   A `calls` budget counts JSON-RPC requests; a disallowed tool or a spent
   budget comes back as a JSON-RPC error on 200 so the session survives.

Refusals come back in the provider's error shape: 401 for a missing or
unknown key, 403 for a model outside the key's list, 429 with `Retry-After`
when the budget for the window is spent.
