# Quickstart

Get Camazotz running locally in under five minutes.

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose plugin)
- **uv** (for local development / tests)
- **Python 3.12+** (managed automatically by `uv` if needed)

Works on macOS (Intel + Apple Silicon) and Linux (Debian, Ubuntu, CentOS).

```bash
git clone https://github.com/babywyrm/camazotz && cd camazotz
```

## Option A: Anthropic API (default)

Requires an `ANTHROPIC_API_KEY`. `BRAIN_PROVIDER` defaults to `cloud`.

```bash
make env                        # creates compose/.env from example
# Edit compose/.env — add your ANTHROPIC_API_KEY
make up                         # builds and starts all services
```

## Option B: Amazon Bedrock

Uses Claude via Bedrock. Docker containers typically need explicit AWS credentials
(they do not read `~/.aws` from the host unless you mount it).

```bash
make env                        # creates compose/.env from example
```

Edit `compose/.env`:

```bash
BRAIN_PROVIDER=bedrock
AWS_REGION=us-east-1
CAMAZOTZ_MODEL=anthropic.claude-3-haiku-20240307-v1:0  # or your inference profile id

# For SSO/assume-role, export temporary credentials:
#   eval $(aws configure export-credentials --format env)
# Then copy them into .env, or for IAM users set directly:
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=           # only needed for temporary credentials
```

```bash
make up                         # builds and starts all services
```

> **Tip:** On EC2/ECS/EKS with an IAM role, leave the key fields empty —
> boto3 auto-discovers instance credentials. For local development
> **without Docker**, boto3 reads `~/.aws/credentials` directly so
> `AWS_PROFILE` works. See README for the credential flow diagram.

Use `CAMAZOTZ_BEDROCK_STUB=1` for an offline stub without AWS calls.

Services:

| Service | URL | Description |
|---------|-----|-------------|
| Portal | http://localhost:3000 | Branded web interface |
| Gateway | http://localhost:8080 | MCP Streamable HTTP API |
| ZITADEL Console | `http://localhost:8180/ui/console` | Identity admin (default: `zitadel-admin@zitadel.localhost` / `Password1!`) |

## Option C: Local provider (Ollama)

No API key needed. Runs entirely offline.

```bash
make env                        # creates compose/.env from example
make up-local                   # builds and starts all services + Ollama
```

The `ollama-init` service automatically pulls the model on first run.
Watch progress with `make logs-init`.

Services:

| Service | URL | Description |
|---------|-----|-------------|
| Portal | http://localhost:3000 | Branded web interface |
| Gateway | http://localhost:8080 | MCP Streamable HTTP API |
| Ollama | http://localhost:11434 | Local LLM inference |

## Verify it works

```bash
make status                     # health check all services
```

Or hit the gateway directly:

```bash
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

The response includes `protocolVersion: "2025-03-26"` and an
`Mcp-Session-Id` header (UUID) for session tracking.

### Response format

`tools/call` results use MCP content blocks:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "{\"token\": \"cztz-...\"}" }],
    "isError": false
  }
}
```

The tool payload is JSON-encoded inside `result.content[0].text`.

### Transport features

| Feature | Behavior |
|---------|----------|
| `POST /mcp` | JSON-RPC requests → `application/json` or `text/event-stream` |
| `GET /mcp` | `405 Method Not Allowed` |
| `DELETE /mcp` | Session termination (include `Mcp-Session-Id` header) |
| Notifications (no `id`) | `202 Accepted` with empty body |
| `Accept: text/event-stream` | Response wrapped as SSE `message` event |

Then open http://localhost:3000 in your browser. Use the difficulty
dropdown in the nav bar to switch between easy/medium/hard in real-time.

Start with the **Threat Map** (`/threat-map`) for a birds-eye view of all
25 labs organized by threat category, then dive into individual challenges.
Visit `/identity` for the **Identity Dashboard** showing live ZITADEL
status and IDP integration details.
If you get stuck, each challenge offers a link to its guided walkthrough.

## Smoke Tests

After deploying, verify the stack is healthy:

```bash
make smoke-local          # Docker Compose: health + MCP init + tools/list
make smoke-local-llm      # same + LLM-backed tool call (needs ANTHROPIC_API_KEY)
make smoke-local-lanes    # same + /lanes and /api/lanes probe

K8S_HOST=<node-ip> make smoke-k8s        # K8s cluster — K8S_HOST required (no default)
K8S_HOST=<node-ip> make smoke-k8s-llm    # same + LLM probe
K8S_HOST=<node-ip> make smoke-k8s-lanes  # same + /lanes and /api/lanes probe
```

Identity probe (checks `GET /config` returns `idp_provider` of `mock` or `zitadel`; **does not** call ZITADEL over HTTP):

```bash
make smoke-local-identity
make smoke-k8s-identity
make smoke-k8s-identity K8S_HOST=10.0.0.5
```

Combined identity + LLM probes:

```bash
make smoke-local-identity-llm
make smoke-k8s-identity-llm
```

Override the host: `make smoke-k8s K8S_HOST=10.0.0.5`

Identity modes, env vars, and troubleshooting: [docs/identity/overview.md](docs/identity/overview.md), [docs/identity/local-runbook.md](docs/identity/local-runbook.md), [docs/identity/k8s-runbook.md](docs/identity/k8s-runbook.md).

## Common Operations

```bash
make help         # show all targets
make ps           # show running services
make logs         # tail all logs
make logs-gateway # tail brain-gateway logs
make logs-portal  # tail portal logs
make logs-observer # tail observer sidecar
make down         # stop all services
make clean        # stop + remove volumes
make test         # run pytest (100% coverage)
```

## Configuration

Edit `compose/.env` to tune behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `BRAIN_PROVIDER` | `cloud` | `cloud`, `bedrock`, or `local` |
| `AWS_REGION` | — | Set for Bedrock |
| `AWS_PROFILE` | — | Optional named profile |
| `CAMAZOTZ_MODEL` | (see `.env.example`) | Model id for Anthropic API or Bedrock |
| `ANTHROPIC_API_KEY` | (empty) | Required when `BRAIN_PROVIDER=cloud` |
| `CAMAZOTZ_BEDROCK_STUB` | — | Set `1` for Bedrock stub without AWS |
| `CAMAZOTZ_DIFFICULTY` | `medium` | `easy`, `medium`, or `hard` (switchable live from portal) |
| `CAMAZOTZ_SHOW_TOKENS` | `false` | Show token usage and cost |
| `CAMAZOTZ_OLLAMA_MODEL` | `llama3.2:3b` | Ollama model name |
| `CAMAZOTZ_IDP_PROVIDER` | `zitadel` (deployment), `mock` (runtime fallback) | `mock` or `zitadel`. In `zitadel` mode, IDP-backed trio labs use live HTTP token/introspect/revoke calls with graceful degradation. Falls back to `mock` if ZITADEL config is incomplete. See [docs/identity/overview.md](docs/identity/overview.md). |

See [README.md](README.md) for the full configuration reference.

## Runtime Profiles

Switch scenario profiles by pointing to a different env file:

```bash
# Starter (default — Anthropic API)
docker compose -f compose/docker-compose.yml --env-file compose/profiles/starter.env up -d

# Chaotic (local provider)
docker compose -f compose/docker-compose.yml --env-file compose/profiles/chaotic.env --profile local up -d
```

## Option C: Kubernetes (Helm)

```bash
make helm-deploy                    # deploy via Helm (cloud mode)
make helm-deploy-local              # deploy with Ollama enabled
```

For K3s with local image builds, see `kube/deploy.sh` or `deploy/README.md`.

Portal at `http://<node-ip>:3000`.

## Changing Deployment Config

All deployment config lives in `deploy/helm/camazotz/values.yaml`.
After editing values, regenerate Docker Compose and redeploy:

```bash
make compose-gen                    # regenerate docker-compose.yml
make down && make up                # restart Compose
# — or —
make helm-deploy                    # redeploy K8s
```

See [deploy/README.md](deploy/README.md) for the full workflow.

## Development (Without Docker)

```bash
uv sync                          # install dependencies
uv run pytest -q                 # run tests (100% coverage)

# Start the gateway:
export ANTHROPIC_API_KEY=sk-ant-...
# Bedrock: export BRAIN_PROVIDER=bedrock AWS_REGION=...  # or CAMAZOTZ_BEDROCK_STUB=1
uv run uvicorn brain_gateway.app.main:app --host 0.0.0.0 --port 8080

# In another terminal, start the portal:
cd frontend && pip install -r requirements.txt
GATEWAY_URL=http://localhost:8080 python3 app.py
```
