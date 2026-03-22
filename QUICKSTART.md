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

## Option A: Cloud provider (Claude)

Requires an `ANTHROPIC_API_KEY`.

```bash
make env                        # creates compose/.env from example
# Edit compose/.env — add your ANTHROPIC_API_KEY
make up                         # builds and starts all services
```

Services:

| Service | URL | Description |
|---------|-----|-------------|
| Portal | http://localhost:3000 | Branded web interface |
| Gateway | http://localhost:8080 | MCP JSON-RPC API |

## Option B: Local provider (Ollama)

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
| Gateway | http://localhost:8080 | MCP JSON-RPC API |
| Ollama | http://localhost:11434 | Local LLM inference |

## Verify it works

```bash
make status                     # health check all services
```

Or hit the gateway directly:

```bash
curl -s http://localhost:8080/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

Then open http://localhost:3000 in your browser. Use the difficulty
dropdown in the nav bar to switch between easy/medium/hard in real-time.

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
| `BRAIN_PROVIDER` | `cloud` | `cloud` (Claude) or `local` (Ollama) |
| `ANTHROPIC_API_KEY` | (empty) | Required for Claude |
| `CAMAZOTZ_DIFFICULTY` | `medium` | `easy`, `medium`, or `hard` (switchable live from portal) |
| `CAMAZOTZ_SHOW_TOKENS` | `false` | Show token usage and cost |
| `CAMAZOTZ_OLLAMA_MODEL` | `llama3.2:3b` | Ollama model name |

See [README.md](README.md) for the full configuration reference.

## Runtime Profiles

Switch scenario profiles by pointing to a different env file:

```bash
# Starter (default — cloud provider)
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
uv run uvicorn brain_gateway.app.main:app --host 0.0.0.0 --port 8080

# In another terminal, start the portal:
cd frontend && pip install -r requirements.txt
GATEWAY_URL=http://localhost:8080 python3 app.py
```
