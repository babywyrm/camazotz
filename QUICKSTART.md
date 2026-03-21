# Camazotz Quickstart

Get Camazotz running locally in a few minutes using `uv` and Docker Compose.

## 1) Prerequisites

- `uv` installed
- Docker Desktop (or Docker Engine + Compose plugin)
- Python 3.13+ (managed automatically by `uv` if needed)

## 2) Install dependencies

From the project root:

```bash
uv sync
```

## 3) Verify tests

Camazotz is pytest-driven with strict coverage:

```bash
uv run pytest tests -v
```

## 4) Start Camazotz

Default startup uses the cloud brain provider:

```bash
docker compose -f compose/docker-compose.yml up -d
```

## 5) Confirm MCP endpoint works

Initialize:

```bash
curl -s http://localhost:8080/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

List tools:

```bash
curl -s http://localhost:8080/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## 6) Switch runtime profiles

Starter profile (default behavior):

```bash
docker compose --env-file compose/profiles/starter.env -f compose/docker-compose.yml up -d
```

Weird profile:

```bash
docker compose --env-file compose/profiles/weird.env -f compose/docker-compose.yml up -d
```

Chaotic profile (currently local provider default):

```bash
docker compose --env-file compose/profiles/chaotic.env -f compose/docker-compose.yml up -d
```

## 7) Toggle brain provider explicitly

Cloud (Claude-style provider):

```bash
BRAIN_PROVIDER=cloud docker compose -f compose/docker-compose.yml up -d
```

Local (Ollama/Qwen path):

```bash
BRAIN_PROVIDER=local docker compose -f compose/docker-compose.yml up -d
```

## 8) Run a first scanner check (mcpvenom)

Example target:

```bash
./scan --targets http://localhost:8080/mcp --verbose
```

Or JSON output:

```bash
./scan --targets http://localhost:8080/mcp --json camazotz-scan.json
```

## 9) Stop and clean up

```bash
docker compose -f compose/docker-compose.yml down
```

