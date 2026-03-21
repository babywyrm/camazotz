# Camazotz Quickstart

Get Camazotz running locally in a few minutes using `uv` and Docker Compose.

## 1) Prerequisites

- `uv` installed
- Docker Desktop (or Docker Engine + Compose plugin)
- Python 3.13+ (managed automatically by `uv` if needed)
- Optional: `ANTHROPIC_API_KEY` for live Claude-powered tools

## 2) Install dependencies

From the project root:

```bash
uv sync
```

## 3) Verify tests

Camazotz is pytest-driven with strict 100% coverage:

```bash
uv run pytest tests -v
```

## 4) Configure environment

Copy the example env file and add your API key:

```bash
cp compose/.env.example compose/.env
```

Edit `compose/.env` and set `ANTHROPIC_API_KEY` if you want live Claude responses.
Without a key, Claude-powered tools return deterministic stub responses (still useful for testing).

## 5) Start Camazotz

```bash
docker compose -f compose/docker-compose.yml --env-file compose/.env up -d --build
```

## 6) Confirm MCP endpoint works

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

## 7) Try a scenario

Call the context injection tool:

```bash
curl -s http://localhost:8080/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
    "name":"context.injectable_summary",
    "arguments":{"text":"Hello world. This is a test."}
  }}'
```

See `docs/scenarios.md` for the full scenario reference with red team and blue team exercises.

## 8) Switch runtime profiles

Starter profile (default):

```bash
docker compose --env-file compose/profiles/starter.env -f compose/docker-compose.yml up -d
```

Chaotic profile (local provider):

```bash
docker compose --env-file compose/profiles/chaotic.env -f compose/docker-compose.yml up -d
```

## 9) Run without Docker (alternative)

You can also run the gateway directly with uv:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uv run uvicorn brain_gateway.app.main:app --host 0.0.0.0 --port 8080
```

## 10) Run a scanner check (mcpvenom)

```bash
./scan --targets http://localhost:8080/mcp --verbose
```

## 11) Stop and clean up

```bash
docker compose -f compose/docker-compose.yml down
```
