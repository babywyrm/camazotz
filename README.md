# camazotz

MCP security playground for intentionally vulnerable module labs.

Camazotz is a local-first sandbox for learning MCP security. It ships with four
vulnerability scenarios covering indirect prompt injection, confused deputy auth
bypass, SSRF via tool, and rug pull tool drift. Two scenarios use a live Claude
LLM; two are fully deterministic.

See `QUICKSTART.md` for the fastest path to run locally.
See `docs/scenarios.md` for the full scenario reference with red and blue team exercises.
See `docs/module-authoring.md` for adding new vulnerability modules.

## Development workflow

- Use `uv` for dependency management and command execution.
- Run `uv sync` after dependency changes.
- Run tests with `uv run pytest`.
- Coverage is enforced at 100%.

## Local run

With Docker Compose:

```bash
cp compose/.env.example compose/.env
# Edit compose/.env to add ANTHROPIC_API_KEY for live Claude tools
docker compose -f compose/docker-compose.yml --env-file compose/.env up -d --build
```

Without Docker:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uv run uvicorn brain_gateway.app.main:app --host 0.0.0.0 --port 8080
```

## Current tools

| Tool | Type | Vulnerability |
|------|------|---------------|
| `context.injectable_summary` | Claude-powered | Indirect prompt injection |
| `auth.issue_token` | Claude-powered | Confused deputy auth bypass |
| `egress.fetch_url` | Static | SSRF via tool |
| `tool.mutate_behavior` | Static | Rug pull / tool drift |

## Regression checks

- Baseline file: `tests/regression/baselines/starter.json`
- Run baseline tests: `uv run pytest tests/regression -v`
- Use these assets to compare `mcpvenom` scan deltas over time.
