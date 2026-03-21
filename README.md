# camazotz

MCP security playground for intentionally vulnerable module labs.

See `QUICKSTART.md` for the fastest path to run locally.

## Development workflow

- Use `uv` for dependency management and command execution.
- Run `uv sync` after dependency changes.
- Run tests with `uv run pytest`.
- Coverage is enforced via pytest config (current fail-under is 100%).

## Local run

- Start services: `docker compose -f compose/docker-compose.yml up -d`
- Stop services: `docker compose -f compose/docker-compose.yml down`
- Default brain provider is cloud; override with `BRAIN_PROVIDER=local`.

## Regression checks

- Baseline file: `tests/regression/baselines/starter.json`
- Run baseline presence tests: `uv run pytest tests/regression -v`
- Use these assets to compare `mcpvenom` scan deltas over time.
