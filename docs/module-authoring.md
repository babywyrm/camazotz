# Camazotz Module Authoring Guide

## Module contract

Each module class must expose:

- `list_tools() -> list[dict]`
- `call_tool(name: str, arguments: dict) -> dict | None`

Tool metadata must include:

- `name`
- `description`

## Naming rules

- Prefix tool names by domain (`auth.`, `tool.`, `context.`, `egress.`).
- Keep names stable so scanner regressions stay meaningful.

## Telemetry expectations

Tool calls are recorded by the gateway observer using:

- `request_id`
- `tool_name`
- `module`
- `timestamp`

## Testing rules

- Add pytest coverage for every module code path.
- Keep global coverage at 100%.
- Run tests with `uv run pytest`.
