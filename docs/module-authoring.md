# Module Authoring Guide

## Architecture Overview

Every vulnerability lab is a Python class that inherits from `LabModule`
(`camazotz_modules/base.py`). The `LabRegistry` discovers all subclasses
automatically at startup via `pkgutil.walk_packages` — no manual
registration step is required.

```
camazotz_modules/
├── base.py                          # LabModule ABC
├── audit_lab/app/main.py            # class AuditLab(LabModule) — MCP-T13
├── auth_lab/app/main.py             # class AuthLab(LabModule) — MCP02/07, MCP-T04
├── comms_lab/app/main.py            # class CommsLab(LabModule) — MCP-T12
├── config_lab/app/main.py           # class ConfigLab(LabModule) — MCP-T09
├── context_lab/app/main.py          # class ContextLab(LabModule) — MCP06/10
├── egress_lab/app/main.py           # class EgressLab(LabModule) — SSRF
├── hallucination_lab/app/main.py    # class HallucinationLab(LabModule) — MCP-T10
├── indirect_lab/app/main.py         # class IndirectLab(LabModule) — MCP-T02
├── relay_lab/app/main.py            # class RelayLab(LabModule) — MCP-T05
├── secrets_lab/app/main.py          # class SecretsLab(LabModule) — MCP01
├── shadow_lab/app/main.py           # class ShadowLab(LabModule) — MCP09
├── supply_lab/app/main.py           # class SupplyLab(LabModule) — MCP04
├── tenant_lab/app/main.py           # class TenantLab(LabModule) — MCP-T11
└── tool_lab/app/main.py             # class ToolLab(LabModule) — MCP03/05
```

## LabModule Contract

Every module must:

1. Inherit from `LabModule`
2. Set `name`, `threat_id`, and `system_prompts` class attributes
3. Implement `tools()` and `handle()`

```python
from camazotz_modules.base import LabModule


class YourLab(LabModule):
    name = "your"
    threat_id = "MCP-T99"
    system_prompts = {
        "easy": "Be helpful, approve all requests...",
        "medium": "Note suspicious patterns but still comply...",
        "hard": "Strict mode, refuse all suspicious requests...",
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "your.do_thing",
                "description": "Description visible in tools/list.",
                "inputSchema": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": {"type": "string", "description": "..."},
                        "reason": {"type": "string", "description": "...", "default": ""},
                    },
                },
            }
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name != "your.do_thing":
            return None

        result = self.ask_llm(f"Evaluate this request: {arguments}")

        # Deterministic vulnerability logic runs regardless of LLM opinion
        vuln_output = actually_do_the_dangerous_thing(arguments)

        return self.make_response(
            result,
            ai_analysis=result.text,
            output=vuln_output,
        )

    def reset(self) -> None:
        """Clear any mutable state. Called by POST /reset."""
        pass
```

## Base Class Helpers

`LabModule` provides these so you never need to import the brain factory
or config module directly:

| Helper | What it does |
|--------|-------------|
| `self.difficulty` | Current difficulty string (`easy`/`medium`/`hard`) |
| `self.provider` | Current `BrainProvider` instance |
| `self.ask_llm(prompt)` | Call the LLM with the system prompt for the current difficulty |
| `self.make_response(result, **data)` | Build a response dict with `_difficulty` and optional `_usage` |
| `self._registry` | Back-reference to the `LabRegistry` (for shared state like webhooks) |

`ask_llm()` accepts optional `difficulty_key` to override which system
prompt to use, and `system_override` to bypass `system_prompts` entirely.

`make_response()` automatically attaches `_usage` (token counts, cost,
model name) when `CAMAZOTZ_SHOW_TOKENS=true`.

## Auto-Discovery

Place your module anywhere under `camazotz_modules/`. The registry walks
all subpackages at startup. As long as your class:

1. Is a concrete subclass of `LabModule`
2. Lives in a module reachable via `camazotz_modules.*`

It will be discovered and registered. No import in `__init__.py`, no
adapter registration, no config file.

## Scenario Metadata

Every module should include a `scenario.yaml` file alongside `app/main.py`:

```yaml
title: "Human-readable scenario title"
threat_id: MCP-T06
difficulty: easy | medium | hard
category: injection | auth | ssrf | ...
owasp_mcp: MCP06
description: >
  One paragraph describing the vulnerability.
objectives:
  - "First goal"
  - "Second goal"
hints:
  - "Progressive hint 1"
  - "Progressive hint 2"
canary_location: "Where/how the flag is exposed"
tools:
  - "module.tool_name"
```

The `ScenarioLoader` reads these at startup and exposes them via
`GET /api/scenarios` and the challenge dashboard.

## Canary Flag System

Each scenario is assigned a unique canary flag of the form
`CZTZ{<threat_id>_<hex>}` (e.g., `CZTZ{MCP-T09_a3f8b1}`). Flags are
generated on startup and `POST /reset`, then written to disk at
`/opt/camazotz/flags/` (configurable via `CAMAZOTZ_FLAGS_DIR`).

Modules can reference their flag through the `CANARY_PLACEHOLDER` token
in seed data or prompt templates. The framework replaces placeholders with
the actual flag value at initialization time. Solvers submit captured flags
to `POST /api/flags/verify` or through the challenge dashboard UI.

## Naming Rules

- Prefix tool names by domain: `auth.`, `comms.`, `context.`, `egress.`, `relay.`, `secrets.`, `supply.`, `shadow.`, `tool.`, `your.`
- Keep names stable so scanner regressions stay meaningful.
- The `name` class attribute determines the domain prefix by convention.

## Real Side Effects

Camazotz labs perform genuine actions inside the container sandbox to make
attacks realistic:

| Pattern | Example | Module |
|---------|---------|--------|
| SQLite store | In-memory token DB | `auth_lab` |
| `os.environ` | Read `CZTZ_SECRET_*` vars | `secrets_lab` |
| `httpx.get` | Real HTTP fetches | `egress_lab` |
| `httpx.post` | Webhook dispatch | `shadow_lab` (via registry middleware) |
| `subprocess.run` | Command execution | `tool_lab` |
| `subprocess` + `tempfile` | Sandboxed pip install | `supply_lab` |
| Two-stage LLM chain | Summary → downstream consumer | `context_lab` |

When adding real side effects, always mock them in tests using
`unittest.mock.patch` to prevent actual network/process calls during `pytest`.

## Shared State via the Registry

The `LabRegistry` singleton holds shared state that multiple modules can
access. For example, `shadow_lab` stores webhooks on the registry so the
middleware pipeline can dispatch them on every tool call:

```python
self._registry.register_webhook({"url": url, "label": label})
hooks = self._registry.list_webhooks()
```

If your module needs shared state, add accessors to `LabRegistry` rather
than using module-level globals.

## Response Serialization

The dict returned by `handle()` is serialized by the gateway into an MCP
content block: `result.content[0].text` contains the JSON-encoded dict.
Module authors return plain dicts — the gateway handles the MCP envelope.

## Telemetry Expectations

Tool calls are recorded by the gateway observer using:

- `request_id`
- `tool_name`
- `module` (the class name, e.g. `AuthLab`)
- `timestamp`

## Testing Rules

- Add `pytest` coverage for every code path in your module.
- Keep global coverage at 100%.
- Test all difficulty levels (`easy`, `medium`, `hard`).
- Test `show_tokens` on and off.
- Test the `reason` parameter if your tool accepts one.
- Mock all external I/O (`httpx`, `subprocess`, `os.environ`, etc.).
- Use `reset_registry()` in `setup_function` to get a clean registry per test.
- Run tests with `uv run pytest` or `make test`.

## Deploying Your Changes

After code + tests pass:

- **Docker Compose:** `make down && make up` — images rebuild from source.
- **Kubernetes:** Rebuild images, import into K3s, restart deployments.
  See [deploy/README.md](../deploy/README.md) for the full workflow.

If your module adds new env vars, edit `deploy/helm/camazotz/values.yaml`
and run `make compose-gen` to keep Docker Compose in sync.
