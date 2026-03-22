# Module Authoring Guide

## Architecture Overview

Every vulnerability lab is a Python class that inherits from `LabModule`
(`camazotz_modules/base.py`). The `LabRegistry` discovers all subclasses
automatically at startup via `pkgutil.walk_packages` — no manual
registration step is required.

```
camazotz_modules/
├── base.py                  # LabModule ABC
├── auth_lab/app/main.py     # class AuthLab(LabModule) — T03, T04
├── comms_lab/app/main.py    # class CommsLab(LabModule) — T12
├── context_lab/app/main.py  # class ContextLab(LabModule) — T01, T02
├── egress_lab/app/main.py   # class EgressLab(LabModule) — T06
├── relay_lab/app/main.py    # class RelayLab(LabModule) — T05
├── secrets_lab/app/main.py  # class SecretsLab(LabModule) — T07
├── shadow_lab/app/main.py   # class ShadowLab(LabModule) — T10
├── supply_lab/app/main.py   # class SupplyLab(LabModule) — T04/supply
└── tool_lab/app/main.py     # class ToolLab(LabModule) — T03/tool
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

## Naming Rules

- Prefix tool names by domain: `auth.`, `context.`, `egress.`, `secrets.`, `supply.`, `shadow.`, `tool.`, `your.`
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
