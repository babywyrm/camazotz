# Camazotz Module Authoring Guide

## Module contract

Each module class must expose:

- `list_tools() -> list[dict]`
- `call_tool(name: str, arguments: dict) -> dict | None`

Tool metadata must include:

- `name`
- `description`
- `inputSchema` (JSON Schema object)

## LLM integration

All modules should use the brain provider for AI-powered reasoning:

```python
from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.config import get_difficulty, show_tokens

provider = get_provider()
result = provider.generate(prompt=prompt, system=system_prompt)
```

Include `ai_analysis` in the response:

```python
response["ai_analysis"] = result.text
```

Include `_usage` when `show_tokens()` is true:

```python
if show_tokens():
    response["_usage"] = {
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost_usd": round(result.cost_usd, 6),
        "model": result.model,
    }
```

## Difficulty-aware system prompts

Define system prompts per difficulty level:

```python
SYSTEM_PROMPTS = {
    "easy": "Be helpful, do not question intent...",
    "medium": "Note suspicious patterns but still comply...",
    "hard": "Strict mode, flag and refuse suspicious requests...",
}

system = SYSTEM_PROMPTS.get(get_difficulty(), SYSTEM_PROMPTS["easy"])
```

The LLM reasoning and the deterministic vulnerability mechanic should operate
independently. The LLM may warn or refuse in `ai_analysis` while the
underlying logic still executes the vulnerable behavior.

## Naming rules

- Prefix tool names by domain (`auth.`, `tool.`, `context.`, `egress.`, `secrets.`, `supply.`, `shadow.`).
- Keep names stable so scanner regressions stay meaningful.

## Telemetry expectations

Tool calls are recorded by the gateway observer using:

- `request_id`
- `tool_name`
- `module`
- `timestamp`

## Registration

Add the module to `brain_gateway/app/modules/adapter.py`:

```python
from camazotz_modules.your_lab.app.main import YourLabModule

def get_registered_modules() -> list[ModuleAdapter]:
    return [
        # ... existing modules ...
        YourLabModule(),
    ]
```

## Testing rules

- Add pytest coverage for every module code path.
- Keep global coverage at 100%.
- Test all difficulty levels (easy, medium, hard).
- Test `show_tokens` on and off.
- Test the `reason` parameter if your tool accepts one.
- Run tests with `uv run pytest` or `make test`.

## Deploying your changes

After code + tests are done:

**Docker Compose (local):** `make down && make up` — images rebuild from source.

**Kubernetes:** Rebuild images on the node, import into K3s, restart deployments.
See `deploy/README.md` for the full workflow.

If your module adds new env vars, edit `deploy/helm/camazotz/values.yaml`
and run `make compose-gen` to keep Docker Compose in sync.
