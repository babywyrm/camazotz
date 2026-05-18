# Testing Guide

Camazotz has **1298+ tests** that run in ~35 seconds with zero mocks for
the happy paths. This document explains the philosophy, how tests are
structured, and how to run useful subsets.

---

## Philosophy

Every lab test is an **integration test** — it spins up the real FastAPI
gateway, fires real JSON-RPC tool calls via `TestClient`, and asserts on
deterministic output. No mocks unless the test is specifically checking
interaction with an external service (httpx calls in `egress_lab`,
AWS SDK in bedrock live-path tests).

This gives you high confidence that what passes in CI actually works when
deployed. The alternative — smaller unit tests with lots of mocks — passes
green while real tool calls silently regress.

---

## Test Categories (pytest marks)

Tests are automatically tagged by `conftest.py` based on the lab's
`scenario.yaml` category. No `@pytest.mark` decorators needed in test
files — the tagging happens at collection time.

| Mark | What it covers | Example `-m` usage |
|------|---------------|-------------------|
| `lab` | All 52 lab-specific tests | `pytest -m lab` |
| `identity` | Identity, auth, delegation, DPoP, agent chain | `pytest -m identity` |
| `injection` | Prompt injection, blocklist bypass, indirect, RAG, SSRF | `pytest -m injection` |
| `secrets` | Credential leak, exfiltration, persistence, audit | `pytest -m secrets` |
| `governance` | AI governance, tool mutation, hallucination | `pytest -m governance` |
| `defense` | Policy authoring, response inspection, budget tuning | `pytest -m defense` |
| `teleport` | Teleport machine-identity labs | `pytest -m teleport` |
| `infrastructure` | Brain provider, registry, config, smoke | `pytest -m infrastructure` |
| `slow` | Tests that start real services or make real HTTP calls | `pytest -m "not slow"` |

### Common commands

```bash
# Run everything (default — fastest CI path)
uv run pytest -q

# Run everything without coverage gate (during local development)
uv run pytest -q --no-cov

# Only identity labs
uv run pytest -m identity --no-cov

# Only injection labs
uv run pytest -m injection --no-cov

# Skip slow live-path tests
uv run pytest -m "not slow" --no-cov

# Only infrastructure tests (no lab tests)
uv run pytest -m infrastructure --no-cov

# Run a single lab
uv run pytest tests/test_egress_lab.py --no-cov

# Run with verbose output to see what each test does
uv run pytest tests/test_egress_lab.py -v --no-cov
```

---

## Test file naming convention

Every lab has exactly one test file:

```
tests/test_<module_name>_lab.py   → most labs
tests/test_<module_name>.py       → a few older labs (e.g. test_egress_lab.py)
```

The module name comes from `scenario.yaml:module_name` and the
`LabModule.name` class attribute.

---

## What every lab test must cover

Each lab test file should include at minimum:

1. **Tool registration** — verifies the lab's tools appear in `tools/list`
2. **Easy-mode happy path** — the intended exploit succeeds on `easy`
3. **Hard-mode defense** — the exploit is blocked or made harder on `hard`
4. **Flag format** — `content.startswith("CZTZ{")` and `content.endswith("}")`
5. **Difficulty propagation** — `result["_difficulty"]` matches the set difficulty

For labs with multiple tools:
6. **Each tool exercised** — at least one test per tool
7. **State reset** — tests that mutate state call `reset_registry()` or
   `setup_function()`

### Minimal lab test skeleton

```python
"""Tests for the <LabName> lab (MCP-Txx)."""

from fastapi.testclient import TestClient
from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "module.tool_name" in names


def test_easy_mode_allows_exploit() -> None:
    client = TestClient(app)
    result = tool_call(client, "module.tool_name", {"arg": "value"})
    assert result.get("status") == "allowed"
    assert "CZTZ{" in result.get("output", "")


def test_hard_mode_blocks() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "module.tool_name", {"arg": "value"})
    assert result.get("status") == "blocked"


def test_flag_format() -> None:
    client = TestClient(app)
    result = tool_call(client, "module.tool_name", {"arg": "value"})
    flag = result.get("output", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        client = TestClient(app)
        result = tool_call(client, "module.tool_name", {})
        assert result.get("_difficulty") == diff
```

---

## Helper functions

```python
from tests.helpers import rpc_call, tool_call
```

| Function | Signature | What it does |
|----------|-----------|-------------|
| `rpc_call` | `(client, method, params, req_id)` | Send a JSON-RPC request, return parsed response |
| `tool_call` | `(client, tool_name, arguments)` | Call a tool, unwrap the content block, parse the JSON result |

`tool_call` is the workhorse — it calls `tools/call`, extracts
`result.content[0].text`, and parses it as JSON.

---

## Cross-repo vocabulary tests

`tests/test_lane_taxonomy.py` includes four vocabulary-drift checks that
verify every `scenario.yaml` in the corpus is consistent with the
agentic-sec Identity Flow Framework vocabulary:

| Test | What it checks |
|------|---------------|
| `test_all_threat_ids_follow_mcp_t_format` | Every `threat_id` matches `MCP-T<digits>` |
| `test_no_duplicate_threat_ids` | No two labs share a `threat_id` |
| `test_agentic_block_lane_ids_are_valid` | `primary_lane` and `secondary_lanes` are 1–5 |
| `test_agentic_block_transport_codes_are_valid` | `transport` is one of A B C D E |
| `test_agentic_block_required_keys_present` | `agentic:` block has `primary_lane`, `transport`, `blurb` |

These run on every `pytest` invocation and catch drift before it reaches
mcpnuke finding tags or nullfield policy labels.

---

## Adding a new lab — testing checklist

When you add a new lab (`camazotz_modules/<name>/`):

- [ ] Create `tests/test_<name>_lab.py`
- [ ] Cover the five required scenarios above
- [ ] Add `scenario.yaml` with `threat_id`, `agentic.primary_lane`,
  `agentic.transport`, `agentic.blurb`
- [ ] Run `uv run pytest tests/test_<name>_lab.py --no-cov` — all pass
- [ ] Run `uv run pytest tests/test_scenarios.py tests/test_threat_id_consistency.py tests/test_lane_taxonomy.py --no-cov` — no regressions
- [ ] Run `uv run pytest -q` — 100% coverage maintained, 0 failures

---

## Coverage

Coverage is enforced at 100% in CI (`--cov-fail-under=100` in
`pyproject.toml`). Pass `--no-cov` locally to skip the gate during
development. The coverage report is written to `coverage.xml` for CI
consumption.

```bash
# Full run with coverage (CI-equivalent)
uv run pytest -q

# Skip coverage (fast local iteration)
uv run pytest -q --no-cov

# Coverage report only for changed files
uv run pytest -q --cov=camazotz_modules/egress_lab
```
