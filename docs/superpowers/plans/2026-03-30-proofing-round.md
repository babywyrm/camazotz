# Proofing Round Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Camazotz and upgrade mcpnuke based on cross-scan findings, maintaining zero regressions.

**Architecture:** Two interleaved streams — mcpnuke reporting/detection upgrades and Camazotz platform hardening — where each stream's improvements validate the other. Tests run before every commit boundary.

**Tech Stack:** Python 3.12+, FastAPI (Camazotz gateway), pytest, dataclasses, Rich (mcpnuke console), threading

---

## File Map

### mcpnuke changes (`/Users/tms/mcpnuke/`)

| File | Action | Purpose |
|------|--------|---------|
| `mcpnuke/patterns/probes.py` | Modify | Add SSTI engine-specific fingerprint payloads |
| `mcpnuke/checks/tool_probes.py` | Modify | LLM-aware SSTI classification, parallel input_sanitization |
| `mcpnuke/checks/chaining.py` | Modify | Populate structured `attack_chains` on TargetResult |
| `mcpnuke/core/models.py` | Modify | Add `AttackChain` dataclass and `attack_chains` field |
| `mcpnuke/reporting/json_out.py` | Modify | Serialize `attack_chains` array in JSON output |
| `mcpnuke/__main__.py` | Modify | Exit code 0/1/2 semantics |
| `mcpnuke/__init__.py` | Modify | Bump version to 6.3.0 |
| `mcpnuke/CHANGELOG.md` | Modify | Document all changes |
| `mcpnuke/README.md` | Modify | Update docs |
| `tests/test_ssti_fingerprint.py` | Create | Tests for SSTI engine identification |
| `tests/test_attack_chains_json.py` | Create | Tests for structured chain output |
| `tests/test_exit_codes.py` | Create | Tests for exit code semantics |
| `tests/test_input_sanitization_perf.py` | Create | Parallel fuzzing tests |

### Camazotz changes (`/Users/tms/camazotz/`)

| File | Action | Purpose |
|------|--------|---------|
| `camazotz_modules/auth_lab/app/main.py` | Modify | Fix threat_id MCP-T03 → MCP-T04 |
| `camazotz_modules/hallucination_lab/app/main.py` | Modify | Add code-level plan validation at MAX |
| `brain_gateway/app/main.py` | Modify | Add rate limiting middleware |
| `brain_gateway/app/rate_limit.py` | Create | Token-bucket rate limiter |
| 14x `camazotz_modules/*/app/main.py` | Modify | Add maxLength to all string params |
| `tests/test_threat_id_consistency.py` | Create | Assert Python threat_id matches YAML |
| `tests/test_hallucination_validation.py` | Create | Test plan validation at MAX |
| `tests/test_rate_limit.py` | Create | Rate limiter unit tests |
| `tests/test_schema_maxlength.py` | Create | Assert all string params have maxLength |
| `CHANGELOG.md` | Modify | Document changes |

---

## Task 1: mcpnuke — LLM-Aware SSTI Classification + Engine Fingerprinting

The current `check_input_sanitization` in `tool_probes.py` flags `{{1333*7}}` → `9331` as "Template injection" without distinguishing between actual code-level SSTI (Jinja2/Mako) and an LLM evaluating math. This task adds engine-specific fingerprinting payloads and an LLM-evaluation heuristic.

**Files:**
- Modify: `/Users/tms/mcpnuke/mcpnuke/patterns/probes.py`
- Modify: `/Users/tms/mcpnuke/mcpnuke/checks/tool_probes.py`
- Create: `/Users/tms/mcpnuke/tests/test_ssti_fingerprint.py`

- [ ] **Step 1: Write the failing test for SSTI engine fingerprinting**

Create `/Users/tms/mcpnuke/tests/test_ssti_fingerprint.py`:

```python
"""Tests for SSTI engine fingerprinting and LLM-aware classification."""

import pytest
from mcpnuke.patterns.probes import SSTI_ENGINE_FINGERPRINTS


def test_ssti_fingerprints_contain_all_engines():
    engines = {fp["engine"] for fp in SSTI_ENGINE_FINGERPRINTS}
    assert "jinja2" in engines
    assert "mako" in engines
    assert "erb" in engines
    assert "el" in engines


def test_ssti_fingerprints_have_unique_expected():
    for fp in SSTI_ENGINE_FINGERPRINTS:
        assert "payload" in fp
        assert "expected" in fp
        assert "engine" in fp
        assert isinstance(fp["expected"], str)
        assert len(fp["expected"]) >= 2


class TestLlmSstiClassification:
    """Verify the heuristic that distinguishes LLM math from code SSTI."""

    def test_math_only_classified_as_llm(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=[], response_latency=1.5
        )
        assert result == "llm_evaluated"

    def test_engine_hit_classified_as_code_ssti(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=["jinja2"], response_latency=0.5
        )
        assert result == "jinja2"

    def test_multiple_engines_returns_first(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=["mako", "el"], response_latency=0.3
        )
        assert result == "mako"

    def test_fast_response_prefers_code_ssti(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=[], response_latency=0.02
        )
        assert result == "code_ssti"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_ssti_fingerprint.py -v`
Expected: FAIL — `SSTI_ENGINE_FINGERPRINTS` and `_classify_ssti` don't exist yet.

- [ ] **Step 3: Add engine fingerprint payloads to probes.py**

In `/Users/tms/mcpnuke/mcpnuke/patterns/probes.py`, add after `TEMPLATE_INJECTION_PROBES_V2`:

```python
SSTI_ENGINE_FINGERPRINTS: list[dict[str, str]] = [
    {"engine": "jinja2", "payload": "{{7*'7'}}", "expected": "7777777"},
    {"engine": "jinja2", "payload": "{{config.items()}}", "expected": "dict_items"},
    {"engine": "mako",   "payload": "${'7'*7}",            "expected": "7777777"},
    {"engine": "erb",    "payload": "<%= '7'*7 %>",         "expected": "7777777"},
    {"engine": "el",     "payload": "${'7'.repeat(7)}",     "expected": "7777777"},
]
```

- [ ] **Step 4: Add `_classify_ssti` function to tool_probes.py**

In `/Users/tms/mcpnuke/mcpnuke/checks/tool_probes.py`, add before `check_input_sanitization`:

```python
def _classify_ssti(
    *,
    math_hit: bool,
    engine_hits: list[str],
    response_latency: float,
) -> str:
    """Classify an SSTI finding as code-level or LLM-evaluated.

    Returns: engine name (e.g. 'jinja2'), 'code_ssti', or 'llm_evaluated'.
    """
    if engine_hits:
        return engine_hits[0]
    if response_latency < 0.1 and math_hit:
        return "code_ssti"
    if math_hit:
        return "llm_evaluated"
    return "unknown"
```

- [ ] **Step 5: Update template injection detection in check_input_sanitization**

In `/Users/tms/mcpnuke/mcpnuke/checks/tool_probes.py`, replace the template injection block (lines ~454-468) inside `check_input_sanitization` with:

```python
                # Dedicated template injection with engine fingerprinting
                if pdef.get("type") in (None, "string"):
                    math_hit = False
                    engine_hits: list[str] = []
                    tpl_latency = 0.0
                    tpl_evidence = ""

                    for tpl_payload, tpl_expected in TEMPLATE_INJECTION_PROBES_V2[:2]:
                        t0 = time.time()
                        test_args = {**base_args, pname: tpl_payload}
                        resp = _call_tool(session, name, test_args, timeout=8)
                        tpl_latency = time.time() - t0
                        text = _response_text(resp)
                        if text and tpl_expected in text:
                            math_hit = True
                            tpl_evidence = text[:300]
                            break

                    if math_hit:
                        from mcpnuke.patterns.probes import SSTI_ENGINE_FINGERPRINTS
                        for fp in SSTI_ENGINE_FINGERPRINTS:
                            fp_args = {**base_args, pname: fp["payload"]}
                            resp = _call_tool(session, name, fp_args, timeout=8)
                            fp_text = _response_text(resp)
                            if fp_text and fp["expected"] in fp_text:
                                engine_hits.append(fp["engine"])
                                break

                        classification = _classify_ssti(
                            math_hit=math_hit,
                            engine_hits=engine_hits,
                            response_latency=tpl_latency,
                        )

                        if classification == "llm_evaluated":
                            severity = "MEDIUM"
                            title = f"LLM evaluates template syntax in '{name}' param '{pname}'"
                            detail = (
                                f"Payload '{{{{1333*7}}}}' yielded '9331' but no engine-specific "
                                f"fingerprint matched — likely LLM math evaluation, not code SSTI"
                            )
                        elif classification == "code_ssti":
                            severity = "CRITICAL"
                            title = f"Probable code-level SSTI in '{name}' param '{pname}'"
                            detail = (
                                f"Fast response ({tpl_latency:.2f}s) with math evaluation "
                                f"but no engine fingerprint — likely unidentified template engine"
                            )
                        else:
                            severity = "CRITICAL"
                            title = f"SSTI ({classification}) in '{name}' param '{pname}'"
                            detail = f"Engine '{classification}' confirmed via fingerprint payload"

                        result.add(
                            "input_sanitization", severity, title, detail,
                            evidence=tpl_evidence,
                        )
                        continue
```

- [ ] **Step 6: Add SSTI_ENGINE_FINGERPRINTS to the import in tool_probes.py**

In the imports at top of `tool_probes.py`, add `SSTI_ENGINE_FINGERPRINTS` to the import from `mcpnuke.patterns.probes`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_ssti_fingerprint.py -v`
Expected: All PASS.

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/ -v --timeout=60`
Expected: All existing tests still PASS (no regressions).

---

## Task 2: mcpnuke — Structured Attack Chains in JSON Output

The `check_attack_chains` function creates `Finding` objects with `check="attack_chain"` but doesn't populate a structured array. JSON consumers get string titles like "Attack chain: prompt_injection → code_execution" but no machine-parseable chain data.

**Files:**
- Modify: `/Users/tms/mcpnuke/mcpnuke/core/models.py`
- Modify: `/Users/tms/mcpnuke/mcpnuke/checks/chaining.py`
- Modify: `/Users/tms/mcpnuke/mcpnuke/reporting/json_out.py`
- Create: `/Users/tms/mcpnuke/tests/test_attack_chains_json.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/mcpnuke/tests/test_attack_chains_json.py`:

```python
"""Tests for structured attack chain JSON output."""

import json
from mcpnuke.core.models import TargetResult, AttackChain


def test_attack_chain_dataclass():
    chain = AttackChain(source="prompt_injection", target="code_execution")
    assert chain.source == "prompt_injection"
    assert chain.target == "code_execution"


def test_target_result_has_attack_chains_field():
    r = TargetResult(url="http://test")
    assert hasattr(r, "attack_chains")
    assert isinstance(r.attack_chains, list)
    assert len(r.attack_chains) == 0


def test_check_attack_chains_populates_both():
    from mcpnuke.checks.chaining import check_attack_chains

    r = TargetResult(url="http://test")
    r.add("prompt_injection", "CRITICAL", "test")
    r.add("code_execution", "CRITICAL", "test")
    check_attack_chains(r)

    assert len(r.attack_chains) > 0
    chain = r.attack_chains[0]
    assert chain.source == "prompt_injection"
    assert chain.target == "code_execution"

    chain_findings = [f for f in r.findings if f.check == "attack_chain"]
    assert len(chain_findings) > 0


def test_json_output_includes_attack_chains():
    from mcpnuke.reporting.json_out import _build_target_dict

    r = TargetResult(url="http://test")
    r.attack_chains.append(AttackChain(source="a", target="b"))
    d = _build_target_dict(r)
    assert "attack_chains" in d
    assert d["attack_chains"][0]["source"] == "a"
    assert d["attack_chains"][0]["target"] == "b"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_attack_chains_json.py -v`
Expected: FAIL — `AttackChain` doesn't exist.

- [ ] **Step 3: Add AttackChain dataclass and field to models.py**

In `/Users/tms/mcpnuke/mcpnuke/core/models.py`, add after the `Finding` class:

```python
@dataclass
class AttackChain:
    source: str
    target: str
```

Add to `TargetResult`:

```python
    attack_chains: list[AttackChain] = field(default_factory=list)
```

- [ ] **Step 4: Update check_attack_chains to populate both findings and chains**

In `/Users/tms/mcpnuke/mcpnuke/checks/chaining.py`, add `AttackChain` to the import from `models` and update `check_attack_chains`:

```python
from mcpnuke.core.models import TargetResult, AttackChain

def check_attack_chains(result: TargetResult):
    with time_check("attack_chains", result):
        checks = {f.check for f in result.findings}
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                result.attack_chains.append(AttackChain(source=a, target=b))
                result.add(
                    "attack_chain",
                    "CRITICAL",
                    f"Attack chain: {a} → {b}",
                    "Two linked vulnerability classes detected in sequence",
                )
```

- [ ] **Step 5: Extract target serialization helper in json_out.py and add chains**

In `/Users/tms/mcpnuke/mcpnuke/reporting/json_out.py`, extract a helper and add `attack_chains`:

```python
def _build_target_dict(r: TargetResult) -> dict:
    return {
        "url": r.url,
        "transport": r.transport,
        "risk_score": r.risk_score(),
        "tools": [t.get("name") for t in r.tools],
        "timings": r.timings,
        "findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in r.findings
        ],
        "attack_chains": [
            {"source": c.source, "target": c.target}
            for c in r.attack_chains
        ],
    }
```

Update `write_json` to use `_build_target_dict(r)` in the list comprehension for `"targets"`.

- [ ] **Step 6: Run tests**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_attack_chains_json.py tests/ -v`
Expected: All PASS.

---

## Task 3: mcpnuke — Exit Code Semantics

Currently exit code 1 means either "scan found CRITICAL/HIGH findings" or "error occurred." This task separates them: 0=clean, 1=findings, 2=error.

**Files:**
- Modify: `/Users/tms/mcpnuke/mcpnuke/__main__.py`
- Create: `/Users/tms/mcpnuke/tests/test_exit_codes.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/mcpnuke/tests/test_exit_codes.py`:

```python
"""Tests for exit code semantics: 0=clean, 1=findings, 2=error."""

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def test_exit_code_constants_importable():
    from mcpnuke.__main__ import EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR
    assert EXIT_CLEAN == 0
    assert EXIT_FINDINGS == 1
    assert EXIT_ERROR == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_exit_codes.py -v`
Expected: FAIL — constants not defined.

- [ ] **Step 3: Add constants and update exit points in __main__.py**

In `/Users/tms/mcpnuke/mcpnuke/__main__.py`, add near the top:

```python
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
```

Then update all three exit code locations:

1. Stdio path (~line 186-188): Replace `sys.exit(1)` with `sys.exit(EXIT_FINDINGS)`, `sys.exit(0)` with `sys.exit(EXIT_CLEAN)`.
2. K8s-only path (~line 340-342): Same replacement.
3. Main multi-target path (~line 403-405): Same replacement.

Wrap the entire `main()` body in a try/except that catches unexpected exceptions and returns `EXIT_ERROR`:

```python
def main():
    try:
        _main_inner()
    except SystemExit:
        raise
    except Exception as exc:
        import traceback
        traceback.print_exc()
        sys.exit(EXIT_ERROR)
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/test_exit_codes.py tests/ -v`
Expected: All PASS.

---

## Task 4: Camazotz — Fix auth_lab threat_id + Consistency Test

**Files:**
- Modify: `/Users/tms/camazotz/camazotz_modules/auth_lab/app/main.py`
- Create: `/Users/tms/camazotz/tests/test_threat_id_consistency.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/camazotz/tests/test_threat_id_consistency.py`:

```python
"""Every module's Python threat_id must match its scenario.yaml threat_id."""

import importlib
import pkgutil
from pathlib import Path

import yaml
import pytest

import camazotz_modules
from camazotz_modules.base import LabModule


def _discover_modules():
    """Yield (module_name, lab_instance, yaml_path) for every lab."""
    pkg_path = Path(camazotz_modules.__file__).parent
    for info in pkgutil.walk_packages([str(pkg_path)], prefix="camazotz_modules."):
        try:
            mod = importlib.import_module(info.name)
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, LabModule)
                and obj is not LabModule
                and hasattr(obj, "threat_id")
            ):
                parts = info.name.split(".")
                lab_dir = parts[1] if len(parts) > 1 else parts[0]
                yaml_path = pkg_path / lab_dir / "scenario.yaml"
                if yaml_path.exists():
                    yield lab_dir, obj, yaml_path


@pytest.mark.parametrize(
    "lab_dir,lab_cls,yaml_path",
    list(_discover_modules()),
    ids=[t[0] for t in _discover_modules()],
)
def test_threat_id_matches_yaml(lab_dir, lab_cls, yaml_path):
    with open(yaml_path) as f:
        scenario = yaml.safe_load(f)
    yaml_tid = scenario.get("threat_id", "")
    python_tid = lab_cls.threat_id
    assert python_tid == yaml_tid, (
        f"{lab_dir}: Python threat_id={python_tid!r} != YAML threat_id={yaml_tid!r}"
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_threat_id_consistency.py -v`
Expected: FAIL for `auth_lab` — Python `MCP-T03` != YAML `MCP-T04`.

- [ ] **Step 3: Fix the threat_id**

In `/Users/tms/camazotz/camazotz_modules/auth_lab/app/main.py`, change:

```python
    threat_id = "MCP-T03"
```

to:

```python
    threat_id = "MCP-T04"
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_threat_id_consistency.py -v`
Expected: All PASS.

Run: `cd /Users/tms/camazotz && uv run pytest tests/ -v`
Expected: All existing tests still PASS.

---

## Task 5: Camazotz — Harden hallucination_lab Plan Validation at MAX

At MAX difficulty, the system prompt says "NEVER include production paths" but there's no code-level validation. The LLM can still generate plans that touch production. Add a post-LLM validation step at MAX difficulty.

**Files:**
- Modify: `/Users/tms/camazotz/camazotz_modules/hallucination_lab/app/main.py`
- Create: `/Users/tms/camazotz/tests/test_hallucination_validation.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/camazotz/tests/test_hallucination_validation.py`:

```python
"""hallucination_lab: MAX difficulty should code-reject production paths."""

from unittest.mock import patch

import pytest

from camazotz_modules.hallucination_lab.app.main import HallucinationLab


@pytest.fixture
def lab():
    return HallucinationLab()


def _make_brain_result(text: str):
    from brain_gateway.app.brain.provider import BrainResult
    return BrainResult(text=text, usage={})


def test_max_strips_production_ops(lab):
    plan_json = '[{"action":"delete","path":"/production/data/customers.db"}]'
    with (
        patch.object(lab, "difficulty", "hard"),
        patch.object(lab, "ask_llm", return_value=_make_brain_result(plan_json)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "clean up"})
    assert result["operations_executed"] == []
    assert result["production_touched"] is False
    assert result.get("blocked_operations", 0) == 1


def test_max_allows_staging_ops(lab):
    plan_json = '[{"action":"delete","path":"/staging/data/temp_logs.csv"}]'
    with (
        patch.object(lab, "difficulty", "hard"),
        patch.object(lab, "ask_llm", return_value=_make_brain_result(plan_json)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "clean up"})
    assert len(result["operations_executed"]) == 1
    assert result["production_touched"] is False


def test_easy_allows_production_ops(lab):
    plan_json = '[{"action":"read","path":"/production/data/customers.db"}]'
    with (
        patch.object(lab, "difficulty", "easy"),
        patch.object(lab, "ask_llm", return_value=_make_brain_result(plan_json)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "check files"})
    assert len(result["operations_executed"]) == 1
    assert result["production_touched"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_hallucination_validation.py -v`
Expected: FAIL — `test_max_strips_production_ops` fails because MAX still executes production paths.

- [ ] **Step 3: Add code-level plan validation at MAX**

In `/Users/tms/camazotz/camazotz_modules/hallucination_lab/app/main.py`, in the `handle` method, after `operations = self._parse_plan(result.text)` and before the execution loop, add:

```python
        blocked_count = 0
        if self.difficulty == "hard":
            safe_ops = []
            for op in operations:
                if op.get("path", "").startswith("/production"):
                    blocked_count += 1
                else:
                    safe_ops.append(op)
            operations = safe_ops
```

And in the return dict, add `blocked_operations=blocked_count`:

```python
        return self.make_response(
            result,
            task=description,
            llm_plan=result.text,
            operations_executed=executed,
            production_touched=production_touched,
            remaining_files=len(self._fs),
            blocked_operations=blocked_count,
        )
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_hallucination_validation.py tests/ -v`
Expected: All PASS.

---

## Task 6: Camazotz — Add Rate Limiting Middleware

**Files:**
- Create: `/Users/tms/camazotz/brain_gateway/app/rate_limit.py`
- Modify: `/Users/tms/camazotz/brain_gateway/app/main.py`
- Create: `/Users/tms/camazotz/tests/test_rate_limit.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/camazotz/tests/test_rate_limit.py`:

```python
"""Rate limiter: EZ=unlimited, MOD=30/min, MAX=10/min."""

import time

import pytest

from brain_gateway.app.rate_limit import TokenBucketLimiter


def test_unlimited_at_easy():
    limiter = TokenBucketLimiter()
    for _ in range(100):
        assert limiter.allow("client1", difficulty="easy")


def test_moderate_allows_within_limit():
    limiter = TokenBucketLimiter()
    for _ in range(30):
        assert limiter.allow("client1", difficulty="medium")


def test_moderate_rejects_over_limit():
    limiter = TokenBucketLimiter()
    for _ in range(30):
        limiter.allow("client1", difficulty="medium")
    assert not limiter.allow("client1", difficulty="medium")


def test_hard_rejects_over_limit():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")


def test_different_clients_independent():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")
    assert limiter.allow("client2", difficulty="hard")


def test_reset_clears_buckets():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")
    limiter.reset()
    assert limiter.allow("client1", difficulty="hard")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_rate_limit.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement the rate limiter**

Create `/Users/tms/camazotz/brain_gateway/app/rate_limit.py`:

```python
"""In-memory token-bucket rate limiter keyed by client + difficulty."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

LIMITS: dict[str, int] = {
    "easy": 0,
    "medium": 30,
    "hard": 10,
}

WINDOW_SECONDS: float = 60.0


@dataclass
class _Bucket:
    tokens: int = 0
    window_start: float = field(default_factory=time.monotonic)


class TokenBucketLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str, *, difficulty: str) -> bool:
        limit = LIMITS.get(difficulty, 0)
        if limit == 0:
            return True

        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(client_id, _Bucket(window_start=now))
            if now - bucket.window_start >= WINDOW_SECONDS:
                bucket.tokens = 0
                bucket.window_start = now
            if bucket.tokens >= limit:
                return False
            bucket.tokens += 1
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
```

- [ ] **Step 4: Wire rate limiter into the gateway**

In `/Users/tms/camazotz/brain_gateway/app/main.py`, after the `app = FastAPI(...)` line, add:

```python
from brain_gateway.app.rate_limit import TokenBucketLimiter
from brain_gateway.app.config import get_difficulty

_rate_limiter = TokenBucketLimiter()
```

Then in the `mcp_endpoint` function, before `result = handle_rpc(payload)`, add:

```python
    client_id = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if not _rate_limiter.allow(client_id, difficulty=get_difficulty()):
        return JSONResponse(
            status_code=429,
            content={"jsonrpc": "2.0", "id": payload.id, "error": {"code": -32000, "message": "Rate limit exceeded"}},
        )
```

Also wire `_rate_limiter.reset()` into the existing `/reset` endpoint.

- [ ] **Step 5: Run tests**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_rate_limit.py tests/ -v`
Expected: All PASS.

---

## Task 7: Camazotz — Add maxLength to All Tool Input Schemas

38 unbounded string params need `maxLength`. This task adds constraints and a test that enforces them going forward.

**Files:**
- Modify: All 14 `camazotz_modules/*/app/main.py` files
- Create: `/Users/tms/camazotz/tests/test_schema_maxlength.py`

- [ ] **Step 1: Write the failing test**

Create `/Users/tms/camazotz/tests/test_schema_maxlength.py`:

```python
"""Every string param in every tool must have a maxLength."""

import pytest

from brain_gateway.app.modules.registry import LabRegistry


@pytest.fixture(scope="module")
def all_tools():
    registry = LabRegistry()
    return registry.list_tools()


def _string_params(tools):
    for tool in tools:
        name = tool["name"]
        props = tool.get("inputSchema", {}).get("properties", {})
        for pname, pdef in props.items():
            if pdef.get("type") in (None, "string"):
                yield name, pname, pdef


def test_all_string_params_have_maxlength(all_tools):
    missing = []
    for tool_name, param_name, pdef in _string_params(all_tools):
        if "maxLength" not in pdef:
            missing.append(f"{tool_name}.{param_name}")
    assert missing == [], f"String params without maxLength: {missing}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_schema_maxlength.py -v`
Expected: FAIL — lists all 38 params missing maxLength.

- [ ] **Step 3: Add maxLength to every string param across all 14 modules**

Apply these limits per param type:
- Short identifiers (key, tenant_id, mode, filter, action, label, resource, username, requested_role, channel, source, package): `"maxLength": 256`
- Content fields (message, text, description, content, value, prompt, question, reason, task): `"maxLength": 4096`
- URL fields (url): `"maxLength": 2048`
- Token fields (token): `"maxLength": 1024`

For each of the 14 module `main.py` files, add `"maxLength": N` to every string property dict in every tool schema.

- [ ] **Step 4: Run tests**

Run: `cd /Users/tms/camazotz && uv run pytest tests/test_schema_maxlength.py tests/ -v`
Expected: All PASS.

---

## Task 8: mcpnuke — Optimize input_sanitization with Parallel Fuzzing

**Files:**
- Modify: `/Users/tms/mcpnuke/mcpnuke/checks/tool_probes.py`

- [ ] **Step 1: Refactor check_input_sanitization to parallelize per-tool fuzzing**

In `check_input_sanitization`, replace the sequential outer loop over tools with a `ThreadPoolExecutor` that fuzzes tools in parallel. The inner per-param loop stays sequential (same tool, shared session safety).

Extract the per-tool fuzzing body into `_fuzz_tool(session, tool, result, opts, base_args_fn)`, then:

```python
def check_input_sanitization(session, result: TargetResult, probe_opts: dict | None = None):
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    probe_workers = opts.get("probe_workers", 1)
    with time_check("input_sanitization", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    fuzzing {len(invokable)} tools for input sanitization[/dim]")

        if probe_workers > 1 and len(invokable) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=min(probe_workers, len(invokable))) as pool:
                futures = {
                    pool.submit(_fuzz_single_tool, session, tool, result, opts, _log, idx, len(invokable)): tool
                    for idx, tool in enumerate(invokable)
                }
                for f in as_completed(futures):
                    f.result()
        else:
            for idx, tool in enumerate(invokable):
                _fuzz_single_tool(session, tool, result, opts, _log, idx, len(invokable))
```

Add early-exit per tool: once any CRITICAL finding is confirmed for a tool, skip remaining payloads for that tool (break out of the param loop).

- [ ] **Step 2: Run tests to verify no regressions**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/ -v --timeout=120`
Expected: All PASS.

---

## Task 9: Version Bumps, Changelogs, and Documentation

**Files:**
- Modify: `/Users/tms/mcpnuke/mcpnuke/__init__.py` (6.2.0 → 6.3.0)
- Modify: `/Users/tms/mcpnuke/CHANGELOG.md`
- Modify: `/Users/tms/mcpnuke/README.md`
- Modify: `/Users/tms/camazotz/CHANGELOG.md`
- Modify: `/Users/tms/camazotz/README.md`

- [ ] **Step 1: Bump mcpnuke version**

In `/Users/tms/mcpnuke/mcpnuke/__init__.py`, change `__version__ = "6.2.0"` to `__version__ = "6.3.0"`.
In `/Users/tms/mcpnuke/pyproject.toml`, change `version = "6.2.0"` to `version = "6.3.0"`.

- [ ] **Step 2: Update mcpnuke CHANGELOG**

Add a `## 6.3.0 (2026-03)` section documenting:
- LLM-aware SSTI classification (distinguishes code SSTI from LLM math evaluation)
- SSTI engine fingerprinting (Jinja2, Mako, ERB, EL)
- Structured `attack_chains` array in JSON output
- Exit code semantics: 0=clean, 1=findings, 2=error
- Parallel input_sanitization fuzzing via `probe_workers`

- [ ] **Step 3: Update mcpnuke README**

Update the check reference table to note SSTI fingerprinting and LLM-aware classification. Document new exit codes.

- [ ] **Step 4: Update Camazotz CHANGELOG**

Add a `## Proofing Round` section documenting:
- Fixed auth_lab threat_id (MCP-T03 → MCP-T04)
- hallucination_lab MAX code-level plan validation
- Token-bucket rate limiting (EZ/MOD/MAX)
- maxLength on all tool input schemas
- New regression tests: threat_id consistency, schema maxLength, rate limiting, hallucination validation

- [ ] **Step 5: Update Camazotz README**

Update test count. Note rate limiting behavior in the guardrails section.

- [ ] **Step 6: Run full test suites on both projects**

Run: `cd /Users/tms/mcpnuke && uv run pytest tests/ -v`
Run: `cd /Users/tms/camazotz && uv run pytest tests/ -v`
Expected: All PASS on both.

---

## Task 10: Validation Rescan

- [ ] **Step 1: Rescan local Camazotz with mcpnuke**

Run: `cd /Users/tms/mcpnuke && ./scan --targets http://localhost:8080/mcp --verbose --json /tmp/nuke_camazotz_post.json --probe-calls 3`

- [ ] **Step 2: Compare findings**

Compare `/tmp/nuke_camazotz_local.json` (pre) vs `/tmp/nuke_camazotz_post.json` (post):
- Template injection findings should be reclassified as MEDIUM (LLM-evaluated) instead of CRITICAL
- Rate limiting check should detect throttling at MOD/MAX
- Schema risk (unbounded string) findings should be eliminated
- Attack chains should appear in structured `attack_chains` array
- Exit code should be 1 (findings exist) not 2

- [ ] **Step 3: Report results and identify any remaining issues**
