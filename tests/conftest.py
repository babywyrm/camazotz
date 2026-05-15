from __future__ import annotations

import pathlib
import re

import pytest

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import _rate_limiter
from brain_gateway.app.modules.registry import reset_registry

# ---------------------------------------------------------------------------
# Category → pytest mark mapping
# Used by pytest_collection_modifyitems to auto-tag lab tests.
# ---------------------------------------------------------------------------

_CATEGORY_MARKS: dict[str, str] = {
    "injection": "injection",
    "ssrf": "injection",
    "ai_governance": "governance",
    "mutation": "governance",
    "hallucination": "governance",
    "identity": "identity",
    "auth": "identity",
    "authentication": "identity",
    "authorization": "identity",
    "authz": "identity",
    "credential_theft": "identity",
    "delegation": "identity",
    "lifecycle": "identity",
    "rbac": "identity",
    "machine-identity": "identity",
    "secrets": "secrets",
    "exfiltration": "secrets",
    "isolation": "secrets",
    "persistence": "secrets",
    "notification": "secrets",
    "supply-chain": "secrets",
    "attribution": "secrets",
    "audit": "secrets",
    "config": "secrets",
    "information_disclosure": "secrets",
    "defense": "defense",
    "availability": "defense",
    "teleport": "teleport",
}

_INFRA_FILE_PATTERNS = re.compile(
    r"test_(brain_provider_selection|bedrock_claude|cloud_claude|"
    r"compose_smoke|contracts|difficulty_and_tokens|feedback_loop|"
    r"frontend_routes|identity_claims|identity_delegation|identity_provider_contract|"
    r"lane_taxonomy|lanes_route|mcp_compliance|mcp_resources|module_routing|"
    r"observer|rate_limit|scenarios|schema|session|smoke_test|"
    r"threat_id_consistency|operator|challenge|canary_flags|"
    r"cross_tool_chains|hallucination_validation)\.py$"
)

_SLOW_FILE_PATTERNS = re.compile(
    r"test_(compose_smoke|bedrock_claude_live_path|cloud_claude_live_path)\.py$"
)

_MODULES_DIR = pathlib.Path(__file__).parent.parent / "camazotz_modules"
_scenario_cache: dict[str, dict] = {}


def _load_scenario(lab_name: str) -> dict:
    if lab_name not in _scenario_cache:
        p = _MODULES_DIR / lab_name / "scenario.yaml"
        if p.exists():
            try:
                import yaml
                _scenario_cache[lab_name] = yaml.safe_load(p.read_text()) or {}
            except Exception:  # pragma: no cover
                _scenario_cache[lab_name] = {}
        else:
            _scenario_cache[lab_name] = {}
    return _scenario_cache[lab_name]


def pytest_collection_modifyitems(items: list) -> None:
    """Auto-apply marks to every collected test item based on file name."""
    for item in items:
        fpath = pathlib.Path(item.fspath.basename)
        fname = fpath.name

        # ── Infrastructure tests ────────────────────────────────────────────
        if _INFRA_FILE_PATTERNS.match(fname):
            item.add_marker(pytest.mark.infrastructure)
            if _SLOW_FILE_PATTERNS.match(fname):
                item.add_marker(pytest.mark.slow)
            continue

        # ── Lab tests — derive lab name from file name ──────────────────────
        # test_<lab_module_name>_lab.py  or  test_<lab_module_name>.py
        m = re.match(r"test_(.+?)(?:_lab)?\.py$", fname)
        if not m:  # pragma: no cover
            continue

        candidate = m.group(1)
        # Try with and without _lab suffix
        for lab_name in (f"{candidate}_lab", candidate):
            scenario = _load_scenario(lab_name)
            if scenario:
                break

        if not scenario:
            continue

        # Every recognised lab test gets the generic `lab` mark
        item.add_marker(pytest.mark.lab)

        category = scenario.get("category", "")
        mark_name = _CATEGORY_MARKS.get(category)
        if mark_name:
            item.add_marker(getattr(pytest.mark, mark_name))


@pytest.fixture(autouse=True)
def _reset_all_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset global singletons before every test to prevent cross-test bleed."""
    reset_registry()
    reset_difficulty()
    _rate_limiter.reset()

    # When developers run pytest with the same shell/env as Docker Compose
    # (ANTHROPIC_API_KEY, BRAIN_PROVIDER=local, OLLAMA_HOST=http://ollama:11434),
    # labs would call real APIs or block on unreachable Ollama (long httpx timeouts).
    # Force fast, deterministic stubs unless a test overrides these via monkeypatch.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_STUB", "1")
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    reset_provider()
    yield
    reset_provider()
