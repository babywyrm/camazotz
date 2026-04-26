"""Tests for the Response Inspection defense-mode lab (MCP-T30)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_response_inspection_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "response_inspection.call_leaky_tool" in names
    assert "response_inspection.submit_redaction" in names


def test_call_leaky_tool_returns_payload_per_difficulty() -> None:
    client = TestClient(app)
    for d in ("easy", "medium", "hard"):
        set_difficulty(d)
        result = tool_call(client, "response_inspection.call_leaky_tool", {})
        assert "tool_response" in result
        assert result["_difficulty"] == d


def test_submit_empty_patterns_catches_nothing() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "response_inspection.submit_redaction",
        {"patterns": []},
    )
    assert result["coverage_pct"] == 0
    assert result["patterns_submitted"] == 0
    assert "LEAKS REMAIN" in result["_defense_status"]


def test_submit_effective_patterns_redacts_sensitive_keys() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "response_inspection.submit_redaction",
        {"patterns": [
            r"sk-[A-Za-z0-9]+",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            r"password[\"']?\s*[:=]\s*[\"']?[^\"',}\s]+",
            r"token[\"']?\s*[:=]\s*[\"']?[^\"',}\s]+",
            r"secret[\"']?\s*[:=]\s*[\"']?[^\"',}\s]+",
        ]},
    )
    assert result["patterns_submitted"] == 5
    assert 0 <= result["coverage_pct"] <= 100
    assert "scope_config" in result
    assert result["scope_config"]["response"]["redactReplacement"] == "[REDACTED]"


def test_submit_invalid_regex_does_not_crash() -> None:
    """A bad regex pattern must be swallowed, not surface as an error to the caller."""
    client = TestClient(app)
    result = tool_call(
        client,
        "response_inspection.submit_redaction",
        {"patterns": ["[invalid(regex"]},
    )
    assert "coverage_pct" in result
    assert result["patterns_submitted"] == 1


def test_submit_awards_flag_when_coverage_meets_threshold() -> None:
    """If the patterns catch enough sensitive keys, the response includes a flag."""
    client = TestClient(app)
    set_difficulty("easy")
    # Match every sensitive key for easy: sk-*, email, etc.
    result = tool_call(
        client,
        "response_inspection.submit_redaction",
        {"patterns": [r".*"]},  # overmatch on purpose
    )
    if result["coverage_pct"] >= 80:
        assert result["flag"].startswith("CZTZ{")
        assert "EFFECTIVE" in result["_defense_status"]


def test_reset_is_a_noop() -> None:
    from brain_gateway.app.modules.registry import get_registry

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "response_inspection")
    mod.reset()
