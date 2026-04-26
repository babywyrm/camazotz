"""Tests for the Policy Authoring defense-mode lab (MCP-T29)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_policy_authoring_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "policy_authoring.get_attack_chain" in names
    assert "policy_authoring.submit_policy" in names
    assert "policy_authoring.get_hint" in names


def test_get_attack_chain_easy_includes_hints() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    chain = tool_call(client, "policy_authoring.get_attack_chain", {})
    assert "_hints" in chain
    assert chain["_difficulty"] == "easy"


def test_get_attack_chain_medium_keeps_recommended_actions() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    chain = tool_call(client, "policy_authoring.get_attack_chain", {})
    assert "recommended_actions" in chain
    assert "_hints" not in chain


def test_get_attack_chain_hard_strips_recommended_actions() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    chain = tool_call(client, "policy_authoring.get_attack_chain", {})
    assert "recommended_actions" not in chain


def test_get_hint_returns_recommended_action_for_known_tool() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    hint = tool_call(
        client,
        "policy_authoring.get_hint",
        {"tool_name": "shadow.register_webhook"},
    )
    assert "recommended_action" in hint


def test_get_hint_returns_not_in_chain_for_unknown_tool() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    hint = tool_call(
        client,
        "policy_authoring.get_hint",
        {"tool_name": "does.not.exist"},
    )
    assert "not in the attack chain" in hint["hint"]


def test_get_hint_hard_returns_no_hints() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    hint = tool_call(
        client,
        "policy_authoring.get_hint",
        {"tool_name": "shadow.register_webhook"},
    )
    assert "No hints" in hint["hint"]


def test_submit_policy_returns_evaluation_and_attempts_count() -> None:
    client = TestClient(app)
    r1 = tool_call(
        client,
        "policy_authoring.submit_policy",
        {"policy_yaml": "rules:\n- action: DENY\n  tools:\n    - shadow.register_webhook\n"},
    )
    assert "evaluation" in r1
    assert r1["attempts"] == 1
    assert r1["attack_chain_id"] == "AC-001"

    r2 = tool_call(
        client,
        "policy_authoring.submit_policy",
        {"policy_yaml": "rules:\n- action: SCOPE\n"},
    )
    assert r2["attempts"] == 2
    assert "_defense_status" in r2


def test_submit_policy_awards_flag_when_evaluation_scores_high(monkeypatch) -> None:
    """A stubbed evaluator returning score>=80 must yield the flag + BLOCKED status."""
    from brain_gateway.app.modules.registry import get_registry

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "policy_authoring")

    class _StubResult:
        text = '{"valid": true, "score": 95, "feedback": "strong policy"}'
        usage = None

    monkeypatch.setattr(mod, "ask_llm", lambda *a, **kw: _StubResult())

    client = TestClient(app)
    result = tool_call(
        client,
        "policy_authoring.submit_policy",
        {"policy_yaml": "rules:\n- action: DENY\n"},
    )
    assert result["flag"].startswith("CZTZ{")
    assert "BLOCKED" in result["_defense_status"]


def test_reset_clears_submitted_policies() -> None:
    from brain_gateway.app.modules.registry import get_registry

    client = TestClient(app)
    tool_call(
        client,
        "policy_authoring.submit_policy",
        {"policy_yaml": "anything"},
    )
    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "policy_authoring")
    assert mod._submitted_policies  # non-empty
    mod.reset()
    assert mod._submitted_policies == []
