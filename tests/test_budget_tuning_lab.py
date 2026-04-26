"""Tests for the Budget Tuning defense-mode lab (MCP-T31)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_budget_tuning_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "budget_tuning.get_traffic_pattern" in names
    assert "budget_tuning.submit_budget" in names
    assert "budget_tuning.simulate" in names


def test_get_traffic_pattern_easy_includes_hint() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "budget_tuning.get_traffic_pattern", {})
    assert "_hint" in result
    assert "legitimate_users" in result
    assert "attackers" in result


def test_get_traffic_pattern_hard_omits_hint() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "budget_tuning.get_traffic_pattern", {})
    assert "_hint" not in result


def test_simulate_too_permissive_budget_lets_attackers_through() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.simulate",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 10_000},
            "onExhausted": "DENY",
        }},
    )
    assert result["attackers_blocked"] == 0
    assert result["legitimate_blocked"] == 0


def test_simulate_tight_budget_blocks_attackers_and_spares_legit() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.simulate",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 40},
            "onExhausted": "DENY",
        }},
    )
    assert result["attackers_blocked"] >= 1
    assert result["legitimate_blocked"] <= result["attackers_blocked"]


def test_simulate_log_action_does_not_block() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.simulate",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 10},
            "onExhausted": "LOG",
        }},
    )
    assert result["attackers_blocked"] == 0
    assert result["legitimate_blocked"] == 0


def test_submit_budget_returns_security_and_usability_scores() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.submit_budget",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 40},
            "onExhausted": "DENY",
        }},
    )
    assert "security_score" in result
    assert "usability_score" in result
    assert "combined_score" in result
    assert "_defense_status" in result
    assert "nullfield_budget_config" in result


def test_submit_budget_awards_flag_on_effective_config() -> None:
    """A budget that blocks every attacker (150+ cph) but lets legit users (<12 cph) through
    must score 100/100 and award the flag."""
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.submit_budget",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 40},
            "perSession": {"maxCallsPerHour": 40},
            "onExhausted": "DENY",
        }},
    )
    assert result["security_score"] == 100
    assert result["usability_score"] == 100
    assert result["combined_score"] == 100
    assert result["flag"].startswith("CZTZ{")
    assert "EFFECTIVE" in result["_defense_status"]


def test_submit_budget_no_flag_on_weak_config() -> None:
    """Too-permissive budget lets attackers through, no flag."""
    client = TestClient(app)
    result = tool_call(
        client,
        "budget_tuning.submit_budget",
        {"budget_config": {
            "perIdentity": {"maxCallsPerHour": 10_000},
            "onExhausted": "DENY",
        }},
    )
    assert result["combined_score"] < 80
    assert "NEEDS TUNING" in result["_defense_status"]
    assert "flag" not in result


def test_reset_is_a_noop() -> None:
    from brain_gateway.app.modules.registry import get_registry

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "budget_tuning")
    mod.reset()
