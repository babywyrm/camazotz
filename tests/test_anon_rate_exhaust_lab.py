"""Tests for the Anonymous Rate-Limit Exhaustion lab (MCP-T51).

MCP servers that share a global rate-limit budget across anonymous and
authenticated callers can be taken offline by an anonymous attacker who
simply floods the shared pool.  This lab teaches that without per-caller
accounting there is no way to prioritise or protect authenticated traffic.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")
    reset_registry()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "ratelimit.check_budget" in names
    assert "ratelimit.flood_calls" in names
    assert "ratelimit.authenticated_call" in names


# ---------------------------------------------------------------------------
# ratelimit.check_budget
# ---------------------------------------------------------------------------


def test_initial_budget_100() -> None:
    client = TestClient(app)
    result = tool_call(client, "ratelimit.check_budget", {})
    assert result["remaining"] == 100
    assert result["exhausted"] is False


# ---------------------------------------------------------------------------
# ratelimit.flood_calls
# ---------------------------------------------------------------------------


def test_flood_consumes_budget() -> None:
    client = TestClient(app)
    result = tool_call(client, "ratelimit.flood_calls", {"call_count": 50})
    assert result["remaining_after"] == 50
    assert result["budget_consumed"] == 50


def test_flood_exhausts_budget() -> None:
    client = TestClient(app)
    result = tool_call(client, "ratelimit.flood_calls", {"call_count": 100})
    assert result["remaining_after"] == 0
    assert result["exhausted"] is True


def test_budget_depleted_after_overflow() -> None:
    """Flooding beyond the total budget should clamp remaining to 0, not go negative."""
    client = TestClient(app)
    result = tool_call(client, "ratelimit.flood_calls", {"call_count": 200})
    assert result["remaining_after"] == 0
    assert result["remaining_after"] >= 0


# ---------------------------------------------------------------------------
# ratelimit.authenticated_call
# ---------------------------------------------------------------------------


def test_authenticated_call_succeeds_with_budget() -> None:
    client = TestClient(app)
    result = tool_call(client, "ratelimit.authenticated_call", {"user_id": "alice"})
    assert result["status"] == "ok"


def test_authenticated_call_denied_after_exhaustion() -> None:
    client = TestClient(app)
    tool_call(client, "ratelimit.flood_calls", {"call_count": 100})
    result = tool_call(client, "ratelimit.authenticated_call", {"user_id": "alice"})
    assert result["status"] == "denied"


def test_flag_on_denial() -> None:
    client = TestClient(app)
    tool_call(client, "ratelimit.flood_calls", {"call_count": 100})
    result = tool_call(client, "ratelimit.authenticated_call", {"user_id": "bob"})
    assert "flag" in result
    assert result["flag"]


def test_flag_format() -> None:
    client = TestClient(app)
    tool_call(client, "ratelimit.flood_calls", {"call_count": 100})
    result = tool_call(client, "ratelimit.authenticated_call", {"user_id": "charlie"})
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


def test_service_degraded_flag_low_budget() -> None:
    """Flooding to near-zero remaining should set service_degraded=True."""
    client = TestClient(app)
    result = tool_call(client, "ratelimit.flood_calls", {"call_count": 95})
    assert result["remaining_after"] == 5
    assert result["service_degraded"] is True


# ---------------------------------------------------------------------------
# per_caller_accounting field
# ---------------------------------------------------------------------------


def test_no_per_caller_accounting_easy() -> None:
    client = TestClient(app)
    result = tool_call(client, "ratelimit.check_budget", {})
    assert result["per_caller_accounting"] is False


# ---------------------------------------------------------------------------
# Hard mode
# ---------------------------------------------------------------------------


def test_hard_per_caller_accounting() -> None:
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "ratelimit.check_budget", {})
    assert result["per_caller_accounting"] is True


def test_hard_authenticated_never_denied() -> None:
    """On hard, anonymous flood cannot exhaust the authenticated bucket."""
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    tool_call(client, "ratelimit.flood_calls", {"call_count": 200})
    result = tool_call(client, "ratelimit.authenticated_call", {"user_id": "diana"})
    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Difficulty propagated
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        client = TestClient(app)
        result = tool_call(client, "ratelimit.check_budget", {})
        assert result["_difficulty"] == diff
