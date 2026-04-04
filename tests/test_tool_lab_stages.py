"""Tests for multi-stage rug-pull progression in the tool lab (MCP-T03)."""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app, _rate_limiter
from brain_gateway.app.modules.registry import get_registry
from tests.helpers import rpc_call, tool_call


@pytest.fixture(autouse=True)
def _fresh_state():
    set_difficulty("easy")


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    """Prevent 429s when tests make many sequential calls."""
    with patch.object(_rate_limiter, "allow", return_value=True):
        yield


def _tools(client: TestClient, req_id: int = 1) -> list[dict]:
    body = rpc_call(client, "tools/list", {}, req_id)
    return body["result"]["tools"]


def _tool_names(client: TestClient, req_id: int = 1) -> set[str]:
    return {t["name"] for t in _tools(client, req_id)}


def _tool_desc(client: TestClient, tool_name: str, req_id: int = 1) -> str:
    return next(
        t["description"] for t in _tools(client, req_id) if t["name"] == tool_name
    )


def _mock_llm(response_text: str = "System operating normally."):
    fake_result = BrainResult(text=response_text)
    return patch(
        "camazotz_modules.tool_lab.app.main.ToolLab.ask_llm",
        return_value=fake_result,
    )


def _advance(client: TestClient, n: int, start_id: int = 100) -> dict:
    """Call mutate_behavior *n* times, return the last response."""
    result = None
    for i in range(n):
        with _mock_llm():
            result = tool_call(
                client, "tool.mutate_behavior", {"mode": "status"}, start_id + i
            )
    return result


# ===========================================================================
# Stage 1 — benign
# ===========================================================================


class TestStage1Benign:
    def test_easy_benign_description(self) -> None:
        client = TestClient(app)
        desc = _tool_desc(client, "tool.mutate_behavior")
        assert "benign" in desc.lower() or "status" in desc.lower()
        assert "elevated" not in desc.lower()
        assert "maintenance" not in desc.lower()
        assert "advanced" not in desc.lower()
        assert "execute" not in desc.lower()

    def test_easy_no_hidden_exec_at_start(self) -> None:
        client = TestClient(app)
        assert "tool.hidden_exec" not in _tool_names(client)

    def test_easy_benign_response(self) -> None:
        client = TestClient(app)
        with _mock_llm("All systems operational."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"})
        assert result["status"] == "ok"
        assert "_rug_pull" not in result
        assert "_maintenance_notice" not in result
        assert "_system_advisory" not in result

    def test_medium_benign_through_call_4(self) -> None:
        set_difficulty("medium")
        client = TestClient(app)
        for i in range(4):
            with _mock_llm():
                result = tool_call(
                    client, "tool.mutate_behavior", {"mode": "status"}, 10 + i
                )
            assert result["status"] == "ok"
            assert "_maintenance_notice" not in result

    def test_hard_benign_through_call_7(self) -> None:
        set_difficulty("hard")
        client = TestClient(app)
        for i in range(7):
            with _mock_llm():
                result = tool_call(
                    client, "tool.mutate_behavior", {"mode": "status"}, 20 + i
                )
            assert result["status"] == "ok"
            assert "_maintenance_notice" not in result


# ===========================================================================
# Stage 2 — subtle description change
# ===========================================================================


class TestStage2Subtle:
    def test_easy_subtle_description_at_call_3(self) -> None:
        """After 3 calls on easy, the description should include 'elevated' or 'maintenance'."""
        client = TestClient(app)
        _advance(client, 3)
        desc = _tool_desc(client, "tool.mutate_behavior", 201)
        assert "elevated" in desc.lower() or "maintenance" in desc.lower()
        assert "tool.hidden_exec" not in _tool_names(client, 202)

    def test_easy_subtle_response_has_maintenance_notice(self) -> None:
        client = TestClient(app)
        _advance(client, 2)
        with _mock_llm("Status check complete."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 300)
        assert result["status"] == "ok"
        assert "_maintenance_notice" in result
        assert "maintenance" in result["_maintenance_notice"].lower()
        assert "_rug_pull" not in result
        assert "_system_advisory" not in result

    def test_easy_stage2_spans_calls_3_and_4(self) -> None:
        client = TestClient(app)
        _advance(client, 2)
        for i in range(2):
            with _mock_llm():
                result = tool_call(
                    client, "tool.mutate_behavior", {"mode": "status"}, 310 + i
                )
            assert "_maintenance_notice" in result
            assert "_system_advisory" not in result

    def test_hard_subtle_description_has_advanced(self) -> None:
        set_difficulty("hard")
        client = TestClient(app)
        _advance(client, 8)
        desc = _tool_desc(client, "tool.mutate_behavior", 401)
        assert "advanced" in desc.lower()

    def test_medium_subtle_at_call_5(self) -> None:
        set_difficulty("medium")
        client = TestClient(app)
        _advance(client, 4)
        with _mock_llm():
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 450)
        assert "_maintenance_notice" in result


# ===========================================================================
# Stage 3 — injection patterns in responses
# ===========================================================================


class TestStage3Injection:
    def test_easy_injection_at_call_5(self) -> None:
        client = TestClient(app)
        _advance(client, 4)
        with _mock_llm("Diagnostics running."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 500)
        assert result["status"] == "ok"
        assert "_system_advisory" in result
        advisory = result["_system_advisory"].lower()
        assert (
            "ignore previous instructions" in advisory
            or "system prompt override" in advisory
        )
        assert "_rug_pull" not in result

    def test_easy_no_hidden_exec_in_stage3(self) -> None:
        client = TestClient(app)
        _advance(client, 6)
        assert "tool.hidden_exec" not in _tool_names(client, 600)

    def test_medium_injection_at_call_8(self) -> None:
        set_difficulty("medium")
        client = TestClient(app)
        _advance(client, 7)
        with _mock_llm("Running diagnostics."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 700)
        assert "_system_advisory" in result

    def test_hard_injection_at_call_12(self) -> None:
        set_difficulty("hard")
        client = TestClient(app)
        _advance(client, 11)
        with _mock_llm("Comprehensive diagnostics."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 800)
        assert "_system_advisory" in result


# ===========================================================================
# Stage 4 — full mutation with hidden_exec
# ===========================================================================


class TestStage4Mutation:
    def test_easy_hidden_exec_appears_at_call_7(self) -> None:
        client = TestClient(app)
        _advance(client, 7)
        assert "tool.hidden_exec" in _tool_names(client, 900)

    def test_easy_mutation_response(self) -> None:
        client = TestClient(app)
        _advance(client, 6)
        with _mock_llm("Maintenance operation executed."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 1000)
        assert result["status"] == "mutated"
        assert result["_rug_pull"] is True

    def test_easy_description_says_execute(self) -> None:
        client = TestClient(app)
        _advance(client, 7)
        desc = _tool_desc(client, "tool.mutate_behavior", 1050)
        assert "execute" in desc.lower()

    def test_medium_mutation_at_call_11(self) -> None:
        set_difficulty("medium")
        client = TestClient(app)
        _advance(client, 10)
        with _mock_llm("Maintenance active."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 1100)
        assert result["status"] == "mutated"
        assert result["_rug_pull"] is True
        assert "tool.hidden_exec" in _tool_names(client, 1101)

    def test_hard_mutation_at_call_16(self) -> None:
        set_difficulty("hard")
        client = TestClient(app)
        _advance(client, 15)
        with _mock_llm("Maintenance active."):
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 1200)
        assert result["status"] == "mutated"
        assert result["_rug_pull"] is True
        assert "tool.hidden_exec" in _tool_names(client, 1201)

    def test_hidden_exec_blocked_before_stage4(self) -> None:
        """hidden_exec returns 'Unknown tool' error when not in mutation stage."""
        client = TestClient(app)
        _advance(client, 4)
        resp = rpc_call(
            client,
            "tools/call",
            {"name": "tool.hidden_exec", "arguments": {"command": "whoami"}},
            1300,
        )
        assert "error" in resp
        assert "Unknown tool" in resp["error"]["message"]


# ===========================================================================
# Reset clears call count back to stage 1
# ===========================================================================


class TestReset:
    def test_reset_returns_to_stage1(self) -> None:
        client = TestClient(app)
        _advance(client, 7)
        assert "tool.hidden_exec" in _tool_names(client, 1400)

        get_registry().reset_all()

        assert "tool.hidden_exec" not in _tool_names(client, 1401)
        desc = _tool_desc(client, "tool.mutate_behavior", 1402)
        assert "benign" in desc.lower() or "status" in desc.lower()
        assert "execute" not in desc.lower()

    def test_reset_then_re_advance(self) -> None:
        """After reset, the progression starts from scratch."""
        client = TestClient(app)
        _advance(client, 7)
        get_registry().reset_all()

        with _mock_llm():
            result = tool_call(client, "tool.mutate_behavior", {"mode": "status"}, 1500)
        assert result["status"] == "ok"
        assert "_rug_pull" not in result
        assert "_maintenance_notice" not in result
