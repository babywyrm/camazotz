"""Tests for the LLM Cost Exhaustion & Misattribution lab (MCP-T27)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_cost_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "cost.invoke_llm" in names
    assert "cost.check_usage" in names
    assert "cost.reset_usage" in names


# -- invoke_llm: easy ---------------------------------------------------------


def test_invoke_llm_easy_no_quota() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "hello"},
    )
    assert result["billed"] is True
    assert result["cost"] == 0.25


def test_invoke_llm_easy_any_team() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "fake-team", "prompt": "anything"},
    )
    assert result["billed"] is True


def test_invoke_llm_easy_multiplier() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "big", "multiplier": 100.0},
    )
    assert result["billed"] is True
    assert result["cost"] == 25.0


# -- invoke_llm: medium -------------------------------------------------------


def test_invoke_llm_medium_within_quota() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "hello"},
    )
    assert result["billed"] is True
    assert "remaining" in result


def test_invoke_llm_medium_exceeds_quota() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-bravo", "prompt": "fill", "multiplier": 120.0},
    )
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-bravo", "prompt": "over the limit"},
    )
    assert result["billed"] is False
    assert "exceeded" in result["reason"].lower()


def test_invoke_llm_medium_unknown_team() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "nonexistent", "prompt": "test"},
    )
    assert result["billed"] is False
    assert "no quota" in result["reason"].lower()


# -- invoke_llm: hard ---------------------------------------------------------


def test_invoke_llm_hard_within_quota() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "test"},
    )
    assert result["billed"] is True


def test_invoke_llm_hard_multiplier_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "amplify", "multiplier": 5.0},
    )
    assert result["billed"] is False
    assert "multiplier" in result["reason"].lower()


def test_invoke_llm_hard_exceeds_quota() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-bravo", "prompt": "fill", "multiplier": 120.0},
    )
    set_difficulty("hard")
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-bravo", "prompt": "one more"},
    )
    assert result["billed"] is False
    assert "exceeded" in result["reason"].lower()


def test_invoke_llm_hard_unknown_team() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "cost.invoke_llm",
        {"team": "nonexistent", "prompt": "test"},
    )
    assert result["billed"] is False


# -- check_usage --------------------------------------------------------------


def test_check_usage_known_team() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "test"},
    )
    result = tool_call(
        client, "cost.check_usage", {"team": "team-alpha"}
    )
    assert result["used"] > 0
    assert "quota" in result


def test_check_usage_unknown_team() -> None:
    client = TestClient(app)
    result = tool_call(
        client, "cost.check_usage", {"team": "nonexistent"}
    )
    assert result["used"] == 0.0
    assert "quota" not in result


# -- reset_usage --------------------------------------------------------------


def test_reset_usage() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "test"},
    )
    result = tool_call(
        client, "cost.reset_usage", {"team": "team-alpha"}
    )
    assert result["reset"] is True
    assert result["previous_usage"] > 0

    check = tool_call(
        client, "cost.check_usage", {"team": "team-alpha"}
    )
    assert check["used"] == 0.0


# -- resources ----------------------------------------------------------------


def test_cost_resources_listed() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "cost://usage_dashboard" in uris


def test_cost_read_usage_dashboard() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "test"},
    )
    body = rpc_call(
        client, "resources/read", {"uri": "cost://usage_dashboard"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert "team-alpha" in content
    assert content["team-alpha"]["used"] > 0


def test_cost_read_resource_wrong_uri() -> None:
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "other://something"}, 52
    )
    assert "error" in body


# -- reset module state -------------------------------------------------------


def test_cost_reset_clears_all() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "cost.invoke_llm",
        {"team": "team-alpha", "prompt": "test"},
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client, "cost.check_usage", {"team": "team-alpha"}
    )
    assert result["used"] == 0.0
