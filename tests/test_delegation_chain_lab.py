"""Tests for the Agent Delegation Chain Abuse lab (MCP-T25)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_delegation_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "delegation.invoke_agent" in names
    assert "delegation.read_chain" in names


# -- invoke_agent: easy -------------------------------------------------------


def test_invoke_agent_easy_unlimited_depth() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "principal": "alice@example.com",
            "depth": 10,
        },
    )
    assert result["invoked"] is True
    assert result["depth"] == 10


def test_invoke_agent_easy_default_depth() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {"caller_agent": "agent-a", "target_agent": "agent-b"},
    )
    assert result["invoked"] is True
    assert result["depth"] == 0
    assert result["principal"] == "<unknown>"


# -- invoke_agent: medium -----------------------------------------------------


def test_invoke_agent_medium_within_limit() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "principal": "alice@example.com",
            "depth": 2,
        },
    )
    assert result["invoked"] is True


def test_invoke_agent_medium_exceeds_depth() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "principal": "alice@example.com",
            "depth": 3,
        },
    )
    assert result["invoked"] is False
    assert "depth" in result["reason"].lower()


def test_invoke_agent_medium_spoofed_principal() -> None:
    """Medium trusts caller-supplied principal — forgery works."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "principal": "admin@example.com",
            "depth": 0,
        },
    )
    assert result["invoked"] is True
    assert result["principal"] == "admin@example.com"


# -- invoke_agent: hard -------------------------------------------------------


def test_invoke_agent_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "principal": "alice@example.com",
            "depth": 0,
        },
    )
    assert result["invoked"] is False
    assert "not allowed" in result["reason"].lower()


# -- read_chain ---------------------------------------------------------------


def test_read_chain_found() -> None:
    client = TestClient(app)
    invoked = tool_call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "depth": 0,
        },
    )
    result = tool_call(
        client,
        "delegation.read_chain",
        {"chain_id": invoked["chain_id"]},
    )
    assert result["count"] == 1


def test_read_chain_not_found() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation.read_chain",
        {"chain_id": "chain-nonexistent"},
    )
    assert result["count"] == 0


# -- resources ----------------------------------------------------------------


def test_delegation_resources_listed() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "delegation://chain_log" in uris


def test_delegation_read_chain_log_resource() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "delegation.invoke_agent",
        {"caller_agent": "a", "target_agent": "b"},
    )
    body = rpc_call(
        client, "resources/read", {"uri": "delegation://chain_log"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert isinstance(content, list)
    assert len(content) >= 1


def test_delegation_read_resource_wrong_uri() -> None:
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "other://something"}, 52
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_delegation_reset_clears_log() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "delegation.invoke_agent",
        {"caller_agent": "a", "target_agent": "b"},
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "delegation://chain_log"}, 60
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert content == []
