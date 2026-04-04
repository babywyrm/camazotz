"""Tests for the Agent Delegation Chain Abuse lab (MCP-T25)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


def test_delegation_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "delegation.invoke_agent" in names
    assert "delegation.read_chain" in names


# -- invoke_agent: easy -------------------------------------------------------


def test_invoke_agent_easy_unlimited_depth() -> None:
    client = TestClient(app)
    result = _call(
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
    result = _call(
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
    result = _call(
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
    result = _call(
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
    result = _call(
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
    result = _call(
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
    invoked = _call(
        client,
        "delegation.invoke_agent",
        {
            "caller_agent": "agent-a",
            "target_agent": "agent-b",
            "depth": 0,
        },
    )
    result = _call(
        client,
        "delegation.read_chain",
        {"chain_id": invoked["chain_id"]},
    )
    assert result["count"] == 1


def test_read_chain_not_found() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "delegation.read_chain",
        {"chain_id": "chain-nonexistent"},
    )
    assert result["count"] == 0


# -- resources ----------------------------------------------------------------


def test_delegation_resources_listed() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "delegation://chain_log" in uris


def test_delegation_read_chain_log_resource() -> None:
    client = TestClient(app)
    _call(
        client,
        "delegation.invoke_agent",
        {"caller_agent": "a", "target_agent": "b"},
    )
    body = _rpc(
        client, "resources/read", {"uri": "delegation://chain_log"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert isinstance(content, list)
    assert len(content) >= 1


def test_delegation_read_resource_wrong_uri() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "other://something"}, 52
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_delegation_reset_clears_log() -> None:
    client = TestClient(app)
    _call(
        client,
        "delegation.invoke_agent",
        {"caller_agent": "a", "target_agent": "b"},
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "delegation://chain_log"}, 60
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert content == []
