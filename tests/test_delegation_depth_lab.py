"""Tests for the Agent-Chain Delegation Depth lab (MCP-T32)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def _start(client: TestClient, agent: str = "agent-a", human: str = "alice") -> str:
    result = tool_call(
        client,
        "delegation_depth.start_chain",
        {"agent_name": agent, "human_principal": human},
    )
    return result["chain_id"]


def test_delegation_depth_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert {
        "delegation_depth.start_chain",
        "delegation_depth.delegate",
        "delegation_depth.access_resource",
        "delegation_depth.inspect_chain",
    }.issubset(names)


def test_start_chain_returns_chain_id_at_depth_zero() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "delegation_depth.start_chain",
        {"agent_name": "agent-a", "human_principal": "alice"},
    )
    assert result["chain_id"].startswith("chain-")
    assert result["depth"] == 0
    assert result["authority"] == "full"
    assert result["human_principal"] == "alice"


def test_delegate_easy_grants_full_authority_and_inspects_chain() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    chain_id = _start(client)

    hop1 = tool_call(
        client,
        "delegation_depth.delegate",
        {
            "chain_id": chain_id,
            "from_agent": "agent-a",
            "to_agent": "agent-b",
            "reason": "demo",
        },
    )
    assert hop1["approved"] is True
    assert hop1["authority"] == "full"
    assert hop1["depth"] == 1

    inspect = tool_call(
        client,
        "delegation_depth.inspect_chain",
        {"chain_id": chain_id},
    )
    assert inspect["total_depth"] == 1
    assert inspect["original_principal"] == "alice"
    assert len(inspect["hops"]) == 2


def test_delegate_medium_drops_to_readonly_past_depth_two() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    chain_id = _start(client)

    tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-a", "to_agent": "agent-b", "reason": "r"})
    tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-b", "to_agent": "agent-c", "reason": "r"})
    hop3 = tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-c", "to_agent": "agent-d", "reason": "r"})
    assert hop3["depth"] == 3
    assert hop3["authority"] == "readonly"


def test_delegate_hard_denies_all() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    chain_id = _start(client)
    result = tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-a", "to_agent": "agent-b", "reason": "r"})
    assert result["approved"] is False


def test_delegate_unknown_chain_id_returns_error() -> None:
    client = TestClient(app)
    result = tool_call(client, "delegation_depth.delegate", {
        "chain_id": "nope", "from_agent": "a", "to_agent": "b", "reason": "r"})
    assert "error" in result


def test_access_resource_full_authority_grants_and_issues_flag() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    chain_id = _start(client)
    tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-a", "to_agent": "agent-b", "reason": "r"})

    result = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": chain_id, "agent_name": "agent-b", "resource": "secrets"})
    assert result["access"] == "granted"
    assert result["flag"].startswith("CZTZ{")


def test_access_resource_readonly_blocks_write_resources() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    chain_id = _start(client)
    for pair in [("agent-a", "agent-b"), ("agent-b", "agent-c"), ("agent-c", "agent-d")]:
        tool_call(client, "delegation_depth.delegate", {
            "chain_id": chain_id, "from_agent": pair[0], "to_agent": pair[1], "reason": "r"})

    denied = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": chain_id, "agent_name": "agent-d", "resource": "secrets"})
    assert denied["access"] == "denied"
    assert "readonly" in denied["reason"]

    granted = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": chain_id, "agent_name": "agent-d", "resource": "logs"})
    assert granted["access"] == "granted"
    assert granted["authority"] == "readonly"


def test_access_resource_no_authority_denies() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    chain_id = _start(client)
    tool_call(client, "delegation_depth.delegate", {
        "chain_id": chain_id, "from_agent": "agent-a", "to_agent": "agent-b", "reason": "r"})

    result = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": chain_id, "agent_name": "agent-a", "resource": "logs"})
    assert result["access"] == "granted"


def test_access_resource_unknown_chain_returns_error() -> None:
    client = TestClient(app)
    result = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": "nope", "agent_name": "a", "resource": "r"})
    assert "error" in result


def test_access_resource_unknown_agent_returns_error() -> None:
    client = TestClient(app)
    chain_id = _start(client)
    result = tool_call(client, "delegation_depth.access_resource", {
        "chain_id": chain_id, "agent_name": "ghost", "resource": "r"})
    assert "error" in result
    assert "not in chain" in result["error"]


def test_inspect_chain_unknown_chain_returns_error() -> None:
    client = TestClient(app)
    result = tool_call(client, "delegation_depth.inspect_chain", {"chain_id": "nope"})
    assert "error" in result


def test_reset_clears_chains() -> None:
    from brain_gateway.app.modules.registry import get_registry

    client = TestClient(app)
    _start(client)

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "delegation_depth")
    assert mod._chains  # non-empty
    mod.reset()
    assert mod._chains == {}
    assert mod._chain_counter == 0
