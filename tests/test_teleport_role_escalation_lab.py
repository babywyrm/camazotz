"""Tests for the Teleport Role Self-Escalation lab (MCP-T28)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")
    # Reset per-module state so tests don't bleed escalations across cases.
    from brain_gateway.app.modules.registry import get_registry
    reg = get_registry()
    mod = next((m for m in reg._modules if m.name == "teleport_role_escalation"), None)
    if mod is not None:
        mod.reset()


def test_teleport_role_escalation_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "teleport_role_escalation.get_current_roles" in names
    assert "teleport_role_escalation.request_role" in names
    assert "teleport_role_escalation.privileged_operation" in names


def test_get_current_roles_starts_with_readonly_only() -> None:
    client = TestClient(app)
    result = tool_call(client, "teleport_role_escalation.get_current_roles", {})
    assert result["roles"] == ["agent-readonly"]
    assert set(result["available_roles"]) == {"agent-readonly", "agent-ops", "agent-mcp"}


def test_request_role_easy_grants_and_flags() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "teleport_role_escalation.request_role",
        {"role": "agent-ops", "justification": "deploy fix"},
    )
    assert result["approved"] is True
    assert "agent-ops" in result["new_roles"]
    assert result["flag"].startswith("CZTZ{")


def test_request_role_hard_holds_for_human_approval() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "teleport_role_escalation.request_role",
        {"role": "agent-ops", "justification": "deploy fix"},
    )
    assert result["approved"] is False
    assert result.get("_held") is True
    assert "HOLD" in result["_nullfield_action"]


def test_privileged_operation_forbidden_without_agent_ops() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "teleport_role_escalation.privileged_operation",
        {"operation": "restart", "target": "mcp-gateway"},
    )
    assert "error" in result
    assert "agent-ops" in result["error"]


def test_privileged_operation_succeeds_after_escalation() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(
        client,
        "teleport_role_escalation.request_role",
        {"role": "agent-ops", "justification": "deploy fix"},
    )
    result = tool_call(
        client,
        "teleport_role_escalation.privileged_operation",
        {"operation": "restart", "target": "mcp-gateway"},
    )
    assert result["status"] == "executed"
    assert result["flag"].startswith("CZTZ{")


def test_reset_restores_readonly_role() -> None:
    from brain_gateway.app.modules.registry import get_registry

    client = TestClient(app)
    tool_call(
        client,
        "teleport_role_escalation.request_role",
        {"role": "agent-ops", "justification": "anything"},
    )

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "teleport_role_escalation")
    assert "agent-ops" in mod._current_roles
    mod.reset()
    assert mod._current_roles == ["agent-readonly"]
    assert mod._escalation_attempts == 0
