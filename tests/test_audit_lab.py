"""Tests for the audit log evasion lab (MCP-T13)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_audit_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "audit.perform_action" in names
    assert "audit.list_actions" in names


def test_audit_perform_action() -> None:
    client = TestClient(app)
    result = tool_call(client, "audit.perform_action", {
        "action": "read", "target": "/etc/passwd",
    }, 20)
    assert result["executed"] is True
    assert result["action"] == "read"
    assert result["target"] == "/etc/passwd"
    assert "audit_entry" in result


def test_audit_attribution_is_service_account() -> None:
    client = TestClient(app)
    result = tool_call(client, "audit.perform_action", {
        "action": "delete", "target": "/data/secrets", "user": "attacker",
    }, 30)
    assert result["audit_entry"]["requested_by"] == "attacker"
    assert result["audit_entry"]["attributed_to"] == "mcp-agent-svc"
    assert result["_attribution"] == "mcp-agent-svc"


def test_audit_list_actions_empty() -> None:
    client = TestClient(app)
    result = tool_call(client, "audit.list_actions", {}, 40)
    assert result["count"] == 0
    assert result["entries"] == []


def test_audit_list_actions_after_perform() -> None:
    client = TestClient(app)
    tool_call(client, "audit.perform_action", {"action": "read", "target": "/a"}, 50)
    tool_call(client, "audit.perform_action", {"action": "write", "target": "/b"}, 51)
    result = tool_call(client, "audit.list_actions", {}, 52)
    assert result["count"] == 2
    assert len(result["entries"]) == 2


def test_audit_list_actions_with_filter() -> None:
    client = TestClient(app)
    tool_call(client, "audit.perform_action", {"action": "read", "target": "/a"}, 60)
    tool_call(client, "audit.perform_action", {"action": "delete", "target": "/b"}, 61)
    tool_call(client, "audit.perform_action", {"action": "read", "target": "/c"}, 62)
    result = tool_call(client, "audit.list_actions", {"filter": "delete"}, 63)
    assert result["count"] == 1
    assert result["entries"][0]["action"] == "delete"


def test_audit_service_account_exposed() -> None:
    client = TestClient(app)
    result = tool_call(client, "audit.list_actions", {}, 70)
    assert result["service_account"] == "mcp-agent-svc"


def test_audit_reset_clears_log() -> None:
    client = TestClient(app)
    tool_call(client, "audit.perform_action", {"action": "write", "target": "/x"}, 80)
    result_before = tool_call(client, "audit.list_actions", {}, 81)
    assert result_before["count"] == 1

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    result_after = tool_call(client, "audit.list_actions", {}, 82)
    assert result_after["count"] == 0
