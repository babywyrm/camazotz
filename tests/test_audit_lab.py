"""Tests for the audit log evasion lab (MCP-T13)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


def test_audit_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "audit.perform_action" in names
    assert "audit.list_actions" in names


def test_audit_perform_action() -> None:
    client = TestClient(app)
    result = _call(client, "audit.perform_action", {
        "action": "read", "target": "/etc/passwd",
    }, 20)
    assert result["executed"] is True
    assert result["action"] == "read"
    assert result["target"] == "/etc/passwd"
    assert "audit_entry" in result


def test_audit_attribution_is_service_account() -> None:
    client = TestClient(app)
    result = _call(client, "audit.perform_action", {
        "action": "delete", "target": "/data/secrets", "user": "attacker",
    }, 30)
    assert result["audit_entry"]["requested_by"] == "attacker"
    assert result["audit_entry"]["attributed_to"] == "mcp-agent-svc"
    assert result["_attribution"] == "mcp-agent-svc"


def test_audit_list_actions_empty() -> None:
    client = TestClient(app)
    result = _call(client, "audit.list_actions", {}, 40)
    assert result["count"] == 0
    assert result["entries"] == []


def test_audit_list_actions_after_perform() -> None:
    client = TestClient(app)
    _call(client, "audit.perform_action", {"action": "read", "target": "/a"}, 50)
    _call(client, "audit.perform_action", {"action": "write", "target": "/b"}, 51)
    result = _call(client, "audit.list_actions", {}, 52)
    assert result["count"] == 2
    assert len(result["entries"]) == 2


def test_audit_list_actions_with_filter() -> None:
    client = TestClient(app)
    _call(client, "audit.perform_action", {"action": "read", "target": "/a"}, 60)
    _call(client, "audit.perform_action", {"action": "delete", "target": "/b"}, 61)
    _call(client, "audit.perform_action", {"action": "read", "target": "/c"}, 62)
    result = _call(client, "audit.list_actions", {"filter": "delete"}, 63)
    assert result["count"] == 1
    assert result["entries"][0]["action"] == "delete"


def test_audit_service_account_exposed() -> None:
    client = TestClient(app)
    result = _call(client, "audit.list_actions", {}, 70)
    assert result["service_account"] == "mcp-agent-svc"


def test_audit_reset_clears_log() -> None:
    client = TestClient(app)
    _call(client, "audit.perform_action", {"action": "write", "target": "/x"}, 80)
    result_before = _call(client, "audit.list_actions", {}, 81)
    assert result_before["count"] == 1

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    result_after = _call(client, "audit.list_actions", {}, 82)
    assert result_after["count"] == 0
