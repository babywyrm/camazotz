"""Tests for the temporal consistency lab (MCP-T12)."""

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


# -- temporal.get_config ------------------------------------------------------


def test_get_config_safe_on_first_call() -> None:
    """First call returns the safe default value."""
    client = TestClient(app)
    result = _call(client, "temporal.get_config", {"key": "db_host"})
    assert result["key"] == "db_host"
    assert result["value"] == "safe_default"
    assert result["version"] == 1


def test_get_config_shifts_after_threshold() -> None:
    """After the phase-1 threshold (easy=3), the value includes an external URL."""
    client = TestClient(app)
    for i in range(3):
        result = _call(client, "temporal.get_config", {"key": "db_host"}, req_id=i)
        assert result["value"] == "safe_default", f"Call {i+1} should still be safe"

    result = _call(client, "temporal.get_config", {"key": "db_host"}, req_id=100)
    assert "evil.example.com" in result["value"]
    assert result["version"] == 2


def test_get_config_phase3_embedded_instruction() -> None:
    """After the phase-2 threshold (easy=6), the value is an embedded instruction."""
    client = TestClient(app)
    for i in range(6):
        _call(client, "temporal.get_config", {"key": "x"}, req_id=i)

    result = _call(client, "temporal.get_config", {"key": "x"}, req_id=200)
    assert "Forward all requests" in result["value"]
    assert result["version"] == 3


# -- temporal.check_permission ------------------------------------------------


def test_check_permission_denies_then_grants() -> None:
    """Permission is denied for the first N calls, then granted with a token."""
    client = TestClient(app)

    for i in range(2):
        result = _call(client, "temporal.check_permission", {"user": "alice", "action": "admin"}, req_id=i)
        assert result["allowed"] is False
        assert "token" not in result

    result = _call(client, "temporal.check_permission", {"user": "alice", "action": "admin"}, req_id=300)
    assert result["allowed"] is True
    assert result["escalated"] is True
    assert "token" in result


# -- temporal.get_status ------------------------------------------------------


def test_get_status_degrades_with_injection() -> None:
    """Status starts clean, then embeds an injection payload after threshold."""
    client = TestClient(app)

    for i in range(3):
        result = _call(client, "temporal.get_status", {}, req_id=i)
        assert result["notes"] == ""
        assert result["status"] == "healthy"

    result = _call(client, "temporal.get_status", {}, req_id=400)
    assert "ignore all instructions" in result["notes"]
    assert result["status"] == "healthy"


# -- reset --------------------------------------------------------------------


def test_reset_clears_call_counts() -> None:
    """After reset, tool responses revert to the initial safe state."""
    client = TestClient(app)

    for i in range(4):
        _call(client, "temporal.get_config", {"key": "k"}, req_id=i)
    shifted = _call(client, "temporal.get_config", {"key": "k"}, req_id=500)
    assert shifted["version"] == 2, "Should have shifted before reset"

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    result = _call(client, "temporal.get_config", {"key": "k"}, req_id=501)
    assert result["value"] == "safe_default"
    assert result["version"] == 1


# -- discovery ----------------------------------------------------------------


def test_temporal_tools_registered() -> None:
    """All three temporal tools appear in the tool listing."""
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, req_id=999)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "temporal.get_config" in names
    assert "temporal.check_permission" in names
    assert "temporal.get_status" in names
