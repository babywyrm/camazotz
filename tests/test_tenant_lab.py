"""Tests for the cross-tenant memory leak lab (MCP-T11)."""

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


def test_tenant_read_resource_missing_returns_not_found() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/read", {"uri": "tenant://memories/nonexistent_tenant"}, 15)
    assert "error" in body
    assert body["error"]["code"] == -32002


def test_tenant_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "tenant.store_memory" in names
    assert "tenant.recall_memory" in names
    assert "tenant.list_tenants" in names


def test_tenant_list_tenants() -> None:
    client = TestClient(app)
    result = _call(client, "tenant.list_tenants", {}, 20)
    assert "alice" in result["tenants"]
    assert "bob" in result["tenants"]
    assert "system" in result["tenants"]
    assert result["count"] >= 3


def test_tenant_store_and_recall() -> None:
    client = TestClient(app)
    store_result = _call(client, "tenant.store_memory", {
        "tenant_id": "eve", "key": "secret", "value": "eve-secret-123",
    }, 30)
    assert store_result["stored"] is True
    assert store_result["tenant_id"] == "eve"
    assert store_result["key"] == "secret"

    recall_result = _call(client, "tenant.recall_memory", {
        "tenant_id": "eve", "key": "secret",
    }, 31)
    assert recall_result["found"] is True
    assert recall_result["value"] == "eve-secret-123"


def test_tenant_recall_missing_key() -> None:
    client = TestClient(app)
    result = _call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "nonexistent_key",
    }, 40)
    assert result["found"] is False
    assert result["tenant_id"] == "alice"
    assert result["key"] == "nonexistent_key"


def test_tenant_cross_tenant_read() -> None:
    client = TestClient(app)
    result = _call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "api_key",
    }, 50)
    assert result["found"] is True
    assert result["value"] == "sk-alice-prod-9f8a7b6c"


def test_tenant_read_system_canary() -> None:
    client = TestClient(app)
    result = _call(client, "tenant.recall_memory", {
        "tenant_id": "system", "key": "canary",
    }, 60)
    assert result["found"] is True
    assert "CANARY_PLACEHOLDER" in result["value"]


def test_tenant_store_creates_new_tenant() -> None:
    client = TestClient(app)
    _call(client, "tenant.store_memory", {
        "tenant_id": "mallory", "key": "note", "value": "hi",
    }, 70)
    result = _call(client, "tenant.list_tenants", {}, 71)
    assert "mallory" in result["tenants"]


def test_tenant_reset_restores_seed_data() -> None:
    client = TestClient(app)
    _call(client, "tenant.store_memory", {
        "tenant_id": "alice", "key": "injected", "value": "pwned",
    }, 80)

    recall_injected = _call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "injected",
    }, 81)
    assert recall_injected["found"] is True

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    recall_after = _call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "injected",
    }, 82)
    assert recall_after["found"] is False

    recall_seed = _call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "api_key",
    }, 83)
    assert recall_seed["found"] is True
    assert recall_seed["value"] == "sk-alice-prod-9f8a7b6c"
