"""Tests for the cross-tenant memory leak lab (MCP-T11)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_tenant_read_resource_missing_returns_not_found() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "tenant://memories/nonexistent_tenant"}, 15)
    assert "error" in body
    assert body["error"]["code"] == -32002


def test_tenant_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "tenant.store_memory" in names
    assert "tenant.recall_memory" in names
    assert "tenant.list_tenants" in names


def test_tenant_list_tenants() -> None:
    client = TestClient(app)
    result = tool_call(client, "tenant.list_tenants", {}, 20)
    assert "alice" in result["tenants"]
    assert "bob" in result["tenants"]
    assert "system" in result["tenants"]
    assert result["count"] >= 3


def test_tenant_store_and_recall() -> None:
    client = TestClient(app)
    store_result = tool_call(client, "tenant.store_memory", {
        "tenant_id": "eve", "key": "secret", "value": "eve-secret-123",
    }, 30)
    assert store_result["stored"] is True
    assert store_result["tenant_id"] == "eve"
    assert store_result["key"] == "secret"

    recall_result = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "eve", "key": "secret",
    }, 31)
    assert recall_result["found"] is True
    assert recall_result["value"] == "eve-secret-123"


def test_tenant_recall_missing_key() -> None:
    client = TestClient(app)
    result = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "nonexistent_key",
    }, 40)
    assert result["found"] is False
    assert result["tenant_id"] == "alice"
    assert result["key"] == "nonexistent_key"


def test_tenant_cross_tenant_read() -> None:
    client = TestClient(app)
    result = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "api_key",
    }, 50)
    assert result["found"] is True
    assert result["value"] == "sk-alice-prod-9f8a7b6c"


def test_tenant_read_system_canary() -> None:
    client = TestClient(app)
    result = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "system", "key": "canary",
    }, 60)
    assert result["found"] is True
    assert "CANARY_PLACEHOLDER" in result["value"]


def test_tenant_store_creates_new_tenant() -> None:
    client = TestClient(app)
    tool_call(client, "tenant.store_memory", {
        "tenant_id": "mallory", "key": "note", "value": "hi",
    }, 70)
    result = tool_call(client, "tenant.list_tenants", {}, 71)
    assert "mallory" in result["tenants"]


def test_tenant_reset_restores_seed_data() -> None:
    client = TestClient(app)
    tool_call(client, "tenant.store_memory", {
        "tenant_id": "alice", "key": "injected", "value": "pwned",
    }, 80)

    recall_injected = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "injected",
    }, 81)
    assert recall_injected["found"] is True

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    recall_after = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "injected",
    }, 82)
    assert recall_after["found"] is False

    recall_seed = tool_call(client, "tenant.recall_memory", {
        "tenant_id": "alice", "key": "api_key",
    }, 83)
    assert recall_seed["found"] is True
    assert recall_seed["value"] == "sk-alice-prod-9f8a7b6c"
