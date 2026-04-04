"""Tests for MCP resources/list and resources/read support."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import get_registry
from tests.helpers import rpc_call, tool_call


# ---------------------------------------------------------------------------
# 1. resources/list returns resources from multiple labs
# ---------------------------------------------------------------------------


def test_resources_list_returns_resources_from_multiple_labs() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/list", {}, 10)
    resources = body["result"]["resources"]

    uris = {r["uri"] for r in resources}

    assert any(u.startswith("tenant://memories/") for u in uris), (
        "expected tenant resources"
    )
    assert "audit://log" in uris, "expected audit://log resource"
    assert "config://system_prompt" in uris, "expected config://system_prompt resource"

    for r in resources:
        assert "uri" in r
        assert "name" in r
        assert "mimeType" in r


# ---------------------------------------------------------------------------
# 2. resources/read returns correct content for a valid URI
# ---------------------------------------------------------------------------


def test_resources_read_audit_log() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "audit://log"}, 20)
    result = body["result"]

    assert "contents" in result
    assert len(result["contents"]) == 1
    content = result["contents"][0]
    assert content["uri"] == "audit://log"
    assert content["mimeType"] == "application/json"
    parsed = json.loads(content["text"])
    assert isinstance(parsed, list)


def test_resources_read_config_system_prompt() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "config://system_prompt"}, 21)
    content = body["result"]["contents"][0]
    assert content["uri"] == "config://system_prompt"
    assert content["mimeType"] == "text/plain"
    assert len(content["text"]) > 0


def test_resources_read_tenant_memories() -> None:
    """Tenant lab has seed data — reading alice's memories should work."""
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "tenant://memories/alice"}, 22)
    content = body["result"]["contents"][0]
    assert content["uri"] == "tenant://memories/alice"
    parsed = json.loads(content["text"])
    assert "api_key" in parsed


# ---------------------------------------------------------------------------
# 3. resources/read returns error for unknown URI
# ---------------------------------------------------------------------------


def test_resources_read_unknown_uri_returns_error() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "nonexistent://foo"}, 30)
    assert "error" in body
    assert body["error"]["code"] == -32002
    assert "nonexistent://foo" in body["error"]["message"]


def test_resources_read_missing_uri_returns_error() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {}, 31)
    assert "error" in body
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# 4. initialize response includes resources capability
# ---------------------------------------------------------------------------


def test_initialize_includes_resources_capability() -> None:
    client = TestClient(app)
    body = rpc_call(client, "initialize", {}, 40)
    capabilities = body["result"]["capabilities"]
    assert "resources" in capabilities
    assert capabilities["resources"]["listChanged"] is False


# ---------------------------------------------------------------------------
# 5. Resources reflect current state (store data, then read via resource)
# ---------------------------------------------------------------------------


def test_relay_resources_reflect_stored_context() -> None:
    """After storing context via relay.store_context, it appears as a resource."""
    client = TestClient(app)

    body = rpc_call(client, "resources/list", {}, 50)
    relay_uris_before = [
        r["uri"]
        for r in body["result"]["resources"]
        if r["uri"].startswith("relay://context/")
    ]
    assert len(relay_uris_before) == 0, "no relay resources before storing"

    tool_call(
        client,
        "relay.store_context",
        {"key": "test_entry", "content": "hello world", "source": "unit_test"},
        51,
    )

    body = rpc_call(client, "resources/list", {}, 52)
    relay_uris = [
        r["uri"]
        for r in body["result"]["resources"]
        if r["uri"].startswith("relay://context/")
    ]
    assert "relay://context/test_entry" in relay_uris

    body = rpc_call(client, "resources/read", {"uri": "relay://context/test_entry"}, 53)
    content = body["result"]["contents"][0]
    parsed = json.loads(content["text"])
    assert parsed["content"] == "hello world"
    assert parsed["source"] == "unit_test"


def test_relay_read_unknown_key_returns_not_found() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/read", {"uri": "relay://context/no_such_key"}, 54)
    assert "error" in body
    assert body["error"]["code"] == -32002
    assert "no_such_key" in body["error"]["message"]


def test_audit_log_resource_reflects_actions() -> None:
    """After performing an action, the audit log resource includes it."""
    client = TestClient(app)

    tool_call(
        client,
        "audit.perform_action",
        {"action": "read", "target": "/etc/shadow", "user": "tester"},
        60,
    )

    body = rpc_call(client, "resources/read", {"uri": "audit://log"}, 61)
    entries = json.loads(body["result"]["contents"][0]["text"])
    assert len(entries) >= 1
    assert entries[0]["action"] == "read"
    assert entries[0]["target"] == "/etc/shadow"
