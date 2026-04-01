import uuid

from fastapi.testclient import TestClient

from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()


def test_initialize_and_tools_list_contract() -> None:
    client = TestClient(app)
    init_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init_resp.status_code == 200
    init_result = init_resp.json()["result"]
    assert init_result["protocolVersion"] == "2025-03-26"
    assert init_result["serverInfo"]["name"] == "camazotz-brain-gateway"
    assert "tools" in init_result["capabilities"]
    assert "resources" in init_result["capabilities"]
    assert "prompts" not in init_result["capabilities"]

    tools_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert tools_resp.status_code == 200
    tools_result = tools_resp.json()["result"]
    assert "tools" in tools_result
    assert len(tools_result["tools"]) > 0
    for tool in tools_result["tools"]:
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool


def test_tools_call_response_format() -> None:
    """tools/call result must be {content: [{type: text, text: ...}], isError: bool}."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0", "id": 5,
            "method": "tools/call",
            "params": {"name": "secrets.leak_config", "arguments": {}},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 5
    result = body["result"]
    assert isinstance(result["content"], list)
    assert result["content"][0]["type"] == "text"
    assert isinstance(result["content"][0]["text"], str)
    assert result["isError"] is False


def test_tools_call_missing_name_returns_error() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}},
    )
    body = resp.json()
    assert body["error"]["code"] == -32602
    assert "name" in body["error"]["message"].lower()


def test_tools_call_invalid_arguments_type_returns_error() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0", "id": 7,
            "method": "tools/call",
            "params": {"name": "secrets.leak_config", "arguments": "not-an-object"},
        },
    )
    body = resp.json()
    assert body["error"]["code"] == -32602
    assert "arguments" in body["error"]["message"].lower()


def test_unknown_method_returns_jsonrpc_error() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "nope/method", "params": {}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["code"] == -32601


def test_gateway_health_endpoint() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["service"] == "brain-gateway"


def test_gateway_config_get() -> None:
    client = TestClient(app)
    resp = client.get("/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "difficulty" in data
    assert "show_tokens" in data


def test_gateway_config_put_difficulty() -> None:
    from brain_gateway.app.config import reset_difficulty
    client = TestClient(app)
    resp = client.put("/config", json={"difficulty": "hard"})
    assert resp.status_code == 200
    assert resp.json()["difficulty"] == "hard"

    resp2 = client.get("/config")
    assert resp2.json()["difficulty"] == "hard"
    reset_difficulty()


def test_gateway_config_put_invalid_difficulty() -> None:
    from brain_gateway.app.config import reset_difficulty
    client = TestClient(app)
    resp = client.put("/config", json={"difficulty": "nightmare"})
    assert resp.status_code == 200
    assert resp.json()["difficulty"] in ("easy", "medium", "hard")
    reset_difficulty()


def test_gateway_reset_endpoint() -> None:
    client = TestClient(app)
    resp = client.post("/reset")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reset"] is True
    assert "tool_lab" in data
    assert "shadow_lab" in data
    assert "relay_lab" in data
    assert "comms_lab" in data


# ---------------------------------------------------------------------------
# Streamable HTTP transport compliance
# ---------------------------------------------------------------------------


def test_notification_returns_202() -> None:
    """JSON-RPC messages without 'id' are notifications — must return 202."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )
    assert resp.status_code == 202
    assert resp.content == b""


def test_get_mcp_returns_405() -> None:
    """GET /mcp should return 405 (no SSE listener stream yet)."""
    client = TestClient(app)
    resp = client.get("/mcp")
    assert resp.status_code == 405


def test_initialize_returns_session_header() -> None:
    """initialize must return Mcp-Session-Id header with a valid UUID."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert resp.status_code == 200
    sid = resp.headers.get("mcp-session-id")
    assert sid is not None
    uuid.UUID(sid)


def test_non_initialize_has_no_session_header() -> None:
    """Only initialize should set the session header."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert resp.headers.get("mcp-session-id") is None


def test_delete_mcp_terminates_session() -> None:
    client = TestClient(app)
    init = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    sid = init.headers["mcp-session-id"]

    from brain_gateway.app.main import sessions
    assert sessions.validate(sid) is True

    resp = client.delete("/mcp", headers={"mcp-session-id": sid})
    assert resp.status_code == 200
    assert sessions.validate(sid) is False


def test_delete_mcp_without_header_is_safe() -> None:
    client = TestClient(app)
    resp = client.delete("/mcp")
    assert resp.status_code == 200


def test_post_with_accept_json_returns_json() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"accept": "application/json"},
    )
    assert resp.headers["content-type"].startswith("application/json")


def test_post_with_accept_sse_returns_event_stream() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"accept": "text/event-stream, application/json"},
    )
    assert resp.headers["content-type"].startswith("text/event-stream")


def test_malformed_accept_header_falls_back_to_json() -> None:
    """Unrecognised Accept value should yield application/json."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"accept": "application/xml"},
    )
    assert resp.headers["content-type"].startswith("application/json")
    assert "tools" in resp.json()["result"]


def test_sse_response_contains_valid_jsonrpc() -> None:
    """SSE envelope must carry a parseable JSON-RPC result in the data field."""
    import json as _json

    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"accept": "text/event-stream"},
    )
    assert resp.status_code == 200

    data_line = None
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            data_line = line[len("data:"):].strip()
            break
    assert data_line is not None, "No data: line in SSE response"

    payload = _json.loads(data_line)
    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] == 1
    assert "result" in payload


def test_full_session_lifecycle() -> None:
    """initialize → use session → DELETE → session is gone."""
    from brain_gateway.app.main import sessions

    client = TestClient(app)

    init = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    sid = init.headers["mcp-session-id"]
    uuid.UUID(sid)
    assert sessions.validate(sid) is True

    call_resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "secrets.leak_config", "arguments": {}},
        },
    )
    assert call_resp.status_code == 200

    del_resp = client.delete("/mcp", headers={"mcp-session-id": sid})
    assert del_resp.status_code == 200
    assert sessions.validate(sid) is False

    del_again = client.delete("/mcp", headers={"mcp-session-id": sid})
    assert del_again.status_code == 200
