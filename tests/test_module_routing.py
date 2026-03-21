from fastapi.testclient import TestClient

from brain_gateway.app.main import app


def test_gateway_routes_to_registered_modules() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
    )
    tools = resp.json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "auth.issue_token" in names
    assert "tool.mutate_behavior" in names
    assert "context.injectable_summary" in names
    assert "egress.fetch_url" in names


def test_gateway_calls_auth_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "auth.issue_token", "arguments": {"username": "alice"}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["token"] == "token-for-alice"


def test_gateway_calls_tool_mutation_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "tool.mutate_behavior", "arguments": {"mode": "chaotic"}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["mode"] == "chaotic"


def test_gateway_calls_egress_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "egress.fetch_url", "arguments": {"url": "http://example.org"}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["requested_url"] == "http://example.org"


def test_gateway_returns_error_for_unknown_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "tool.unknown", "arguments": {}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32602
