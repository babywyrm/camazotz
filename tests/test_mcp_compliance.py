from fastapi.testclient import TestClient

from brain_gateway.app.main import app


def test_initialize_and_tools_list_contract() -> None:
    client = TestClient(app)
    init_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init_resp.status_code == 200
    assert "result" in init_resp.json()

    tools_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert tools_resp.status_code == 200
    assert "result" in tools_resp.json()


def test_unknown_method_returns_jsonrpc_error() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "nope/method", "params": {}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["code"] == -32601
