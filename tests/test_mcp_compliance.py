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
