from unittest.mock import patch, MagicMock

import httpx
import pytest

import importlib
import sys


@pytest.fixture()
def frontend_client():
    """Import the frontend Flask app and return a test client."""
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


def _mock_mcp_response(result: dict) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": result}
    mock.raise_for_status = MagicMock()
    return mock


def test_index_page(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Camazotz" in resp.data
    assert b"OWASP MCP Top 10" in resp.data


def test_playground_page(frontend_client) -> None:
    client, mod = frontend_client
    tools_result = {"tools": [
        {"name": "test.tool", "description": "A test tool", "inputSchema": {"type": "object", "properties": {}}},
    ]}
    mock_resp = _mock_mcp_response(tools_result)
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.get("/playground")
    assert resp.status_code == 200
    assert b"test.tool" in resp.data


def test_scenarios_page(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/scenarios")
    assert resp.status_code == 200
    assert b"Attack Scenarios" in resp.data
    assert b"MCP01" in resp.data


def test_observer_page_no_events(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/observer")
    assert resp.status_code == 200
    assert b"Observer" in resp.data


def test_observer_page_with_event(frontend_client) -> None:
    client, _ = frontend_client
    event = {"request_id": "req-123", "tool_name": "auth.issue_token", "module": "AuthLabModule", "timestamp": "2026-03-21T00:00:00"}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = event
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/observer")
    assert resp.status_code == 200
    assert b"auth.issue_token" in resp.data


def test_api_tools(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = _mock_mcp_response({"tools": []})
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.get("/api/tools")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "result" in data


def test_api_call_success(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = _mock_mcp_response({"summary": "test summary"})
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.post("/api/call", json={"name": "context.injectable_summary", "arguments": {"text": "hello"}})
    assert resp.status_code == 200


def test_api_call_missing_name(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.post("/api/call", json={"arguments": {}})
    assert resp.status_code == 400


def test_api_observer(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"tool_name": "test"}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/observer")
    assert resp.status_code == 200


def test_health(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_mcp_call_gateway_error(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/call", json={"name": "test.tool", "arguments": {}})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "error" in data


def test_observer_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/observer")
    assert resp.status_code == 200
    assert resp.get_json() == {}


def test_api_config_get(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"difficulty": "medium", "show_tokens": False}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "medium"


def test_api_config_get_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "medium"


def test_api_config_put(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"difficulty": "hard", "show_tokens": False}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "put", return_value=mock_resp):
        resp = client.put("/api/config", json={"difficulty": "hard"})
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "hard"


def test_api_config_put_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "put", side_effect=httpx.ConnectError("refused")):
        resp = client.put("/api/config", json={"difficulty": "hard"})
    assert resp.status_code == 502


def test_api_reset(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"reset": True, "tool_lab": "reset", "shadow_lab": "reset"}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.post("/api/reset")
    assert resp.status_code == 200
    assert resp.get_json()["reset"] is True


def test_api_reset_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/reset")
    assert resp.status_code == 502
