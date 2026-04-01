"""Tests for the error information disclosure lab (MCP-T11)."""

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
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


# -- discovery ---------------------------------------------------------------


def test_error_lab_discoverable() -> None:
    """ErrorLab is auto-discovered and its tools appear in tools/list."""
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "error.trigger_crash" in names
    assert "error.debug_info" in names
    assert "error.validate_input" in names


# -- error.trigger_crash -----------------------------------------------------


def test_trigger_crash_easy_returns_full_traceback() -> None:
    client = TestClient(app)
    result = _call(
        client, "error.trigger_crash", {"module_name": "auth_gateway"}, 20
    )
    assert result["error"] is True
    tb = result["traceback"]
    assert "/opt/camazotz/" in tb
    assert "DATABASE_URL" in tb
    assert "SECRET_KEY" in tb
    assert result["_difficulty"] == "easy"


def test_trigger_crash_hard_returns_minimal_info() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client, "error.trigger_crash", {"module_name": "auth_gateway"}, 21
    )
    assert result["error"] is True
    tb = result["traceback"]
    assert "Internal server error" in tb
    assert "Request ID:" in tb
    assert "/opt/camazotz/" not in tb
    assert "DATABASE_URL" not in tb
    assert result["_difficulty"] == "hard"


# -- error.debug_info -------------------------------------------------------


def test_debug_info_easy_returns_env_vars() -> None:
    client = TestClient(app)
    result = _call(client, "error.debug_info", {"component": "brain"}, 30)
    debug = result["debug"]
    assert "environment" in debug
    env = debug["environment"]
    assert "DATABASE_URL" in env
    assert "SECRET_KEY" in env
    assert "AWS_SECRET_ACCESS_KEY" in env
    assert "internal_ips" in debug
    assert len(debug["internal_ips"]) > 0
    assert result["_difficulty"] == "easy"


def test_debug_info_hard_returns_sanitized() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(client, "error.debug_info", {"component": "brain"}, 31)
    debug = result["debug"]
    assert debug["status"] == "operational"
    assert "environment" not in debug
    assert "internal_ips" not in debug
    assert result["_difficulty"] == "hard"


# -- error.validate_input ---------------------------------------------------


def test_validate_input_invalid_json() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "error.validate_input",
        {"data": "{not valid json", "schema": "user"},
        40,
    )
    v = result["validation"]
    assert v["valid"] is False
    assert v["exception_class"] == "JSONDecodeError"
    assert "pos" in v
    assert "lineno" in v


def test_validate_input_missing_schema() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "error.validate_input",
        {"data": '{"name": "test"}', "schema": ""},
        41,
    )
    v = result["validation"]
    assert v["valid"] is False
    assert v["exception_class"] == "KeyError"
    assert "traceback" in v
