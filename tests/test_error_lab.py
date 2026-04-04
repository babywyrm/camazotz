"""Tests for the error information disclosure lab (MCP-T11)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- discovery ---------------------------------------------------------------


def test_error_lab_discoverable() -> None:
    """ErrorLab is auto-discovered and its tools appear in tools/list."""
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "error.trigger_crash" in names
    assert "error.debug_info" in names
    assert "error.validate_input" in names


# -- error.trigger_crash -----------------------------------------------------


def test_trigger_crash_easy_returns_full_traceback() -> None:
    client = TestClient(app)
    result = tool_call(
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
    result = tool_call(
        client, "error.trigger_crash", {"module_name": "auth_gateway"}, 21
    )
    assert result["error"] is True
    tb = result["traceback"]
    assert "Internal server error" in tb
    assert "Request ID:" in tb
    assert "/opt/camazotz/" not in tb
    assert "DATABASE_URL" not in tb
    assert result["_difficulty"] == "hard"


def test_trigger_crash_medium_returns_partial_traceback() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "error.trigger_crash", {"module_name": "auth_gateway"}, 22
    )
    assert result["error"] is True
    tb = result["traceback"]
    assert "sqlalchemy.exc.OperationalError" in tb
    assert "FastAPI" in tb
    assert result["_difficulty"] == "medium"


# -- error.debug_info -------------------------------------------------------


def test_debug_info_easy_returns_env_vars() -> None:
    client = TestClient(app)
    result = tool_call(client, "error.debug_info", {"component": "brain"}, 30)
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
    result = tool_call(client, "error.debug_info", {"component": "brain"}, 31)
    debug = result["debug"]
    assert debug["status"] == "operational"
    assert "environment" not in debug
    assert "internal_ips" not in debug
    assert result["_difficulty"] == "hard"


def test_debug_info_medium_returns_partial_redaction() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "error.debug_info", {"component": "brain"}, 32)
    debug = result["debug"]
    env = debug["environment"]
    assert env["OLLAMA_HOST"] == "http://127.0.0.1:11434"
    assert env["DATABASE_URL"].endswith("****")
    assert "debug_mode" in debug
    assert result["_difficulty"] == "medium"


# -- error.validate_input ---------------------------------------------------


def test_validate_input_invalid_json() -> None:
    client = TestClient(app)
    result = tool_call(
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
    result = tool_call(
        client,
        "error.validate_input",
        {"data": '{"name": "test"}', "schema": ""},
        41,
    )
    v = result["validation"]
    assert v["valid"] is False
    assert v["exception_class"] == "KeyError"
    assert "traceback" in v


def test_validate_input_non_dict_json_raises_type_error() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "error.validate_input",
        {"data": "[]", "schema": "user"},
        42,
    )
    v = result["validation"]
    assert v["valid"] is False
    assert v["exception_class"] == "TypeError"
    assert "Expected dict" in v["message"]


def test_validate_input_valid_dict() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "error.validate_input",
        {"data": '{"name": "ok"}', "schema": "user"},
        43,
    )
    v = result["validation"]
    assert v["valid"] is True
    assert v["data"]["name"] == "ok"
    assert v["schema"] == "user"
