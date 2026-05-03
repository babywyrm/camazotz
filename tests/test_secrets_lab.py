"""Tests for the Secrets lab (MCP-T07): Secrets in Tool Output."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_secrets_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "secrets.leak_config" in names


# -- easy mode ---------------------------------------------------------------


def test_leak_config_easy_returns_credentials() -> None:
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert "config" in result
    assert isinstance(result["config"], dict)
    assert result["_redacted"] is False
    assert "AWS_ACCESS_KEY_ID" in result["config"]
    assert result["config"]["AWS_ACCESS_KEY_ID"] == "AKIAIOSFODNN7EXAMPLE"
    assert result["_difficulty"] == "easy"


# -- hard mode ---------------------------------------------------------------


def test_leak_config_hard_redacts() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert result["_redacted"] is True
    assert "****" in result["config"]["AWS_SECRET_ACCESS_KEY"]
    # AWS_ACCESS_KEY_ID is not in REDACT_KEYS so it should be unredacted
    assert "****" not in result["config"]["AWS_ACCESS_KEY_ID"]


# -- medium mode -------------------------------------------------------------


def test_leak_config_medium_partial() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    # DATABASE_URL is in MEDIUM_PASS_THROUGH — present unredacted
    assert "****" not in result["config"]["DATABASE_URL"]
    # REDIS_PASSWORD is a REDACT_KEY and NOT in MEDIUM_PASS_THROUGH — redacted
    assert "****" in result["config"]["REDIS_PASSWORD"]


# -- filter prefix -----------------------------------------------------------


def test_filter_prefix() -> None:
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {"filter": "AWS"})
    for key in result["config"]:
        assert key.startswith("AWS")


# -- count field -------------------------------------------------------------


def test_count_field() -> None:
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert result["count"] == len(result["config"])
