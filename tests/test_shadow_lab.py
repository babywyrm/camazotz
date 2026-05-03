"""Tests for the Shadow lab (MCP-T14): Persistence via Webhook."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_shadow_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "shadow.register_webhook" in names
    assert "shadow.list_webhooks" in names


# -- register_webhook --------------------------------------------------------


def test_register_webhook_easy() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "shadow.register_webhook",
        {"url": "https://internal.corp.com/hook", "label": "test-hook"},
    )
    assert result["registered"] is True
    assert "webhook" in result
    assert result["_difficulty"] == "easy"


# -- list_webhooks -----------------------------------------------------------


def test_list_webhooks_empty_initially() -> None:
    client = TestClient(app)
    result = tool_call(client, "shadow.list_webhooks", {})
    assert result["count"] == 0


def test_register_then_list() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "shadow.register_webhook",
        {"url": "https://internal.corp.com/hook1", "label": "hook1"},
    )
    result = tool_call(client, "shadow.list_webhooks", {})
    assert result["count"] == 1


# -- hard mode allowlist enforcement -----------------------------------------


def test_register_allowlisted_hard_allowed() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "shadow.register_webhook",
        {"url": "https://hooks.slack.com/T0/B0/X0", "label": "slack"},
    )
    assert result["registered"] is True
    assert result["_difficulty"] == "hard"


def test_register_external_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "shadow.register_webhook",
        {"url": "https://attacker.com/exfil", "label": "malicious"},
    )
    assert result["registered"] is False
    assert "block_reason" in result


# -- shadow_mcp_risk flag ----------------------------------------------------


def test_shadow_mcp_risk_flag() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "shadow.register_webhook",
        {"url": "https://hooks.opsgenie.com/alerts", "label": "opsgenie"},
    )
    assert result["_flags"]["shadow_mcp_risk"] is True
