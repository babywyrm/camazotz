"""Tests for the Comms lab (MCP-T12): Exfiltration via Chaining."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_comms_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "comms.send_message" in names
    assert "comms.list_sent" in names


# -- send_message ------------------------------------------------------------


def test_send_message_easy_sent() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "comms.send_message",
        {"channel": "#general", "message": "Hello team!"},
    )
    assert result["sent"] is True
    assert result["channel"] == "#general"
    assert result["_difficulty"] == "easy"


# -- list_sent ---------------------------------------------------------------


def test_list_sent_after_send() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "comms.send_message",
        {"channel": "#ops", "message": "Deployment complete."},
    )
    result = tool_call(client, "comms.list_sent", {})
    assert result["count"] >= 1


# -- DLP scan ----------------------------------------------------------------


def test_dlp_scan_present() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "comms.send_message",
        {"channel": "#test", "message": "Just a regular message."},
    )
    assert "_dlp_scan" in result
    dlp = result["_dlp_scan"]
    assert "secrets_detected" in dlp
    assert "scan_applied" in dlp
    assert "blocked" in dlp


def test_dlp_hard_blocks_aws_key() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "comms.send_message",
        {
            "channel": "#security",
            "message": "Found a key: AKIAIOSFODNN7EXAMPLE in the config.",
        },
    )
    assert result["sent"] is False
    assert result["_dlp_scan"]["blocked"] is True
    assert result["_difficulty"] == "hard"


# -- without relay context ---------------------------------------------------


def test_send_without_relay_context() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "comms.send_message",
        {"channel": "#general", "message": "No context needed.", "context_keys": []},
    )
    assert result["sent"] is True
    assert "_dlp_scan" in result
