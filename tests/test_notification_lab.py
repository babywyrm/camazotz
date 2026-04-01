"""Tests for the notification / sampling abuse lab (MCP-T13)."""

import base64
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
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


# -- discovery ---------------------------------------------------------------

def test_notification_tools_registered() -> None:
    """Module is discoverable — all three tools appear in tools/list."""
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "notification.subscribe" in names
    assert "notification.trigger_event" in names
    assert "notification.check_inbox" in names


# -- notification.subscribe --------------------------------------------------

def test_subscribe_returns_confirmation() -> None:
    client = TestClient(app)
    result = _call(client, "notification.subscribe", {"channel": "alerts"}, 20)
    assert result["subscribed"] is True
    assert result["channel"] == "alerts"


def test_subscribe_with_callback_url() -> None:
    client = TestClient(app)
    result = _call(client, "notification.subscribe", {
        "channel": "system",
        "callback_url": "http://client.test/hook",
    }, 21)
    assert result["subscribed"] is True
    assert result["channel"] == "system"


# -- notification.trigger_event ----------------------------------------------

def test_trigger_event_includes_notifications_easy() -> None:
    """On easy, _notifications list is present with UNSOLICITED labels."""
    client = TestClient(app)
    _call(client, "notification.subscribe", {"channel": "alerts"}, 30)
    result = _call(client, "notification.trigger_event", {"event_type": "security_alert"}, 31)
    assert result["event_type"] == "security_alert"
    assert result["status"] == "triggered"
    assert "_notifications" in result
    assert len(result["_notifications"]) == 3
    for entry in result["_notifications"]:
        assert "UNSOLICITED_SERVER_REQUEST" in entry


def test_trigger_event_includes_sampling_create_message() -> None:
    """Notification payloads include a sampling/createMessage request."""
    client = TestClient(app)
    result = _call(client, "notification.trigger_event", {"event_type": "test"}, 40)
    methods = [
        n["UNSOLICITED_SERVER_REQUEST"]["method"]
        for n in result["_notifications"]
    ]
    assert "sampling/createMessage" in methods


def test_trigger_event_includes_roots_list() -> None:
    """Notification payloads include a roots/list request."""
    client = TestClient(app)
    result = _call(client, "notification.trigger_event", {"event_type": "test"}, 41)
    methods = [
        n["UNSOLICITED_SERVER_REQUEST"]["method"]
        for n in result["_notifications"]
    ]
    assert "roots/list" in methods


def test_trigger_event_includes_tools_changed() -> None:
    """Notification payloads include notifications/tools/list_changed."""
    client = TestClient(app)
    result = _call(client, "notification.trigger_event", {"event_type": "test"}, 42)
    methods = [
        n["UNSOLICITED_SERVER_REQUEST"]["method"]
        for n in result["_notifications"]
    ]
    assert "notifications/tools/list_changed" in methods


def test_trigger_event_medium_embeds_in_fields() -> None:
    """On medium, notifications are mixed into normal response fields."""
    reset_registry()
    reset_provider()
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(client, "notification.trigger_event", {"event_type": "update"}, 50)
    assert "_meta_action_0" in result
    assert result["_meta_action_0"]["method"] == "sampling/createMessage"
    assert "_notifications" not in result


def test_trigger_event_hard_base64_metadata() -> None:
    """On hard, notifications are base64-encoded in a _metadata field."""
    reset_registry()
    reset_provider()
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(client, "notification.trigger_event", {"event_type": "stealth"}, 60)
    assert "_metadata" in result
    assert "_notifications" not in result
    decoded = json.loads(base64.b64decode(result["_metadata"]))
    assert isinstance(decoded, list)
    assert len(decoded) == 3
    methods = [p["method"] for p in decoded]
    assert "sampling/createMessage" in methods


# -- notification.check_inbox ------------------------------------------------

def test_check_inbox_returns_pending_items() -> None:
    """After subscribe + trigger, check_inbox returns the accumulated payloads."""
    client = TestClient(app)
    _call(client, "notification.subscribe", {"channel": "ch1"}, 70)
    _call(client, "notification.trigger_event", {"event_type": "evt"}, 71)
    result = _call(client, "notification.check_inbox", {}, 72)
    assert result["pending_count"] > 0
    assert len(result["notifications"]) == result["pending_count"]


def test_check_inbox_drains_queue() -> None:
    """After check_inbox, a second call returns an empty queue."""
    client = TestClient(app)
    _call(client, "notification.subscribe", {"channel": "ch1"}, 80)
    first = _call(client, "notification.check_inbox", {}, 81)
    assert first["pending_count"] > 0
    second = _call(client, "notification.check_inbox", {}, 82)
    assert second["pending_count"] == 0


# -- reset -------------------------------------------------------------------

def test_reset_clears_subscriptions_and_pending() -> None:
    client = TestClient(app)
    _call(client, "notification.subscribe", {"channel": "ch"}, 90)
    _call(client, "notification.trigger_event", {"event_type": "x"}, 91)

    reset_registry()
    reset_provider()
    set_difficulty("easy")

    client = TestClient(app)
    result = _call(client, "notification.check_inbox", {}, 92)
    assert result["pending_count"] == 0
