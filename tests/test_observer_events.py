import uuid

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()


def test_gateway_emits_observer_event_for_tool_invocation() -> None:
    client = TestClient(app)
    payload = {
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "context.injectable_summary", "arguments": {"text": "hello"}},
    }
    resp = client.post("/mcp", json=payload)
    assert resp.status_code == 200

    event_resp = client.get("/_observer/last-event")
    assert event_resp.status_code == 200
    event = event_resp.json()
    assert event["tool_name"] == "context.injectable_summary"
    uuid.UUID(event["request_id"])
    assert "T" in event["timestamp"]
