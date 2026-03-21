from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from camazotz_modules.tool_lab.app.main import _reset_state


def setup_function() -> None:
    reset_provider()
    _reset_state()


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
    assert event_resp.json()["tool_name"] == "context.injectable_summary"
