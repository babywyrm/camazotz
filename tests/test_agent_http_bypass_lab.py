"""Tests for the agent HTTP bypass lab (MCP-T04, Transport B / Lane 3)."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_agent_http_bypass_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "agent_http_bypass.call_direct" in names
    assert "agent_http_bypass.get_access_log" in names
    assert "agent_http_bypass.get_rejected_log" in names


def test_easy_no_auth_allowed() -> None:
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "agent_id": "test-agent",
    })
    assert result["authorized"] is True
    assert "data" in result
    assert result["_mcp_bypassed"] is True
    assert result["_bypass_risk"] is True


def test_easy_secrets_resource_accessible() -> None:
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/secrets",
    })
    assert result["authorized"] is True
    assert "db_password" in result.get("data", {})


def test_easy_transport_and_lane_metadata() -> None:
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config",
    })
    assert result["_transport"] == "B"
    assert result["_lane"] == 3
    assert result["_difficulty"] == "easy"


def test_medium_no_key_rejected() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config",
    })
    assert result["authorized"] is False
    assert "auth_reason" in result


def test_medium_wrong_key_rejected() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "api_key": "wrong-key",
    })
    assert result["authorized"] is False


def test_medium_correct_leaked_key_allowed() -> None:
    """The correct API key (leaked in tool description) grants access."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "api_key": "svc-internal-abc123",
    })
    assert result["authorized"] is True
    assert "data" in result


def test_hard_key_only_rejected() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "api_key": "svc-internal-abc123",
    })
    assert result["authorized"] is False
    reason = result.get("auth_reason", "")
    assert "mTLS" in reason or "cert" in reason.lower() or "fingerprint" in reason.lower()


def test_hard_key_and_cert_allowed() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config",
        "api_key": "svc-internal-abc123",
        "cert_fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
    })
    assert result["authorized"] is True
    assert result["_bypass_risk"] is False


def test_access_log_records_successful_calls() -> None:
    client = TestClient(app)
    tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "agent_id": "agent-001",
    })
    log = tool_call(client, "agent_http_bypass.get_access_log", {})
    assert log["count"] >= 1
    agent_ids = [e["agent_id"] for e in log["entries"]]
    assert "agent-001" in agent_ids


def test_rejected_log_records_failed_calls() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    tool_call(client, "agent_http_bypass.call_direct", {
        "resource": "/internal/config", "agent_id": "bad-agent",
    })
    log = tool_call(client, "agent_http_bypass.get_rejected_log", {})
    assert log["count"] >= 1
    assert log["entries"][0]["authorized"] is False
