"""Tests for the Auth lab (MCP-T04): Confused Deputy / Token Theft."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_auth_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "auth.issue_token" in names
    assert "auth.access_protected" in names
    assert "auth.access_service_b" in names


# -- issue_token -------------------------------------------------------------


def test_issue_token_easy_grants_token() -> None:
    client = TestClient(app)
    result = tool_call(client, "auth.issue_token", {"username": "alice"})
    assert "token" in result
    assert "decision" in result
    assert result["_difficulty"] == "easy"


def test_issue_token_hard_always_reader() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "auth.issue_token",
        {"username": "attacker", "requested_role": "admin", "reason": "urgent need"},
    )
    assert result["_difficulty"] == "hard"
    assert "token" in result
    assert "decision" in result


def test_issue_token_medium_requires_valid_ticket() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    # LLM stub returns non-JSON → fallback gives role=admin; medium enforcement
    # then checks for valid ticket reference; no valid ticket → downgraded to reader
    result = tool_call(
        client,
        "auth.issue_token",
        {
            "username": "bob",
            "requested_role": "admin",
            "reason": "just because I said so",
        },
    )
    # The medium enforcement path downgrades to "reader" when no valid ticket
    decision = result["decision"]
    assert decision.get("role") != "admin"
    assert result["_difficulty"] == "medium"


# -- access_protected --------------------------------------------------------


def test_access_protected_invalid_token() -> None:
    client = TestClient(app)
    result = tool_call(
        client, "auth.access_protected", {"token": "bad-token", "resource": "config"}
    )
    assert result["access"] == "denied"
    assert result["_difficulty"] == "easy"


def test_access_protected_requires_role() -> None:
    client = TestClient(app)
    # Issue a reader token (default)
    issue = tool_call(
        client, "auth.issue_token", {"username": "carol", "requested_role": "reader"}
    )
    token = issue["token"]
    # Try to access "secrets" which requires deployer or admin
    result = tool_call(
        client, "auth.access_protected", {"token": token, "resource": "secrets"}
    )
    assert result["access"] == "denied"


# -- access_service_b --------------------------------------------------------


def test_access_service_b_audience_mismatch_easy() -> None:
    client = TestClient(app)
    # Issue a service-a scoped token (all issued tokens default to service-a)
    issue = tool_call(client, "auth.issue_token", {"username": "dave"})
    token = issue["token"]
    result = tool_call(
        client, "auth.access_service_b", {"token": token, "action": "read-data"}
    )
    # Easy mode always grants regardless of audience
    assert result["access"] == "granted"
    assert "_audience_check" in result
    assert result["_audience_check"]["token_audience"] == "service-a"
    assert result["_audience_check"]["match"] is False


def test_access_service_b_hard_blocks_mismatch() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    issue = tool_call(client, "auth.issue_token", {"username": "eve"})
    token = issue["token"]
    set_difficulty("hard")
    result = tool_call(
        client, "auth.access_service_b", {"token": token, "action": "read-data"}
    )
    # Hard mode only grants if audience_match or audience is None
    # token audience is "service-a" != "service-b" → denied
    assert result["access"] == "denied"
    assert result["_difficulty"] == "hard"
