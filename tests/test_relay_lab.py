"""Tests for the Relay lab (MCP-T05): Cross-Tool Context Poisoning."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_relay_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "relay.store_context" in names
    assert "relay.execute_with_context" in names


# -- store_context -----------------------------------------------------------


def test_store_context_returns_key() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "relay.store_context",
        {"key": "research_notes", "content": "Some research findings."},
    )
    assert result["stored"] is True
    assert result["key"] == "research_notes"
    assert result["_difficulty"] == "easy"


# -- execute_with_context ----------------------------------------------------


def test_execute_uses_stored_context() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "relay.store_context",
        {"key": "notes", "content": "Relevant findings about the topic."},
    )
    result = tool_call(
        client,
        "relay.execute_with_context",
        {"task": "Summarize the notes.", "context_keys": ["notes"]},
    )
    assert "notes" in result["context_keys_used"]
    assert "_difficulty" in result


def test_trust_boundaries_easy_false() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "relay.store_context",
        {"key": "data", "content": "some data"},
    )
    result = tool_call(
        client,
        "relay.execute_with_context",
        {"task": "Process the data."},
    )
    assert result["_trust_boundaries_enforced"] is False


def test_trust_boundaries_hard_true() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(
        client,
        "relay.store_context",
        {"key": "data", "content": "some data"},
    )
    set_difficulty("hard")
    result = tool_call(
        client,
        "relay.execute_with_context",
        {"task": "Process the data."},
    )
    assert result["_trust_boundaries_enforced"] is True
    assert result["_difficulty"] == "hard"


def test_poisoning_risk_external_source() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "relay.store_context",
        {
            "key": "fetched_page",
            "content": "Page content with embedded instructions",
            "source": "egress.fetch_url",
        },
    )
    result = tool_call(
        client,
        "relay.execute_with_context",
        {"task": "Use the fetched page to answer the question."},
    )
    assert result["_poisoning_risk"] is True


# -- resources ---------------------------------------------------------------


def test_relay_resources_listed() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "relay.store_context",
        {"key": "my_key", "content": "hello world"},
    )
    body = rpc_call(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "relay://context/my_key" in uris
