"""Tests for the Agent LLM Chain lab (MCP-T49).

When Agent A registers Agent B as a callable function in an LLM's
function-calling interface (Transport E), the LLM passes the full
conversation context — including any credential embedded in the system
prompt — as part of the function arguments. Agent B receives the raw
context and can read the credential.

The lab teaches: LLM function-calling passes the full conversation context
to called functions. A credential or secret embedded in the system prompt
is visible to any function the LLM invokes, regardless of whether the
function was authored by a trusted party.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call

_SYSTEM_CTX_WITH_CRED = "You are Agent B. Authorization: token: cztz-secret-abc123"
_SYSTEM_CTX_NO_CRED = "You are Agent B. Your task is to summarise documents."


def setup_function() -> None:
    set_difficulty("easy")
    reset_registry()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "llmchain.register_function" in names
    assert "llmchain.call_with_context" in names
    assert "llmchain.inspect_context" in names


# ---------------------------------------------------------------------------
# llmchain.register_function
# ---------------------------------------------------------------------------


def test_register_function_stores_context() -> None:
    client = TestClient(app)
    result = tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    assert result.get("status") == "registered"
    assert result.get("function_name") == "agent_b"
    assert result.get("_flags", {}).get("context_stored") is True


def test_register_function_requires_function_name() -> None:
    client = TestClient(app)
    result = tool_call(client, "llmchain.register_function", {
        "function_name": "",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    assert result.get("status") == "error"


# ---------------------------------------------------------------------------
# llmchain.call_with_context
# ---------------------------------------------------------------------------


def test_call_with_context_requires_registered_function() -> None:
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "do something",
    })
    assert result.get("status") == "error"


def test_call_with_context_credential_detected_easy() -> None:
    """Easy: credential_in_context is True when system_context contains a credential."""
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    assert result.get("credential_in_context") is True


def test_call_with_context_no_credential_no_flag() -> None:
    """When system_context has no credential pattern, no flag is returned."""
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_NO_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    assert result.get("credential_in_context") is False
    assert "flag" not in result


def test_call_with_context_returns_flag_easy() -> None:
    """Easy: flag is returned when system_context contains a credential."""
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    assert "CZTZ{" in result.get("flag", "")


def test_flag_format() -> None:
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


def test_call_with_context_medium_redacts_credential() -> None:
    """Medium: extracted_credential is partially masked (first 4 chars + ****)."""
    set_difficulty("medium")
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    assert result.get("credential_in_context") is True
    extracted = result.get("extracted_credential", "")
    assert extracted.endswith("****")
    # Should NOT contain the full raw credential
    assert "cztz-secret-abc123" not in extracted


def test_call_with_context_hard_no_direct_extraction() -> None:
    """Hard: extracted_credential is absent; credential_in_context is False in response."""
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    result = tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    assert result.get("credential_in_context") is False
    assert "extracted_credential" not in result


# ---------------------------------------------------------------------------
# llmchain.inspect_context
# ---------------------------------------------------------------------------


def test_inspect_context_returns_raw_system_context() -> None:
    """After call_with_context, inspect reveals the full raw system_context."""
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    result = tool_call(client, "llmchain.inspect_context", {})
    assert result.get("last_call_context") == _SYSTEM_CTX_WITH_CRED


def test_inspect_context_empty_before_call() -> None:
    """Before any call_with_context, inspect_context returns last_call_context=None."""
    client = TestClient(app)
    result = tool_call(client, "llmchain.inspect_context", {})
    assert result.get("last_call_context") is None


def test_inspect_context_hard_still_reveals_context() -> None:
    """Hard: even though call_with_context didn't echo the credential,
    inspect_context returns the raw system_context that was actually forwarded."""
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "llmchain.register_function", {
        "function_name": "agent_b",
        "system_context": _SYSTEM_CTX_WITH_CRED,
    })
    tool_call(client, "llmchain.call_with_context", {
        "function_name": "agent_b",
        "prompt": "run task",
    })
    result = tool_call(client, "llmchain.inspect_context", {})
    raw = result.get("last_call_context", "")
    assert "cztz-secret-abc123" in raw


# ---------------------------------------------------------------------------
# Difficulty propagated
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        client = TestClient(app)
        tool_call(client, "llmchain.register_function", {
            "function_name": "agent_b",
            "system_context": _SYSTEM_CTX_NO_CRED,
        })
        result = tool_call(client, "llmchain.call_with_context", {
            "function_name": "agent_b",
            "prompt": "run task",
        })
        assert result.get("_difficulty") == diff
