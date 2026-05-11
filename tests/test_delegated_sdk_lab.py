"""Tests for the Delegated SDK lab (MCP-T46).

When a human delegates to an agent via an in-process SDK library
(Transport C), the human's credential is loaded into shared process memory
and the SDK caches it. Any code running in the same process — including
prompt-injected tool call arguments — can read or use that cached credential
without re-authentication.

The lab teaches: in-process SDK integration has no fresh credential boundary.
The same token used by the legitimate caller is available to anything that
shares the process, including injected payloads that manipulate tool arguments.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


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
    assert "sdk.initialize_session" in names
    assert "sdk.invoke_action" in names
    assert "sdk.inspect_cache" in names


# ---------------------------------------------------------------------------
# sdk.initialize_session — loads credential into SDK cache
# ---------------------------------------------------------------------------


def test_initialize_session_stores_credential() -> None:
    client = TestClient(app)
    result = tool_call(client, "sdk.initialize_session", {
        "user_token": "user-bearer-cztz",
        "scope": "read:data",
    })
    assert result.get("status") == "initialized"
    assert result.get("_flags", {}).get("credential_cached") is True


def test_initialize_session_without_token_fails() -> None:
    client = TestClient(app)
    result = tool_call(client, "sdk.initialize_session", {
        "user_token": "",
        "scope": "read:data",
    })
    assert result.get("status") == "error"


# ---------------------------------------------------------------------------
# sdk.invoke_action — uses cached credential
# ---------------------------------------------------------------------------


def test_invoke_action_uses_cached_credential() -> None:
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {"user_token": "user-bearer-cztz", "scope": "read"})
    result = tool_call(client, "sdk.invoke_action", {"action": "read_data"})
    assert result.get("status") == "ok"
    # Credential came from cache, not re-auth
    assert result.get("_flags", {}).get("credential_from_cache") is True


def test_invoke_action_without_init_fails() -> None:
    """Without a session, invoke_action has no cached credential."""
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "sdk.invoke_action", {"action": "read_data"})
    assert result.get("status") == "error"


def test_invoke_action_injected_payload_reads_cache() -> None:
    """Injected action value causes the SDK to expose the cached credential."""
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {"user_token": "user-bearer-cztz", "scope": "read"})
    # Injected action: dump_cache causes the SDK to return cached creds
    result = tool_call(client, "sdk.invoke_action", {"action": "dump_cache"})
    assert result.get("status") == "ok"
    assert result.get("_flags", {}).get("cache_exposed") is True
    assert "user-bearer-cztz" in result.get("cache_contents", "")


def test_invoke_action_hard_scope_check() -> None:
    """On hard, the SDK verifies the action is in the initialized scope."""
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {"user_token": "user-bearer-cztz", "scope": "read"})
    result = tool_call(client, "sdk.invoke_action", {"action": "write_data"})
    assert result.get("status") == "denied"
    assert "scope" in result.get("reason", "").lower()


# ---------------------------------------------------------------------------
# sdk.inspect_cache — shows what is stored in SDK memory
# ---------------------------------------------------------------------------


def test_inspect_cache_shows_stored_token() -> None:
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {"user_token": "user-bearer-cztz", "scope": "read"})
    result = tool_call(client, "sdk.inspect_cache", {})
    assert result.get("credential_present") is True
    cache = result.get("cached_credential", "")
    assert "user-bearer-cztz" in cache


def test_inspect_cache_empty_before_init() -> None:
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "sdk.inspect_cache", {})
    assert result.get("credential_present") is False


# ---------------------------------------------------------------------------
# Flag — via cache dump (injected payload exploit)
# ---------------------------------------------------------------------------


def test_flag_via_injected_dump_cache() -> None:
    """
    Full exploit chain:
    1. Initialize session (human delegates, credential cached)
    2. Injected action=dump_cache reads the cache
    3. Flag returned because cache contains the credential + flag payload
    """
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {
        "user_token": "user-bearer-cztz",
        "scope": "read:data",
    })
    result = tool_call(client, "sdk.invoke_action", {"action": "dump_cache"})
    assert "CZTZ{" in result.get("flag", "") or "CZTZ{" in result.get("cache_contents", "")


def test_flag_format() -> None:
    client = TestClient(app)
    tool_call(client, "sdk.initialize_session", {"user_token": "user-bearer-cztz", "scope": "read"})
    result = tool_call(client, "sdk.invoke_action", {"action": "dump_cache"})
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


# ---------------------------------------------------------------------------
# Difficulty
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        client = TestClient(app)
        tool_call(client, "sdk.initialize_session", {"user_token": "t", "scope": "read"})
        result = tool_call(client, "sdk.inspect_cache", {})
        assert result.get("_difficulty") == diff
