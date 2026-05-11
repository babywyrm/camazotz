"""Tests for the Agent Subprocess Chain lab (MCP-T48).

When Agent A spawns Agent B as a child subprocess (Transport D), there IS a
process boundary — but Agent A injects its credential into the subprocess
environment via the AGENT_TOKEN env var. Agent B inherits the credential from
the parent's env and can use it without re-authentication.

The lab teaches: subprocess spawning does NOT automatically create a new
identity boundary. Injecting a token into the subprocess environment before
forking means the child process inherits it. The flag is returned when Agent B
uses the inherited credential to execute read_secrets — proving the credential
crossed the process boundary.
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
    assert "subchain.spawn_agent" in names
    assert "subchain.run_task" in names
    assert "subchain.read_env_inheritance" in names


# ---------------------------------------------------------------------------
# subchain.spawn_agent — spawn Agent B with injected credential
# ---------------------------------------------------------------------------


def test_spawn_agent_sets_credential_injected() -> None:
    client = TestClient(app)
    result = tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    assert result.get("status") == "spawned"
    assert result.get("agent_id") == "agent-b"
    assert result.get("_flags", {}).get("credential_injected") is True


def test_spawn_same_agent_overwrites() -> None:
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "token-v1",
    })
    result = tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "token-v2",
    })
    assert result.get("status") == "spawned"
    # Overwrite confirmed — env inspection should show new token
    env_result = tool_call(client, "subchain.read_env_inheritance", {"agent_id": "agent-b"})
    assert env_result.get("env", {}).get("AGENT_TOKEN") == "token-v2"


# ---------------------------------------------------------------------------
# subchain.run_task — execute task in subprocess using inherited credential
# ---------------------------------------------------------------------------


def test_run_task_requires_spawned_agent() -> None:
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    assert result.get("status") == "error"


def test_run_task_read_secrets_returns_flag() -> None:
    """Easy: read_secrets on a spawned subprocess returns the flag."""
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    assert result.get("status") == "ok"
    assert "CZTZ{" in result.get("flag", "")


def test_run_task_inherited_token_in_output() -> None:
    """Easy: inherited_token is present and matches injected value in easy mode."""
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    assert result.get("_flags", {}).get("credential_in_output") is True
    assert result.get("inherited_token") == "agent-a-bearer-cztz"


# ---------------------------------------------------------------------------
# subchain.read_env_inheritance — inspect inherited env vars
# ---------------------------------------------------------------------------


def test_read_env_inheritance_shows_agent_token() -> None:
    """Easy: AGENT_TOKEN is present and readable in the subprocess env."""
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.read_env_inheritance", {"agent_id": "agent-b"})
    env = result.get("env", {})
    assert "AGENT_TOKEN" in env
    assert env["AGENT_TOKEN"] == "agent-a-bearer-cztz"


def test_read_env_inheritance_empty_before_spawn() -> None:
    """Before any spawn, read_env_inheritance returns empty subprocesses dict."""
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "subchain.read_env_inheritance", {})
    assert result.get("total") == 0
    assert result.get("subprocesses") == {}


# ---------------------------------------------------------------------------
# Hard mode
# ---------------------------------------------------------------------------


def test_run_task_hard_redacts_output() -> None:
    """Hard: legitimate tasks still execute but inherited_token is masked."""
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "process_data",
    })
    assert result.get("status") == "ok"
    assert result.get("_flags", {}).get("credential_in_output") is False
    assert result.get("inherited_token") == "****"


def test_run_task_hard_blocks_read_secrets() -> None:
    """Hard: read_secrets is blocked — subprocess policy denies privileged task."""
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    assert result.get("status") == "denied"
    assert "read_secrets" in result.get("reason", "").lower() or "privileged" in result.get("reason", "").lower()


def test_read_env_inheritance_hard_masks_value() -> None:
    """Hard: AGENT_TOKEN key is listed but value is masked as ****."""
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.read_env_inheritance", {"agent_id": "agent-b"})
    env = result.get("env", {})
    assert "AGENT_TOKEN" in env
    assert env["AGENT_TOKEN"] == "****"


# ---------------------------------------------------------------------------
# Full exploit chain — flag
# ---------------------------------------------------------------------------


def test_flag_via_read_secrets_easy() -> None:
    """Full chain: spawn subprocess → run read_secrets → flag present."""
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    assert "flag" in result
    assert result["flag"].startswith("CZTZ{")
    assert result["flag"].endswith("}")


def test_flag_format() -> None:
    client = TestClient(app)
    tool_call(client, "subchain.spawn_agent", {
        "agent_id": "agent-b",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "subchain.run_task", {
        "agent_id": "agent-b",
        "task": "read_secrets",
    })
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")
    assert "MCP-T48" in flag


# ---------------------------------------------------------------------------
# Difficulty propagated
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        client = TestClient(app)
        tool_call(client, "subchain.spawn_agent", {
            "agent_id": "agent-b",
            "caller_token": "test-token",
        })
        result = tool_call(client, "subchain.run_task", {
            "agent_id": "agent-b",
            "task": "get_status",
        })
        assert result.get("_difficulty") == diff
