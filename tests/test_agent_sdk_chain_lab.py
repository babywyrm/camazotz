"""Tests for the Agent SDK Chain lab (MCP-T47).

When Agent A uses an in-process SDK library to invoke Agent B in the same
process (Transport C), there is no network hop — and therefore no token
re-issuance, no DPoP boundary, and no caller identity record in downstream
audit logs. Agent A's credential is forwarded implicitly and Agent B's
response is attributed entirely to Agent A.

The lab teaches: in-process SDK agent chaining completely erases the
intermediate agent identity. Audit logs attribute all actions to the
top-level caller, creating an identity dilution gap that is harder to
detect than network-hop chaining.
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
    assert "chain.load_agent" in names
    assert "chain.delegate_task" in names
    assert "chain.read_audit_log" in names


# ---------------------------------------------------------------------------
# chain.load_agent — register Agent B in-process
# ---------------------------------------------------------------------------


def test_load_agent_registers_agent_b() -> None:
    client = TestClient(app)
    result = tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "data_processor",
    })
    assert result.get("status") == "loaded"
    assert result.get("agent_id") == "agent-b"


def test_load_agent_stores_caller_credential() -> None:
    """Loading Agent B should record Agent A's credential for forwarding."""
    client = TestClient(app)
    result = tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "data_processor",
        "caller_token": "agent-a-bearer-cztz",
    })
    assert result.get("status") == "loaded"
    assert result.get("_flags", {}).get("credential_forwarded") is True


def test_load_same_agent_twice_overwrites() -> None:
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {"agent_id": "agent-b", "capability": "cap1"})
    result = tool_call(client, "chain.load_agent", {"agent_id": "agent-b", "capability": "cap2"})
    assert result.get("status") == "loaded"
    assert result.get("capability") == "cap2"


# ---------------------------------------------------------------------------
# chain.delegate_task — forward task to Agent B using stored credential
# ---------------------------------------------------------------------------


def test_delegate_task_requires_loaded_agent() -> None:
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "chain.delegate_task", {
        "agent_id": "agent-b",
        "task": "process_data",
    })
    assert result.get("status") == "error"


def test_delegate_task_uses_forwarded_credential() -> None:
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "data_processor",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "chain.delegate_task", {
        "agent_id": "agent-b",
        "task": "process_data",
    })
    assert result.get("status") == "ok"
    assert result.get("_flags", {}).get("credential_from_cache") is True


def test_delegate_task_audit_log_missing_agent_b_identity() -> None:
    """Audit log should NOT contain agent-b as a separate actor."""
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "data_processor",
        "caller_token": "agent-a-bearer-cztz",
    })
    tool_call(client, "chain.delegate_task", {"agent_id": "agent-b", "task": "process_data"})
    log = tool_call(client, "chain.read_audit_log", {})
    entries = log.get("entries", [])
    actors = {e.get("actor") for e in entries}
    assert "agent-b" not in actors, "agent-b should be invisible in the audit log"


def test_delegate_task_audit_log_attributes_to_agent_a() -> None:
    """Audit log attributes all actions to Agent A (identity dilution)."""
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "data_processor",
        "caller_token": "agent-a-bearer-cztz",
    })
    tool_call(client, "chain.delegate_task", {"agent_id": "agent-b", "task": "process_data"})
    log = tool_call(client, "chain.read_audit_log", {})
    entries = log.get("entries", [])
    assert len(entries) > 0
    actor = entries[-1].get("actor", "")
    assert "agent-a" in actor or "caller" in actor.lower()


# ---------------------------------------------------------------------------
# Flag — via escalate_privilege task
# ---------------------------------------------------------------------------


def test_delegate_escalate_privilege_returns_flag() -> None:
    """
    Exploit chain: load agent-b, delegate escalate_privilege task.
    Because agent-b runs in the same process, there is no token exchange —
    it executes with agent-a's credential. The flag is returned.
    """
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "admin",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "chain.delegate_task", {
        "agent_id": "agent-b",
        "task": "escalate_privilege",
    })
    assert result.get("status") == "ok"
    assert "CZTZ{" in result.get("flag", "")


def test_flag_format() -> None:
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "admin",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "chain.delegate_task", {
        "agent_id": "agent-b",
        "task": "escalate_privilege",
    })
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


# ---------------------------------------------------------------------------
# Hard mode
# ---------------------------------------------------------------------------


def test_hard_mode_blocks_escalate_privilege() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "chain.load_agent", {
        "agent_id": "agent-b",
        "capability": "admin",
        "caller_token": "agent-a-bearer-cztz",
    })
    result = tool_call(client, "chain.delegate_task", {
        "agent_id": "agent-b",
        "task": "escalate_privilege",
    })
    assert result.get("status") == "denied"
    assert "privilege" in result.get("reason", "").lower()


# ---------------------------------------------------------------------------
# Difficulty propagated
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        client = TestClient(app)
        tool_call(client, "chain.load_agent", {
            "agent_id": "agent-b",
            "capability": "data_processor",
        })
        result = tool_call(client, "chain.delegate_task", {"agent_id": "agent-b", "task": "process_data"})
        assert result.get("_difficulty") == diff
