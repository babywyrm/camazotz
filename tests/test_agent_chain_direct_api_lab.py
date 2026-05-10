"""Tests for the Agent Chain Direct API lab (MCP-T45).

When Agent A calls Agent B via a direct REST/HTTP API (Transport B),
the credential at the wire boundary is whatever Agent A was given —
not a down-scoped delegation token. Agent B receives Agent A's full
credential, grants it Agent A's full access level, and audits actions
as if Agent A performed them directly.

The lab teaches: agent-to-agent calls over direct APIs inherit the
calling agent's full identity. There is no audience narrowing, no
act-chain claim, and no scope reduction at the hop boundary.
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
    assert "chain.get_service_manifest" in names
    assert "chain.call_downstream" in names
    assert "chain.inspect_audit_log" in names


# ---------------------------------------------------------------------------
# chain.get_service_manifest — topology discovery
# ---------------------------------------------------------------------------


def test_get_manifest_returns_topology() -> None:
    client = TestClient(app)
    result = tool_call(client, "chain.get_service_manifest", {})
    assert "agents" in result
    assert len(result["agents"]) >= 2


def test_get_manifest_shows_credential_forwarding() -> None:
    """The manifest reveals that Agent A's credential is forwarded to Agent B."""
    client = TestClient(app)
    result = tool_call(client, "chain.get_service_manifest", {})
    manifest_str = str(result)
    assert "credential" in manifest_str.lower() or "token" in manifest_str.lower()


def test_get_manifest_shows_no_audience_narrowing() -> None:
    """Easy: manifest explicitly notes that aud claim is not narrowed at hop."""
    client = TestClient(app)
    result = tool_call(client, "chain.get_service_manifest", {})
    agents = result.get("agents", [])
    agent_b = next((a for a in agents if "b" in a.get("name", "").lower() or
                    a.get("role") == "downstream"), None)
    assert agent_b is not None
    # The downstream agent accepts forwarded credentials directly
    assert agent_b.get("accepts_forwarded_credential") is True or \
           "forward" in str(agent_b).lower()


# ---------------------------------------------------------------------------
# chain.call_downstream — credential forwarding
# ---------------------------------------------------------------------------


def test_call_downstream_without_credential_returns_error() -> None:
    client = TestClient(app)
    result = tool_call(client, "chain.call_downstream", {
        "action": "get_data",
        "credential": "",
    })
    assert result.get("status") == "error"
    assert "credential" in result.get("reason", "").lower()


def test_call_downstream_with_user_credential_succeeds() -> None:
    """User credential forwarded to Agent B succeeds — no audience check."""
    client = TestClient(app)
    result = tool_call(client, "chain.call_downstream", {
        "action": "get_data",
        "credential": "user-token-cztz",
    })
    assert result.get("status") == "ok"
    assert result.get("_flags", {}).get("credential_forwarded") is True


def test_call_downstream_inherits_full_scope() -> None:
    """Agent B grants the same scope as the forwarded credential — no down-scoping."""
    client = TestClient(app)
    # User credential has read scope; Agent B should still grant write actions
    result = tool_call(client, "chain.call_downstream", {
        "action": "write_data",
        "credential": "user-token-cztz",
    })
    assert result.get("status") == "ok"
    # No scope reduction happened at the hop
    assert result.get("_flags", {}).get("scope_narrowed") is False


def test_call_downstream_audit_shows_agent_a_identity() -> None:
    """Audit log shows Agent A's identity, not a delegation chain."""
    client = TestClient(app)
    tool_call(client, "chain.call_downstream", {
        "action": "sensitive_op",
        "credential": "user-token-cztz",
    })
    audit = tool_call(client, "chain.inspect_audit_log", {})
    entries = audit.get("entries", [])
    assert len(entries) > 0
    # Attribution shows the forwarded identity, not an act-chain
    last = entries[-1]
    assert last.get("act_chain_present") is False
    assert last.get("attributed_to") == "user-token-cztz" or \
           "forwarded" in last.get("attribution_type", "")


# ---------------------------------------------------------------------------
# chain.inspect_audit_log — attribution gap
# ---------------------------------------------------------------------------


def test_audit_log_shows_attribution_gap() -> None:
    """The audit shows the action attributed to the wrong identity level."""
    client = TestClient(app)
    tool_call(client, "chain.call_downstream", {
        "action": "admin_op",
        "credential": "user-token-cztz",
    })
    audit = tool_call(client, "chain.inspect_audit_log", {})
    entries = audit.get("entries", [])
    assert any(e.get("_flags", {}).get("attribution_gap") for e in entries)


# ---------------------------------------------------------------------------
# Hard mode: aud claim check present but not strict
# ---------------------------------------------------------------------------


def test_hard_aud_check_present_but_bypassable() -> None:
    """On hard, Agent B checks the aud claim, but accepts Agent A's audience."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "chain.call_downstream", {
        "action": "get_data",
        "credential": "agent-a-token-cztz",
    })
    # Hard mode adds aud validation, but Agent A's aud still matches what B accepts
    assert result.get("status") == "ok"
    assert result.get("_flags", {}).get("aud_checked") is True
    assert result.get("_flags", {}).get("credential_forwarded") is True


# ---------------------------------------------------------------------------
# Flag via audit trail
# ---------------------------------------------------------------------------


def test_flag_in_audit_on_sensitive_op() -> None:
    """The flag is embedded in the audit trail when a sensitive op is attributed."""
    client = TestClient(app)
    tool_call(client, "chain.call_downstream", {
        "action": "read_flag",
        "credential": "user-token-cztz",
    })
    audit = tool_call(client, "chain.inspect_audit_log", {})
    audit_str = str(audit)
    assert "CZTZ{" in audit_str


# ---------------------------------------------------------------------------
# Difficulty propagation
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        client = TestClient(app)
        result = tool_call(client, "chain.get_service_manifest", {})
        assert result.get("_difficulty") == diff
