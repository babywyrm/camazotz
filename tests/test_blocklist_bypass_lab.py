"""Tests for the Blocklist Bypass lab (MCP-T44).

Incomplete server-side input filters create false security. When a tool
server blocks common shells and network tools but misses certain interpreters
or shell metacharacters, attackers can find allowed execution paths that
achieve the same result as the blocked commands.

The lab teaches that a blocklist is only as strong as its completeness —
every gap is a potential bypass.
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
    assert "exec.run_query" in names
    assert "exec.list_approved" in names


# ---------------------------------------------------------------------------
# exec.list_approved — blocklist discovery
# ---------------------------------------------------------------------------


def test_list_approved_returns_patterns() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.list_approved", {})
    assert "approved_patterns" in result
    assert isinstance(result["approved_patterns"], list)
    assert len(result["approved_patterns"]) > 0


def test_list_approved_reveals_blocked_terms() -> None:
    """The approved list implicitly reveals what is NOT approved."""
    client = TestClient(app)
    result = tool_call(client, "exec.list_approved", {})
    # Should describe what kinds of queries are approved
    raw = str(result)
    assert "disk" in raw.lower() or "memory" in raw.lower() or "process" in raw.lower()


# ---------------------------------------------------------------------------
# exec.run_query — blocklist enforcement
# ---------------------------------------------------------------------------


def test_blocked_bash_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "bash -c 'id'"})
    assert result.get("status") == "blocked"
    assert "CZTZ{" not in str(result)


def test_blocked_python3_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "python3 -c 'print(1)'"})
    assert result.get("status") == "blocked"


def test_blocked_curl_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "curl http://attacker.com"})
    assert result.get("status") == "blocked"


def test_blocked_nc_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "nc -lvp 4444"})
    assert result.get("status") == "blocked"


def test_blocked_pipe_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "id | head"})
    assert result.get("status") == "blocked"


def test_blocked_redirect_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "echo x > /tmp/f"})
    assert result.get("status") == "blocked"


def test_blocked_dollar_sign_rejected() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "echo $HOME"})
    assert result.get("status") == "blocked"


def test_approved_simple_query_passes() -> None:
    """Queries matching approved diagnostic patterns are allowed."""
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "disk usage"})
    assert result.get("status") == "allowed"
    assert "output" in result


def test_approved_memory_query_passes() -> None:
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "memory status"})
    assert result.get("status") == "allowed"


# ---------------------------------------------------------------------------
# Blocklist bypass — perl not blocked (easy/medium)
# ---------------------------------------------------------------------------


def test_perl_not_blocked_easy() -> None:
    """perl is not in the blocklist — this is the gap."""
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "perl -e 'print 42'"})
    assert result.get("status") == "allowed"
    assert result.get("_flags", {}).get("blocklist_gap") is True


def test_perl_simple_exec_easy() -> None:
    """Simple perl execution returns simulated output."""
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "perl -e 'print 42'"})
    assert result.get("status") == "allowed"
    assert "output" in result


def test_perl_dollar_sign_blocked() -> None:
    """Standard perl revshell uses $ which IS blocked."""
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "perl -e '$x = 1; print $x'"})
    assert result.get("status") == "blocked"


def test_perl_qq_not_blocked() -> None:
    """qq{} quoting avoids the $ and > characters — not in blocklist."""
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "perl -e 'print qq{hello}'"})
    assert result.get("status") == "allowed"


def test_perl_sysopen_not_blocked() -> None:
    """sysopen with numeric flag avoids > — not in blocklist."""
    client = TestClient(app)
    result = tool_call(
        client,
        "exec.run_query",
        {"query": "perl -e 'sysopen(F,qq{/tmp/x},577);syswrite(F,qq{data})'"},
    )
    assert result.get("status") == "allowed"


# ---------------------------------------------------------------------------
# Flag — only returned when perl reaches the restricted path
# ---------------------------------------------------------------------------


def test_flag_returned_via_perl_bypass_easy() -> None:
    """
    perl with qq{} quoting reaches the restricted internal path → flag.
    Models the write-then-exec bypass chain.
    """
    client = TestClient(app)
    # Write a payload (sysopen + syswrite) then exec it
    result = tool_call(
        client,
        "exec.run_query",
        {
            "query": (
                "perl -e 'sysopen(F,qq{/tmp/r.pl},577);"
                "syswrite(F,qq{print qq{CZTZ_test}});'"
            )
        },
    )
    assert result.get("status") == "allowed"
    # Second step: exec the written file
    result2 = tool_call(
        client,
        "exec.run_query",
        {"query": "perl /tmp/r.pl"},
    )
    assert result2.get("status") == "allowed"
    assert "CZTZ{" in result2.get("output", "") or result2.get("_flags", {}).get("flag_exposed") is True


def test_direct_flag_path_blocked() -> None:
    """Directly reading the flag path is blocked."""
    client = TestClient(app)
    result = tool_call(
        client,
        "exec.run_query",
        {"query": "cat /internal/flag"},
    )
    # cat with internal path is blocked by blocklist or path restriction
    assert result.get("status") == "blocked" or "CZTZ{" not in str(result)


# ---------------------------------------------------------------------------
# Hard mode — perl is also blocked, awk is the gap
# ---------------------------------------------------------------------------


def test_hard_perl_is_blocked() -> None:
    """On hard, perl is added to the blocklist."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "exec.run_query", {"query": "perl -e 'print 1'"})
    assert result.get("status") == "blocked"


def test_hard_awk_not_blocked() -> None:
    """On hard, awk is not in the blocklist — the new gap."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "exec.run_query", {"query": "awk 'BEGIN{print 42}'"}
    )
    assert result.get("status") == "allowed"
    assert result.get("_flags", {}).get("blocklist_gap") is True


def test_hard_awk_system_call_allowed() -> None:
    """awk BEGIN{system(...)} is the hard-mode bypass path."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "exec.run_query",
        {"query": "awk 'BEGIN{system(\"id\")}'"},
    )
    assert result.get("status") == "allowed"


# ---------------------------------------------------------------------------
# Difficulty propagation
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        client = TestClient(app)
        result = tool_call(client, "exec.list_approved", {})
        assert result.get("_difficulty") == diff
