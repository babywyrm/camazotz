"""Tests for the Shell Command Wrapping Injection lab (MCP-T53).

Lane 3 / Transport D — shell wrapper around subprocess.run(shell=True).

Validates the three attack vectors:
  1. Shell metacharacter injection via raw interpolation
  2. Dangerous base command bypass of shlex.quote
  3. Allowlist + quoting combined defense
across the three difficulty tiers.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from camazotz_modules.shell_exec_wrap_lab.app.main import FLAG
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_shellwrap_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "shellwrap.exec" in names
    assert "shellwrap.list_commands" in names


def test_list_commands_returns_allowlist() -> None:
    client = TestClient(app)
    result = tool_call(client, "shellwrap.list_commands", {})
    assert "echo" in result["allowed_commands"]
    assert "date" in result["allowed_commands"]
    assert "whoami" in result["allowed_commands"]


# ---------------------------------------------------------------------------
# Easy difficulty — raw interpolation + shell=True
# ---------------------------------------------------------------------------


def test_easy_normal_echo_succeeds() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "shellwrap.exec", {"base_cmd": "echo", "args": "hello"})
    assert result["returncode"] == 0
    assert "hello" in result["stdout"]


def test_easy_semicolon_injection() -> None:
    """Core attack: ; chains a second command."""
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "safe; echo INJECTED"},
    )
    assert result["_signals"]["injection_detected"] is True
    assert result["flag"] == FLAG
    assert "INJECTED" in result["stdout"]


def test_easy_pipe_injection() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "data | cat"},
    )
    assert result["_signals"]["metachar_in_args"] is True


def test_easy_subshell_injection() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "$(whoami)"},
    )
    assert result["_signals"]["injection_detected"] is True
    assert result["flag"] == FLAG


def test_easy_backtick_injection() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "`whoami`"},
    )
    assert result["_signals"]["injection_detected"] is True
    assert result["flag"] == FLAG


def test_easy_empty_base_cmd_returns_error() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "shellwrap.exec", {"base_cmd": ""})
    assert result["status"] == "error"
    assert "required" in result["reason"]


def test_easy_no_allowlist_enforcement() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "shellwrap.list_commands", {})
    assert result["allowlist_enforced"] is False


# ---------------------------------------------------------------------------
# Medium difficulty — shlex.quote() on args, no base_cmd restriction
# ---------------------------------------------------------------------------


def test_medium_semicolon_neutralised() -> None:
    """shlex.quote wraps args — ; is inside single quotes."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "safe; echo INJECTED"},
    )
    assert result["_signals"]["injection_detected"] is False
    assert "flag" not in result


def test_medium_subshell_neutralised() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "$(whoami)"},
    )
    assert result["_signals"]["injection_detected"] is False
    assert "flag" not in result


def test_medium_dangerous_base_bash() -> None:
    """On medium, base_cmd is not restricted — put the whole command there."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "bash -c id"},
    )
    assert result["_signals"]["dangerous_base_used"] is True
    assert result["flag"] == FLAG


def test_medium_dangerous_base_sh() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "sh -c whoami"},
    )
    assert result["_signals"]["dangerous_base_used"] is True
    assert result["flag"] == FLAG


def test_medium_safe_base_echo_no_flag() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "hello"},
    )
    assert result["_signals"]["injection_detected"] is False
    assert "flag" not in result


def test_medium_args_quoted() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "shellwrap.list_commands", {})
    assert result["args_quoted"] is True


# ---------------------------------------------------------------------------
# Hard difficulty — allowlist + quoting
# ---------------------------------------------------------------------------


def test_hard_allowlisted_echo_succeeds() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "hello"},
    )
    assert result["returncode"] == 0
    assert result["_signals"]["allowlist_enforced"] is True
    assert "flag" not in result


def test_hard_allowlisted_date_succeeds() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "shellwrap.exec", {"base_cmd": "date"})
    assert result["returncode"] == 0


def test_hard_bash_denied_by_allowlist() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "bash", "args": "-c id"},
    )
    assert result["status"] == "denied"
    assert "allowlist" in result["reason"].lower()


def test_hard_arbitrary_command_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "cat", "args": "/etc/passwd"},
    )
    assert result["status"] == "denied"
    assert "allowlist" in result["reason"].lower()


def test_hard_injection_in_args_neutralised() -> None:
    """Even with echo (allowlisted), shell metacharacters in args are quoted."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "; rm -rf /"},
    )
    assert result["_signals"]["injection_detected"] is False
    assert "flag" not in result
    assert result["_signals"]["args_were_quoted"] is True


def test_hard_subshell_in_args_neutralised() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "shellwrap.exec",
        {"base_cmd": "echo", "args": "$(cat /etc/passwd)"},
    )
    assert result["_signals"]["injection_detected"] is False
    assert "flag" not in result


# ---------------------------------------------------------------------------
# State / metadata
# ---------------------------------------------------------------------------


def test_exec_count_increments() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    r1 = tool_call(client, "shellwrap.exec", {"base_cmd": "echo", "args": "1"})
    r2 = tool_call(client, "shellwrap.exec", {"base_cmd": "echo", "args": "2"})
    assert r2["exec_id"] == r1["exec_id"] + 1


def test_reset_clears_exec_count() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(client, "shellwrap.exec", {"base_cmd": "echo", "args": "x"})
    resp = client.post("/reset")
    assert resp.status_code == 200
    result = tool_call(client, "shellwrap.exec", {"base_cmd": "echo", "args": "y"})
    assert result["exec_id"] == 1


# ---------------------------------------------------------------------------
# Scenario / lane metadata
# ---------------------------------------------------------------------------


def test_shell_exec_wrap_lab_in_scenarios() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    scenarios = resp.json()
    names = [s["module_name"] for s in scenarios]
    assert "shell_exec_wrap_lab" in names


def test_shell_exec_wrap_lab_declares_lane_3_transport_d() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    scenarios = resp.json()
    lab = next(s for s in scenarios if s["module_name"] == "shell_exec_wrap_lab")
    ag = lab["agentic"]
    assert ag["primary_lane"] == 3
    assert ag["transport"] == "D"
    assert lab["threat_id"] == "MCP-T53"
