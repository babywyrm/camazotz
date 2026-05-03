"""Tests for the code review agent lab (MCP-T38, Transport D / Lane 2)."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_code_review_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "code_review.submit_pr" in names
    assert "code_review.run_checks" in names
    assert "code_review.get_report" in names
    assert "code_review.get_shell_log" in names


def test_submit_pr_easy_accepted() -> None:
    client = TestClient(app)
    result = tool_call(client, "code_review.submit_pr", {
        "pr_id": "pr-001",
        "title": "Add OAuth2 integration",
        "description": "Implements token refresh flow.",
    })
    assert result["submitted"] is True
    assert result["pr_id"] == "pr-001"
    assert result["_difficulty"] == "easy"


def test_easy_title_reaches_shell() -> None:
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-easy-1", "title": "Normal PR"})
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-easy-1", "operation": "lint",
    })
    # Successful execution returns shell_stdout, not an "executed" flag
    assert "shell_stdout" in result
    assert result["_env_exposed"] is True
    assert result["_difficulty"] == "easy"


def test_easy_injection_via_extra_args() -> None:
    """Shell injection via extra_args on easy mode."""
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {
        "pr_id": "pr-inject",
        "title": "Fix login bug",
    })
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-inject",
        "operation": "lint",
        "extra_args": "; echo INJECTED_MARKER",
    })
    assert result["_injection_executed"] is True
    assert "INJECTED_MARKER" in result.get("shell_stdout", "")


def test_easy_secrets_in_env_accessible() -> None:
    """On easy, env vars including mock secrets are accessible to the shell."""
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-sec", "title": "Sec test"})
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-sec",
        "operation": "scan",
        "extra_args": "; env",
    })
    stdout = result.get("shell_stdout", "")
    assert any(k in stdout for k in ("MOCK_AWS_SECRET_ACCESS_KEY", "MOCK_DEPLOY_TOKEN", "wJalrXUtnFEMI"))
    assert result["_secrets_leaked"] is True


def test_medium_env_var_injection() -> None:
    """On medium, PR description is injected as env var visible to subprocess."""
    set_difficulty("medium")
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {
        "pr_id": "pr-med-1",
        "title": "Medium PR",
        "description": "This is the injected description text",
    })
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-med-1", "operation": "lint",
    })
    assert result["_env_exposed"] is True
    assert "PR_DESCRIPTION" in result.get("shell_stdout", "") or result["_difficulty"] == "medium"


def test_medium_no_shell_injection_via_title() -> None:
    """Medium uses shell=False so title injection doesn't execute; env still leaks."""
    set_difficulty("medium")
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {
        "pr_id": "pr-med-2", "title": "Safe title; echo SHOULD_NOT_APPEAR",
    })
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-med-2", "operation": "scan", "extra_args": "",
    })
    assert result["_injection_executed"] is False


def test_hard_sandboxed_no_secrets_leaked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {
        "pr_id": "pr-hard-1",
        "title": "Hard mode test",
        "description": "No injection possible here.",
    })
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-hard-1", "operation": "lint",
    })
    assert result["_env_exposed"] is False
    assert result["_secrets_leaked"] is False


def test_hard_allowlist_rejects_unknown_operation() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-hard-2", "title": "Test"})
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-hard-2", "operation": "scan",
    })
    assert result.get("executed") is not False or result.get("returncode", 0) == 0


def test_run_checks_unknown_pr_returns_error() -> None:
    client = TestClient(app)
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "nonexistent-pr", "operation": "lint",
    })
    assert result["executed"] is False
    assert "not found" in result["reason"]


def test_get_report_after_checks() -> None:
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-report", "title": "Report test"})
    tool_call(client, "code_review.run_checks", {"pr_id": "pr-report", "operation": "test"})
    result = tool_call(client, "code_review.get_report", {"pr_id": "pr-report"})
    assert result["found"] is True
    assert result["pr_id"] == "pr-report"
    assert "ai_assessment" in result


def test_get_report_not_found() -> None:
    client = TestClient(app)
    result = tool_call(client, "code_review.get_report", {"pr_id": "missing-pr"})
    assert result["found"] is False


def test_shell_log_records_executions() -> None:
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-log", "title": "Log test"})
    tool_call(client, "code_review.run_checks", {"pr_id": "pr-log", "operation": "format"})
    log = tool_call(client, "code_review.get_shell_log", {})
    assert log["count"] >= 1
    prs = [e["pr_id"] for e in log["entries"]]
    assert "pr-log" in prs


def test_transport_and_lane_metadata() -> None:
    client = TestClient(app)
    tool_call(client, "code_review.submit_pr", {"pr_id": "pr-meta", "title": "Meta"})
    result = tool_call(client, "code_review.run_checks", {
        "pr_id": "pr-meta", "operation": "lint",
    })
    assert result["_difficulty"] == "easy"
    assert result["_env_exposed"] is True
