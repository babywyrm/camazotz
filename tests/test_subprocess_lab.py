"""Tests for the Subprocess Credential Inheritance lab (MCP-T34).

Lane 3 / Transport D — first lab in the new Transport D bucket.

Validates the three threat vectors:
  1. Argv injection via shell metacharacter passthrough
  2. Environment variable leakage to child process
  3. Operation drift (subcommand selection)
across the three difficulty tiers.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_subprocess_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "subprocess.invoke_worker" in names
    assert "subprocess.list_allowlist" in names


def test_list_allowlist_returns_canonical_set() -> None:
    client = TestClient(app)
    result = tool_call(client, "subprocess.list_allowlist", {})
    assert sorted(result["allowlisted_operations"]) == ["list", "status"]
    assert result["enforced_on_difficulty"] == "hard"


# ---------------------------------------------------------------------------
# Easy difficulty — shell=True, full env passthrough, no allowlist
# ---------------------------------------------------------------------------


def test_easy_normal_invocation_succeeds() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status"},
    )
    assert result["returncode"] == 0
    assert "argv" in result["worker_payload"]


def test_easy_env_leakage_exposes_mock_secrets() -> None:
    """Core threat 2: child inherits all parent env including mock secrets."""
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status"},
    )
    leaked = result["_signals"]["leaked_mock_secrets"]
    assert "MOCK_AWS_SECRET_ACCESS_KEY" in leaked
    assert "MOCK_K8S_BEARER_TOKEN" in leaked
    assert result["_signals"]["leaked_count"] == 4


def test_easy_argv_injection_via_shell_metacharacter() -> None:
    """Core threat 1: shell=True + raw concat lets ; chain a second command."""
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status", "extra_args": "; echo PWNED"},
    )
    assert result["_signals"]["argv_injection_detected"] is True


def test_easy_arbitrary_operation_accepted() -> None:
    """No allowlist on easy — any operation string gets passed to worker."""
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "totally-unknown-operation"},
    )
    assert result["returncode"] == 0
    assert "totally-unknown-operation" in result["worker_payload"]["argv"]


# ---------------------------------------------------------------------------
# Medium difficulty — args list (no shell), full env passthrough
# ---------------------------------------------------------------------------


def test_medium_argv_injection_blocked() -> None:
    """Args list defeats shell-metacharacter injection."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status", "extra_args": "; echo PWNED"},
    )
    assert result["_signals"]["argv_injection_detected"] is False


def test_medium_env_leakage_still_exposes_secrets() -> None:
    """Env passthrough is the remaining threat on medium."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status"},
    )
    leaked = result["_signals"]["leaked_mock_secrets"]
    assert "MOCK_AWS_SECRET_ACCESS_KEY" in leaked
    assert result["_signals"]["leaked_count"] == 4


def test_medium_arbitrary_operation_still_accepted() -> None:
    """No allowlist enforcement on medium — operation string still passes through."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "rogue-op"},
    )
    assert result["returncode"] == 0


# ---------------------------------------------------------------------------
# Hard difficulty — args list + allowlist + curated env
# ---------------------------------------------------------------------------


def test_hard_allowlisted_operation_succeeds_with_curated_env() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status"},
    )
    assert result["returncode"] == 0
    assert result["_signals"]["env_curated"] is True
    assert result["_signals"]["leaked_count"] == 0
    assert result["_signals"]["leaked_mock_secrets"] == []


def test_hard_unallowlisted_operation_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "rogue-op"},
    )
    assert result["access"] == "denied"
    assert "allowlist" in result["reason"].lower()


def test_hard_extra_args_rejected() -> None:
    """Hard mode rejects extra_args entirely — no injection surface."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status", "extra_args": "anything"},
    )
    assert result["access"] == "denied"
    assert "extra_args" in result["reason"]


def test_hard_argv_injection_blocked_even_if_attempted() -> None:
    """Even if extra_args were permitted on hard, args-list mode blocks shell injection."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "status", "extra_args": "; echo PWNED"},
    )
    # Denied at the extra_args check before subprocess even runs.
    assert result["access"] == "denied"


def test_hard_env_curation_strips_mock_secrets() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "subprocess.invoke_worker",
        {"operation": "list"},
    )
    env_keys = result["worker_payload"]["env_keys"]
    assert "PATH" in env_keys
    for mock_key in (
        "MOCK_AWS_SECRET_ACCESS_KEY",
        "MOCK_K8S_BEARER_TOKEN",
        "MOCK_GITHUB_TOKEN",
        "MOCK_TELEPORT_CERT_PATH",
    ):
        assert mock_key not in env_keys, (
            f"hard mode must strip {mock_key} from child env; got {env_keys}"
        )


# ---------------------------------------------------------------------------
# State / metadata
# ---------------------------------------------------------------------------


def test_invocation_count_increments() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    r1 = tool_call(client, "subprocess.invoke_worker", {"operation": "status"})
    r2 = tool_call(client, "subprocess.invoke_worker", {"operation": "status"})
    assert r2["invocation_id"] == r1["invocation_id"] + 1


def test_reset_clears_invocation_count() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(client, "subprocess.invoke_worker", {"operation": "status"})
    resp = client.post("/reset")
    assert resp.status_code == 200
    result = tool_call(client, "subprocess.invoke_worker", {"operation": "status"})
    assert result["invocation_id"] == 1


# ---------------------------------------------------------------------------
# Scenario / lane metadata
# ---------------------------------------------------------------------------


def test_subprocess_lab_in_scenarios() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    scenarios = resp.json()
    names = [s["module_name"] for s in scenarios]
    assert "subprocess_lab" in names


def test_subprocess_lab_declares_lane_3_transport_d() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    scenarios = resp.json()
    sub = next(s for s in scenarios if s["module_name"] == "subprocess_lab")
    ag = sub["agentic"]
    assert ag["primary_lane"] == 3
    assert ag["transport"] == "D"
