"""Tests for the Execution Context & Attribution Forgery lab (MCP-T22)."""

import json
import hmac
import hashlib
import time

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


# -- tool registration -------------------------------------------------------


def test_attribution_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "attribution.submit_action" in names
    assert "attribution.verify_context" in names
    assert "attribution.read_audit" in names


# -- submit_action: easy ------------------------------------------------------


def test_submit_action_easy_accepts_anything() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "deploy-prod",
            "principal": "forged@example.com",
            "owning_team": "fake-team",
            "execution_id": "exec-forged-1234",
            "pattern": "A",
        },
    )
    assert result["recorded"] is True
    assert result["entry"]["principal"] == "forged@example.com"


def test_submit_action_easy_generates_execution_id() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {"action": "test-action"},
    )
    assert result["recorded"] is True
    assert result["entry"]["execution_id"].startswith("exec-")


# -- submit_action: medium ----------------------------------------------------


def test_submit_action_medium_valid_fields() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "read-config",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "exec-a1b2c3d4",
            "pattern": "A",
        },
    )
    assert result["recorded"] is True
    assert result["entry"]["verified"] is True


def test_submit_action_medium_missing_fields() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {"action": "deploy-prod"},
    )
    assert result["recorded"] is False
    assert "execution_id is required" in result["errors"]
    assert "principal is required" in result["errors"]
    assert "owning_team is required" in result["errors"]


def test_submit_action_medium_short_execution_id() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "test",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "short",
            "pattern": "A",
        },
    )
    assert result["recorded"] is False
    assert "execution_id too short" in result["errors"]


def test_submit_action_medium_invalid_pattern() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "test",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "exec-a1b2c3d4",
            "pattern": "X",
        },
    )
    assert result["recorded"] is False
    assert any("pattern must be" in e for e in result["errors"])


# -- submit_action: hard ------------------------------------------------------


def test_submit_action_hard_missing_signature() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "deploy-prod",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "exec-a1b2c3d4",
            "pattern": "A",
        },
    )
    assert result["recorded"] is False
    assert any("signature" in e for e in result["errors"])


def test_submit_action_hard_bad_signature() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "deploy-prod",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "exec-a1b2c3d4",
            "pattern": "A",
            "signature": "0000deadbeef",
        },
    )
    assert result["recorded"] is False
    assert "signature verification failed" in result["errors"]


def test_submit_action_hard_valid_signature() -> None:
    set_difficulty("hard")
    client = TestClient(app)

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    principal = "alice@example.com"
    owning_team = "team-alpha"
    execution_id = "exec-valid-sig"

    key = f"cztz-hmac-attribution-secret:{ts}".encode()
    msg = f"{principal}|{owning_team}|{execution_id}".encode()
    sig = hmac.new(key, msg, hashlib.sha256).hexdigest()

    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "deploy-prod",
            "principal": principal,
            "owning_team": owning_team,
            "execution_id": execution_id,
            "pattern": "A",
            "signature": sig,
        },
    )
    assert result["recorded"] is True
    assert result["entry"]["signature_valid"] is True


def test_submit_action_hard_empty_execution_id() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {"action": "test", "pattern": "X"},
    )
    assert result["recorded"] is False
    assert any("execution_id" in e for e in result["errors"])
    assert any("pattern must be" in e for e in result["errors"])


def test_submit_action_hard_short_execution_id() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.submit_action",
        {
            "action": "test",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "short",
            "pattern": "A",
        },
    )
    assert result["recorded"] is False
    assert any("too short" in e for e in result["errors"])


# -- verify_context -----------------------------------------------------------


def test_verify_context_found() -> None:
    client = TestClient(app)
    _call(
        client,
        "attribution.submit_action",
        {
            "action": "test",
            "principal": "alice@example.com",
            "owning_team": "team-alpha",
            "execution_id": "exec-verify-me",
            "pattern": "B",
        },
    )
    result = _call(
        client,
        "attribution.verify_context",
        {"execution_id": "exec-verify-me"},
    )
    assert result["found"] is True
    assert result["count"] == 1


def test_verify_context_not_found() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "attribution.verify_context",
        {"execution_id": "nonexistent"},
    )
    assert result["found"] is False


# -- read_audit ---------------------------------------------------------------


def test_read_audit_returns_entries() -> None:
    client = TestClient(app)
    _call(
        client,
        "attribution.submit_action",
        {
            "action": "first",
            "principal": "bob@example.com",
            "owning_team": "team-bravo",
            "execution_id": "exec-audit-read",
            "pattern": "0",
        },
    )
    result = _call(
        client,
        "attribution.read_audit",
        {"execution_id": "exec-audit-read"},
    )
    assert result["count"] == 1
    assert result["entries"][0]["principal"] == "bob@example.com"


def test_read_audit_empty_for_unknown_id() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "attribution.read_audit",
        {"execution_id": "exec-none"},
    )
    assert result["count"] == 0


# -- resources ----------------------------------------------------------------


def test_attribution_resources_listed() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "attribution://audit_log" in uris


def test_attribution_read_audit_log_resource() -> None:
    client = TestClient(app)
    _call(
        client,
        "attribution.submit_action",
        {
            "action": "log-test",
            "principal": "eve@example.com",
            "execution_id": "exec-resource-test",
            "pattern": "B",
        },
    )
    body = _rpc(
        client, "resources/read", {"uri": "attribution://audit_log"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert isinstance(content, list)
    assert any(e["execution_id"] == "exec-resource-test" for e in content)


def test_attribution_read_resource_wrong_uri() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "other://something"}, 52
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_attribution_reset_clears_log() -> None:
    client = TestClient(app)
    _call(
        client,
        "attribution.submit_action",
        {
            "action": "before-reset",
            "execution_id": "exec-reset-test",
            "pattern": "B",
        },
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    result = _call(
        client,
        "attribution.read_audit",
        {"execution_id": "exec-reset-test"},
    )
    assert result["count"] == 0
