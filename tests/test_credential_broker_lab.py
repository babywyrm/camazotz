"""Tests for the Credential Isolation & Sidecar Tampering lab (MCP-T23)."""

import json

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


def test_cred_broker_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "cred_broker.list_vaults" in names
    assert "cred_broker.read_credential" in names
    assert "cred_broker.configure_sidecar" in names


# -- list_vaults --------------------------------------------------------------


def test_list_vaults_easy_returns_all_teams() -> None:
    client = TestClient(app)
    result = _call(
        client, "cred_broker.list_vaults", {"caller_team": "team-alpha"}
    )
    assert "team-alpha" in result["vaults"]
    assert "team-bravo" in result["vaults"]
    assert "team-admin" in result["vaults"]
    assert result["_difficulty"] == "easy"


def test_list_vaults_medium_returns_own_team_only() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client, "cred_broker.list_vaults", {"caller_team": "team-alpha"}
    )
    assert "team-alpha" in result["vaults"]
    assert "team-bravo" not in result["vaults"]


def test_list_vaults_medium_unknown_team_empty() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client, "cred_broker.list_vaults", {"caller_team": "team-unknown"}
    )
    assert result["vaults"] == {}


def test_list_vaults_hard_returns_own_team_only() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client, "cred_broker.list_vaults", {"caller_team": "team-bravo"}
    )
    assert "team-bravo" in result["vaults"]
    assert "aws" in result["vaults"]["team-bravo"]
    assert "team-alpha" not in result["vaults"]


# -- read_credential ---------------------------------------------------------


def test_read_credential_easy_own_team() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-alpha",
            "service": "github",
        },
    )
    assert result["found"] is True
    assert result["credential"]["value"] == "cztz-gh-alpha-a1b2c3d4"


def test_read_credential_easy_cross_team_leaks() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-admin",
            "service": "platform-api",
        },
    )
    assert result["found"] is True
    assert result["credential"]["value"] == "cztz-admin-key-m3n4o5p6"


def test_read_credential_medium_own_team_full_access() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-bravo",
            "target_team": "team-bravo",
            "service": "grafana",
        },
    )
    assert result["found"] is True
    assert result["credential"]["value"] == "cztz-grafana-bravo-i9j0k1l2"
    assert "_warning" not in result


def test_read_credential_medium_cross_team_redacted() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-admin",
            "service": "platform-api",
        },
    )
    assert result["found"] is True
    assert result["credential"]["value"].endswith("...")
    assert "_warning" in result


def test_read_credential_hard_cross_team_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-bravo",
            "service": "aws",
        },
    )
    assert result["found"] is False
    assert "Access denied" in result["reason"]


def test_read_credential_hard_own_team_allowed() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-alpha",
            "service": "jira",
        },
    )
    assert result["found"] is True
    assert result["credential"]["value"] == "cztz-jira-alpha-e5f6g7h8"


def test_read_credential_unknown_team() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-unknown",
            "service": "github",
        },
    )
    assert result["found"] is False
    assert "not found" in result["reason"]


def test_read_credential_unknown_service() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.read_credential",
        {
            "caller_team": "team-alpha",
            "target_team": "team-alpha",
            "service": "nonexistent",
        },
    )
    assert result["found"] is False
    assert "not found" in result["reason"]


# -- configure_sidecar -------------------------------------------------------


def test_configure_sidecar_easy_accepts_anything() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-alpha",
            "vault_path": "/vault/team-bravo/aws",
            "mount_path": "/secrets/stolen",
            "env_var": "STOLEN_CRED",
        },
    )
    assert result["configured"] is True
    assert result["entry"]["vault_path"] == "/vault/team-bravo/aws"


def test_configure_sidecar_medium_own_team_no_warning() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-alpha",
            "vault_path": "/vault/team-alpha/github",
            "mount_path": "/secrets/gh",
            "env_var": "GH_TOKEN",
        },
    )
    assert result["configured"] is True
    assert "_warning" not in result


def test_configure_sidecar_medium_cross_team_warns() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-alpha",
            "vault_path": "/vault/team-admin/platform-api",
            "mount_path": "/secrets/admin",
            "env_var": "ADMIN_KEY",
        },
    )
    assert result["configured"] is True
    assert "_warning" in result
    assert "does not belong" in result["_warning"]


def test_configure_sidecar_hard_cross_team_rejected() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-alpha",
            "vault_path": "/vault/team-bravo/grafana",
            "mount_path": "/secrets/grafana",
            "env_var": "GRAFANA_TOKEN",
        },
    )
    assert result["configured"] is False
    assert "Access denied" in result["reason"]


def test_configure_sidecar_hard_own_team_accepted() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-bravo",
            "vault_path": "/vault/team-bravo/grafana",
            "mount_path": "/secrets/grafana",
            "env_var": "GRAFANA_TOKEN",
        },
    )
    assert result["configured"] is True


# -- resources ----------------------------------------------------------------


def test_cred_broker_resources_listed() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "cred_broker://sidecar_config" in uris


def test_cred_broker_read_sidecar_config_easy() -> None:
    client = TestClient(app)
    body = _rpc(
        client,
        "resources/read",
        {"uri": "cred_broker://sidecar_config"},
        51,
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert isinstance(content, list)
    teams = {e["team"] for e in content}
    assert "team-alpha" in teams
    assert "team-bravo" in teams


def test_cred_broker_read_sidecar_config_hard_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    body = _rpc(
        client,
        "resources/read",
        {"uri": "cred_broker://sidecar_config"},
        52,
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert "error" in content
    assert "Access denied" in content["error"]


def test_cred_broker_read_resource_wrong_uri_ignored() -> None:
    client = TestClient(app)
    body = _rpc(
        client,
        "resources/read",
        {"uri": "other://something"},
        53,
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_cred_broker_reset_clears_state() -> None:
    client = TestClient(app)
    _call(
        client,
        "cred_broker.configure_sidecar",
        {
            "caller_team": "team-alpha",
            "vault_path": "/vault/team-alpha/new",
            "mount_path": "/secrets/new",
            "env_var": "NEW_TOKEN",
        },
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    body = _rpc(
        client,
        "resources/read",
        {"uri": "cred_broker://sidecar_config"},
        60,
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert len(content) == 5
