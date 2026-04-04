"""Tests for the Authentication Pattern Downgrade lab (MCP-T24)."""

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


def test_downgrade_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "downgrade.check_pattern" in names
    assert "downgrade.authenticate" in names
    assert "downgrade.list_capabilities" in names


# -- check_pattern ------------------------------------------------------------


def test_check_pattern_known_service() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.check_pattern", {"service": "github"}
    )
    assert result["found"] is True
    assert result["pattern"] == "A"
    assert result["oauth_supported"] is True


def test_check_pattern_non_oauth_service() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.check_pattern", {"service": "grafana"}
    )
    assert result["found"] is True
    assert result["pattern"] == "B"
    assert result["oauth_supported"] is False


def test_check_pattern_unknown_service() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.check_pattern", {"service": "nonexistent"}
    )
    assert result["found"] is False


# -- authenticate: easy -------------------------------------------------------


def test_authenticate_easy_default_pattern() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {"service": "github", "principal": "alice@example.com"},
    )
    assert result["authenticated"] is True
    assert result["pattern_used"] == "A"
    assert result["token_type"] == "oauth_user"


def test_authenticate_easy_force_downgrade() -> None:
    """Easy: client-controlled force_pattern downgrades from A to B."""
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "alice@example.com",
            "force_pattern": "B",
        },
    )
    assert result["authenticated"] is True
    assert result["pattern_used"] == "B"
    assert result["token_type"] == "service_account"
    assert "_warning" in result
    assert "Downgraded" in result["_warning"]


def test_authenticate_easy_force_invalid_ignored() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "alice@example.com",
            "force_pattern": "X",
        },
    )
    assert result["pattern_used"] == "A"


def test_authenticate_easy_unknown_service() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {"service": "nonexistent", "principal": "alice@example.com"},
    )
    assert result["authenticated"] is False
    assert "not found" in result["reason"]


# -- authenticate: medium -----------------------------------------------------


def test_authenticate_medium_default_uses_server_caps() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {"service": "github", "principal": "alice@example.com"},
    )
    assert result["pattern_used"] == "A"


def test_authenticate_medium_capability_override_downgrade() -> None:
    """Medium: crafted capability_override tricks the selector."""
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "alice@example.com",
            "capability_override": {"oauth_supported": False},
        },
    )
    assert result["pattern_used"] == "B"
    assert "_warning" in result


def test_authenticate_medium_no_override_for_pattern_b_service() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {"service": "grafana", "principal": "bob@example.com"},
    )
    assert result["pattern_used"] == "B"
    assert "_warning" not in result


# -- authenticate: hard -------------------------------------------------------


def test_authenticate_hard_ignores_force_pattern() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "alice@example.com",
            "force_pattern": "B",
        },
    )
    assert result["pattern_used"] == "A"
    assert "_warning" not in result


def test_authenticate_hard_ignores_capability_override() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "alice@example.com",
            "capability_override": {"oauth_supported": False},
        },
    )
    assert result["pattern_used"] == "A"


def test_authenticate_hard_non_oauth_stays_pattern_b() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "downgrade.authenticate",
        {"service": "internal-api", "principal": "bob@example.com"},
    )
    assert result["pattern_used"] == "B"


# -- list_capabilities --------------------------------------------------------


def test_list_capabilities_all() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.list_capabilities", {}
    )
    assert result["count"] == 4
    assert "github" in result["services"]
    assert "grafana" in result["services"]


def test_list_capabilities_single_service() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.list_capabilities", {"service": "jira"}
    )
    assert result["count"] == 1
    assert result["services"]["jira"]["oauth_supported"] is True


def test_list_capabilities_unknown_service() -> None:
    client = TestClient(app)
    result = _call(
        client, "downgrade.list_capabilities", {"service": "nonexistent"}
    )
    assert result["count"] == 0
    assert result["services"] == {}


# -- resources ----------------------------------------------------------------


def test_downgrade_resources_listed() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "downgrade://pattern_log" in uris


def test_downgrade_read_pattern_log() -> None:
    client = TestClient(app)
    _call(
        client,
        "downgrade.authenticate",
        {
            "service": "github",
            "principal": "eve@example.com",
            "force_pattern": "B",
        },
    )
    body = _rpc(
        client, "resources/read", {"uri": "downgrade://pattern_log"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert isinstance(content, list)
    assert any(e["downgraded"] for e in content)


def test_downgrade_read_resource_wrong_uri() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "other://something"}, 52
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_downgrade_reset_clears_log() -> None:
    client = TestClient(app)
    _call(
        client,
        "downgrade.authenticate",
        {"service": "github", "principal": "alice@example.com"},
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "downgrade://pattern_log"}, 60
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert content == []
