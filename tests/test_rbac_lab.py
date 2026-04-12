"""Tests for the RBAC & Isolation Boundary Bypass lab (MCP-T20)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


# -- tool registration -------------------------------------------------------


def test_rbac_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "rbac.list_agents" in names
    assert "rbac.trigger_agent" in names
    assert "rbac.check_membership" in names


# -- list_agents --------------------------------------------------------------


def test_list_agents_easy_returns_all() -> None:
    client = TestClient(app)
    result = tool_call(client, "rbac.list_agents", {"principal": "eve@example.com"})
    assert result["count"] == 4
    assert result["_difficulty"] == "easy"
    agent_names = {a["name"] for a in result["agents"]}
    assert "agent-admin-v1" in agent_names


def test_list_agents_medium_with_matching_groups() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "rbac.list_agents", {"principal": "bob@example.com"})
    agent_names = {a["name"] for a in result["agents"]}
    assert "agent-coder-v1" in agent_names
    assert "agent-deployer-v2" in agent_names
    assert "agent-docs-v1" in agent_names
    assert "agent-admin-v1" not in agent_names


def test_list_agents_medium_fallthrough_returns_all() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(client, "rbac.list_agents", {"principal": "eve@example.com"})
    assert result["count"] == 4


def test_list_agents_hard_strict_filter() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "rbac.list_agents", {"principal": "alice@example.com"})
    agent_names = {a["name"] for a in result["agents"]}
    assert "agent-coder-v1" in agent_names
    assert "agent-docs-v1" in agent_names
    assert "agent-deployer-v2" not in agent_names
    assert "agent-admin-v1" not in agent_names
    assert result["count"] == 2


def test_list_agents_hard_unknown_principal_empty() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "rbac.list_agents", {"principal": "nobody@example.com"})
    assert result["count"] == 0
    assert result["agents"] == []


# -- trigger_agent ------------------------------------------------------------


def test_trigger_agent_easy_always_authorized() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "eve@example.com", "agent_id": "agent-admin-v1"},
    )
    assert result["triggered"] is True
    assert "execution_id" in result
    assert result["owning_team"] == "team-admin"


def test_trigger_agent_easy_with_override() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {
            "principal": "eve@example.com",
            "agent_id": "agent-admin-v1",
            "group_override": "anything",
        },
    )
    assert result["triggered"] is True


def test_trigger_agent_unknown_agent() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "alice@example.com", "agent_id": "nonexistent"},
    )
    assert result["triggered"] is False
    assert "not found" in result["reason"]


def test_trigger_agent_medium_prefix_bypass() -> None:
    """The prefix-matching vulnerability: 'plat' matches 'platform-admin'."""
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {
            "principal": "eve@example.com",
            "agent_id": "agent-admin-v1",
            "group_override": "plat",
        },
    )
    assert result["triggered"] is True


def test_trigger_agent_medium_authorized_without_override() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "bob@example.com", "agent_id": "agent-deployer-v2"},
    )
    assert result["triggered"] is True


def test_trigger_agent_medium_denied_without_override() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "eve@example.com", "agent_id": "agent-admin-v1"},
    )
    assert result["triggered"] is False
    assert "not authorized" in result["reason"]


def test_trigger_agent_hard_authorized() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "admin@example.com", "agent_id": "agent-admin-v1"},
    )
    assert result["triggered"] is True


def test_trigger_agent_hard_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "eve@example.com", "agent_id": "agent-admin-v1"},
    )
    assert result["triggered"] is False


def test_trigger_agent_hard_override_ignored() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "rbac.trigger_agent",
        {
            "principal": "eve@example.com",
            "agent_id": "agent-admin-v1",
            "group_override": "platform-admin",
        },
    )
    assert result["triggered"] is False


# -- check_membership --------------------------------------------------------


def test_check_membership_known_principal() -> None:
    client = TestClient(app)
    result = tool_call(
        client, "rbac.check_membership", {"principal": "alice@example.com"}
    )
    assert "platform-eng" in result["groups"]
    assert "docs-team" in result["groups"]
    assert result["group_count"] == 2


def test_check_membership_unknown_principal() -> None:
    client = TestClient(app)
    result = tool_call(
        client, "rbac.check_membership", {"principal": "nobody@example.com"}
    )
    assert result["groups"] == []
    assert result["group_count"] == 0


# -- resources ----------------------------------------------------------------


def test_rbac_resources_listed() -> None:
    client = TestClient(app)
    body = rpc_call(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "rbac://policy/platform-eng" in uris
    assert "rbac://policy/platform-admin" in uris


def test_rbac_read_resource_valid_group() -> None:
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "rbac://policy/platform-eng"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert content["group"] == "platform-eng"
    assert len(content["allowed_agents"]) >= 2
    assert "alice@example.com" in content["members"]


def test_rbac_read_resource_unknown_group_returns_error() -> None:
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "rbac://policy/nonexistent-group"}, 52
    )
    assert "error" in body


def test_rbac_read_resource_wrong_prefix_ignored() -> None:
    client = TestClient(app)
    body = rpc_call(
        client, "resources/read", {"uri": "other://something"}, 53
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_rbac_lab_mock_mode_hard_filter_unchanged(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "mock")
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.list_agents", {"principal": "alice@example.com"}
    )
    agent_names = {a["name"] for a in result["agents"]}
    assert "agent-deployer-v2" not in agent_names
    assert "_idp_group_merge" not in result


def test_rbac_lab_realism_no_merge_when_groups_env_unset(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.delenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", raising=False)
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.list_agents", {"principal": "alice@example.com"}
    )
    assert "_idp_group_merge" not in result
    assert "agent-deployer-v2" not in {a["name"] for a in result["agents"]}


def test_rbac_lab_realism_merge_skipped_when_sub_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_SUB", "bob@example.com")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", "sre-oncall")
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.list_agents", {"principal": "alice@example.com"}
    )
    assert "sre-oncall" not in result["groups"]
    assert "_idp_group_merge" not in result


def test_rbac_lab_realism_merge_skipped_when_groups_only_separators(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_SUB", "alice@example.com")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", "  , ,  ")
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.list_agents", {"principal": "alice@example.com"}
    )
    assert "_idp_group_merge" not in result


def test_rbac_lab_realism_check_membership_merges_groups(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_SUB", "alice@example.com")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", "sre-oncall")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.check_membership", {"principal": "alice@example.com"}
    )
    assert "sre-oncall" in result["groups"]
    assert result["_idp_group_merge"] is True


def test_rbac_lab_realism_mode_merges_claim_groups_for_principal(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_SUB", "alice@example.com")
    monkeypatch.setenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", "sre-oncall")
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client, "rbac.list_agents", {"principal": "alice@example.com"}
    )
    assert "sre-oncall" in result["groups"]
    agent_names = {a["name"] for a in result["agents"]}
    assert "agent-deployer-v2" in agent_names
    assert result["_idp_group_merge"] is True


def test_rbac_reset_clears_access_log() -> None:
    client = TestClient(app)
    tool_call(
        client,
        "rbac.trigger_agent",
        {"principal": "alice@example.com", "agent_id": "agent-coder-v1"},
    )
    reset_registry()
    set_difficulty("easy")
