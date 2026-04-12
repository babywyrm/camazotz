"""Tests for the Token Lifecycle & Revocation Gaps lab (MCP-T26)."""

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def _enable_zitadel_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
    monkeypatch.setenv(
        "CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "http://zitadel.example/introspect"
    )
    monkeypatch.setenv(
        "CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "http://zitadel.example/revoke"
    )


def _issue(client: TestClient, principal: str = "alice@example.com") -> dict:
    return tool_call(
        client,
        "revocation.issue_token",
        {"principal": principal, "service": "github"},
    )


def test_revocation_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "revocation.issue_token" in names
    assert "revocation.revoke_principal" in names
    assert "revocation.use_token" in names


# -- issue_token --------------------------------------------------------------


def test_issue_token() -> None:
    client = TestClient(app)
    result = _issue(client)
    assert result["issued"] is True
    assert result["token_id"].startswith("tok-")
    assert result["access_token"].startswith("cztz-access-")
    assert result["principal"] == "alice@example.com"


# -- easy: revoked tokens still valid -----------------------------------------


def test_easy_revoked_token_still_valid() -> None:
    client = TestClient(app)
    issued = _issue(client)
    tid = issued["token_id"]

    tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )

    result = tool_call(client, "revocation.use_token", {"token_id": tid})
    assert result["valid"] is True
    assert "_warning" in result
    assert "cached" in result["_warning"].lower()


def test_easy_non_revoked_token_valid() -> None:
    client = TestClient(app)
    issued = _issue(client)
    result = tool_call(
        client, "revocation.use_token", {"token_id": issued["token_id"]}
    )
    assert result["valid"] is True
    assert "_warning" not in result


# -- medium: refresh revoked, access still valid ------------------------------


def test_medium_revoked_refresh_access_still_valid() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    issued = _issue(client)
    tid = issued["token_id"]

    tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )

    result = tool_call(client, "revocation.use_token", {"token_id": tid})
    assert result["valid"] is True
    assert "_warning" in result
    assert "access token" in result["_warning"].lower()


def test_medium_non_revoked_valid() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    issued = _issue(client)
    result = tool_call(
        client, "revocation.use_token", {"token_id": issued["token_id"]}
    )
    assert result["valid"] is True
    assert "_warning" not in result


def test_medium_full_revoke_denied() -> None:
    """If both revoked flags are set, medium denies."""
    set_difficulty("medium")
    client = TestClient(app)
    issued = _issue(client)
    tid = issued["token_id"]

    set_difficulty("hard")
    tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )

    set_difficulty("medium")
    result = tool_call(client, "revocation.use_token", {"token_id": tid})
    assert result["valid"] is False
    assert "revoked" in result["reason"].lower()


# -- hard: immediate revocation -----------------------------------------------


def test_hard_revoked_immediately_invalid() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    issued = _issue(client)
    tid = issued["token_id"]

    tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )

    result = tool_call(client, "revocation.use_token", {"token_id": tid})
    assert result["valid"] is False
    assert "immediate" in result["reason"].lower()


def test_hard_non_revoked_valid() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    issued = _issue(client)
    result = tool_call(
        client, "revocation.use_token", {"token_id": issued["token_id"]}
    )
    assert result["valid"] is True


# -- use_token: unknown -------------------------------------------------------


def test_use_token_unknown() -> None:
    client = TestClient(app)
    result = tool_call(
        client, "revocation.use_token", {"token_id": "tok-nonexistent"}
    )
    assert result["valid"] is False
    assert "not found" in result["reason"]


# -- revoke_principal: no tokens ----------------------------------------------


def test_revoke_principal_no_tokens() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "nobody@example.com"},
    )
    assert result["revoked_count"] == 0


def test_revoke_principal_skips_other_principals() -> None:
    client = TestClient(app)
    alice = _issue(client, "alice@example.com")
    bob = _issue(client, "bob@example.com")

    tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )

    bob_result = tool_call(
        client, "revocation.use_token", {"token_id": bob["token_id"]}
    )
    assert bob_result["valid"] is True
    assert "_warning" not in bob_result


# -- resources ----------------------------------------------------------------


def test_revocation_resources_dynamic() -> None:
    client = TestClient(app)
    issued = _issue(client)

    body = rpc_call(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert f"revocation://token_status/{issued['token_id']}" in uris


def test_revocation_read_resource() -> None:
    client = TestClient(app)
    issued = _issue(client)

    body = rpc_call(
        client,
        "resources/read",
        {"uri": f"revocation://token_status/{issued['token_id']}"},
        51,
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert content["principal"] == "alice@example.com"


def test_revocation_read_resource_unknown_token() -> None:
    client = TestClient(app)
    body = rpc_call(
        client,
        "resources/read",
        {"uri": "revocation://token_status/tok-nonexistent"},
        52,
    )
    assert "error" in body


def test_revocation_read_resource_wrong_prefix() -> None:
    client = TestClient(app)
    body = rpc_call(
        client,
        "resources/read",
        {"uri": "other://something"},
        53,
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_revocation_lab_mock_mode_issue_without_idp_metadata(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "mock")
    client = TestClient(app)
    result = _issue(client)
    assert "_idp_provider" not in result
    assert result["access_token"].startswith("cztz-access-")


def test_revocation_lab_realism_mode_surfaces_idp_hooks(monkeypatch) -> None:
    _enable_zitadel_mode(monkeypatch)

    class _Provider:
        def revoke_token(self, *, token: str) -> dict:
            return {"revoked": True, "token_hint": token[:8]}

        def introspect_token(self, *, token: str) -> dict:
            return {"active": False, "sub": "alice@example.com"}

    monkeypatch.setattr(
        "camazotz_modules.revocation_lab.app.main.get_identity_provider",
        lambda: _Provider(),
    )
    client = TestClient(app)
    issued = _issue(client)
    assert issued["_idp_provider"] == "zitadel"

    revoke = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )
    assert revoke["_idp_provider"] == "zitadel"
    assert revoke["_idp_revocation_hook"] == "provider.revoke_token"

    use = tool_call(
        client, "revocation.use_token", {"token_id": issued["token_id"]}
    )
    assert use["_idp_token_status"] == "inactive"


def test_revocation_lab_realism_mode_uses_identity_provider_hooks(monkeypatch) -> None:
    _enable_zitadel_mode(monkeypatch)

    class _Provider:
        def revoke_token(self, *, token: str) -> dict:
            assert token
            return {"revoked": True, "token_hint": token[:8]}

        def introspect_token(self, *, token: str) -> dict:
            return {"active": False, "sub": "alice@example.com"}

    monkeypatch.setattr(
        "camazotz_modules.revocation_lab.app.main.get_identity_provider",
        lambda: _Provider(),
    )
    client = TestClient(app)
    issued = _issue(client)
    revoke = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "alice@example.com"},
    )
    assert revoke["_idp_provider"] == "zitadel"
    assert revoke["_idp_revocation_hook"] == "provider.revoke_token"
    use = tool_call(
        client, "revocation.use_token", {"token_id": issued["token_id"]}
    )
    assert use["_idp_token_status"] == "inactive"


def test_revocation_reset_clears_all() -> None:
    client = TestClient(app)
    _issue(client)
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    body = rpc_call(client, "resources/list", {}, 60)
    rev_uris = [
        r["uri"]
        for r in body["result"]["resources"]
        if r["uri"].startswith("revocation://")
    ]
    assert rev_uris == []
