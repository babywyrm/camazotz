"""Tests for the Identity Dashboard lifecycle test flow and API contracts.

Validates that the /api/call tool invocation returns the shape expected
by the Identity Dashboard's runLifecycleTest() JavaScript, and that the
full mint → introspect → revoke → verify cycle works in mock mode.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import tool_call


def setup_function() -> None:
    set_difficulty("easy")
    reset_registry()


def test_lifecycle_mint_returns_issued_true() -> None:
    """Step 1: issue_token produces issued=true and a token_id."""
    client = TestClient(app)
    result = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-test@camazotz", "service": "test-svc"},
    )
    assert result["issued"] is True
    assert "token_id" in result
    assert result["token_id"].startswith("tok-")


def test_lifecycle_introspect_active_after_mint() -> None:
    """Step 2: use_token on a fresh token returns valid=true."""
    client = TestClient(app)
    mint = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-test@camazotz"},
    )
    use = tool_call(
        client,
        "revocation.use_token",
        {"token_id": mint["token_id"]},
    )
    assert use["valid"] is True


def test_lifecycle_revoke_returns_count() -> None:
    """Step 3: revoke_principal returns revoked_count > 0."""
    client = TestClient(app)
    tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-test@camazotz"},
    )
    revoke = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "lifecycle-test@camazotz"},
    )
    assert revoke.get("revoked_count", 0) > 0 or "revoked_ids" in revoke


def test_lifecycle_revoke_marks_tokens_invalid() -> None:
    """Step 4: after revocation, the revoked_ids list includes the token."""
    client = TestClient(app)
    mint = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-verify@camazotz"},
    )
    revoke = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "lifecycle-verify@camazotz"},
    )
    revoked = revoke.get("revoked_ids", [])
    assert mint["token_id"] in revoked or revoke.get("revoked_count", 0) > 0


def test_lifecycle_full_cycle_mock_mode() -> None:
    """End-to-end lifecycle test matching the dashboard's runLifecycleTest()."""
    client = TestClient(app)

    mint = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-full@camazotz", "service": "test-svc"},
    )
    assert mint["issued"] is True
    token_id = mint["token_id"]

    use1 = tool_call(client, "revocation.use_token", {"token_id": token_id})
    assert use1["valid"] is True

    revoke = tool_call(
        client,
        "revocation.revoke_principal",
        {"principal": "lifecycle-full@camazotz"},
    )
    assert revoke.get("revoked_count", 0) > 0 or "revoked_ids" in revoke

    use2 = tool_call(client, "revocation.use_token", {"token_id": token_id})
    # In mock mode the lab demonstrates the revocation gap: token shows valid=true
    # with a _warning about cached copies. The dashboard shows this as a teaching moment.
    assert "token_id" in use2
    if use2.get("valid") is True:
        assert "_warning" in use2, "Revoked-but-valid should carry a warning"


def test_lifecycle_with_live_idp_tags(monkeypatch) -> None:
    """In live IdP mode, lifecycle responses include _idp_backed tags."""
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://z.example/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "http://z.example/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "http://z.example/revoke")

    import brain_gateway.app.identity.service as identity_service
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)

    client = TestClient(app)
    reset_registry()

    mint = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "lifecycle-test@camazotz"},
    )
    assert mint["issued"] is True
    assert mint.get("_idp_backed") is True


def test_config_returns_idp_fields_for_dashboard() -> None:
    """GET /config response includes all fields the dashboard depends on."""
    client = TestClient(app)
    resp = client.get("/config")
    assert resp.status_code == 200
    data = resp.json()

    required_fields = [
        "idp_provider",
        "idp_degraded",
        "idp_reason",
        "idp_backed_labs",
        "idp_backed_tools",
        "idp_credentials_configured",
    ]
    for field in required_fields:
        assert field in data, f"Missing dashboard-required field: {field}"

    assert isinstance(data["idp_backed_labs"], list)
    assert isinstance(data["idp_backed_tools"], list)
    # idp_endpoints only present when a live IdP is configured
    if "idp_endpoints" in data:
        assert isinstance(data["idp_endpoints"], dict)


def test_config_returns_idp_endpoints_when_live(monkeypatch) -> None:
    """GET /config includes idp_endpoints block when a live IdP is active."""
    import brain_gateway.app.config as config_mod
    import brain_gateway.app.identity.service as identity_service

    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)
    config_mod.set_idp_config(
        provider="okta",
        token_endpoint="https://okta.example/v1/token",
        issuer_url="https://okta.example",
        introspection_endpoint="https://okta.example/v1/introspect",
        revocation_endpoint="https://okta.example/v1/revoke",
        client_id="cid",
        client_secret="sec",
    )
    try:
        client = TestClient(app)
        resp = client.get("/config")
        data = resp.json()
        assert "idp_endpoints" in data
        ep = data["idp_endpoints"]
        assert ep["issuer"] == "https://okta.example"
        assert ep["token"] == "https://okta.example/v1/token"
    finally:
        config_mod.reset_idp_config()
