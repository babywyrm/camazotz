"""Okta identity provider flow tests — mirrors test_zitadel_flows.py for Okta."""

from fastapi.testclient import TestClient

from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.main import app
from tests.helpers import tool_call


def test_oauth_exchange_uses_provider_in_okta_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    client = TestClient(app)

    class _Provider:
        def exchange_token(
            self,
            *,
            subject_token: str,
            actor_token: str | None,
            audience: str,
            scope: str,
        ) -> dict:
            assert subject_token == "alice@example.com"
            return {
                "access_token": "okta-provider-access",
                "aud": audience,
                "scope": scope,
                "act": actor_token,
                "sub": subject_token,
            }

    monkeypatch.setattr(
        "camazotz_modules.oauth_delegation_lab.app.main.get_identity_provider",
        lambda: _Provider(),
    )
    set_difficulty("easy")
    result = tool_call(
        client,
        "oauth.exchange_token",
        {"principal": "alice@example.com", "service": "github", "refresh_token": "anything"},
    )
    reset_difficulty()
    assert result["exchanged"] is True
    assert result["access_token"] == "okta-provider-access"
    assert result["_idp_provider"] == "okta"
    assert result["_idp_backed"] is True


def test_revocation_uses_provider_hooks_in_okta_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/revoke")
    client = TestClient(app)

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
    issued = tool_call(client, "revocation.issue_token", {"principal": "alice@example.com", "service": "github"})
    assert issued["_idp_provider"] == "okta"

    revoke = tool_call(client, "revocation.revoke_principal", {"principal": "alice@example.com"})
    assert revoke["_idp_revocation_hook"] == "provider.revoke_token"
    assert revoke["_idp_provider"] == "okta"

    use = tool_call(client, "revocation.use_token", {"token_id": issued["token_id"]})
    assert use["_idp_token_status"] == "inactive"


def test_rbac_idp_backed_in_okta_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    client = TestClient(app)
    result = tool_call(client, "rbac.check_membership", {"principal": "alice@example.com"})
    assert result.get("_idp_backed") is True


def test_oauth_exchange_degrades_gracefully_on_okta_failure(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")

    class _FailingProvider:
        def exchange_token(self, **kwargs: object) -> dict:
            raise ConnectionError("okta down")

    monkeypatch.setattr(
        "camazotz_modules.oauth_delegation_lab.app.main.get_identity_provider",
        lambda: _FailingProvider(),
    )
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "oauth.exchange_token",
        {"principal": "alice@example.com", "service": "github", "refresh_token": "anything"},
    )
    reset_difficulty()
    assert result["exchanged"] is True
    assert result["_idp_degraded"] is True
    assert result["access_token"].startswith("okta-at-")


def test_config_endpoint_exposes_okta_endpoints(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_ISSUER_URL", "https://dev-example.okta.com/oauth2/default")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/revoke")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_ID", "okta-cid")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_SECRET", "okta-secret")
    import brain_gateway.app.identity.service as svc
    monkeypatch.setattr(svc, "_idp_is_reachable", lambda _url: True)

    client = TestClient(app)
    payload = client.get("/config").json()
    assert payload["idp_provider"] == "okta"
    assert "idp_endpoints" in payload
    assert "dev-example.okta.com" in payload["idp_endpoints"]["issuer"]
