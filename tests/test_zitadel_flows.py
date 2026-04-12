"""Dedicated ZITADEL flow tests (provider wiring + cloud-brain compatibility)."""

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.main import app
from tests.helpers import tool_call


def test_config_exposes_idp_backed_maps() -> None:
    client = TestClient(app)
    payload = client.get("/config").json()
    assert "idp_backed_labs" in payload
    assert "idp_backed_tools" in payload
    assert "oauth_delegation_lab" in payload["idp_backed_labs"]
    assert "revocation.revoke_principal" in payload["idp_backed_tools"]


def test_oauth_exchange_uses_provider_in_zitadel_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
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
                "access_token": "zitadel-provider-access",
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
    assert result["access_token"] == "zitadel-provider-access"
    assert result["_idp_provider"] == "zitadel"


def test_revocation_uses_provider_hooks_in_zitadel_mode(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "http://zitadel.example/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "http://zitadel.example/revoke")
    client = TestClient(app)

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
    issued = tool_call(
        client,
        "revocation.issue_token",
        {"principal": "alice@example.com", "service": "github"},
    )
    revoke = tool_call(client, "revocation.revoke_principal", {"principal": "alice@example.com"})
    use = tool_call(client, "revocation.use_token", {"token_id": issued["token_id"]})
    assert revoke["_idp_revocation_hook"] == "provider.revoke_token"
    assert use["_idp_token_status"] == "inactive"


def test_config_exposes_degraded_field() -> None:
    client = TestClient(app)
    payload = client.get("/config").json()
    assert "idp_degraded" in payload
    assert "idp_reason" in payload


def test_oauth_exchange_degrades_gracefully_on_provider_failure(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")

    class _FailingProvider:
        def exchange_token(self, **kwargs: object) -> dict:
            raise ConnectionError("zitadel down")

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
    assert result["_idp_reason"] == "provider_call_failed"
    assert result["access_token"].startswith("zitadel-at-")


def test_revocation_degrades_gracefully_on_provider_failure(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "http://zitadel.example/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "http://zitadel.example/revoke")

    class _FailingProvider:
        def revoke_token(self, **kwargs: object) -> dict:
            raise ConnectionError("zitadel down")

        def introspect_token(self, **kwargs: object) -> dict:
            raise ConnectionError("zitadel down")

    monkeypatch.setattr(
        "camazotz_modules.revocation_lab.app.main.get_identity_provider",
        lambda: _FailingProvider(),
    )
    client = TestClient(app)
    issued = tool_call(client, "revocation.issue_token", {"principal": "alice@example.com"})
    revoke = tool_call(client, "revocation.revoke_principal", {"principal": "alice@example.com"})
    assert revoke["_idp_degraded"] is True
    assert revoke["_idp_reason"] == "revocation_call_failed"
    use = tool_call(client, "revocation.use_token", {"token_id": issued["token_id"]})
    assert use["_idp_degraded"] is True
    assert use["_idp_reason"] == "introspection_call_failed"


def test_trio_responses_include_idp_backed_field(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "http://zitadel.example/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "http://zitadel.example/revoke")

    class _Provider:
        def exchange_token(self, **kwargs: object) -> dict:
            return {"access_token": "z-at", "aud": "", "scope": "", "act": None, "sub": ""}
        def revoke_token(self, **kwargs: object) -> dict:
            return {"revoked": True, "token_hint": ""}
        def introspect_token(self, **kwargs: object) -> dict:
            return {"active": False, "sub": ""}

    monkeypatch.setattr(
        "camazotz_modules.oauth_delegation_lab.app.main.get_identity_provider",
        lambda: _Provider(),
    )
    monkeypatch.setattr(
        "camazotz_modules.revocation_lab.app.main.get_identity_provider",
        lambda: _Provider(),
    )
    set_difficulty("easy")
    client = TestClient(app)
    oauth = tool_call(client, "oauth.exchange_token", {
        "principal": "alice@example.com", "service": "github", "refresh_token": "anything",
    })
    assert oauth.get("_idp_backed") is True

    issued = tool_call(client, "revocation.issue_token", {"principal": "alice@example.com"})
    assert issued.get("_idp_backed") is True

    revoke = tool_call(client, "revocation.revoke_principal", {"principal": "alice@example.com"})
    assert revoke.get("_idp_backed") is True

    use = tool_call(client, "revocation.use_token", {"token_id": issued["token_id"]})
    assert use.get("_idp_backed") is True

    rbac = tool_call(client, "rbac.check_membership", {"principal": "alice@example.com"})
    assert rbac.get("_idp_backed") is True
    reset_difficulty()


def test_cloud_brain_path_works_with_zitadel_mode(monkeypatch) -> None:
    reset_provider()
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "http://zitadel.example/token")
    client = TestClient(app)
    result = tool_call(client, "config.ask_agent", {"question": "respond briefly"})
    assert "answer" in result
    assert "[cloud-stub]" in result["answer"]
    reset_provider()
