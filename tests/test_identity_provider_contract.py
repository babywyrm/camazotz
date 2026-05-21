from typing import Literal, get_type_hints

import pytest
import httpx

from brain_gateway.app.config import get_idp_provider, is_live_idp
from brain_gateway.app.identity import IdentityProvider, MockIdentityProvider, OidcIdentityProvider, OktaIdentityProvider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider as MockIdentityProviderDirect
from brain_gateway.app.identity.provider import IdentityProvider as IdentityProviderProtocol
import brain_gateway.app.identity.service as identity_service
from brain_gateway.app.identity.service import get_identity_provider
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider
from brain_gateway.app.identity.types import (
    ClientCredentialsTokenResponse,
    ExchangeTokenResponse,
    IdentityClaimsDict,
    IntrospectTokenResponse,
    RevokeTokenResponse,
)


def test_mock_provider_exposes_required_methods() -> None:
    provider = MockIdentityProviderDirect()
    assert hasattr(provider, "client_credentials_token")
    assert hasattr(provider, "exchange_token")
    assert hasattr(provider, "introspect_token")
    assert hasattr(provider, "revoke_token")


def test_identity_package_exports() -> None:
    assert IdentityProvider is not None
    assert MockIdentityProvider is MockIdentityProviderDirect


def test_get_idp_provider_defaults_to_mock(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    assert get_idp_provider() == "mock"


def test_get_idp_provider_accepts_zitadel(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://issuer.example/oauth/v2/token")
    assert get_idp_provider() == "zitadel"


def test_get_idp_provider_invalid_falls_back_to_mock(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "unknown")
    assert get_idp_provider() == "mock"


def test_get_idp_provider_zitadel_without_token_endpoint_falls_back_to_mock(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.delenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", raising=False)
    assert get_idp_provider() == "mock"


def test_get_idp_provider_accepts_okta(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    assert get_idp_provider() == "okta"


def test_is_live_idp_true_for_zitadel(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://issuer.example/oauth/v2/token")
    assert is_live_idp() is True


def test_is_live_idp_true_for_okta(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-example.okta.com/oauth2/default/v1/token")
    assert is_live_idp() is True


def test_is_live_idp_false_for_mock(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    assert is_live_idp() is False


def test_get_idp_provider_return_type_is_idp_literal() -> None:
    ret = get_type_hints(get_idp_provider)["return"]
    assert ret == Literal["mock", "zitadel", "okta", "auth0"]
    assert getattr(ret, "__args__", ()) == ("mock", "zitadel", "okta", "auth0")


def test_get_identity_provider_return_type_is_protocol() -> None:
    ret = get_type_hints(get_identity_provider)["return"]
    assert ret is IdentityProviderProtocol


def test_mock_provider_methods_use_response_typed_dicts() -> None:
    assert (
        get_type_hints(MockIdentityProviderDirect.client_credentials_token)["return"]
        is ClientCredentialsTokenResponse
    )
    assert get_type_hints(MockIdentityProviderDirect.exchange_token)["return"] is ExchangeTokenResponse
    assert (
        get_type_hints(MockIdentityProviderDirect.introspect_token)["return"]
        is IntrospectTokenResponse
    )
    assert get_type_hints(MockIdentityProviderDirect.revoke_token)["return"] is RevokeTokenResponse


def test_mock_provider_methods_return_dicts() -> None:
    p = MockIdentityProviderDirect()
    cc = p.client_credentials_token(audience="api://x", scope="openid")
    assert cc["access_token"] == "mock-access"
    ex = p.exchange_token(
        subject_token="subj",
        actor_token="act",
        audience="api://x",
        scope="s",
    )
    assert ex["access_token"] == "mock-exchanged"
    assert ex["act"] == "act"
    assert ex["sub"] == "subj"
    intro = p.introspect_token(token="mock-abc")
    assert intro["active"] is True
    intro_inactive = p.introspect_token(token="other")
    assert intro_inactive["active"] is False
    rev = p.revoke_token(token="secret-token")
    assert rev["revoked"] is True


def test_identity_claims_dict_typed_dict() -> None:
    raw: IdentityClaimsDict = {"sub": "u1", "env": "local"}
    assert raw["sub"] == "u1"


def test_zitadel_provider_requires_token_endpoint_for_client_credentials() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    with pytest.raises(ValueError, match="token endpoint"):
        provider.client_credentials_token(audience="api://x", scope="openid")


def test_zitadel_provider_requires_token_endpoint_for_exchange() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    with pytest.raises(ValueError, match="token endpoint"):
        provider.exchange_token(
            subject_token="subj",
            actor_token=None,
            audience="api://x",
            scope="openid",
        )


def test_zitadel_provider_requires_introspection_endpoint() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    with pytest.raises(ValueError, match="introspection endpoint"):
        provider.introspect_token(token="t")


def test_zitadel_provider_requires_revocation_endpoint() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="",
        client_id="cid",
        client_secret="secret",
    )
    with pytest.raises(ValueError, match="revocation endpoint"):
        provider.revoke_token(token="t")


def test_zitadel_provider_methods_return_typed_shapes_when_configured(monkeypatch) -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )

    class _Resp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._payload

    def _fake_post(url: str, *, data: dict[str, str], headers=None, timeout: float = 5.0):
        if "introspect" in url:
            if data["token"] == "zitadel-live":
                return _Resp({"active": True, "sub": "subj"})
            return _Resp({"active": False, "sub": ""})
        return _Resp({"access_token": "zitadel-access"})

    monkeypatch.setattr(httpx, "post", _fake_post)
    cc = provider.client_credentials_token(audience="api://x", scope="openid")
    assert cc["access_token"]
    assert cc["aud"] == "api://x"
    ex = provider.exchange_token(
        subject_token="subj",
        actor_token="act",
        audience="api://x",
        scope="s",
    )
    assert ex["sub"] == "subj"
    assert ex["act"] == "act"
    intro = provider.introspect_token(token="zitadel-live")
    assert intro["active"] is True
    assert "sub" in intro
    inactive = provider.introspect_token(token="any")
    assert inactive["active"] is False
    rev = provider.revoke_token(token="secret-token")
    assert rev["revoked"] is True


def test_get_identity_provider_returns_mock_by_default(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    p = get_identity_provider()
    assert isinstance(p, MockIdentityProviderDirect)


def test_get_identity_provider_returns_zitadel_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://issuer.example/oauth/v2/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "https://issuer.example/oauth/v2/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "https://issuer.example/oauth/v2/revoke")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_ID", "cid")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_SECRET", "secret")
    p = get_identity_provider()
    assert isinstance(p, ZitadelIdentityProvider)
    assert p.issuer_url == "https://issuer.example"


def test_get_identity_provider_falls_back_to_mock_when_zitadel_misconfigured(
    monkeypatch,
) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.delenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", raising=False)
    p = get_identity_provider()
    assert isinstance(p, MockIdentityProviderDirect)


def test_get_identity_provider_falls_back_to_mock_when_zitadel_unreachable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://issuer.example/oauth/v2/token")
    p = get_identity_provider()
    assert isinstance(p, MockIdentityProviderDirect)


def test_zitadel_provider_client_credentials_uses_token_endpoint(monkeypatch) -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    called: dict[str, object] = {}

    class _Resp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"access_token": "real-access"}

    def _fake_post(url: str, *, data: dict[str, str], headers=None, timeout: float = 5.0):
        called["url"] = url
        called["data"] = data
        called["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(httpx, "post", _fake_post)
    out = provider.client_credentials_token(audience="api://cam", scope="openid profile")
    assert out["access_token"] == "real-access"
    assert out["aud"] == "api://cam"
    assert out["scope"] == "openid profile"
    assert called["url"] == "https://example/token"
    assert called["data"] == {
        "grant_type": "client_credentials",
        "client_id": "cid",
        "client_secret": "secret",
        "audience": "api://cam",
        "scope": "openid profile",
    }


def test_zitadel_provider_introspection_uses_endpoint(monkeypatch) -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    called: dict[str, object] = {}

    class _Resp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"active": True, "sub": "alice@example.com"}

    def _fake_post(url: str, *, data: dict[str, str], headers=None, timeout: float = 5.0):
        called["url"] = url
        called["data"] = data
        called["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(httpx, "post", _fake_post)
    out = provider.introspect_token(token="token-123")
    assert out == {"active": True, "sub": "alice@example.com"}
    assert called["url"] == "https://example/introspect"
    assert called["data"] == {
        "token": "token-123",
        "client_id": "cid",
        "client_secret": "secret",
    }


# --- Coverage fill for defensive paths ---


def test_host_probe_url_returns_input_when_missing_scheme_or_netloc() -> None:
    """URLs that don't parse into scheme+netloc fall through unchanged."""
    from brain_gateway.app.identity.service import _host_probe_url

    assert _host_probe_url("not-a-url") == "not-a-url"
    assert _host_probe_url("") == ""


def test_idp_is_reachable_caches_recent_result(monkeypatch) -> None:
    """Two calls within the TTL window reuse the cached health status."""
    import brain_gateway.app.identity.service as svc

    monkeypatch.setattr(svc, "_idp_health_ok", True)
    monkeypatch.setattr(svc, "_idp_health_checked_at", __import__("time").monotonic())

    def _should_not_be_called(*a, **kw):  # pragma: no cover — asserts below guarantee it isn't
        raise AssertionError("urlopen must not be called when cache is fresh")

    monkeypatch.setattr(svc, "urlopen", _should_not_be_called)
    assert svc._idp_is_reachable("https://zitadel.example/token") is True


def test_idp_is_reachable_success_path(monkeypatch) -> None:
    """Fresh cache + successful urlopen sets health to True."""
    import brain_gateway.app.identity.service as svc

    monkeypatch.setattr(svc, "_idp_health_ok", None)
    monkeypatch.setattr(svc, "_idp_health_checked_at", 0.0)

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(svc, "urlopen", lambda *a, **kw: _FakeConn())
    assert svc._idp_is_reachable("https://zitadel.example/token") is True


def test_client_credentials_raises_when_access_token_missing(monkeypatch) -> None:
    """Zitadel token endpoint returning no access_token must raise ValueError."""
    provider = ZitadelIdentityProvider(
        issuer_url="https://example",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )

    class _EmptyResp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"token_type": "Bearer"}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: _EmptyResp())
    with pytest.raises(ValueError, match="no access token"):
        provider.client_credentials_token(audience="aud", scope="s")


def test_okta_provider_inherits_oidc_base() -> None:
    assert issubclass(OktaIdentityProvider, OidcIdentityProvider)
    assert OktaIdentityProvider.provider_name == "okta"


def test_zitadel_provider_inherits_oidc_base() -> None:
    assert issubclass(ZitadelIdentityProvider, OidcIdentityProvider)
    assert ZitadelIdentityProvider.provider_name == "zitadel"


def test_okta_provider_from_env(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_ISSUER_URL", "https://dev-test.okta.com/oauth2/default")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/revoke")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_ID", "okta-client-id")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_SECRET", "okta-client-secret")
    p = OktaIdentityProvider.from_env()
    assert p.issuer_url == "https://dev-test.okta.com/oauth2/default"
    assert p.client_id == "okta-client-id"
    assert p.provider_name == "okta"


def test_okta_provider_methods_return_typed_shapes(monkeypatch) -> None:
    provider = OktaIdentityProvider(
        issuer_url="https://dev-test.okta.com/oauth2/default",
        token_endpoint="https://dev-test.okta.com/oauth2/default/v1/token",
        introspection_endpoint="https://dev-test.okta.com/oauth2/default/v1/introspect",
        revocation_endpoint="https://dev-test.okta.com/oauth2/default/v1/revoke",
        client_id="okta-cid",
        client_secret="okta-secret",
    )

    class _Resp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._payload

    def _fake_post(url: str, *, data: dict[str, str], headers=None, timeout: float = 5.0):
        if "introspect" in url:
            return _Resp({"active": True, "sub": "okta-user@example.com"})
        return _Resp({"access_token": "okta-access-token"})

    monkeypatch.setattr(httpx, "post", _fake_post)
    cc = provider.client_credentials_token(audience="api://default", scope="openid")
    assert cc["access_token"] == "okta-access-token"
    ex = provider.exchange_token(
        subject_token="subj", actor_token=None, audience="api://default", scope="s",
    )
    assert ex["access_token"] == "okta-access-token"
    intro = provider.introspect_token(token="okta-tok")
    assert intro["active"] is True
    rev = provider.revoke_token(token="okta-tok-12345678")
    assert rev["revoked"] is True


def test_get_identity_provider_returns_okta_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "okta")
    monkeypatch.setenv("CAMAZOTZ_IDP_ISSUER_URL", "https://dev-test.okta.com/oauth2/default")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/token")
    monkeypatch.setenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/introspect")
    monkeypatch.setenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "https://dev-test.okta.com/oauth2/default/v1/revoke")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_ID", "okta-cid")
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_SECRET", "okta-secret")
    p = get_identity_provider()
    assert isinstance(p, OktaIdentityProvider)
    assert p.issuer_url == "https://dev-test.okta.com/oauth2/default"


def test_oidc_provider_from_issuer_uses_discovery(monkeypatch) -> None:
    """OidcIdentityProvider.from_issuer() fetches .well-known and populates endpoints."""
    import brain_gateway.app.identity.oidc_provider as oidc_mod
    import json as _json

    discovery_response = _json.dumps({
        "issuer": "https://dev-test.okta.com/oauth2/default",
        "token_endpoint": "https://dev-test.okta.com/oauth2/default/v1/token",
        "introspection_endpoint": "https://dev-test.okta.com/oauth2/default/v1/introspect",
        "revocation_endpoint": "https://dev-test.okta.com/oauth2/default/v1/revoke",
    }).encode()

    class _FakeResp:
        def read(self):
            return discovery_response
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(oidc_mod, "urlopen", lambda *a, **kw: _FakeResp())
    provider = OidcIdentityProvider.from_issuer(
        "https://dev-test.okta.com/oauth2/default",
        client_id="cid",
        client_secret="secret",
    )
    assert provider.issuer_url == "https://dev-test.okta.com/oauth2/default"
    assert provider.token_endpoint == "https://dev-test.okta.com/oauth2/default/v1/token"
    assert provider.introspection_endpoint == "https://dev-test.okta.com/oauth2/default/v1/introspect"
    assert provider.revocation_endpoint == "https://dev-test.okta.com/oauth2/default/v1/revoke"


def test_exchange_token_raises_when_access_token_missing(monkeypatch) -> None:
    """Zitadel token exchange returning no access_token must raise ValueError."""
    provider = ZitadelIdentityProvider(
        issuer_url="https://example",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )

    class _EmptyResp:
        status_code = 200
        is_success = True
        headers: dict = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: _EmptyResp())
    with pytest.raises(ValueError, match="token exchange returned no access token"):
        provider.exchange_token(
            subject_token="alice@example.com",
            actor_token="agent-1",
            audience="mcp",
            scope="read",
        )
