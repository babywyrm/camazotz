from typing import Literal, get_type_hints

import pytest

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity import IdentityProvider, MockIdentityProvider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider as MockIdentityProviderDirect
from brain_gateway.app.identity.provider import IdentityProvider as IdentityProviderProtocol
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
    assert get_idp_provider() == "zitadel"


def test_get_idp_provider_invalid_falls_back_to_mock(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "unknown")
    assert get_idp_provider() == "mock"


def test_get_idp_provider_return_type_is_idp_literal() -> None:
    ret = get_type_hints(get_idp_provider)["return"]
    assert ret == Literal["mock", "zitadel"]
    assert getattr(ret, "__args__", ()) == ("mock", "zitadel")


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


def test_zitadel_provider_methods_return_typed_shapes_when_configured() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="https://example/token",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
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
