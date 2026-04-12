from typing import Literal, get_type_hints

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity import IdentityProvider, MockIdentityProvider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider as MockIdentityProviderDirect
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
