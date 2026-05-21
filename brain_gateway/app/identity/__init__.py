"""Identity provider abstraction (mock default; ZITADEL, Okta, and Auth0 live)."""

from __future__ import annotations

from brain_gateway.app.identity.auth0_provider import Auth0IdentityProvider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.oidc_provider import OidcIdentityProvider
from brain_gateway.app.identity.okta_provider import OktaIdentityProvider
from brain_gateway.app.identity.provider import IdentityProvider

__all__ = [
    "Auth0IdentityProvider",
    "IdentityProvider",
    "MockIdentityProvider",
    "OidcIdentityProvider",
    "OktaIdentityProvider",
]
