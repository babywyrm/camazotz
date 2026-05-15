"""Identity provider abstraction (mock default; ZITADEL and Okta live)."""

from __future__ import annotations

from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.oidc_provider import OidcIdentityProvider
from brain_gateway.app.identity.okta_provider import OktaIdentityProvider
from brain_gateway.app.identity.provider import IdentityProvider

__all__ = [
    "IdentityProvider",
    "MockIdentityProvider",
    "OidcIdentityProvider",
    "OktaIdentityProvider",
]
