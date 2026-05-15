"""ZITADEL identity provider — thin subclass of OidcIdentityProvider."""

from __future__ import annotations

from brain_gateway.app.config import (
    get_idp_client_id,
    get_idp_client_secret,
    get_idp_introspection_endpoint,
    get_idp_issuer_url,
    get_idp_revocation_endpoint,
    get_idp_token_endpoint,
)
from brain_gateway.app.identity.oidc_provider import OidcIdentityProvider


class ZitadelIdentityProvider(OidcIdentityProvider):
    """Live ZITADEL identity provider.

    Inherits all OAuth2 RFC logic from OidcIdentityProvider.
    Provides a ``from_env()`` factory for CAMAZOTZ_IDP_* env vars
    and a ``from_issuer()`` that targets ZITADEL's discovery endpoint.
    """

    provider_name: str = "zitadel"

    @classmethod
    def from_env(cls) -> ZitadelIdentityProvider:
        return cls(
            issuer_url=get_idp_issuer_url(),
            token_endpoint=get_idp_token_endpoint(),
            introspection_endpoint=get_idp_introspection_endpoint(),
            revocation_endpoint=get_idp_revocation_endpoint(),
            client_id=get_idp_client_id(),
            client_secret=get_idp_client_secret(),
        )
