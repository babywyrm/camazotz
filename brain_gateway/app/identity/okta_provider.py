"""Okta identity provider — thin subclass of OidcIdentityProvider.

Supports two construction modes:
  - ``from_env()``: reads the same ``CAMAZOTZ_IDP_*`` env vars (explicit endpoints)
  - ``from_issuer()``: OIDC discovery from an Okta org URL or authorization server

Okta authorization server URLs follow the pattern:
  - Org authorization server: ``https://{your-org}.okta.com``
  - Custom authorization server: ``https://{your-org}.okta.com/oauth2/{server-id}``
  - Default authorization server: ``https://{your-org}.okta.com/oauth2/default``
"""

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


class OktaIdentityProvider(OidcIdentityProvider):
    """Live Okta identity provider.

    Inherits all OAuth2 RFC logic from OidcIdentityProvider.
    """

    provider_name: str = "okta"

    @classmethod
    def from_env(cls) -> OktaIdentityProvider:
        """Build from ``CAMAZOTZ_IDP_*`` environment variables."""
        return cls(
            issuer_url=get_idp_issuer_url(),
            token_endpoint=get_idp_token_endpoint(),
            introspection_endpoint=get_idp_introspection_endpoint(),
            revocation_endpoint=get_idp_revocation_endpoint(),
            client_id=get_idp_client_id(),
            client_secret=get_idp_client_secret(),
        )
