"""Auth0 identity provider — thin subclass of OidcIdentityProvider.

Supports two construction modes:
  - ``from_env()``: reads the same ``CAMAZOTZ_IDP_*`` env vars (explicit endpoints)
  - ``from_issuer()``: OIDC discovery from an Auth0 tenant URL

Auth0 tenant URLs follow the pattern:
  - ``https://{your-tenant}.auth0.com``
  - ``https://{your-tenant}.{region}.auth0.com``
  - Custom domain: ``https://auth.{your-domain}.com``
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


class Auth0IdentityProvider(OidcIdentityProvider):
    """Live Auth0 identity provider.

    Inherits all OAuth2 RFC logic from OidcIdentityProvider.
    """

    provider_name: str = "auth0"

    @classmethod
    def from_env(cls) -> Auth0IdentityProvider:
        """Build from ``CAMAZOTZ_IDP_*`` environment variables."""
        return cls(
            issuer_url=get_idp_issuer_url(),
            token_endpoint=get_idp_token_endpoint(),
            introspection_endpoint=get_idp_introspection_endpoint(),
            revocation_endpoint=get_idp_revocation_endpoint(),
            client_id=get_idp_client_id(),
            client_secret=get_idp_client_secret(),
        )
