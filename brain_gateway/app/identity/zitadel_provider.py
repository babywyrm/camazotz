from __future__ import annotations

from brain_gateway.app.config import (
    get_idp_client_id,
    get_idp_client_secret,
    get_idp_introspection_endpoint,
    get_idp_issuer_url,
    get_idp_revocation_endpoint,
    get_idp_token_endpoint,
)
from brain_gateway.app.identity.types import (
    ClientCredentialsTokenResponse,
    ExchangeTokenResponse,
    IntrospectTokenResponse,
    RevokeTokenResponse,
)


class ZitadelIdentityProvider:
    """Task 2 stub provider for ZITADEL-backed identity.

    This class validates configuration and returns deterministic placeholder
    responses. Real HTTP interactions are introduced in later tasks.
    """

    def __init__(
        self,
        *,
        issuer_url: str,
        token_endpoint: str,
        introspection_endpoint: str,
        revocation_endpoint: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self.issuer_url = issuer_url
        self.token_endpoint = token_endpoint
        self.introspection_endpoint = introspection_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.client_id = client_id
        self.client_secret = client_secret

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

    def _require_token_endpoint(self) -> None:
        if not self.token_endpoint:
            raise ValueError("Missing token endpoint")

    def client_credentials_token(
        self, *, audience: str, scope: str
    ) -> ClientCredentialsTokenResponse:
        self._require_token_endpoint()
        return {
            "access_token": "zitadel-placeholder",
            "aud": audience,
            "scope": scope,
        }

    def exchange_token(
        self,
        *,
        subject_token: str,
        actor_token: str | None,
        audience: str,
        scope: str,
    ) -> ExchangeTokenResponse:
        self._require_token_endpoint()
        return {
            "access_token": "zitadel-exchanged-placeholder",
            "aud": audience,
            "scope": scope,
            "act": actor_token,
            "sub": subject_token,
        }

    def introspect_token(self, *, token: str) -> IntrospectTokenResponse:
        if not self.introspection_endpoint:
            raise ValueError("Missing introspection endpoint")
        return {"active": token.startswith("zitadel-"), "sub": ""}

    def revoke_token(self, *, token: str) -> RevokeTokenResponse:
        if not self.revocation_endpoint:
            raise ValueError("Missing revocation endpoint")
        hint = token[:8] if len(token) >= 8 else token
        return {"revoked": True, "token_hint": hint}