"""Generic OIDC identity provider — standard OAuth2 RFC calls.

Implements client credentials (RFC 6749), token exchange (RFC 8693),
introspection (RFC 7662), and revocation (RFC 7009).  Subclassed by
ZitadelIdentityProvider and OktaIdentityProvider for factory methods.
"""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

import httpx

from brain_gateway.app.identity.types import (
    ClientCredentialsTokenResponse,
    ExchangeTokenResponse,
    IntrospectTokenResponse,
    RevokeTokenResponse,
)


class OidcIdentityProvider:
    """Standard OIDC provider using RFC-compliant OAuth2 endpoints."""

    provider_name: str = "oidc"

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
    def from_issuer(cls, issuer_url: str, *, client_id: str, client_secret: str) -> OidcIdentityProvider:
        """Build from OIDC discovery (``/.well-known/openid-configuration``)."""
        discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        req = Request(discovery_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=5) as resp:
            meta = json.loads(resp.read())

        return cls(
            issuer_url=meta.get("issuer", issuer_url),
            token_endpoint=meta.get("token_endpoint", ""),
            introspection_endpoint=meta.get("introspection_endpoint", ""),
            revocation_endpoint=meta.get("revocation_endpoint", ""),
            client_id=client_id,
            client_secret=client_secret,
        )

    def _require_token_endpoint(self) -> None:
        if not self.token_endpoint:
            raise ValueError("Missing token endpoint")

    def client_credentials_token(
        self, *, audience: str, scope: str
    ) -> ClientCredentialsTokenResponse:
        self._require_token_endpoint()
        response = httpx.post(
            self.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": audience,
                "scope": scope,
            },
            timeout=5.0,
        )
        response.raise_for_status()
        payload = response.json()
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError(f"{self.provider_name} token endpoint returned no access token")
        return {
            "access_token": access_token,
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
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": subject_token,
            "audience": audience,
            "scope": scope,
        }
        if actor_token:
            data["actor_token"] = actor_token
        response = httpx.post(self.token_endpoint, data=data, timeout=5.0)
        response.raise_for_status()
        payload = response.json()
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError(f"{self.provider_name} token exchange returned no access token")
        return {
            "access_token": access_token,
            "aud": audience,
            "scope": scope,
            "act": actor_token,
            "sub": subject_token,
        }

    def introspect_token(self, *, token: str) -> IntrospectTokenResponse:
        if not self.introspection_endpoint:
            raise ValueError("Missing introspection endpoint")
        response = httpx.post(
            self.introspection_endpoint,
            data={
                "token": token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=5.0,
        )
        response.raise_for_status()
        payload = response.json()
        return {
            "active": bool(payload.get("active", False)),
            "sub": payload.get("sub", "") if isinstance(payload.get("sub", ""), str) else "",
        }

    def revoke_token(self, *, token: str) -> RevokeTokenResponse:
        if not self.revocation_endpoint:
            raise ValueError("Missing revocation endpoint")
        response = httpx.post(
            self.revocation_endpoint,
            data={
                "token": token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=5.0,
        )
        response.raise_for_status()
        hint = token[:8] if len(token) >= 8 else token
        return {"revoked": True, "token_hint": hint}
