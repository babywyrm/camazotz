"""Generic OIDC identity provider — standard OAuth2 RFC calls.

Implements client credentials (RFC 6749), token exchange (RFC 8693),
introspection (RFC 7662), and revocation (RFC 7009).  Subclassed by
ZitadelIdentityProvider and OktaIdentityProvider for factory methods.

DPoP (RFC 9449) is handled transparently: if a token endpoint returns
``invalid_dpop_proof``, the provider creates a DPoP context and retries
with a signed proof.  The context is reused for subsequent requests so
that introspection and revocation proofs are bound to the same key.
"""

from __future__ import annotations

import json
import logging
from urllib.request import Request, urlopen

import httpx

from brain_gateway.app.identity.types import (
    ClientCredentialsTokenResponse,
    ExchangeTokenResponse,
    IntrospectTokenResponse,
    RevokeTokenResponse,
)

_log = logging.getLogger(__name__)


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
        self._dpop = None
        self._dpop_required: bool | None = None
        self._dpop_nonce: str | None = None

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

    def _ensure_dpop(self):
        """Lazily create or return the DPoP context."""
        if self._dpop is None:
            from brain_gateway.app.identity.dpop import DPoPContext
            self._dpop = DPoPContext()
            _log.info("%s: created ephemeral DPoP key pair", self.provider_name)
        return self._dpop

    def _extract_dpop_nonce(self, response: httpx.Response) -> str | None:
        """Extract server-provided nonce from DPoP-Nonce header (RFC 9449 §8)."""
        return response.headers.get("dpop-nonce") or response.headers.get("DPoP-Nonce")

    def _dpop_token_request(
        self, data: dict[str, str],
    ) -> httpx.Response:
        """Execute a token request with automatic DPoP negotiation.

        Handles the two-step handshake some providers (e.g. Okta) require:
        1. First request → ``invalid_dpop_proof`` → create DPoP context
        2. Retry with proof → ``use_dpop_nonce`` → extract nonce, retry again
        """
        headers: dict[str, str] = {}
        max_retries = 3

        if self._dpop_required is True:
            dpop = self._ensure_dpop()
            headers["DPoP"] = dpop.create_proof(
                "POST", self.token_endpoint, nonce=self._dpop_nonce,
            )

        for attempt in range(max_retries):
            response = httpx.post(
                self.token_endpoint, data=data, headers=headers, timeout=5.0,
            )

            dpop_err = self._dpop_error(response)
            if dpop_err is None:
                break

            if dpop_err == "invalid_dpop_proof" and self._dpop_required is None:
                _log.info("%s: DPoP required, retrying with proof", self.provider_name)
                self._dpop_required = True
                dpop = self._ensure_dpop()

            server_nonce = self._extract_dpop_nonce(response)
            if server_nonce:
                _log.info("%s: server provided DPoP nonce", self.provider_name)
                self._dpop_nonce = server_nonce

            if self._dpop_required:
                dpop = self._ensure_dpop()
                headers["DPoP"] = dpop.create_proof(
                    "POST", self.token_endpoint, nonce=self._dpop_nonce,
                )

        if self._dpop_required is None and response.is_success:
            self._dpop_required = False

        return response

    def _dpop_error(self, response: httpx.Response) -> str | None:
        """Return the DPoP error type, or None if not a DPoP error."""
        if response.status_code != 400:
            return None
        try:
            body = response.json()
        except Exception:
            return None
        err = body.get("error", "")
        if err in ("invalid_dpop_proof", "use_dpop_nonce"):
            return err
        return None

    def client_credentials_token(
        self, *, audience: str, scope: str
    ) -> ClientCredentialsTokenResponse:
        self._require_token_endpoint()
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": audience,
            "scope": scope,
        }
        response = self._dpop_token_request(data)
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
        headers: dict[str, str] = {}
        if self._dpop_required and self._dpop:
            headers["DPoP"] = self._dpop.create_proof(
                "POST", self.introspection_endpoint,
                access_token=token, nonce=self._dpop_nonce,
            )
        response = httpx.post(
            self.introspection_endpoint,
            data={
                "token": token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers=headers,
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
        headers: dict[str, str] = {}
        if self._dpop_required and self._dpop:
            headers["DPoP"] = self._dpop.create_proof(
                "POST", self.revocation_endpoint,
                access_token=token, nonce=self._dpop_nonce,
            )
        response = httpx.post(
            self.revocation_endpoint,
            data={
                "token": token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers=headers,
            timeout=5.0,
        )
        response.raise_for_status()
        hint = token[:8] if len(token) >= 8 else token
        return {"revoked": True, "token_hint": hint}
