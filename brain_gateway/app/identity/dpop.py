"""DPoP (Demonstrating Proof of Possession) proof generator — RFC 9449.

Generates ephemeral EC P-256 key pairs and signed DPoP proof JWTs for
binding access tokens to a specific client.  Each proof includes the
HTTP method, target URL, and a unique jti to prevent replay.

Usage:
    ctx = DPoPContext()                         # new ephemeral key pair
    proof = ctx.create_proof("POST", url)       # signed JWT
    headers = {"DPoP": proof}                   # attach to token request

The same DPoPContext should be reused for the lifetime of a DPoP-bound
token (access token bound to the public key).  For subsequent requests
using that token, create new proofs with the same context and include
the ``ath`` (access token hash) claim.
"""

from __future__ import annotations

import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


class DPoPContext:
    """Manages an ephemeral EC P-256 key pair for DPoP proof generation."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()
        self._public_numbers = self._public_key.public_numbers()

    def _jwk_thumbprint(self) -> dict:
        """Return the public key as a JWK dict for the JWT header."""
        x_bytes = self._public_numbers.x.to_bytes(32, "big")
        y_bytes = self._public_numbers.y.to_bytes(32, "big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url(x_bytes),
            "y": _base64url(y_bytes),
        }

    def create_proof(
        self,
        htm: str,
        htu: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        """Create a signed DPoP proof JWT.

        Args:
            htm: HTTP method (e.g. "POST").
            htu: Target URL (e.g. the token endpoint).
            access_token: If provided, includes the ``ath`` claim
                (base64url-encoded SHA-256 hash of the token) for
                resource server requests with a bound token.
            nonce: Server-provided nonce (RFC 9449 §8).  Required by
                some providers (e.g. Okta) after the initial handshake.
        """
        headers = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self._jwk_thumbprint(),
        }
        payload: dict = {
            "jti": uuid.uuid4().hex,
            "htm": htm,
            "htu": _strip_query(htu),
            "iat": int(time.time()),
        }
        if nonce:
            payload["nonce"] = nonce
        if access_token:
            payload["ath"] = _base64url(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
        return jwt.encode(payload, self._private_key, algorithm="ES256", headers=headers)


def _base64url(data: bytes) -> str:
    """Base64url encode without padding (RFC 7515 §2)."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _strip_query(url: str) -> str:
    """Strip query/fragment from URL per RFC 9449 §4.3."""
    for sep in ("?", "#"):
        url = url.split(sep, 1)[0]
    return url
