"""Tests for DPoP proof generation and OIDC provider DPoP integration."""

from __future__ import annotations

import json
import time

import jwt
import pytest

from brain_gateway.app.identity.dpop import DPoPContext
from brain_gateway.app.identity.oidc_provider import OidcIdentityProvider


# -- DPoPContext unit tests ---------------------------------------------------


class TestDPoPContext:
    def test_create_proof_returns_valid_jwt(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/oauth2/token")
        header = jwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header

    def test_proof_header_contains_ec_public_key(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/oauth2/token")
        header = jwt.get_unverified_header(proof)
        jwk = header["jwk"]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_proof_claims_contain_required_fields(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/oauth2/token")
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://idp.example/oauth2/token"
        assert "jti" in claims
        assert "iat" in claims
        assert abs(claims["iat"] - time.time()) < 5

    def test_proof_strips_query_from_htu(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/token?foo=bar")
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert claims["htu"] == "https://idp.example/token"

    def test_proof_strips_fragment_from_htu(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("GET", "https://idp.example/token#frag")
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert claims["htu"] == "https://idp.example/token"

    def test_proof_includes_ath_when_access_token_provided(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof(
            "POST", "https://idp.example/introspect",
            access_token="eyJhbGciOi.test.token",
        )
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert "ath" in claims
        assert len(claims["ath"]) > 0

    def test_proof_omits_ath_when_no_access_token(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/token")
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert "ath" not in claims

    def test_proof_includes_nonce_when_provided(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof(
            "POST", "https://idp.example/token", nonce="server-nonce-abc",
        )
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert claims["nonce"] == "server-nonce-abc"

    def test_proof_omits_nonce_when_not_provided(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/token")
        claims = jwt.decode(proof, options={"verify_signature": False})
        assert "nonce" not in claims

    def test_successive_proofs_have_unique_jti(self) -> None:
        ctx = DPoPContext()
        p1 = ctx.create_proof("POST", "https://idp.example/token")
        p2 = ctx.create_proof("POST", "https://idp.example/token")
        c1 = jwt.decode(p1, options={"verify_signature": False})
        c2 = jwt.decode(p2, options={"verify_signature": False})
        assert c1["jti"] != c2["jti"]

    def test_same_context_reuses_key(self) -> None:
        ctx = DPoPContext()
        p1 = ctx.create_proof("POST", "https://idp.example/token")
        p2 = ctx.create_proof("POST", "https://idp.example/token")
        h1 = jwt.get_unverified_header(p1)
        h2 = jwt.get_unverified_header(p2)
        assert h1["jwk"] == h2["jwk"]

    def test_different_contexts_use_different_keys(self) -> None:
        ctx1 = DPoPContext()
        ctx2 = DPoPContext()
        p1 = ctx1.create_proof("POST", "https://idp.example/token")
        p2 = ctx2.create_proof("POST", "https://idp.example/token")
        h1 = jwt.get_unverified_header(p1)
        h2 = jwt.get_unverified_header(p2)
        assert h1["jwk"] != h2["jwk"]

    def test_proof_signature_verifies(self) -> None:
        ctx = DPoPContext()
        proof = ctx.create_proof("POST", "https://idp.example/token")
        header = jwt.get_unverified_header(proof)
        from cryptography.hazmat.primitives.asymmetric import ec
        public_key = ctx._public_key
        decoded = jwt.decode(
            proof, public_key, algorithms=["ES256"],
            options={"verify_aud": False},
        )
        assert decoded["htm"] == "POST"


# -- OIDC provider DPoP integration tests ------------------------------------


def _mock_resp(status_code: int, body: dict, *, dpop_nonce: str | None = None):
    """Build a fake httpx.Response-like object for test mocks."""
    hdrs = {}
    if dpop_nonce:
        hdrs["dpop-nonce"] = dpop_nonce

    class _Headers(dict):
        def get(self, key, default=None):
            return super().get(key.lower(), default)

    class _R:
        def __init__(self):
            self.status_code = status_code
            self.is_success = status_code < 400
            self.headers = _Headers({k.lower(): v for k, v in hdrs.items()})

        def json(self):
            return body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP {self.status_code}")

    return _R()


def _make_provider(**overrides) -> OidcIdentityProvider:
    defaults = {
        "issuer_url": "https://idp.example",
        "token_endpoint": "https://idp.example/oauth2/token",
        "introspection_endpoint": "https://idp.example/oauth2/introspect",
        "revocation_endpoint": "https://idp.example/oauth2/revoke",
        "client_id": "test-client",
        "client_secret": "test-secret",
    }
    defaults.update(overrides)
    return OidcIdentityProvider(**defaults)


class TestOidcDPoPIntegration:
    def test_provider_starts_with_no_dpop_context(self) -> None:
        provider = _make_provider()
        assert provider._dpop is None
        assert provider._dpop_required is None

    def test_dpop_auto_detected_on_invalid_dpop_proof(self, monkeypatch) -> None:
        """Provider detects DPoP requirement and retries with proof."""
        call_count = 0

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_resp(400, {"error": "invalid_dpop_proof"}, dpop_nonce="srv-nonce")
            if call_count == 2:
                return _mock_resp(200, {"access_token": "dpop-bound-token", "token_type": "DPoP"})
            return _mock_resp(200, {"access_token": "dpop-bound-token"})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        result = provider.client_credentials_token(audience="api://test", scope="openid")
        assert result["access_token"] == "dpop-bound-token"
        assert provider._dpop_required is True
        assert provider._dpop is not None

    def test_dpop_nonce_negotiation(self, monkeypatch) -> None:
        """Provider handles the DPoP + nonce two-step handshake (Okta-style)."""
        call_count = 0

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_resp(400, {"error": "invalid_dpop_proof"}, dpop_nonce="nonce-1")
            if call_count == 2:
                proof = (headers or {}).get("DPoP", "")
                claims = jwt.decode(proof, options={"verify_signature": False})
                if claims.get("nonce") == "nonce-1":
                    return _mock_resp(200, {"access_token": "nonce-bound-token"})
                return _mock_resp(400, {"error": "use_dpop_nonce"}, dpop_nonce="nonce-1")
            return _mock_resp(200, {"access_token": "nonce-bound-token"})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        result = provider.client_credentials_token(audience="api://test", scope="openid")
        assert result["access_token"] == "nonce-bound-token"
        assert provider._dpop_nonce == "nonce-1"

    def test_dpop_not_required_cached(self, monkeypatch) -> None:
        """When first request succeeds without DPoP, provider remembers."""
        def _mock_post(url, *, data=None, headers=None, timeout=None):
            return _mock_resp(200, {"access_token": "plain-token"})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        result = provider.client_credentials_token(audience="api://test", scope="openid")
        assert result["access_token"] == "plain-token"
        assert provider._dpop_required is False
        assert provider._dpop is None

    def test_dpop_proof_sent_on_subsequent_calls(self, monkeypatch) -> None:
        """Once DPoP is detected, subsequent calls include proof immediately."""
        captured_headers: list[dict] = []

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            captured_headers.append(dict(headers or {}))
            return _mock_resp(200, {"access_token": "token-" + str(len(captured_headers))})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        provider._dpop_required = True
        result = provider.client_credentials_token(audience="api://test", scope="openid")
        assert "DPoP" in captured_headers[0]
        proof = captured_headers[0]["DPoP"]
        header = jwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"

    def test_introspect_includes_dpop_when_required(self, monkeypatch) -> None:
        captured_headers: list[dict] = []

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            captured_headers.append(dict(headers or {}))
            return _mock_resp(200, {"active": True, "sub": "user@test"})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        provider._dpop_required = True
        provider._dpop = DPoPContext()
        provider.introspect_token(token="some-access-token")
        assert "DPoP" in captured_headers[0]
        claims = jwt.decode(captured_headers[0]["DPoP"], options={"verify_signature": False})
        assert "ath" in claims

    def test_revoke_includes_dpop_when_required(self, monkeypatch) -> None:
        captured_headers: list[dict] = []

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            captured_headers.append(dict(headers or {}))
            return _mock_resp(200, {})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        provider._dpop_required = True
        provider._dpop = DPoPContext()
        provider.revoke_token(token="some-access-token")
        assert "DPoP" in captured_headers[0]
        claims = jwt.decode(captured_headers[0]["DPoP"], options={"verify_signature": False})
        assert "ath" in claims

    def test_introspect_no_dpop_when_not_required(self, monkeypatch) -> None:
        captured_headers: list[dict] = []

        def _mock_post(url, *, data=None, headers=None, timeout=None):
            captured_headers.append(dict(headers or {}))
            return _mock_resp(200, {"active": True, "sub": "user@test"})

        monkeypatch.setattr("brain_gateway.app.identity.oidc_provider.httpx.post", _mock_post)
        provider = _make_provider()
        provider._dpop_required = False
        provider.introspect_token(token="some-token")
        assert "DPoP" not in captured_headers[0]
