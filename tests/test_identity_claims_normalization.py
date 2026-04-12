from __future__ import annotations

from brain_gateway.app.identity.service import normalize_claims


def test_normalize_claims_keeps_required_fields() -> None:
    raw = {"sub": "u1", "aud": ["api://cam"], "scope": "openid profile", "groups": ["platform-eng"]}
    normalized = normalize_claims(raw, env="local", tenant_id="camazotz-local")
    assert normalized["sub"] == "u1"
    assert normalized["env"] == "local"
    assert normalized["tenant_id"] == "camazotz-local"


def test_normalize_claims_coerces_string_aud_to_list() -> None:
    raw = {"sub": "u1", "aud": "api://single", "iss": "https://issuer.example"}
    normalized = normalize_claims(raw, env="nuc", tenant_id="camazotz-nuc")
    assert normalized["aud"] == ["api://single"]


def test_normalize_claims_includes_spec_envelope_fields() -> None:
    raw = {
        "sub": "user-42",
        "iss": "https://idp.example",
        "aud": ["api://a", "api://b"],
        "exp": 1700000000,
        "iat": 1699990000,
        "scope": "openid api",
        "client_id": "cid-1",
        "azp": "cid-1",
        "jti": "jit-1",
        "act": {"sub": "agent-1"},
        "team": "sec",
        "groups": ["g1"],
    }
    normalized = normalize_claims(raw, env="local", tenant_id="t1")
    assert normalized["iss"] == "https://idp.example"
    assert normalized["exp"] == 1700000000
    assert normalized["iat"] == 1699990000
    assert normalized["scope"] == "openid api"
    assert normalized["client_id"] == "cid-1"
    assert normalized["azp"] == "cid-1"
    assert normalized["jti"] == "jit-1"
    assert normalized["act"] == {"sub": "agent-1"}
    assert normalized["team"] == "sec"
    assert normalized["groups"] == ["g1"]


def test_normalize_claims_uses_azp_when_client_id_missing() -> None:
    raw = {"sub": "u", "azp": "portal-ui"}
    normalized = normalize_claims(raw, env="local", tenant_id="t")
    assert normalized["client_id"] == "portal-ui"


def test_normalize_claims_defaults_for_missing_optional_raw_claims() -> None:
    raw: dict = {"sub": "only-sub"}
    normalized = normalize_claims(raw, env="nuc", tenant_id="tenant-x")
    assert normalized["iss"] == ""
    assert normalized["aud"] == []
    assert normalized["exp"] == 0
    assert normalized["iat"] == 0
    assert normalized["scope"] == ""
    assert normalized["client_id"] == ""
    assert normalized["azp"] is None
    assert normalized["jti"] == ""
    assert normalized["act"] is None
    assert normalized["team"] == ""
    assert normalized["groups"] == []
