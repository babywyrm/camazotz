"""Tests for the SDK Token Cache Poisoning lab (MCP-T33).

Lane 1 / Transport C: SDK-level trust — cached JWT reused without re-validating
the signature.  Attacker writes a crafted token to the SDK cache and invokes a
privileged operation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call

_SIGNING_SECRET = b"cztz-sdk-hmac-secret-v1"
_ISSUER = "https://camazotz.local/sdk-idp"


def _forge_token(role: str, exp_offset: int = 3600, sign: bool = False) -> str:
    """Build a fake JWT-shaped token; optionally sign with the real secret."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": "attacker",
                "role": role,
                "iss": _ISSUER,
                "exp": int(time.time()) + exp_offset,
                "iat": int(time.time()),
            }
        ).encode()
    ).rstrip(b"=")
    signing_input = header + b"." + payload
    if sign:
        sig = hmac.new(_SIGNING_SECRET, signing_input, hashlib.sha256).digest()
    else:
        sig = b"fakesignature"
    signature = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + signature).decode()


def setup_function() -> None:
    set_difficulty("easy")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_sdk_tamper_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "sdk.get_cached_token" in names
    assert "sdk.write_cache" in names
    assert "sdk.invoke_as_cached" in names


# ---------------------------------------------------------------------------
# Easy difficulty — blind cache trust
# ---------------------------------------------------------------------------


def test_easy_get_cached_returns_reader_token() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "sdk.get_cached_token", {})
    assert result["cached_role"] == "reader"
    assert result["_difficulty"] == "easy"


def test_easy_write_cache_accepts_arbitrary_token() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "sdk.write_cache",
        {"token": "totally-fake-token", "cached_role": "admin"},
    )
    assert result["written"] is True
    assert result["cached_role"] == "admin"


def test_easy_invoke_grants_admin_from_poisoned_cache() -> None:
    """Core exploit: write admin role to cache, invoke succeeds on easy."""
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(
        client,
        "sdk.write_cache",
        {"token": "attacker-token", "cached_role": "admin"},
    )
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-secrets"})
    assert result["access"] == "granted"
    assert result["effective_role"] == "admin"
    assert "api_key" in result["data"]


def test_easy_read_config_accessible_to_reader() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    # Reset to default reader cache.
    tool_call(
        client,
        "sdk.write_cache",
        {"token": "reader-token", "cached_role": "reader"},
    )
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-config"})
    assert result["access"] == "granted"


def test_easy_admin_reset_denied_for_reader() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(
        client,
        "sdk.write_cache",
        {"token": "reader-token", "cached_role": "reader"},
    )
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "admin-reset"})
    assert result["access"] == "denied"


# ---------------------------------------------------------------------------
# Medium difficulty — expiry checked, signature not verified
# ---------------------------------------------------------------------------


def test_medium_forged_unexpired_token_grants_admin() -> None:
    """Medium: signature is never checked — an unsigned forged token with valid exp works."""
    set_difficulty("medium")
    client = TestClient(app)
    forged = _forge_token("admin", exp_offset=3600, sign=False)
    tool_call(client, "sdk.write_cache", {"token": forged, "cached_role": "admin"})
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-secrets"})
    assert result["access"] == "granted"
    assert result["effective_role"] == "admin"


def test_medium_expired_token_is_denied() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    expired = _forge_token("admin", exp_offset=-3600, sign=False)
    tool_call(client, "sdk.write_cache", {"token": expired, "cached_role": "admin"})
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-secrets"})
    assert result["access"] == "denied"
    assert "expired" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Hard difficulty — full signature + issuer validation
# ---------------------------------------------------------------------------


def test_hard_unsigned_forged_token_is_rejected() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    forged = _forge_token("admin", exp_offset=3600, sign=False)
    tool_call(client, "sdk.write_cache", {"token": forged, "cached_role": "admin"})
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-secrets"})
    assert result["access"] == "denied"
    assert "signature" in result["reason"].lower()


def test_hard_correctly_signed_admin_token_grants_access() -> None:
    """Hard: a token signed with the real secret is accepted."""
    set_difficulty("hard")
    client = TestClient(app)
    valid = _forge_token("admin", exp_offset=3600, sign=True)
    tool_call(client, "sdk.write_cache", {"token": valid, "cached_role": "admin"})
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "admin-reset"})
    assert result["access"] == "granted"
    assert result["effective_role"] == "admin"


def test_hard_expired_but_valid_sig_is_denied() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    expired = _forge_token("admin", exp_offset=-3600, sign=True)
    tool_call(client, "sdk.write_cache", {"token": expired, "cached_role": "admin"})
    result = tool_call(client, "sdk.invoke_as_cached", {"operation": "read-secrets"})
    assert result["access"] == "denied"
    assert "expired" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Reset / state isolation
# ---------------------------------------------------------------------------


def test_reset_restores_reader_cache() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    tool_call(
        client,
        "sdk.write_cache",
        {"token": "attacker-token", "cached_role": "admin"},
    )
    # Reset state via the gateway reset endpoint.
    resp = client.post("/reset")
    assert resp.status_code == 200
    result = tool_call(client, "sdk.get_cached_token", {})
    assert result["cached_role"] == "reader"


# ---------------------------------------------------------------------------
# Scenario metadata
# ---------------------------------------------------------------------------


def test_sdk_tamper_scenario_yaml_present() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    names = [s["module_name"] for s in scenarios]
    assert "sdk_tamper_lab" in names


def test_sdk_tamper_agentic_lane_metadata() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    scenarios = resp.json()
    sdk = next(s for s in scenarios if s["module_name"] == "sdk_tamper_lab")
    ag = sdk.get("agentic", {})
    assert ag.get("primary_lane") == 1
    assert ag.get("transport") == "C"
