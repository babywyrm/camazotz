"""Tests for the DPoP Forgery lab (MCP-T43).

DPoP (RFC 9449) binds tokens to a cryptographic key. When the private key
is leaked, an attacker can forge DPoP proofs with correct htm/htu bindings
and gain access to protected resources. The gateway returns descriptive
401 errors that guide the player through the required claims.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")
    reset_registry()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_all_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "dpop.get_service_info" in names
    assert "dpop.request_access" in names
    assert "dpop.sign_proof" in names
    assert "dpop.access_resource" in names


# ---------------------------------------------------------------------------
# dpop.get_service_info — leaks RSA key material
# ---------------------------------------------------------------------------


def test_get_service_info_returns_topology() -> None:
    client = TestClient(app)
    result = tool_call(client, "dpop.get_service_info", {})
    assert "service" in result
    assert "dpop_required" in result
    assert result["dpop_required"] is True


def test_get_service_info_leaks_key_easy() -> None:
    """On easy, the private key material is directly present."""
    client = TestClient(app)
    result = tool_call(client, "dpop.get_service_info", {})
    assert "dpop_private_key" in result
    key = result["dpop_private_key"]
    assert isinstance(key, str) and len(key) > 10


def test_get_service_info_hard_key_nested() -> None:
    """On hard, the key is in a nested deployment_config field."""
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "dpop.get_service_info", {})
    # On hard, the key is not at top level
    assert "dpop_private_key" not in result
    # But is findable in deployment_config
    assert "deployment_config" in result
    config = result["deployment_config"]
    assert "signing_key" in config or "dpop_key" in config


# ---------------------------------------------------------------------------
# dpop.request_access — iterative 401 discovery
# ---------------------------------------------------------------------------


def test_request_access_no_auth_returns_401() -> None:
    client = TestClient(app)
    result = tool_call(client, "dpop.request_access", {"authorization": ""})
    assert result.get("http_status") == 401
    assert "no bearer token" in result.get("error", "").lower()


def test_request_access_garbage_token_401() -> None:
    client = TestClient(app)
    result = tool_call(client, "dpop.request_access", {"authorization": "Bearer garbage123"})
    assert result.get("http_status") == 401
    assert "malformed" in result.get("error", "").lower() or "invalid" in result.get("error", "").lower()


def test_request_access_missing_htm_returns_401() -> None:
    """Valid JWT structure but missing htm claim → descriptive 401."""
    client = TestClient(app)
    result = tool_call(client, "dpop.request_access", {
        "authorization": "Bearer eyJ.valid_but_no_htm.sig",
    })
    assert result.get("http_status") == 401
    assert "htm" in result.get("error", "").lower()


def test_request_access_wrong_htm_returns_401() -> None:
    """htm=POST on a GET endpoint → descriptive 401."""
    client = TestClient(app)
    result = tool_call(client, "dpop.request_access", {
        "authorization": "Bearer eyJ.wrong_htm.sig",
        "htm": "POST",
    })
    assert result.get("http_status") == 401
    assert "htm" in result.get("error", "").lower()


def test_request_access_wrong_htu_returns_401() -> None:
    """Correct htm but wrong htu → descriptive 401."""
    client = TestClient(app)
    result = tool_call(client, "dpop.request_access", {
        "authorization": "Bearer eyJ.wrong_htu.sig",
        "htm": "GET",
        "htu": "http://wrong.endpoint/other",
    })
    assert result.get("http_status") == 401
    assert "htu" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# dpop.sign_proof — forges a DPoP JWT
# ---------------------------------------------------------------------------


def test_sign_proof_returns_token() -> None:
    client = TestClient(app)
    # Get the key first
    info = tool_call(client, "dpop.get_service_info", {})
    key = info["dpop_private_key"]
    result = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    assert "proof_token" in result
    assert result.get("success") is True


def test_sign_proof_wrong_key_fails() -> None:
    client = TestClient(app)
    result = tool_call(client, "dpop.sign_proof", {
        "key_material": "wrong-key-material",
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    assert result.get("success") is False


def test_sign_proof_includes_htm_htu_in_claims() -> None:
    client = TestClient(app)
    info = tool_call(client, "dpop.get_service_info", {})
    key = info["dpop_private_key"]
    result = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    claims = result.get("claims", {})
    assert claims.get("htm") == "GET"
    assert claims.get("htu") == "http://gateway.internal/api/secret"


# ---------------------------------------------------------------------------
# dpop.access_resource — protected resource, flag behind DPoP
# ---------------------------------------------------------------------------


def test_access_resource_no_proof_denied() -> None:
    client = TestClient(app)
    result = tool_call(client, "dpop.access_resource", {
        "proof": "",
        "method": "GET",
        "path": "/api/secret",
    })
    assert result.get("status") == "denied"
    assert "CZTZ{" not in str(result)


def test_access_resource_wrong_htm_denied() -> None:
    """Proof with wrong htm is rejected even with correct key."""
    client = TestClient(app)
    info = tool_call(client, "dpop.get_service_info", {})
    key = info["dpop_private_key"]
    # Sign with wrong method
    proof = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "POST",  # wrong — should be GET
        "htu": "http://gateway.internal/api/secret",
    })
    result = tool_call(client, "dpop.access_resource", {
        "proof": proof["proof_token"],
        "method": "GET",
        "path": "/api/secret",
    })
    assert result.get("status") == "denied"
    assert "htm" in result.get("reason", "").lower()


def test_access_resource_wrong_htu_denied() -> None:
    """Proof with wrong htu is rejected even with correct key and htm."""
    client = TestClient(app)
    info = tool_call(client, "dpop.get_service_info", {})
    key = info["dpop_private_key"]
    proof = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "GET",
        "htu": "http://gateway.internal/api/other",  # wrong path
    })
    result = tool_call(client, "dpop.access_resource", {
        "proof": proof["proof_token"],
        "method": "GET",
        "path": "/api/secret",
    })
    assert result.get("status") == "denied"
    assert "htu" in result.get("reason", "").lower()


def test_access_resource_valid_proof_succeeds() -> None:
    """Correct key + correct htm + correct htu = access granted + flag."""
    client = TestClient(app)
    info = tool_call(client, "dpop.get_service_info", {})
    key = info["dpop_private_key"]
    proof = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    result = tool_call(client, "dpop.access_resource", {
        "proof": proof["proof_token"],
        "method": "GET",
        "path": "/api/secret",
    })
    assert result.get("status") == "allowed"
    assert "CZTZ{" in result.get("secret", "")
    assert result.get("_flags", {}).get("dpop_forged") is True


# ---------------------------------------------------------------------------
# Full bypass chain
# ---------------------------------------------------------------------------


def test_full_bypass_chain_easy() -> None:
    """
    1. get_service_info leaks key
    2. request_access iterates through 401 errors (htm, htu discovery)
    3. sign_proof forges token with correct htm/htu
    4. access_resource succeeds → flag
    """
    client = TestClient(app)

    # Step 1: get leaked key
    info = tool_call(client, "dpop.get_service_info", {})
    assert "dpop_private_key" in info
    key = info["dpop_private_key"]

    # Step 2: iterative discovery (optional, skip to known claims)
    r1 = tool_call(client, "dpop.request_access", {"authorization": ""})
    assert r1["http_status"] == 401

    # Step 3: forge proof
    proof = tool_call(client, "dpop.sign_proof", {
        "key_material": key,
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    assert proof["success"] is True

    # Step 4: access resource
    result = tool_call(client, "dpop.access_resource", {
        "proof": proof["proof_token"],
        "method": "GET",
        "path": "/api/secret",
    })
    assert result["status"] == "allowed"
    assert "CZTZ{" in result["secret"]


def test_flag_format() -> None:
    client = TestClient(app)
    info = tool_call(client, "dpop.get_service_info", {})
    proof = tool_call(client, "dpop.sign_proof", {
        "key_material": info["dpop_private_key"],
        "htm": "GET",
        "htu": "http://gateway.internal/api/secret",
    })
    result = tool_call(client, "dpop.access_resource", {
        "proof": proof["proof_token"],
        "method": "GET",
        "path": "/api/secret",
    })
    secret = result.get("secret", "")
    assert secret.startswith("CZTZ{")
    assert secret.endswith("}")


def test_difficulty_propagated() -> None:
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        client = TestClient(app)
        result = tool_call(client, "dpop.get_service_info", {})
        assert result.get("_difficulty") == diff
