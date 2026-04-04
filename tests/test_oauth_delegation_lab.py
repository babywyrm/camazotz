"""Tests for the OAuth Token Theft & Replay lab (MCP-T21)."""

import base64
import json

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


def test_oauth_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "oauth.list_connections" in names
    assert "oauth.exchange_token" in names
    assert "oauth.call_downstream" in names


# -- list_connections ---------------------------------------------------------


def test_list_connections_easy_leaks_tokens() -> None:
    client = TestClient(app)
    result = _call(
        client, "oauth.list_connections", {"principal": "alice@example.com"}
    )
    assert result["count"] == 2
    assert "access_token" in result["connections"]["github"]


def test_list_connections_medium_hides_tokens() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client, "oauth.list_connections", {"principal": "alice@example.com"}
    )
    assert "access_token" not in result["connections"]["github"]
    assert result["connections"]["github"]["connected"] is True


def test_list_connections_unknown_principal() -> None:
    client = TestClient(app)
    result = _call(
        client, "oauth.list_connections", {"principal": "nobody@example.com"}
    )
    assert result["count"] == 0


# -- exchange_token -----------------------------------------------------------


def test_exchange_token_easy_any_refresh_works() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "anything",
        },
    )
    assert result["exchanged"] is True
    assert result["access_token"].startswith("cztz-")


def test_exchange_token_medium_valid_refresh() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "cztz-gh-refresh-alice-c3d4",
        },
    )
    assert result["exchanged"] is True


def test_exchange_token_medium_base64_encoded_refresh() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    encoded = base64.b64encode(b"cztz-gh-refresh-alice-c3d4").decode()
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": encoded,
        },
    )
    assert result["exchanged"] is True


def test_exchange_token_medium_invalid_refresh() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "wrong-token",
        },
    )
    assert result["exchanged"] is False
    assert "Invalid" in result["reason"]


def test_exchange_token_medium_bad_base64() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "!!!not-base64!!!",
        },
    )
    assert result["exchanged"] is False


def test_exchange_token_hard_valid_refresh() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "cztz-gh-refresh-alice-c3d4",
        },
    )
    assert result["exchanged"] is True


def test_exchange_token_hard_invalid_refresh() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "wrong",
        },
    )
    assert result["exchanged"] is False


def test_exchange_token_unknown_service() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "nonexistent",
            "refresh_token": "anything",
        },
    )
    assert result["exchanged"] is False
    assert "No token found" in result["reason"]


# -- call_downstream ----------------------------------------------------------


def test_call_downstream_valid_token() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "oauth.call_downstream",
        {
            "service": "github",
            "access_token": "cztz-gh-access-alice-a1b2",
            "action": "read-repos",
        },
    )
    assert result["success"] is True
    assert result["acted_as"] == "alice@example.com"


def test_call_downstream_invalid_token() -> None:
    client = TestClient(app)
    result = _call(
        client,
        "oauth.call_downstream",
        {
            "service": "github",
            "access_token": "invalid-token",
        },
    )
    assert result["success"] is False
    assert "Invalid" in result["reason"]


# -- resources ----------------------------------------------------------------


def test_oauth_resources_listed() -> None:
    client = TestClient(app)
    body = _rpc(client, "resources/list", {}, 50)
    uris = {r["uri"] for r in body["result"]["resources"]}
    assert "oauth://token_store/github" in uris


def test_oauth_read_resource_easy_leaks_tokens() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "oauth://token_store/github"}, 51
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert "alice@example.com" in content
    assert content["alice@example.com"]["access_token"].startswith("cztz-")


def test_oauth_read_resource_medium_base64() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "oauth://token_store/github"}, 52
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    raw = base64.b64decode(
        content["alice@example.com"]["access_token"]
    ).decode()
    assert raw.startswith("cztz-")


def test_oauth_read_resource_hard_no_tokens() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "oauth://token_store/github"}, 53
    )
    content = json.loads(body["result"]["contents"][0]["text"])
    assert "access_token" not in content["alice@example.com"]
    assert content["alice@example.com"]["has_token"] is True


def test_oauth_read_resource_unknown_service() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "oauth://token_store/nonexistent"}, 54
    )
    assert "error" in body


def test_oauth_read_resource_wrong_prefix() -> None:
    client = TestClient(app)
    body = _rpc(
        client, "resources/read", {"uri": "other://something"}, 55
    )
    assert "error" in body


# -- reset --------------------------------------------------------------------


def test_oauth_reset_restores_tokens() -> None:
    client = TestClient(app)
    _call(
        client,
        "oauth.exchange_token",
        {
            "principal": "alice@example.com",
            "service": "github",
            "refresh_token": "anything",
        },
    )
    reset_registry()
    set_difficulty("easy")
    client = TestClient(app)
    result = _call(
        client, "oauth.list_connections", {"principal": "alice@example.com"}
    )
    assert result["connections"]["github"]["access_token"] == "cztz-gh-access-alice-a1b2"
