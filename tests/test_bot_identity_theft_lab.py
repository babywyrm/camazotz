"""Tests for the Bot Identity Theft lab (MCP-T18)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_bot_identity_theft_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "bot_identity_theft.read_tbot_secret" in names
    assert "bot_identity_theft.replay_identity" in names
    assert "bot_identity_theft.check_session_binding" in names


def test_read_tbot_secret_easy_returns_full_identity() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.read_tbot_secret",
        {"namespace": "teleport"},
    )
    assert result["accessible"] is True
    assert result["cert_serial"]
    assert "agent-mcp" in result["roles"]
    assert result["_difficulty"] == "easy"


def test_read_tbot_secret_medium_narrows_roles() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.read_tbot_secret",
        {"namespace": "teleport"},
    )
    assert result["accessible"] is True
    assert result["roles"] == ["agent-readonly"]
    assert "_note" in result


def test_read_tbot_secret_hard_is_forbidden() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.read_tbot_secret",
        {"namespace": "teleport"},
    )
    assert result["accessible"] is False
    assert "forbidden" in result["error"].lower()


def test_replay_identity_easy_grants_access_with_flag() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.replay_identity",
        {"cert_serial": "any-value"},
    )
    assert result["valid"] is True
    assert result["flag"].startswith("CZTZ{")


def test_replay_identity_medium_rejects_wrong_serial() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.replay_identity",
        {"cert_serial": "wrong-value"},
    )
    assert result["valid"] is False
    assert "mismatch" in result["reason"]


def test_replay_identity_medium_accepts_correct_serial() -> None:
    """The medium path grants access when the stolen cert_serial is presented verbatim."""
    from camazotz_modules.bot_identity_theft_lab.app.main import _BOT_CERT_SERIAL

    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.replay_identity",
        {"cert_serial": _BOT_CERT_SERIAL},
    )
    assert result["valid"] is True
    assert result["flag"].startswith("CZTZ{")


def test_replay_identity_hard_rejects_with_session_binding_signal() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "bot_identity_theft.replay_identity",
        {"cert_serial": "anything"},
    )
    assert result["valid"] is False
    assert result["_session_binding"] == "MISMATCH_DETECTED"


def test_check_session_binding_detects_mismatch() -> None:
    client = TestClient(app)
    mismatch = tool_call(
        client,
        "bot_identity_theft.check_session_binding",
        {"original_identity": "alice", "presented_identity": "bob"},
    )
    assert mismatch["session_binding_check"] == "MISMATCH"
    assert mismatch["nullfield_action"].startswith("DENY")


def test_check_session_binding_allows_matching_identity() -> None:
    client = TestClient(app)
    ok = tool_call(
        client,
        "bot_identity_theft.check_session_binding",
        {"original_identity": "alice", "presented_identity": "alice"},
    )
    assert ok["session_binding_check"] == "OK"
    assert ok["nullfield_action"] == "ALLOW"


def test_reset_restarts_issued_at() -> None:
    import time
    from brain_gateway.app.modules.registry import get_registry

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "bot_identity_theft")
    old = mod._issued_at
    time.sleep(0.01)
    mod.reset()
    assert mod._issued_at >= old
    assert mod._stolen_count == 0
