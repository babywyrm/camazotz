"""Tests for the Short-Lived Certificate Replay lab (MCP-T19)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_cert_replay_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 1)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "cert_replay.get_expired_cert" in names
    assert "cert_replay.replay_cert" in names
    assert "cert_replay.check_replay_detection" in names


def test_get_expired_cert_returns_unique_id() -> None:
    client = TestClient(app)
    a = tool_call(client, "cert_replay.get_expired_cert", {"age_seconds": 5})
    b = tool_call(client, "cert_replay.get_expired_cert", {"age_seconds": 5})
    assert a["cert_id"] != b["cert_id"]
    assert a["expired_seconds_ago"] == 5
    # not_before < not_after (TTL-seconds earlier), and both are in the past.
    assert a["not_before"] < a["not_after"]


def test_replay_cert_easy_accepts_any_expired_cert() -> None:
    import time
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "c1", "not_after": time.time() - 10},
    )
    assert result["access"] == "granted"
    assert result["flag"].startswith("CZTZ{")


def test_replay_cert_medium_accepts_inside_grace_window() -> None:
    import time
    set_difficulty("medium")
    client = TestClient(app)
    inside = tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "c2", "not_after": time.time() - 10},
    )
    assert inside["access"] == "granted"
    assert "grace_window" in inside


def test_replay_cert_medium_rejects_outside_grace_window() -> None:
    import time
    set_difficulty("medium")
    client = TestClient(app)
    outside = tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "c3", "not_after": time.time() - 120},
    )
    assert outside["access"] == "denied"
    assert "grace" in outside["reason"]


def test_replay_cert_hard_rejects_and_detects_replay() -> None:
    import time
    set_difficulty("hard")
    client = TestClient(app)
    first = tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "replay-me", "not_after": time.time() - 10},
    )
    assert first["access"] == "denied"

    replay = tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "replay-me", "not_after": time.time() - 10},
    )
    assert replay["access"] == "denied"
    assert replay.get("_replay_detected") is True


def test_check_replay_detection_first_use_and_seen() -> None:
    import time
    set_difficulty("hard")
    client = TestClient(app)
    first = tool_call(
        client,
        "cert_replay.check_replay_detection",
        {"cert_id": "nonce-1"},
    )
    assert first["previously_seen"] is False
    assert first["replay_detection"] == "FIRST_USE"

    tool_call(
        client,
        "cert_replay.replay_cert",
        {"cert_id": "nonce-1", "not_after": time.time() - 5},
    )
    seen = tool_call(
        client,
        "cert_replay.check_replay_detection",
        {"cert_id": "nonce-1"},
    )
    assert seen["previously_seen"] is True
    assert seen["replay_detection"] == "BLOCKED"


def test_reset_clears_replay_set() -> None:
    from brain_gateway.app.modules.registry import get_registry

    reg = get_registry()
    mod = next(m for m in reg._modules if m.name == "cert_replay")
    mod._seen_cert_ids.add("x")
    mod._replay_count = 1
    mod.reset()
    assert mod._seen_cert_ids == set()
    assert mod._replay_count == 0
