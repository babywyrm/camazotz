import os
import uuid

import pytest

from brain_gateway.app import observer
from brain_gateway.app.observer import (
    _check_canary,
    _derive_outcome,
    _derive_verdict,
    _summarize_response,
    get_buffer_info,
    get_events,
    get_events_since,
    get_last_event,
    record_event,
    reset_events,
)


def _make_event(**overrides):
    defaults = dict(
        tool_name="test.tool",
        module="test_module",
        guardrail="none",
        arguments={"key": "value"},
        result={"allowed": True},
        ai_analysis="",
        duration_ms=42,
    )
    defaults.update(overrides)
    return defaults


@pytest.fixture(autouse=True)
def _clean_buffer(monkeypatch):
    monkeypatch.delenv("OBSERVER_BUFFER_SIZE", raising=False)
    observer._init_buffer()
    yield
    observer._init_buffer()


# ── ring buffer basics ──────────────────────────────────────────────

def test_ring_buffer_stores_events():
    record_event(**_make_event(tool_name="probe.scan", module="recon"))
    events = get_events()
    assert len(events) == 1
    ev = events[0]
    uuid.UUID(ev["request_id"])
    assert "T" in ev["timestamp"]
    assert ev["tool_name"] == "probe.scan"
    assert ev["module"] == "recon"
    assert ev["guardrail"] == "none"
    assert ev["arguments"] == {"key": "value"}
    assert ev["outcome"] == "granted"
    assert ev["ai_analysis"] == ""
    assert ev["verdict"] == "ai_irrelevant"
    assert ev["duration_ms"] == 42
    assert isinstance(ev["response_summary"], dict)
    assert ev["canary_exposed"] is False


def test_ring_buffer_respects_max_size(monkeypatch):
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "3")
    observer._init_buffer()
    for i in range(5):
        record_event(**_make_event(tool_name=f"tool_{i}"))
    events = get_events()
    assert len(events) == 3
    assert events[0]["tool_name"] == "tool_4"
    assert events[2]["tool_name"] == "tool_2"
    info = get_buffer_info()
    assert info["buffer_size"] == 3
    assert info["total_recorded"] == 5


def test_get_events_limit():
    for i in range(5):
        record_event(**_make_event(tool_name=f"tool_{i}"))
    events = get_events(limit=2)
    assert len(events) == 2
    assert events[0]["tool_name"] == "tool_4"
    assert events[1]["tool_name"] == "tool_3"


def test_get_events_since():
    record_event(**_make_event(tool_name="A"))
    record_event(**_make_event(tool_name="B"))
    watermark = get_events()[0]["request_id"]  # B is newest
    record_event(**_make_event(tool_name="C"))
    since = get_events_since(watermark)
    assert len(since) == 1
    assert since[0]["tool_name"] == "C"


def test_get_events_since_unknown_id():
    record_event(**_make_event(tool_name="X"))
    record_event(**_make_event(tool_name="Y"))
    since = get_events_since("nonexistent-id")
    assert len(since) == 2
    assert since[0]["tool_name"] == "Y"


# ── outcome derivation ──────────────────────────────────────────────

def test_derive_outcome_granted():
    assert _derive_outcome({"token": "abc123"}) == "granted"
    assert _derive_outcome({"allowed": True}) == "granted"
    assert _derive_outcome({"executed": True}) == "granted"


def test_derive_outcome_denied():
    assert _derive_outcome({"allowed": False}) == "denied"
    assert _derive_outcome({"denied": True}) == "denied"
    assert _derive_outcome({"blocked": True}) == "denied"
    assert _derive_outcome({"registered": False}) == "denied"


def test_derive_outcome_leaked():
    assert _derive_outcome({"_redacted": False}) == "leaked"


def test_derive_outcome_error():
    assert _derive_outcome({"_error": "something broke"}) == "error"


def test_derive_outcome_unknown():
    assert _derive_outcome({"some_random_key": 42}) == "unknown"


# ── verdict derivation ──────────────────────────────────────────────

def test_derive_verdict_ai_denied_tool_allowed():
    result = {"token": "abc123"}
    analysis = "I would not recommend allowing this tool invocation"
    assert _derive_verdict(analysis, result) == "ai_denied_tool_allowed"


def test_derive_verdict_ai_agreed():
    result = {"token": "abc123"}
    analysis = "This invocation looks safe and expected"
    assert _derive_verdict(analysis, result) == "ai_agreed"


def test_derive_verdict_ai_irrelevant():
    assert _derive_verdict("", {"token": "abc"}) == "ai_irrelevant"
    assert _derive_verdict("", {}) == "ai_irrelevant"


# ── helpers ─────────────────────────────────────────────────────────

def test_summarize_response_truncates():
    result = {"short": "hi", "long": "x" * 200}
    summary = _summarize_response(result)
    assert summary["short"] == "hi"
    assert len(summary["long"]) == 103  # 100 + "..."
    assert summary["long"].endswith("...")


def test_check_canary_true():
    assert _check_canary({"data": "flag is CZTZ{s3cr3t}"}) is True


def test_check_canary_false():
    assert _check_canary({"data": "nothing here"}) is False


# ── backwards compatibility ─────────────────────────────────────────

def test_backwards_compatible_last_event():
    record_event(**_make_event(tool_name="compat.tool"))
    ev = get_last_event()
    assert ev["tool_name"] == "compat.tool"
    uuid.UUID(ev["request_id"])
    assert "T" in ev["timestamp"]


# ── buffer size clamping ────────────────────────────────────────────

def test_buffer_size_clamped_high(monkeypatch):
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "999")
    observer._init_buffer()
    info = get_buffer_info()
    assert info["buffer_size"] == 200


def test_buffer_size_clamped_low(monkeypatch):
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "0")
    observer._init_buffer()
    info = get_buffer_info()
    assert info["buffer_size"] == 1


# ── integration (existing test, updated for new signature) ──────────

def test_gateway_emits_observer_event_for_tool_invocation():
    from fastapi.testclient import TestClient

    from brain_gateway.app.main import app

    reset_events()
    client = TestClient(app)
    payload = {
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "context.injectable_summary", "arguments": {"text": "hello"}},
    }
    resp = client.post("/mcp", json=payload)
    assert resp.status_code == 200

    event_resp = client.get("/_observer/last-event")
    assert event_resp.status_code == 200
    event = event_resp.json()
    assert event["tool_name"] == "context.injectable_summary"
    uuid.UUID(event["request_id"])
    assert "T" in event["timestamp"]


def test_observer_events_endpoint() -> None:
    from fastapi.testclient import TestClient

    from brain_gateway.app.main import app

    reset_events()
    record_event(tool_name="test.a", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    record_event(tool_name="test.b", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=2)

    client = TestClient(app)
    resp = client.get("/_observer/events")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "buffer_size" in data
    assert "total_recorded" in data
    assert len(data["events"]) == 2
    assert data["events"][0]["tool_name"] == "test.b"


def test_observer_events_limit() -> None:
    from fastapi.testclient import TestClient

    from brain_gateway.app.main import app

    reset_events()
    for i in range(5):
        record_event(tool_name=f"t.{i}", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)

    client = TestClient(app)
    resp = client.get("/_observer/events?limit=2")
    data = resp.json()
    assert len(data["events"]) == 2


def test_observer_events_since() -> None:
    from fastapi.testclient import TestClient

    from brain_gateway.app.main import app

    reset_events()
    record_event(tool_name="old", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    watermark = get_events()[0]["request_id"]
    record_event(tool_name="new", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)

    client = TestClient(app)
    resp = client.get(f"/_observer/events?since={watermark}")
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["tool_name"] == "new"
