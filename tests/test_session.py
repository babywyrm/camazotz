"""Tests for MCP session manager."""

from brain_gateway.app.session import SessionManager


def test_create_session_returns_uuid():
    mgr = SessionManager()
    sid = mgr.create()
    assert isinstance(sid, str)
    assert len(sid) == 36


def test_validate_known_session():
    mgr = SessionManager()
    sid = mgr.create()
    assert mgr.validate(sid) is True


def test_validate_unknown_session():
    mgr = SessionManager()
    assert mgr.validate("bogus") is False


def test_destroy_session():
    mgr = SessionManager()
    sid = mgr.create()
    mgr.destroy(sid)
    assert mgr.validate(sid) is False


def test_destroy_nonexistent_is_noop():
    mgr = SessionManager()
    mgr.destroy("does-not-exist")


def test_get_state_returns_defaults():
    mgr = SessionManager()
    sid = mgr.create()
    state = mgr.get_state(sid)
    assert isinstance(state, dict)
    assert state["difficulty"] == "medium"


def test_get_state_unknown_returns_empty():
    mgr = SessionManager()
    assert mgr.get_state("bogus") == {}


def test_set_state():
    mgr = SessionManager()
    sid = mgr.create()
    mgr.set_state(sid, "difficulty", "hard")
    assert mgr.get_state(sid)["difficulty"] == "hard"


def test_set_state_unknown_is_noop():
    mgr = SessionManager()
    mgr.set_state("bogus", "difficulty", "hard")


def test_sessions_are_isolated():
    mgr = SessionManager()
    s1 = mgr.create()
    s2 = mgr.create()
    mgr.set_state(s1, "difficulty", "hard")
    assert mgr.get_state(s1)["difficulty"] == "hard"
    assert mgr.get_state(s2)["difficulty"] == "medium"
