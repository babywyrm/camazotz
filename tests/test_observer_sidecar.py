import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture()
def observer_mod():
    """Import the observer sidecar module."""
    observer_dir = str(Path(__file__).resolve().parents[1] / "compose" / "observer")
    if observer_dir not in sys.path:
        sys.path.insert(0, observer_dir)
    sys.modules.pop("main", None)
    import main as mod
    mod._last_seen_id = None
    yield mod
    sys.path.remove(observer_dir)
    sys.modules.pop("main", None)


def test_log_outputs_json(observer_mod, capsys) -> None:
    observer_mod._log("info", "test message", extra_key="val")
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["level"] == "info"
    assert data["msg"] == "test message"
    assert data["extra_key"] == "val"
    assert "ts" in data


def test_poll_once_new_event(observer_mod, capsys) -> None:
    event = {"request_id": "req-1", "tool_name": "auth.issue_token", "module": "AuthLabModule"}
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(event).encode()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("main.urlopen", return_value=mock_resp):
        observer_mod.poll_once()

    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["level"] == "event"
    assert data["tool_name"] == "auth.issue_token"
    assert observer_mod._last_seen_id == "req-1"


def test_poll_once_duplicate_event_ignored(observer_mod, capsys) -> None:
    observer_mod._last_seen_id = "req-1"
    event = {"request_id": "req-1", "tool_name": "auth.issue_token"}
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(event).encode()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("main.urlopen", return_value=mock_resp):
        observer_mod.poll_once()

    out = capsys.readouterr().out.strip()
    assert out == ""


def test_poll_once_empty_response(observer_mod, capsys) -> None:
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"{}"
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("main.urlopen", return_value=mock_resp):
        observer_mod.poll_once()

    out = capsys.readouterr().out.strip()
    assert out == ""


def test_poll_once_gateway_unreachable(observer_mod, capsys) -> None:
    from urllib.error import URLError
    with patch("main.urlopen", side_effect=URLError("refused")):
        observer_mod.poll_once()
    out = capsys.readouterr().out.strip()
    assert out == ""


def test_poll_once_gateway_unreachable_debug(observer_mod, capsys, monkeypatch) -> None:
    monkeypatch.setattr(observer_mod, "LOG_LEVEL", "debug")
    from urllib.error import URLError
    with patch("main.urlopen", side_effect=URLError("refused")):
        observer_mod.poll_once()
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["level"] == "debug"
    assert "unreachable" in data["msg"]


def test_main_loop_runs_and_can_break(observer_mod, capsys) -> None:
    call_count = 0

    def fake_sleep(_):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise KeyboardInterrupt

    with patch("main.poll_once"), patch("main.time.sleep", side_effect=fake_sleep):
        with pytest.raises(KeyboardInterrupt):
            observer_mod.main()

    out = capsys.readouterr().out.strip()
    assert "observer sidecar starting" in out
    assert call_count == 2
