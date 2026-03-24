"""MCP session manager — Streamable HTTP transport.

Each session gets a UUID, isolated state, and a creation timestamp.
Thread-safe for concurrent access.
"""

from __future__ import annotations

import threading
import uuid
from typing import Any


class SessionManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}

    def create(self) -> str:
        sid = str(uuid.uuid4())
        with self._lock:
            self._sessions[sid] = {
                "difficulty": "medium",
            }
        return sid

    def validate(self, sid: str) -> bool:
        with self._lock:
            return sid in self._sessions

    def destroy(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def get_state(self, sid: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return {}
            return dict(session)

    def set_state(self, sid: str, key: str, value: Any) -> None:
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                session[key] = value
