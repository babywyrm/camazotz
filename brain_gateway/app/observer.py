"""Observer — records tool invocation events for audit trail.

Each event gets a UUID request_id and ISO-8601 timestamp.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

_lock = threading.Lock()
_last_event: dict | None = None


def record_event(tool_name: str, module: str) -> None:
    global _last_event
    with _lock:
        _last_event = {
            "request_id": str(uuid.uuid4()),
            "tool_name": tool_name,
            "module": module,
            "timestamp": datetime.now(UTC).isoformat(),
        }


def get_last_event() -> dict:
    with _lock:
        return dict(_last_event) if _last_event else {}
