import threading
from datetime import UTC, datetime

_lock = threading.Lock()
_last_event: dict | None = None


def record_event(tool_name: str, module: str) -> None:
    global _last_event
    now = datetime.now(UTC)
    with _lock:
        _last_event = {
            "request_id": f"req-{now.timestamp()}",
            "tool_name": tool_name,
            "module": module,
            "timestamp": now.isoformat(),
        }


def get_last_event() -> dict:
    with _lock:
        return dict(_last_event) if _last_event else {}
