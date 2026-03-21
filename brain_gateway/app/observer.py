from datetime import UTC, datetime

_last_event: dict | None = None


def record_event(tool_name: str, module: str) -> None:
    global _last_event
    _last_event = {
        "request_id": f"req-{datetime.now(UTC).timestamp()}",
        "tool_name": tool_name,
        "module": module,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def get_last_event() -> dict:
    return _last_event or {}
