"""Observer sidecar — polls the brain gateway for tool invocation events.

Intentionally weak audit trail (OWASP MCP08). Logs events to stdout
in JSON format. No persistence, no correlation, no tamper protection.
"""

import json
import os
import sys
import time
from datetime import UTC, datetime
from urllib.error import URLError
from urllib.request import Request, urlopen

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://brain-gateway:8080")
POLL_INTERVAL = int(os.getenv("OBSERVER_POLL_INTERVAL", "2"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "info").lower()

_last_seen_id: str | None = None


def _log(level: str, msg: str, **extra: object) -> None:
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "msg": msg,
        **extra,
    }
    print(json.dumps(entry), flush=True)


def poll_once() -> None:
    global _last_seen_id
    try:
        req = Request(f"{GATEWAY_URL}/_observer/last-event", method="GET")
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except (URLError, OSError, ValueError):
        if LOG_LEVEL == "debug":
            _log("debug", "gateway unreachable")
        return

    if not data:
        return

    request_id = data.get("request_id")
    if request_id and request_id != _last_seen_id:
        _last_seen_id = request_id
        _log("event", "tool_invocation", **data)


def main() -> None:
    _log("info", "observer sidecar starting", gateway=GATEWAY_URL, poll_interval=POLL_INTERVAL)
    while True:
        poll_once()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":  # pragma: no cover
    try:
        main()
    except KeyboardInterrupt:
        _log("info", "observer shutting down")
        sys.exit(0)
