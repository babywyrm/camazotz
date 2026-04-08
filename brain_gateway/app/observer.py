"""Observer — ring-buffered enriched event system for audit trail.

Each event gets a UUID request_id, ISO-8601 timestamp, and derived
outcome/verdict fields. Events are stored in a bounded deque whose
size is controlled by the OBSERVER_BUFFER_SIZE env var (default 50,
clamped to [1, 200]).
"""

from __future__ import annotations

import collections
import json
import os
import re
import threading
import uuid
from datetime import UTC, datetime

_lock = threading.Lock()
_last_event: dict | None = None
_buffer: collections.deque[dict] = collections.deque(maxlen=50)
_total_recorded: int = 0

_GRANT_KEYS = frozenset({
    "token", "approved", "registered", "executed", "allowed",
    "found", "triggered", "exchanged", "recorded", "billed",
})

# Strong denial cues only — avoid bare "suspicious" (false positives on
# phrases like "not suspicious" / "nothing suspicious").
_DENY_PATTERN = re.compile(
    r"\b(?:"
    r"deny|denied|reject|rejected|refuse|refused|block|blocked|unsafe|"
    r"not recommend|must not|should not|do not allow|cannot allow|"
    r"I (?:would|do) not recommend|recommend against"
    r")\b",
    re.IGNORECASE,
)


def _init_buffer() -> None:
    """(Re)initialise the ring buffer from OBSERVER_BUFFER_SIZE env var."""
    global _buffer, _total_recorded, _last_event
    raw = os.environ.get("OBSERVER_BUFFER_SIZE", "")
    try:
        size = int(raw)
    except (ValueError, TypeError):
        size = 50
    size = max(1, min(size, 200))
    _buffer = collections.deque(maxlen=size)
    _total_recorded = 0
    _last_event = None


def _derive_outcome(result: dict) -> str:
    if "_error" in result:
        return "error"
    if result.get("_redacted") is False:
        return "leaked"
    if (
        result.get("registered") is False
        or result.get("allowed") is False
        or result.get("denied") is True
        or result.get("blocked") is True
    ):
        return "denied"
    for key in _GRANT_KEYS:
        if key in result and result[key] is not False:
            return "granted"
    return "unknown"


def _derive_verdict(ai_analysis: str, result: dict) -> str:
    if not ai_analysis:
        return "ai_irrelevant"
    if _DENY_PATTERN.search(ai_analysis):
        for key in _GRANT_KEYS:
            if key in result and result[key] is not False:
                return "ai_denied_tool_allowed"
    return "ai_agreed"


def _derive_signal_tier(
    outcome: str,
    verdict: str,
    canary_exposed: bool,
) -> str:
    """Rough priority for triage: high = review first, low = usually benign."""
    if canary_exposed or outcome == "leaked" or verdict == "ai_denied_tool_allowed":
        return "high"
    if outcome == "error":
        return "high"
    if outcome == "granted":
        return "medium"
    if outcome == "unknown":
        return "medium"
    if outcome == "denied":
        return "low"
    return "low"


def _derive_reason_code(
    outcome: str,
    verdict: str,
    canary_exposed: bool,
) -> str:
    """Short machine-readable label for UI and cross-tool correlation."""
    if canary_exposed:
        return "canary_exposed"
    if outcome == "leaked":
        return "sensitive_disclosure"
    if outcome == "error":
        return "tool_error"
    if verdict == "ai_denied_tool_allowed":
        return "confused_deputy"
    if outcome == "denied":
        return "policy_denied"
    if outcome == "granted":
        if verdict == "ai_agreed":
            return "ai_endorsed_grant"
        if verdict == "ai_irrelevant":
            return "unreviewed_grant"
        return "grant"
    if verdict == "ai_agreed":
        return "ai_endorsed"
    return "inconclusive"


def _summarize_response(result: dict) -> dict:
    summary: dict[str, str] = {}
    for key, value in result.items():
        s = str(value)
        summary[key] = s[:100] + "..." if len(s) > 100 else s
    return summary


def _check_canary(result: dict) -> bool:
    return "CZTZ{" in json.dumps(result)


def record_event(
    *,
    tool_name: str,
    module: str,
    guardrail: str,
    arguments: dict,
    result: dict,
    ai_analysis: str,
    duration_ms: int,
) -> None:
    global _last_event, _total_recorded
    outcome = _derive_outcome(result)
    verdict = _derive_verdict(ai_analysis, result)
    canary = _check_canary(result)
    event = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "tool_name": tool_name,
        "module": module,
        "guardrail": guardrail,
        "arguments": arguments,
        "outcome": outcome,
        "ai_analysis": ai_analysis[:200] if ai_analysis else "",
        "verdict": verdict,
        "signal_tier": _derive_signal_tier(outcome, verdict, canary),
        "reason_code": _derive_reason_code(outcome, verdict, canary),
        "duration_ms": duration_ms,
        "response_summary": _summarize_response(result),
        "canary_exposed": canary,
    }
    with _lock:
        _buffer.append(event)
        _total_recorded += 1
        _last_event = event


def get_last_event() -> dict:
    with _lock:
        return dict(_last_event) if _last_event else {}


def get_events(limit: int | None = None) -> list[dict]:
    with _lock:
        events = list(reversed(_buffer))
    if limit is not None:
        return events[:limit]
    return events


def get_events_since(request_id: str) -> list[dict]:
    with _lock:
        items = list(_buffer)
    idx = None
    for i, ev in enumerate(items):
        if ev["request_id"] == request_id:
            idx = i
            break
    if idx is None:
        return list(reversed(items))
    after = items[idx + 1:]
    after.reverse()
    return after


def get_buffer_info() -> dict:
    with _lock:
        return {
            "buffer_size": _buffer.maxlen,
            "total_recorded": _total_recorded,
        }


def reset_events() -> None:
    global _total_recorded, _last_event
    with _lock:
        _buffer.clear()
        _total_recorded = 0
        _last_event = None


# Initialise on import
_init_buffer()
