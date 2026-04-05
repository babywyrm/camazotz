# Observer Telemetry Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the observer from a single-event stub into a ring-buffered telemetry system with enriched events, two frontend modes (Vulnerable/Enhanced), and a walkthrough telemetry strip.

**Architecture:** Enrich `brain_gateway/app/observer.py` with a `deque`-backed ring buffer and derivation helpers. Expand `record_event()` signature in `mcp_handlers.py`. Add `GET /_observer/events` endpoint. Redesign the observer frontend with two tabs. Add a compact telemetry strip to the walkthrough player.

**Tech Stack:** Python/FastAPI backend, vanilla JS frontend, `collections.deque` for ring buffer, pytest for testing.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `brain_gateway/app/observer.py` | **Major rewrite.** Ring buffer, enriched event model, derivation helpers. |
| `brain_gateway/app/mcp_handlers.py` | **Modify.** Enrich `record_event()` call with timing, guardrail, arguments, result. |
| `brain_gateway/app/main.py` | **Modify.** Add `GET /_observer/events` endpoint. |
| `frontend/app.py` | **Modify.** Add `/api/observer/events` proxy route, update `/observer` route. |
| `frontend/templates/observer.html` | **Major rewrite.** Two-tab layout, enhanced timeline, verdict highlighting. |
| `frontend/templates/operator.html` | **Modify.** Add telemetry strip to walkthrough player. |
| `tests/test_observer_events.py` | **Extend.** Ring buffer, enrichment, new endpoint tests. |
| `tests/test_operator.py` | **Extend.** Telemetry strip rendering assertions. |
| `deploy/helm/camazotz/values.yaml` | **Modify.** Add `observerBufferSize`. |
| `deploy/helm/camazotz/templates/configmap.yaml` | **Modify.** Add `OBSERVER_BUFFER_SIZE`. |
| `compose/.env.example` | **Modify.** Add `OBSERVER_BUFFER_SIZE=10`. |

---

## Task 1: Ring buffer and enriched event model

**Files:**
- Modify: `brain_gateway/app/observer.py`
- Test: `tests/test_observer_events.py`

- [ ] **Step 1: Write failing tests for ring buffer and enrichment**

Add to `tests/test_observer_events.py`:

```python
from brain_gateway.app.observer import record_event, get_events, get_events_since, get_last_event, _derive_outcome, _derive_verdict, _summarize_response, _check_canary, reset_events


def test_ring_buffer_stores_events() -> None:
    reset_events()
    record_event(
        tool_name="auth.issue_token", module="AuthLab", guardrail="medium",
        arguments={"username": "alice"}, result={"token": "cztz-test", "_difficulty": "medium"},
        ai_analysis="Looks fine", duration_ms=100,
    )
    events = get_events()
    assert len(events) == 1
    assert events[0]["tool_name"] == "auth.issue_token"
    assert events[0]["guardrail"] == "medium"
    assert events[0]["duration_ms"] == 100


def test_ring_buffer_respects_max_size(monkeypatch) -> None:
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "3")
    from brain_gateway.app import observer
    observer._init_buffer()
    reset_events()
    for i in range(5):
        record_event(
            tool_name=f"tool.{i}", module="Test", guardrail="easy",
            arguments={}, result={}, ai_analysis="", duration_ms=1,
        )
    events = get_events()
    assert len(events) == 3
    assert events[0]["tool_name"] == "tool.4"


def test_get_events_limit() -> None:
    reset_events()
    for i in range(5):
        record_event(
            tool_name=f"tool.{i}", module="Test", guardrail="easy",
            arguments={}, result={}, ai_analysis="", duration_ms=1,
        )
    events = get_events(limit=2)
    assert len(events) == 2


def test_get_events_since() -> None:
    reset_events()
    record_event(tool_name="a", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    record_event(tool_name="b", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    all_events = get_events()
    watermark = all_events[1]["request_id"]
    record_event(tool_name="c", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    since = get_events_since(watermark)
    assert len(since) == 1
    assert since[0]["tool_name"] == "c"


def test_get_events_since_unknown_id() -> None:
    reset_events()
    record_event(tool_name="a", module="T", guardrail="easy", arguments={}, result={}, ai_analysis="", duration_ms=1)
    since = get_events_since("nonexistent-id")
    assert len(since) == 1


def test_derive_outcome_granted() -> None:
    assert _derive_outcome({"token": "abc", "_difficulty": "easy"}) == "granted"


def test_derive_outcome_denied() -> None:
    assert _derive_outcome({"registered": False, "block_reason": "not allowed"}) == "denied"


def test_derive_outcome_leaked() -> None:
    assert _derive_outcome({"config": {"DB": "secret"}, "_redacted": False}) == "leaked"


def test_derive_outcome_error() -> None:
    assert _derive_outcome({"_error": "timeout"}) == "error"


def test_derive_outcome_unknown() -> None:
    assert _derive_outcome({"_difficulty": "easy"}) == "unknown"


def test_derive_verdict_ai_denied_tool_allowed() -> None:
    assert _derive_verdict("I recommend denying this request", {"token": "abc"}) == "ai_denied_tool_allowed"


def test_derive_verdict_ai_agreed() -> None:
    assert _derive_verdict("This looks safe, approving", {"token": "abc"}) == "ai_agreed"


def test_derive_verdict_ai_irrelevant() -> None:
    assert _derive_verdict("", {"tenants": ["alice"]}) == "ai_irrelevant"


def test_summarize_response_truncates() -> None:
    result = {"key": "x" * 200, "short": "ok"}
    summary = _summarize_response(result)
    assert len(summary["key"]) <= 103
    assert summary["short"] == "ok"


def test_check_canary_true() -> None:
    assert _check_canary({"data": "found CZTZ{test_flag} here"}) is True


def test_check_canary_false() -> None:
    assert _check_canary({"data": "nothing special"}) is False


def test_backwards_compatible_last_event() -> None:
    reset_events()
    record_event(
        tool_name="test.tool", module="TestMod", guardrail="easy",
        arguments={}, result={}, ai_analysis="", duration_ms=50,
    )
    last = get_last_event()
    assert last["tool_name"] == "test.tool"
    assert "request_id" in last
    assert "timestamp" in last


def test_buffer_size_clamped_high(monkeypatch) -> None:
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "999")
    from brain_gateway.app import observer
    observer._init_buffer()
    assert observer._events.maxlen == 200


def test_buffer_size_clamped_low(monkeypatch) -> None:
    monkeypatch.setenv("OBSERVER_BUFFER_SIZE", "0")
    from brain_gateway.app import observer
    observer._init_buffer()
    assert observer._events.maxlen == 10
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_observer_events.py -v --no-cov`
Expected: FAIL (functions don't exist yet)

- [ ] **Step 3: Implement the enriched observer**

Rewrite `brain_gateway/app/observer.py`:

```python
"""Observer — records enriched tool invocation events with ring buffer.

Each event includes tool metadata, guardrail context, AI analysis,
outcome/verdict derivation, and timing. Buffer size is configurable
via OBSERVER_BUFFER_SIZE (default 10, max 200).
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from collections import deque
from datetime import UTC, datetime

_MAX_BUFFER = 200
_DEFAULT_BUFFER = 10

_lock = threading.Lock()
_last_event: dict | None = None
_events: deque[dict] = deque(maxlen=_DEFAULT_BUFFER)
_total_recorded: int = 0

_DENY_PATTERN = re.compile(r"deny|reject|refus|block|suspicious|not\s+recommend", re.IGNORECASE)
_ALLOW_PATTERN = re.compile(r"approv|allow|safe|proceed|accept|grant", re.IGNORECASE)
_CANARY_PATTERN = re.compile(r"CZTZ\{")

_GRANT_KEYS = {"token", "approved", "registered", "executed", "allowed", "found", "triggered", "exchanged", "recorded", "billed"}
_DENY_KEYS = {"denied", "blocked"}


def _init_buffer() -> None:
    global _events
    raw = os.getenv("OBSERVER_BUFFER_SIZE", str(_DEFAULT_BUFFER))
    try:
        size = int(raw)
    except ValueError:
        size = _DEFAULT_BUFFER
    if size < 1:
        size = _DEFAULT_BUFFER
    if size > _MAX_BUFFER:
        size = _MAX_BUFFER
    with _lock:
        old = list(_events)
        _events = deque(old, maxlen=size)


_init_buffer()


def _derive_outcome(result: dict) -> str:
    if "_error" in result:
        return "error"
    if result.get("_redacted") is False:
        return "leaked"
    for k in _DENY_KEYS:
        if result.get(k) is True:
            return "denied"
    if result.get("registered") is False or result.get("allowed") is False:
        return "denied"
    for k in _GRANT_KEYS:
        if k in result and result[k] is not False:
            return "granted"
    return "unknown"


def _derive_verdict(ai_analysis: str, result: dict) -> str:
    if not ai_analysis:
        return "ai_irrelevant"
    denied_by_ai = bool(_DENY_PATTERN.search(ai_analysis))
    has_grant_keys = any(k in result and result[k] is not False for k in _GRANT_KEYS)
    if denied_by_ai and has_grant_keys:
        return "ai_denied_tool_allowed"
    return "ai_agreed"


def _summarize_response(result: dict) -> dict:
    summary = {}
    for k, v in result.items():
        s = str(v)
        summary[k] = s[:100] + "..." if len(s) > 100 else s
    return summary


def _check_canary(result: dict) -> bool:
    return bool(_CANARY_PATTERN.search(json.dumps(result, default=str)))


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
    event = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "tool_name": tool_name,
        "module": module,
        "guardrail": guardrail,
        "arguments": arguments,
        "outcome": _derive_outcome(result),
        "ai_analysis": ai_analysis[:200] if ai_analysis else "",
        "verdict": _derive_verdict(ai_analysis, result),
        "duration_ms": duration_ms,
        "response_summary": _summarize_response(result),
        "canary_exposed": _check_canary(result),
    }
    with _lock:
        _events.append(event)
        _last_event = event
        _total_recorded += 1


def get_last_event() -> dict:
    with _lock:
        return dict(_last_event) if _last_event else {}


def get_events(limit: int | None = None) -> list[dict]:
    with _lock:
        items = list(_events)
    items.reverse()
    if limit is not None and limit < len(items):
        items = items[:limit]
    return items


def get_events_since(request_id: str) -> list[dict]:
    with _lock:
        items = list(_events)
    idx = None
    for i, ev in enumerate(items):
        if ev["request_id"] == request_id:
            idx = i
            break
    if idx is None:
        items.reverse()
        return items
    after = items[idx + 1:]
    after.reverse()
    return after


def get_buffer_info() -> dict:
    with _lock:
        return {"buffer_size": _events.maxlen, "total_recorded": _total_recorded}


def reset_events() -> None:
    global _last_event, _total_recorded
    with _lock:
        _events.clear()
        _last_event = None
        _total_recorded = 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_observer_events.py -v --no-cov`
Expected: PASS

- [ ] **Step 5: DO NOT COMMIT** (user handles commits)

---

## Task 2: Enrich record_event call in MCP handler

**Files:**
- Modify: `brain_gateway/app/mcp_handlers.py`
- Test: `tests/test_observer_events.py`

- [ ] **Step 1: Write failing test for enriched event after tool call**

Add to `tests/test_observer_events.py`:

```python
def test_gateway_emits_enriched_event() -> None:
    from brain_gateway.app.observer import reset_events, get_events
    from fastapi.testclient import TestClient
    from brain_gateway.app.main import app

    reset_events()
    client = TestClient(app)
    payload = {
        "jsonrpc": "2.0", "id": 30,
        "method": "tools/call",
        "params": {"name": "tenant.list_tenants", "arguments": {}},
    }
    client.post("/mcp", json=payload)
    events = get_events()
    assert len(events) >= 1
    ev = events[0]
    assert ev["tool_name"] == "tenant.list_tenants"
    assert "guardrail" in ev
    assert "arguments" in ev
    assert "duration_ms" in ev
    assert isinstance(ev["duration_ms"], int)
    assert ev["duration_ms"] >= 0
    assert "outcome" in ev
    assert "verdict" in ev
    assert "response_summary" in ev
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_observer_events.py::test_gateway_emits_enriched_event -v --no-cov`
Expected: FAIL (record_event signature mismatch)

- [ ] **Step 3: Update mcp_handlers.py**

In `brain_gateway/app/mcp_handlers.py`, update the `_handle_tools_call` function. Find this section (around line 110-117):

```python
    registry = get_registry()
    result, module_name = registry.call(name=name, arguments=arguments)

    if result is None or module_name is None:
        return _err(req.id, -32602, f"Unknown tool: {name}")

    record_event(tool_name=name, module=module_name)
    logger.info("tools/call %s -> %s", name, module_name)
```

Replace with:

```python
    registry = get_registry()
    t0 = time.monotonic()
    result, module_name = registry.call(name=name, arguments=arguments)
    duration_ms = int((time.monotonic() - t0) * 1000)

    if result is None or module_name is None:
        return _err(req.id, -32602, f"Unknown tool: {name}")

    record_event(
        tool_name=name,
        module=module_name,
        guardrail=get_registry()._difficulty if hasattr(get_registry(), '_difficulty') else "unknown",
        arguments=arguments,
        result=result,
        ai_analysis=result.get("ai_analysis", "") if isinstance(result, dict) else "",
        duration_ms=duration_ms,
    )
    logger.info("tools/call %s -> %s (%dms)", name, module_name, duration_ms)
```

Add `import time` at the top of the file if not already present.

Note: for the `guardrail` value, check how the current difficulty is accessed. Look at `brain_gateway/app/config.py` for the config accessor. Use whatever pattern the codebase already uses to get the current difficulty level.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_observer_events.py -v --no-cov`
Expected: PASS

- [ ] **Step 5: DO NOT COMMIT**

---

## Task 3: Add /_observer/events endpoint

**Files:**
- Modify: `brain_gateway/app/main.py`
- Test: `tests/test_observer_events.py`

- [ ] **Step 1: Write failing tests for events endpoint**

Add to `tests/test_observer_events.py`:

```python
def test_observer_events_endpoint() -> None:
    from brain_gateway.app.observer import reset_events, record_event
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
    from brain_gateway.app.observer import reset_events, record_event
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
    from brain_gateway.app.observer import reset_events, record_event, get_events
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_observer_events.py::test_observer_events_endpoint -v --no-cov`
Expected: FAIL (endpoint doesn't exist)

- [ ] **Step 3: Add the endpoint**

In `brain_gateway/app/main.py`, add import for `get_events`, `get_events_since`, `get_buffer_info` from `observer`. Add after the existing `/_observer/last-event` endpoint:

```python
@app.get("/_observer/events")
def observer_events(limit: int | None = None, since: str | None = None) -> dict:
    """Return recent observer events from the ring buffer."""
    if since:
        events = get_events_since(since)
    else:
        events = get_events(limit=limit)
    info = get_buffer_info()
    return {"events": events, **info}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_observer_events.py -v --no-cov`
Expected: PASS

- [ ] **Step 5: DO NOT COMMIT**

---

## Task 4: Portal proxy routes and observer page data

**Files:**
- Modify: `frontend/app.py`
- Test: `tests/test_operator.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_operator.py`:

```python
def test_observer_events_proxy(frontend_client):
    client, _ = frontend_client
    resp = client.get("/api/observer/events")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "events" in data


def test_observer_page_has_tabs(frontend_client):
    client, _ = frontend_client
    resp = client.get("/observer")
    html = resp.data.decode()
    assert "Vulnerable" in html
    assert "Enhanced" in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_operator.py::test_observer_events_proxy tests/test_operator.py::test_observer_page_has_tabs -v --no-cov`
Expected: FAIL

- [ ] **Step 3: Add proxy route and update observer route**

In `frontend/app.py`, add a new route:

```python
@app.route("/api/observer/events")
def api_observer_events():
    limit = request.args.get("limit", type=int)
    since = request.args.get("since")
    params = {}
    if limit is not None:
        params["limit"] = limit
    if since:
        params["since"] = since
    try:
        resp = httpx.get(f"{GATEWAY_URL}/_observer/events", params=params, timeout=5.0)
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"events": [], "buffer_size": 0, "total_recorded": 0})
```

The `/observer` route stays mostly the same but can pass buffer info if desired. The template will fetch events client-side.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_operator.py -v --no-cov`
Expected: PASS

- [ ] **Step 5: DO NOT COMMIT**

---

## Task 5: Observer frontend redesign — two-tab layout

**Files:**
- Modify: `frontend/templates/observer.html`
- Test: `tests/test_operator.py` (already has tab assertion from Task 4)

- [ ] **Step 1: Rewrite observer.html**

Full rewrite of `frontend/templates/observer.html` with:

**Two tabs:** Vulnerable (default active) and Enhanced. Tab state via URL hash (`#vulnerable` / `#enhanced`).

**Vulnerable tab:**
- MCP08 warning box (preserved from current template)
- Simple event list fetched from `/api/observer/events` — timestamp, tool name, module columns only
- Auto-refresh toggle (3s poll)
- "No events yet" placeholder when empty

**Enhanced tab:**
- Full event timeline from `/api/observer/events`
- Each event row: timestamp, tool name, guardrail badge (colored), outcome badge (green=denied/blocked, red=granted/leaked), verdict label
- Verdict highlighting: `ai_denied_tool_allowed` rows get red left border + warning icon
- Expand row: arguments, AI analysis text, response summary, canary indicator
- Filter controls: module dropdown, guardrail level dropdown, verdict type dropdown
- Auto-refresh toggle (3s poll)
- "Clear" button (POST to `/api/reset`)
- Event count badge in tab header

**Shared:**
- Match existing dark theme CSS variables
- Outcome badges: `granted`/`leaked` = red, `denied`/`blocked` = green, `error` = yellow, `unknown` = grey
- Guardrail badges: EZ = green, MOD = yellow, MAX = red (same as existing nav bar pattern)
- Verdict colors: `ai_denied_tool_allowed` = red highlight, `ai_agreed` = green, `ai_irrelevant` = grey

- [ ] **Step 2: Verify tests pass**

Run: `uv run pytest tests/test_operator.py::test_observer_page_has_tabs -v --no-cov`
Expected: PASS

- [ ] **Step 3: DO NOT COMMIT**

---

## Task 6: Walkthrough telemetry strip

**Files:**
- Modify: `frontend/templates/operator.html`
- Test: `tests/test_operator.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_operator.py`:

```python
def test_operator_has_telemetry_strip(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "telemetry" in html.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_operator.py::test_operator_has_telemetry_strip -v --no-cov`
Expected: FAIL (or may already pass if "telemetry" appears in existing content — check first)

- [ ] **Step 3: Add telemetry strip to walkthrough player**

In `frontend/templates/operator.html`, add below the walkthrough step list (inside the player view):

HTML structure:
- Collapsible panel with header: "Telemetry" + event count badge + expand/collapse toggle
- Collapsed: single-line summary "N events | M verdicts: ai_denied_tool_allowed"
- Expanded: compact event rows — timestamp, tool name, outcome badge, verdict label
- Click row to highlight which walkthrough step triggered it

JS additions:
- `_telemetryWatermark` variable — set when walkthrough starts (step 0), from last-event request_id
- After each step completes, fetch `/api/observer/events?since=<watermark>` and append new events to strip
- `resetWalkthrough()` also clears the telemetry strip
- `toggleTelemetry()` expand/collapse function

- [ ] **Step 4: Verify tests pass**

Run: `uv run pytest tests/test_operator.py -v --no-cov`
Expected: PASS

- [ ] **Step 5: DO NOT COMMIT**

---

## Task 7: Config deployment (Helm + Compose)

**Files:**
- Modify: `deploy/helm/camazotz/values.yaml`
- Modify: `deploy/helm/camazotz/templates/configmap.yaml`
- Modify: `compose/.env.example`

- [ ] **Step 1: Add OBSERVER_BUFFER_SIZE to Helm values**

In `deploy/helm/camazotz/values.yaml`, in the `config:` section, add:

```yaml
  observerBufferSize: "10"
```

- [ ] **Step 2: Add to ConfigMap template**

In `deploy/helm/camazotz/templates/configmap.yaml`, add:

```yaml
  OBSERVER_BUFFER_SIZE: {{ .Values.config.observerBufferSize | quote }}
```

- [ ] **Step 3: Add to compose .env.example**

In `compose/.env.example`, add:

```bash
OBSERVER_BUFFER_SIZE=10
```

- [ ] **Step 4: DO NOT COMMIT**

---

## Task 8: Full test suite + coverage

**Files:**
- Possibly modify: tests and source files for coverage gaps

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest -q`
Expected: All tests pass, 100% coverage

- [ ] **Step 2: Fix any coverage gaps**

Common gaps:
- New observer functions not exercised (add targeted tests)
- New Flask routes not hit (add endpoint tests)
- Error branches in proxy route (gateway unreachable)

- [ ] **Step 3: Run full test suite again**

Run: `uv run pytest -q`
Expected: 100% coverage

- [ ] **Step 4: DO NOT COMMIT**

---

## Task 9: Smoke test and manual verification

- [ ] **Step 1: Run smoke tests**

```bash
make smoke-local
make smoke-k8s K8S_HOST=192.168.1.114
```

Expected: Both pass.

- [ ] **Step 2: Manual verification**

Open `http://localhost:3000/observer` in browser:
- Vulnerable tab: MCP08 warning, simple event list
- Enhanced tab: full timeline with verdicts, filters
- Use Playground to fire a tool call, verify event appears in both tabs
- Verify `ai_denied_tool_allowed` verdict rows have red highlight

Open `http://localhost:3000/operator`:
- Select a lab walkthrough, click Play
- Verify telemetry strip populates as steps execute
- Expand strip, verify event rows link to steps

- [ ] **Step 3: DO NOT COMMIT**
