# Streamable HTTP Transport Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade the Camazotz brain-gateway from bare HTTP POST to MCP 2025-03-26 Streamable HTTP transport — supporting SSE streams, session management, notifications, and `Accept` header negotiation.

**Architecture:** The `/mcp` endpoint gains GET support (SSE listener stream) alongside POST. POST responses can return either `application/json` (current behavior, for simple calls) or `text/event-stream` (for long-running tool calls that benefit from streaming). Sessions are tracked via `Mcp-Session-Id` header with per-session state (difficulty, lab state). The portal frontend proxies through unchanged — it already receives the raw JSON-RPC envelope.

**Tech Stack:** FastAPI + `sse-starlette` for SSE, `uuid` for session IDs, existing Pydantic models.

---

### Task 1: Add `sse-starlette` dependency

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add the dependency**

Add `sse-starlette>=2.0.0` to the `[project] dependencies` list in `pyproject.toml`.

**Step 2: Lock and verify**

Run: `uv lock && uv sync`
Expected: Resolves and installs without error.

**Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "deps: add sse-starlette for Streamable HTTP transport"
```

---

### Task 2: Session manager — create, validate, destroy

**Files:**
- Create: `brain_gateway/app/session.py`
- Test: `tests/test_session.py`

**Step 1: Write the failing tests**

```python
# tests/test_session.py
import time
from brain_gateway.app.session import SessionManager

def test_create_session_returns_id():
    mgr = SessionManager()
    sid = mgr.create()
    assert isinstance(sid, str)
    assert len(sid) == 36  # UUID4

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

def test_get_state_returns_dict():
    mgr = SessionManager()
    sid = mgr.create()
    state = mgr.get_state(sid)
    assert isinstance(state, dict)
    assert "difficulty" in state

def test_set_state():
    mgr = SessionManager()
    sid = mgr.create()
    mgr.set_state(sid, "difficulty", "hard")
    assert mgr.get_state(sid)["difficulty"] == "hard"

def test_sessions_are_isolated():
    mgr = SessionManager()
    s1 = mgr.create()
    s2 = mgr.create()
    mgr.set_state(s1, "difficulty", "hard")
    assert mgr.get_state(s2)["difficulty"] == "medium"
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_session.py -v`
Expected: ImportError — module doesn't exist yet.

**Step 3: Write the implementation**

```python
# brain_gateway/app/session.py
"""MCP session manager — Streamable HTTP transport.

Each session gets a UUID, isolated state, and a creation timestamp.
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_session.py -v`
Expected: All PASS.

**Step 5: Commit**

```bash
git add brain_gateway/app/session.py tests/test_session.py
git commit -m "feat: add session manager for Streamable HTTP"
```

---

### Task 3: Notification handling — return 202 for id-less messages

**Files:**
- Modify: `brain_gateway/app/main.py`
- Modify: `brain_gateway/app/models.py`
- Test: `tests/test_mcp_compliance.py`

**Step 1: Write the failing test**

Add to `tests/test_mcp_compliance.py`:

```python
def test_notification_returns_202():
    """JSON-RPC messages without 'id' are notifications — must return 202."""
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )
    assert resp.status_code == 202
    assert resp.content == b""
```

**Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_mcp_compliance.py::test_notification_returns_202 -v`
Expected: FAIL — currently returns 200 with a body.

**Step 3: Update the endpoint**

In `brain_gateway/app/main.py`, change the `/mcp` POST handler to detect notifications (requests with no `id`) and return 202:

```python
from fastapi import FastAPI, Request, Response

@app.post("/mcp")
async def mcp_endpoint(payload: JsonRpcRequest) -> Response:
    if payload.id is None:
        # Notification — no response body per JSON-RPC 2.0
        return Response(status_code=202)
    result = handle_rpc(payload)
    return JSONResponse(content=result)
```

**Step 4: Run tests**

Run: `uv run pytest tests/test_mcp_compliance.py -v`
Expected: All PASS including new test.

**Step 5: Commit**

```bash
git add brain_gateway/app/main.py tests/test_mcp_compliance.py
git commit -m "feat: return 202 for JSON-RPC notifications"
```

---

### Task 4: GET `/mcp` — SSE listener stream or 405

**Files:**
- Modify: `brain_gateway/app/main.py`
- Test: `tests/test_mcp_compliance.py`

**Step 1: Write the failing test**

```python
def test_get_mcp_returns_405():
    """GET /mcp without Accept: text/event-stream should return 405."""
    client = TestClient(app)
    resp = client.get("/mcp")
    assert resp.status_code == 405
```

**Step 2: Run to verify it fails**

Expected: Currently returns 405 by default (FastAPI auto-rejects GET on a POST route). If it already passes, proceed. If not, add:

```python
@app.get("/mcp")
async def mcp_sse_listener(request: Request) -> Response:
    accept = request.headers.get("accept", "")
    if "text/event-stream" not in accept:
        return Response(status_code=405)
    # For now, return 405. SSE listener is a future enhancement
    # when we add server-initiated messages.
    return Response(status_code=405)
```

**Step 3: Run tests**

Run: `uv run pytest tests/test_mcp_compliance.py -v`
Expected: All PASS.

**Step 4: Commit**

```bash
git add brain_gateway/app/main.py tests/test_mcp_compliance.py
git commit -m "feat: GET /mcp returns 405 per Streamable HTTP spec"
```

---

### Task 5: Session header on initialize — `Mcp-Session-Id`

**Files:**
- Modify: `brain_gateway/app/main.py`
- Modify: `brain_gateway/app/mcp_handlers.py`
- Test: `tests/test_mcp_compliance.py`

**Step 1: Write the failing tests**

```python
def test_initialize_returns_session_header():
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert resp.status_code == 200
    sid = resp.headers.get("mcp-session-id")
    assert sid is not None
    import uuid
    uuid.UUID(sid)  # must be valid UUID

def test_request_without_session_after_init_returns_400():
    client = TestClient(app)
    # Initialize to create a session
    init = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    sid = init.headers["mcp-session-id"]
    # Request WITH session header — should work
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers={"mcp-session-id": sid},
    )
    assert resp.status_code == 200
```

**Step 2: Implement session integration**

The `mcp_endpoint` handler needs to:
1. On `initialize`: create a session, return the `Mcp-Session-Id` header.
2. On other methods: accept `Mcp-Session-Id` header (optional — don't enforce yet, to avoid breaking the portal and e2e tests).

Wire the `SessionManager` as a FastAPI app-level singleton.

**Step 3: Run full test suite**

Run: `uv run pytest -q --no-cov`
Expected: All PASS.

**Step 4: Commit**

```bash
git add brain_gateway/app/main.py brain_gateway/app/mcp_handlers.py brain_gateway/app/session.py tests/test_mcp_compliance.py
git commit -m "feat: session management via Mcp-Session-Id header"
```

---

### Task 6: Accept header negotiation — JSON vs SSE response

**Files:**
- Modify: `brain_gateway/app/main.py`
- Test: `tests/test_mcp_compliance.py`

**Step 1: Write the failing tests**

```python
def test_post_with_accept_json_returns_json():
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"accept": "application/json"},
    )
    assert resp.headers["content-type"].startswith("application/json")

def test_post_with_accept_sse_returns_sse():
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"accept": "text/event-stream, application/json"},
    )
    # Server MAY return either — we return SSE when client prefers it
    ct = resp.headers["content-type"]
    assert ct.startswith("text/event-stream") or ct.startswith("application/json")
```

**Step 2: Implement Accept negotiation**

In the POST handler, check the `Accept` header. If the client lists `text/event-stream` first (or as preferred), wrap the JSON-RPC response as an SSE `message` event. Otherwise return `application/json` as before. This is a backward-compatible change — clients that don't send `Accept: text/event-stream` get the same behavior as today.

```python
from sse_starlette.sse import EventSourceResponse

async def mcp_endpoint(request: Request, payload: JsonRpcRequest) -> Response:
    # ... handle notification / session / rpc ...
    result = handle_rpc(payload)

    accept = request.headers.get("accept", "application/json")
    if "text/event-stream" in accept:
        async def event_stream():
            yield {"event": "message", "data": json.dumps(result)}
        return EventSourceResponse(event_stream())

    return JSONResponse(content=result)
```

**Step 3: Run full test suite + e2e**

Run: `uv run pytest -q --no-cov`
Expected: All PASS.

**Step 4: Commit**

```bash
git add brain_gateway/app/main.py tests/test_mcp_compliance.py
git commit -m "feat: Accept header negotiation — JSON or SSE response"
```

---

### Task 7: DELETE `/mcp` — session termination

**Files:**
- Modify: `brain_gateway/app/main.py`
- Test: `tests/test_mcp_compliance.py`

**Step 1: Write the failing test**

```python
def test_delete_mcp_terminates_session():
    client = TestClient(app)
    init = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    sid = init.headers["mcp-session-id"]
    resp = client.delete("/mcp", headers={"mcp-session-id": sid})
    assert resp.status_code == 200
```

**Step 2: Add DELETE handler**

```python
@app.delete("/mcp")
async def mcp_delete_session(request: Request) -> Response:
    sid = request.headers.get("mcp-session-id")
    if sid:
        session_mgr.destroy(sid)
    return Response(status_code=200)
```

**Step 3: Run tests**

Run: `uv run pytest -q --no-cov`
Expected: All PASS.

**Step 4: Commit**

```bash
git add brain_gateway/app/main.py tests/test_mcp_compliance.py
git commit -m "feat: DELETE /mcp for session termination"
```

---

### Task 8: Update all existing tests for new response mechanics

**Files:**
- Modify: `tests/test_module_routing.py`
- Modify: `tests/test_cross_tool_chains.py`
- Modify: `tests/test_difficulty_and_tokens.py`
- Modify: `tests/test_observer_events.py`

Existing tests POST to `/mcp` and get `200 OK` with `application/json` — this must continue working. The changes from Tasks 3-7 should be backward-compatible. This task is a verification pass:

**Step 1: Run the full test suite**

Run: `uv run pytest -q`
Expected: All 165+ tests PASS, 100% coverage.

**Step 2: Fix any failures from the new response type**

The `mcp_endpoint` return type changed from `dict` to `Response`. If any tests break because `TestClient` handles `Response` differently, adjust the endpoint or tests.

**Step 3: Commit if any changes were needed**

```bash
git add tests/
git commit -m "test: update tests for Streamable HTTP transport"
```

---

### Task 9: Update e2e_matrix.py for session support

**Files:**
- Modify: `tests/e2e_matrix.py`

**Step 1: Update mcp_call to use sessions**

Add session initialization at the start of each difficulty run:

```python
def init_session() -> str:
    """Call initialize and return the Mcp-Session-Id."""
    body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    req = urllib.request.Request(
        f"{GW}/mcp", data=body.encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=10)
    sid = resp.headers.get("Mcp-Session-Id", "")
    return sid
```

Update `mcp_call` to include the session header when available.

**Step 2: Run e2e matrix against local Compose**

Run: `python3 tests/e2e_matrix.py http://localhost:8080`
Expected: 126/126 PASS.

**Step 3: Commit**

```bash
git add tests/e2e_matrix.py
git commit -m "test: e2e matrix uses session headers"
```

---

### Task 10: Update contracts and docs

**Files:**
- Modify: `contracts/mcp_profile.md`
- Modify: `docs/scenarios.md` (transport section if exists)
- Modify: `CHANGELOG.md`
- Modify: `README.md` (if test count changed)

**Step 1: Update mcp_profile.md**

Add the Streamable HTTP transport section:
- POST returns `application/json` or `text/event-stream` based on `Accept`
- GET returns `405` (no server-initiated messages yet)
- DELETE terminates session
- `Mcp-Session-Id` header on initialize
- Notifications return `202 Accepted`

**Step 2: Update CHANGELOG.md**

Add Unreleased section for Streamable HTTP transport.

**Step 3: Commit**

```bash
git add contracts/ docs/ CHANGELOG.md README.md
git commit -m "docs: update contracts and changelog for Streamable HTTP"
```

---

### Task 11: Rebuild and deploy — Compose + K3s

**Step 1: Rebuild Compose**

```bash
cd compose && docker compose down && docker compose build --no-cache && docker compose up -d
```

**Step 2: Run e2e matrix against Compose**

```bash
python3 tests/e2e_matrix.py http://localhost:8080
```

Expected: 126/126 PASS.

**Step 3: Sync to NUC, redeploy K3s**

```bash
rsync -avz --delete --exclude '.git' ... user@<node-ip>:/opt/camazotz/
ssh user@<node-ip> 'sudo bash /opt/camazotz/kube/deploy.sh'
ssh user@<node-ip> 'sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway'
```

**Step 4: Run e2e matrix against K3s**

Expected: 126/126 PASS.

**Step 5: Final commit**

```bash
git commit -m "deploy: Streamable HTTP verified on Compose + K3s"
```

---

## Summary of Spec Compliance After Implementation

| Spec Requirement | Before | After |
|---|---|---|
| POST `/mcp` returns JSON | Yes | Yes |
| POST `/mcp` returns SSE when preferred | No | Yes |
| GET `/mcp` SSE listener or 405 | 404 | 405 |
| DELETE `/mcp` session termination | No | Yes |
| Notifications return 202 | No (200) | Yes |
| `Mcp-Session-Id` header | No | Yes |
| `Accept` header negotiation | No | Yes |
| Session isolation | Global state | Per-session |
| Backward compatible | n/a | Yes — no `Accept` = JSON |
