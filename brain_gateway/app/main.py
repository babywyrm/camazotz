"""Camazotz Brain Gateway — MCP 2025-03-26 Streamable HTTP transport.

Supports:
  - POST /mcp  → JSON-RPC requests (returns JSON or SSE based on Accept)
  - GET  /mcp  → 405 (no server-initiated messages yet)
  - DELETE /mcp → session termination
  - Notifications (id=None) → 202 Accepted
  - Mcp-Session-Id header for session management
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from brain_gateway.app.config import get_difficulty, set_difficulty, show_tokens
from brain_gateway.app.mcp_handlers import handle_rpc
from brain_gateway.app.rate_limit import TokenBucketLimiter
from brain_gateway.app.models import JsonRpcRequest
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import get_buffer_info, get_events, get_events_since, get_last_event
from brain_gateway.app.scenarios import ScenarioLoader, generate_flags, verify_flag
from brain_gateway.app.session import SessionManager

app = FastAPI(title="Camazotz Brain Gateway")
sessions = SessionManager()
_rate_limiter = TokenBucketLimiter()

_scenario_loader: ScenarioLoader | None = None
_loader_lock = threading.Lock()


def _get_loader() -> ScenarioLoader:
    global _scenario_loader
    with _loader_lock:
        if _scenario_loader is None:
            modules_dir = os.environ.get("CAMAZOTZ_MODULES_DIR", "camazotz_modules")
            _scenario_loader = ScenarioLoader(modules_dir)
            _scenario_loader.load_all()
        return _scenario_loader


@app.post("/mcp")
async def mcp_endpoint(request: Request, payload: JsonRpcRequest) -> Response:
    if payload.id is None:
        return Response(status_code=202)

    client_id = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if not _rate_limiter.allow(client_id, difficulty=get_difficulty()):
        return JSONResponse(
            status_code=429,
            content={"jsonrpc": "2.0", "id": payload.id, "error": {"code": -32000, "message": "Rate limit exceeded"}},
        )

    result = handle_rpc(payload)

    headers: dict[str, str] = {}
    if payload.method == "initialize":
        sid = sessions.create()
        headers["mcp-session-id"] = sid

    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        async def _stream() -> AsyncIterator[dict[str, str]]:
            yield {"event": "message", "data": json.dumps(result)}
        return EventSourceResponse(_stream(), headers=headers)

    return JSONResponse(content=result, headers=headers)


@app.get("/mcp")
async def mcp_sse_listener() -> Response:
    return Response(status_code=405)


@app.delete("/mcp")
async def mcp_delete_session(request: Request) -> Response:
    sid = request.headers.get("mcp-session-id")
    if sid:
        sessions.destroy(sid)
    return Response(status_code=200)


@app.get("/_observer/last-event")
def observer_last_event() -> dict[str, object]:
    """Return the most recent observer event for the dashboard."""
    return get_last_event()


@app.get("/_observer/events")
def observer_events(limit: int | None = None, since: str | None = None) -> dict:
    """Return recent observer events from the ring buffer."""
    if since:
        events = get_events_since(since)
    else:
        events = get_events(limit=limit)
    info = get_buffer_info()
    return {"events": events, **info}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "brain-gateway"}


@app.get("/config")
def get_config() -> dict[str, object]:
    """Return current runtime configuration."""
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


class _ConfigUpdate(BaseModel):
    difficulty: str | None = None


@app.put("/config")
def update_config(payload: _ConfigUpdate) -> dict[str, object]:
    """Update runtime difficulty."""
    if payload.difficulty is not None:
        set_difficulty(payload.difficulty)
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


@app.post("/reset")
def reset_labs() -> dict[str, object]:
    """Reset all lab state and clear the rate limiter."""
    get_registry().reset_all()
    _rate_limiter.reset()
    return {
        "reset": True,
        "tool_lab": "call counter reset to 0",
        "shadow_lab": "webhook registry cleared",
        "relay_lab": "context buffer cleared",
        "comms_lab": "outbox cleared",
    }


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, object]]:
    """Return metadata for all loaded scenarios."""
    loader = _get_loader()
    return [
        {
            "threat_id": s.threat_id,
            "title": s.title,
            "difficulty": s.difficulty,
            "category": s.category,
            "description": s.description,
            "objectives": s.objectives,
            "hints": s.hints,
            "tools": s.tools,
            "owasp_mcp": s.owasp_mcp,
            "module_name": s.module_name,
        }
        for s in loader.all()
    ]


class _FlagSubmission(BaseModel):
    threat_id: str = ""
    flag: str = ""


@app.post("/api/flags/verify")
def verify_submitted_flag(payload: _FlagSubmission) -> dict[str, object]:
    """Validate a submitted canary flag against the expected value."""
    correct = verify_flag(payload.threat_id, payload.flag)
    return {"threat_id": payload.threat_id, "correct": correct}
