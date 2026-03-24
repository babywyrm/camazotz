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
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sse_starlette.sse import EventSourceResponse

from brain_gateway.app.config import get_difficulty, set_difficulty, show_tokens
from brain_gateway.app.mcp_handlers import handle_rpc
from brain_gateway.app.models import JsonRpcRequest
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import get_last_event
from brain_gateway.app.session import SessionManager

app = FastAPI(title="Camazotz Brain Gateway")
sessions = SessionManager()


@app.post("/mcp")
async def mcp_endpoint(request: Request, payload: JsonRpcRequest) -> Response:
    if payload.id is None:
        return Response(status_code=202)

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
def observer_last_event() -> dict:
    return get_last_event()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "brain-gateway"}


@app.get("/config")
def get_config() -> dict:
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


@app.put("/config")
def update_config(payload: dict) -> dict:
    if "difficulty" in payload:
        set_difficulty(payload["difficulty"])
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


@app.post("/reset")
def reset_labs() -> dict:
    get_registry().reset_all()
    return {
        "reset": True,
        "tool_lab": "call counter reset to 0",
        "shadow_lab": "webhook registry cleared",
        "relay_lab": "context buffer cleared",
        "comms_lab": "outbox cleared",
    }
