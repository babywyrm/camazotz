"""MCP JSON-RPC handler — spec-compliant with typed responses.

Implements the MCP 2025-03-26 specification:
  - initialize
  - tools/list
  - tools/call  (result wrapped in content blocks)
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from brain_gateway.app.config import get_difficulty
from brain_gateway.app.models import (
    InitializeResult,
    JsonRpcError,
    JsonRpcErrorResponse,
    JsonRpcRequest,
    JsonRpcResultResponse,
    ServerInfo,
    TextContent,
    ToolResult,
)
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import record_event

logger = logging.getLogger(__name__)

_PROTOCOL_VERSION = "2025-03-26"
_SERVER_NAME = "camazotz-brain-gateway"
_SERVER_VERSION = "0.2.0"


def _ok(req_id: int | str | None, result: dict[str, Any]) -> dict[str, Any]:
    return JsonRpcResultResponse(id=req_id, result=result).model_dump()


def _err(req_id: int | str | None, code: int, message: str, data: Any = None) -> dict[str, Any]:
    return JsonRpcErrorResponse(
        id=req_id,
        error=JsonRpcError(code=code, message=message, data=data),
    ).model_dump()


def handle_rpc(req: JsonRpcRequest) -> dict[str, Any]:
    logger.info("MCP %s id=%s", req.method, req.id)

    if req.method == "initialize":
        return _handle_initialize(req)
    if req.method == "tools/list":
        return _handle_tools_list(req)
    if req.method == "tools/call":
        return _handle_tools_call(req)
    if req.method == "resources/list":
        return _handle_resources_list(req)
    if req.method == "resources/read":
        return _handle_resources_read(req)

    logger.warning("Unknown method: %s", req.method)
    return _err(req.id, -32601, f"Method not found: {req.method}")


# ---------------------------------------------------------------------------
# initialize
# ---------------------------------------------------------------------------

def _handle_initialize(req: JsonRpcRequest) -> dict[str, Any]:
    result = InitializeResult(
        protocolVersion=_PROTOCOL_VERSION,
        serverInfo=ServerInfo(name=_SERVER_NAME, version=_SERVER_VERSION),
        capabilities={
            "tools": {"listChanged": False},
            "resources": {"listChanged": False},
        },
    )
    return _ok(req.id, result.model_dump())


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------

def _handle_tools_list(req: JsonRpcRequest) -> dict[str, Any]:
    registry = get_registry()
    tools = registry.list_all_tools()
    logger.debug("tools/list returning %d tools", len(tools))
    return _ok(req.id, {"tools": tools})


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------

def _handle_tools_call(req: JsonRpcRequest) -> dict[str, Any]:
    name = req.params.get("name")
    if not name or not isinstance(name, str):
        return _err(
            req.id, -32602,
            "Invalid params: 'name' is required and must be a string.",
        )

    arguments = req.params.get("arguments", {})
    if not isinstance(arguments, dict):
        return _err(
            req.id, -32602,
            "Invalid params: 'arguments' must be an object.",
        )

    registry = get_registry()
    t0 = time.monotonic()
    result, module_name = registry.call(name=name, arguments=arguments)
    duration_ms = int((time.monotonic() - t0) * 1000)

    if result is None or module_name is None:
        return _err(req.id, -32602, f"Unknown tool: {name}")

    result_dict = result if isinstance(result, dict) else {}
    record_event(
        tool_name=name,
        module=module_name,
        guardrail=get_difficulty(),
        arguments=arguments,
        result=result_dict,
        ai_analysis=result_dict.get("ai_analysis", ""),
        duration_ms=duration_ms,
    )
    logger.info("tools/call %s -> %s", name, module_name)

    tool_result = ToolResult(
        content=[TextContent(text=json.dumps(result, default=str))],
        isError=False,
    )
    return _ok(req.id, tool_result.model_dump())


# ---------------------------------------------------------------------------
# resources/list
# ---------------------------------------------------------------------------

def _handle_resources_list(req: JsonRpcRequest) -> dict[str, Any]:
    registry = get_registry()
    resources = registry.list_all_resources()
    logger.debug("resources/list returning %d resources", len(resources))
    return _ok(req.id, {"resources": resources})


# ---------------------------------------------------------------------------
# resources/read
# ---------------------------------------------------------------------------

def _handle_resources_read(req: JsonRpcRequest) -> dict[str, Any]:
    uri = req.params.get("uri")
    if not uri or not isinstance(uri, str):
        return _err(
            req.id, -32602,
            "Invalid params: 'uri' is required and must be a string.",
        )

    registry = get_registry()
    content = registry.read_resource(uri)

    if content is None:
        return _err(req.id, -32002, f"Resource not found: {uri}")

    return _ok(req.id, {"contents": [content]})
