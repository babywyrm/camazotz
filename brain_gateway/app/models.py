"""JSON-RPC 2.0 and MCP protocol models.

Typed request/response models per the MCP specification (2025-03-26).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 envelope
# ---------------------------------------------------------------------------

class JsonRpcRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JsonRpcErrorResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    error: JsonRpcError


class JsonRpcResultResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    result: dict[str, Any]


# ---------------------------------------------------------------------------
# MCP content blocks (tools/call result payload)
# ---------------------------------------------------------------------------

class TextContent(BaseModel):
    type: str = "text"
    text: str


class ToolResult(BaseModel):
    """MCP tools/call result — content array with optional isError flag."""
    content: list[TextContent]
    isError: bool = False


# ---------------------------------------------------------------------------
# MCP initialize result
# ---------------------------------------------------------------------------

class ServerInfo(BaseModel):
    name: str
    version: str


class InitializeResult(BaseModel):
    protocolVersion: str
    serverInfo: ServerInfo
    capabilities: dict[str, Any]


# ---------------------------------------------------------------------------
# MCP tools/list result
# ---------------------------------------------------------------------------

class ToolDefinition(BaseModel):
    name: str
    description: str
    inputSchema: dict[str, Any]


class ToolsListResult(BaseModel):
    tools: list[ToolDefinition]
