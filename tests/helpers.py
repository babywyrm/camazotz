"""Shared test utilities for MCP JSON-RPC calls."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient


def rpc_call(
    client: TestClient,
    method: str,
    params: dict,
    req_id: int = 1,
    *,
    expected_status: int = 200,
) -> dict:
    """Send a JSON-RPC request and return the parsed response body."""
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    assert resp.status_code == expected_status
    return resp.json()


def tool_call(
    client: TestClient,
    tool: str,
    arguments: dict,
    req_id: int = 1,
) -> dict:
    """Invoke an MCP tool and return the unwrapped content dict."""
    body = rpc_call(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])
