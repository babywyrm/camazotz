"""Gateway JSON-RPC client for the QA harness."""
from __future__ import annotations

import json
from typing import Any

import httpx

from .types import DEFAULT_GATEWAY, DEFAULT_TIMEOUT


class GatewayClient:
    """Thin wrapper around the brain-gateway MCP endpoint."""

    def __init__(self, base_url: str = DEFAULT_GATEWAY, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._id = 0

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        r = httpx.post(
            f"{self._base}/mcp",
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
            timeout=self._timeout,
        )
        return r.json()

    def call_tool(self, tool: str, arguments: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        self._id += 1
        r = httpx.post(
            f"{self._base}/mcp",
            json={"jsonrpc": "2.0", "id": self._id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
            timeout=timeout or self._timeout,
        )
        resp = r.json()
        try:
            return json.loads(resp["result"]["content"][0]["text"])
        except (KeyError, IndexError, json.JSONDecodeError):
            return resp

    def set_guardrail(self, level: str) -> None:
        httpx.put(f"{self._base}/config", json={"difficulty": level}, timeout=5)

    def reset(self) -> None:
        httpx.post(f"{self._base}/reset", timeout=5)

    def list_tools(self) -> list[str]:
        resp = self._rpc("tools/list", {})
        return sorted(t["name"] for t in resp.get("result", {}).get("tools", []))
