"""Gateway JSON-RPC client for the QA harness."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

import httpx

from .types import DEFAULT_GATEWAY, DEFAULT_TIMEOUT

_MAX_RETRIES = 2
_RETRY_DELAY = 2.0


class GatewayClient:
    """Thin wrapper around the brain-gateway MCP endpoint."""

    def __init__(
        self,
        base_url: str = DEFAULT_GATEWAY,
        timeout: float = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._id = 0
        self._verbose = verbose

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(f"  [gw] {msg}", file=sys.stderr, flush=True)

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        for attempt in range(_MAX_RETRIES + 1):
            try:
                r = httpx.post(f"{self._base}/mcp", json=payload, timeout=self._timeout)
                return r.json()
            except (httpx.HTTPError, ValueError) as exc:
                if attempt < _MAX_RETRIES:
                    self._log(f"_rpc {method} attempt {attempt + 1} failed: {exc} — retrying in {_RETRY_DELAY}s")
                    time.sleep(_RETRY_DELAY)
                else:
                    self._log(f"_rpc {method} failed after {_MAX_RETRIES + 1} attempts: {exc}")
                    return {"error": {"code": -1, "message": f"gateway unreachable: {exc}"}}
        return {"error": {"code": -1, "message": "unreachable"}}  # pragma: no cover

    def call_tool(self, tool: str, arguments: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        effective_timeout = timeout or self._timeout
        for attempt in range(_MAX_RETRIES + 1):
            try:
                r = httpx.post(f"{self._base}/mcp", json=payload, timeout=effective_timeout)
                resp = r.json()
                try:
                    return json.loads(resp["result"]["content"][0]["text"])
                except (KeyError, IndexError, json.JSONDecodeError):
                    return resp
            except (httpx.HTTPError, ValueError) as exc:
                if attempt < _MAX_RETRIES:
                    self._log(f"call_tool {tool} attempt {attempt + 1} failed: {exc} — retrying")
                    time.sleep(_RETRY_DELAY)
                else:
                    self._log(f"call_tool {tool} failed after {_MAX_RETRIES + 1} attempts: {exc}")
                    return {"_error": str(exc), "_tool": tool}
        return {"_error": "unreachable", "_tool": tool}  # pragma: no cover

    def set_guardrail(self, level: str) -> None:
        for attempt in range(_MAX_RETRIES + 1):
            try:
                httpx.put(f"{self._base}/config", json={"difficulty": level}, timeout=5)
                return
            except httpx.HTTPError as exc:
                if attempt < _MAX_RETRIES:
                    self._log(f"set_guardrail({level}) attempt {attempt + 1} failed: {exc}")
                    time.sleep(_RETRY_DELAY)
                else:
                    self._log(f"set_guardrail({level}) failed: {exc}")

    def reset(self) -> None:
        for attempt in range(_MAX_RETRIES + 1):
            try:
                httpx.post(f"{self._base}/reset", timeout=5)
                return
            except httpx.HTTPError as exc:
                if attempt < _MAX_RETRIES:
                    self._log(f"reset attempt {attempt + 1} failed: {exc}")
                    time.sleep(_RETRY_DELAY)
                else:
                    self._log(f"reset failed: {exc}")

    def get_config(self) -> dict[str, Any]:
        for attempt in range(_MAX_RETRIES + 1):
            try:
                r = httpx.get(f"{self._base}/config", timeout=5)
                return r.json()
            except (httpx.HTTPError, ValueError) as exc:
                if attempt < _MAX_RETRIES:
                    self._log(f"get_config attempt {attempt + 1} failed: {exc}")
                    time.sleep(_RETRY_DELAY)
                else:
                    self._log(f"get_config failed: {exc}")
                    return {}
        return {}  # pragma: no cover

    def list_tools(self) -> list[str]:
        resp = self._rpc("tools/list", {})
        return sorted(t["name"] for t in resp.get("result", {}).get("tools", []))
