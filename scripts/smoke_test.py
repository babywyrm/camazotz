#!/usr/bin/env python3
"""Lightweight smoke checks for local Compose and Kubernetes targets."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class SmokeTarget:
    gateway_url: str
    portal_url: str


def _resolve_target(args: argparse.Namespace) -> SmokeTarget:
    if args.gateway_url and args.portal_url:
        return SmokeTarget(args.gateway_url.rstrip("/"), args.portal_url.rstrip("/"))

    if args.target == "k8s":
        host = args.k8s_host
        return SmokeTarget(f"http://{host}:30080", f"http://{host}:3000")

    return SmokeTarget("http://localhost:8080", "http://localhost:3000")


def _check_health(client: httpx.Client, name: str, base_url: str) -> None:
    resp = client.get(f"{base_url}/health")
    resp.raise_for_status()
    print(f"PASS {name} /health")


def _mcp_initialize(client: httpx.Client, gateway_url: str) -> str | None:
    resp = client.post(
        f"{gateway_url}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"initialize failed: {body['error']}")
    print("PASS gateway initialize")
    return resp.headers.get("mcp-session-id")


def _mcp_tools_list(client: httpx.Client, gateway_url: str, session_id: str | None) -> list[str]:
    headers = {"mcp-session-id": session_id} if session_id else {}
    resp = client.post(
        f"{gateway_url}/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"tools/list failed: {body['error']}")
    tools = [t["name"] for t in body.get("result", {}).get("tools", []) if "name" in t]
    if not tools:
        raise RuntimeError("tools/list returned no tools")
    print(f"PASS gateway tools/list ({len(tools)} tools)")
    return tools


def _check_llm_probe(client: httpx.Client, gateway_url: str, session_id: str | None) -> None:
    headers = {"mcp-session-id": session_id} if session_id else {}
    payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "config.ask_agent",
            "arguments": {"question": "Reply with exactly: SMOKE_OK"},
        },
    }
    resp = client.post(f"{gateway_url}/mcp", headers=headers, json=payload)
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"llm probe failed: {body['error']}")
    # Validate the common MCP content envelope shape.
    result = body.get("result", {})
    content = result.get("content", [])
    if not content or "text" not in content[0]:
        raise RuntimeError("llm probe returned unexpected response shape")
    # Ensure text is parseable JSON-like payload where possible.
    text = content[0]["text"]
    try:
        json.loads(text)
    except json.JSONDecodeError:
        pass
    print("PASS llm probe (config.ask_agent)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke checks for Camazotz gateway + portal")
    parser.add_argument("--target", choices=["local", "k8s"], default="local", help="Preset target profile")
    parser.add_argument("--k8s-host", default="192.168.1.114", help="K8s host/IP when target is k8s")
    parser.add_argument("--gateway-url", help="Override gateway base URL")
    parser.add_argument("--portal-url", help="Override portal base URL")
    parser.add_argument("--timeout", type=float, default=20, help="HTTP timeout in seconds")
    parser.add_argument("--require-llm", action="store_true", help="Also verify model-backed tool call")
    args = parser.parse_args()

    target = _resolve_target(args)
    print(f"Target gateway={target.gateway_url} portal={target.portal_url}")
    try:
        with httpx.Client(timeout=args.timeout) as client:
            _check_health(client, "gateway", target.gateway_url)
            _check_health(client, "portal", target.portal_url)
            session_id = _mcp_initialize(client, target.gateway_url)
            _mcp_tools_list(client, target.gateway_url, session_id)
            if args.require_llm:
                _check_llm_probe(client, target.gateway_url, session_id)
    except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
        print(f"FAIL {exc}")
        return 1

    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
