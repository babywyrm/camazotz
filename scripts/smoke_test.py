#!/usr/bin/env python3
"""Lightweight smoke checks for local Compose and Kubernetes targets."""

from __future__ import annotations

import argparse
import json
import os
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
        import os

        host = args.k8s_host or os.environ.get("K8S_HOST")
        if not host:
            raise SystemExit(
                "smoke_test: --target k8s requires a cluster node IP/hostname. "
                "Pass --k8s-host <host> or set the K8S_HOST environment variable "
                "(e.g. `K8S_HOST=10.0.0.5 make smoke-k8s`)."
            )
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


def _check_identity_probe(client: httpx.Client, gateway_url: str) -> None:
    resp = client.get(f"{gateway_url}/config")
    resp.raise_for_status()
    body = resp.json()
    provider = body.get("idp_provider")
    if provider not in ("mock", "zitadel"):
        raise RuntimeError(
            f"identity probe: idp_provider must be 'mock' or 'zitadel', got {provider!r}"
        )
    print(f"PASS identity probe (/config idp_provider={provider})")


_EXPECTED_LANE_SLUGS = ("human-direct", "delegated", "machine", "chain", "anonymous")


def _check_policed_probe(client: httpx.Client, policed_url: str) -> None:
    """Verify the nullfield-policed entry point enforces identity.

    Sends an unauthenticated MCP tools/list to the policed gateway and
    expects a -32001 'identity verification failed' error. A 200 OK means
    nullfield is bypassed (sidecar not in path or policy not loaded).
    """
    try:
        resp = client.post(
            f"{policed_url}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Content-Type": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise RuntimeError(f"policed probe: request failed: {exc}") from exc

    if resp.status_code == 200:
        body = resp.json()
        err = body.get("error", {})
        if err.get("code") == -32001:
            print("PASS policed probe (nullfield denied unauthenticated request)")
            return
        raise RuntimeError(
            f"policed probe: expected error -32001, got {body!r} — "
            "nullfield sidecar may be bypassed"
        )
    raise RuntimeError(
        f"policed probe: expected HTTP 200 with JSON-RPC error, got HTTP {resp.status_code}"
    )


def _check_lanes_probe(client: httpx.Client, portal_url: str) -> None:
    """Verify the Agentic Lane View is live: HTML page, JSON endpoint, real labs."""
    html = client.get(f"{portal_url}/lanes")
    html.raise_for_status()
    if "Agentic Identity Lanes" not in html.text:
        raise RuntimeError("lanes probe: GET /lanes did not contain 'Agentic Identity Lanes'")
    print("PASS lanes probe (/lanes renders)")

    api = client.get(f"{portal_url}/api/lanes")
    api.raise_for_status()
    body = api.json()
    schema = body.get("schema")
    if schema != "v1":
        raise RuntimeError(f"lanes probe: /api/lanes schema must be 'v1', got {schema!r}")
    slugs = tuple(lane.get("slug") for lane in body.get("lanes", []))
    if slugs != _EXPECTED_LANE_SLUGS:
        raise RuntimeError(
            f"lanes probe: /api/lanes slugs must be {_EXPECTED_LANE_SLUGS}, got {slugs}"
        )
    labs = body.get("labs", [])
    if not labs:
        raise RuntimeError(
            "lanes probe: /api/lanes returned zero labs — migration likely regressed "
            "or gateway /api/scenarios is not surfacing the agentic field"
        )
    print(f"PASS lanes probe (/api/lanes schema=v1, 5 lanes, {len(labs)} labs mapped)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke checks for Camazotz gateway + portal")
    parser.add_argument("--target", choices=["local", "k8s"], default="local", help="Preset target profile")
    parser.add_argument(
        "--k8s-host",
        default=None,
        help=(
            "K8s node host/IP when --target k8s. If omitted, falls back to the "
            "K8S_HOST env var; if both are unset the script exits with guidance."
        ),
    )
    parser.add_argument("--gateway-url", help="Override gateway base URL")
    parser.add_argument("--portal-url", help="Override portal base URL")
    parser.add_argument("--timeout", type=float, default=20, help="HTTP timeout in seconds")
    parser.add_argument("--require-llm", action="store_true", help="Also verify model-backed tool call")
    parser.add_argument(
        "--require-identity",
        action="store_true",
        help="Also verify GET /config exposes idp_provider (mock or zitadel)",
    )
    parser.add_argument(
        "--require-lanes",
        action="store_true",
        help="Also verify GET /lanes renders and /api/lanes returns schema v1 with 5 lanes",
    )
    parser.add_argument(
        "--require-policed",
        action="store_true",
        help="Also verify the nullfield-policed entry point denies unauthenticated traffic",
    )
    parser.add_argument(
        "--policed-url",
        help="Policed gateway URL (default: http://<k8s-host>:30090 for --target k8s)",
    )
    args = parser.parse_args()

    target = _resolve_target(args)
    print(f"Target gateway={target.gateway_url} portal={target.portal_url}")
    try:
        with httpx.Client(timeout=args.timeout) as client:
            _check_health(client, "gateway", target.gateway_url)
            _check_health(client, "portal", target.portal_url)
            session_id = _mcp_initialize(client, target.gateway_url)
            _mcp_tools_list(client, target.gateway_url, session_id)
            if args.require_identity:
                _check_identity_probe(client, target.gateway_url)
            if args.require_lanes:
                _check_lanes_probe(client, target.portal_url)
            if args.require_policed:
                policed_url = args.policed_url
                if not policed_url:
                    if args.target == "k8s":
                        host = args.k8s_host or os.getenv("K8S_HOST", "")
                        if not host:
                            raise RuntimeError(
                                "--require-policed needs --k8s-host (or K8S_HOST) for k8s target"
                            )
                        policed_url = f"http://{host}:30090"
                    else:
                        raise RuntimeError(
                            "--require-policed has no default for --target local; "
                            "pass --policed-url"
                        )
                _check_policed_probe(client, policed_url)
            if args.require_llm:
                _check_llm_probe(client, target.gateway_url, session_id)
    except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
        print(f"FAIL {exc}")
        return 1

    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
