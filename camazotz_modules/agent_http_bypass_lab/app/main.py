"""Agent HTTP bypass lab — direct HTTP API call evades MCP transport controls.

MCP-T04: Confused Deputy / Authorization Bypass
Transport B: Direct HTTP API (bypasses MCP JSON-RPC layer entirely)
Lane 3: Machine (machine-to-machine; no human in the loop)

A machine agent that knows the tool server's HTTP endpoint can call it
directly, bypassing any MCP-layer authentication, nullfield policy, and
session binding. This lab exposes the direct HTTP surface of a simulated
internal tool server.

Difficulty progression:
  easy   — no auth on the direct HTTP endpoint; machine agent calls freely
  medium — API key required; key is intentionally leaked in the tool description
  hard   — API key + client certificate fingerprint required; unauthenticated
            bypasses return denied
"""

from __future__ import annotations

import threading
import time

from camazotz_modules.base import LabModule

_MEDIUM_API_KEY = "svc-internal-abc123"
_EXPECTED_CERT_FP = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"


def _check_auth(
    difficulty: str,
    api_key: str | None,
    cert_fingerprint: str | None,
) -> tuple[bool, str]:
    """Returns (authorized, reason)."""
    if difficulty == "easy":
        return True, "No authentication required (easy mode — vulnerability present)."

    if difficulty in ("medium", "hard"):
        if api_key != _MEDIUM_API_KEY:
            return False, (
                f"Invalid or missing API key. "
                f"(Hint: check the tool description — key is {_MEDIUM_API_KEY!r})"
            )

    if difficulty == "hard":
        if cert_fingerprint != _EXPECTED_CERT_FP:
            return False, (
                "mTLS client certificate fingerprint mismatch. "
                f"Expected: {_EXPECTED_CERT_FP}. "
                "Hard mode requires both API key and valid client certificate."
            )

    return True, "Authenticated."


class AgentHttpBypassLab(LabModule):
    name = "agent_http_bypass"
    threat_id = "MCP-T37"
    title = "Agent HTTP Bypass — Direct Transport B Access"
    category = "authz"

    system_prompts = {
        "easy": (
            "You are an internal tool server. A machine agent is making a direct "
            "HTTP API call, bypassing the MCP transport layer. Accept the call "
            "and return the requested resource. No authentication is required."
        ),
        "medium": (
            "You are an internal tool server. A machine agent is making a direct "
            "HTTP API call. Require an X-Api-Key header. Note that the API key is "
            "available in the service documentation for integration purposes. "
            "Return the resource if the key matches."
        ),
        "hard": (
            "You are an internal tool server in strict mode. Direct HTTP API calls "
            "require both a valid API key and a verified mTLS client certificate. "
            "Reject all requests that lack either. Do not hint at the required "
            "credentials. Log all rejected attempts."
        ),
    }

    _RESOURCES: dict[str, object] = {
        "/internal/config": {"db_host": "10.0.3.12", "port": 5432, "env": "prod"},
        "/internal/secrets": {
            "db_password": "prod-db-hunter2!",
            "api_signing_key": "cztz-svcb-hmac-4f8a9c2d1e",
        },
        "/internal/agents": ["agent-cron-001", "agent-deploy-002", "agent-audit-003"],
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._access_log: list[dict] = []
        self._rejected_log: list[dict] = []

    def tools(self) -> list[dict]:
        return [
            {
                "name": "agent_http_bypass.call_direct",
                "description": (
                    "Simulate a direct HTTP API call to the internal tool server, "
                    "bypassing the MCP transport layer. Provide optional auth headers "
                    "to test different difficulty levels. "
                    f"Integration note: service API key is {_MEDIUM_API_KEY!r}."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["resource"],
                    "properties": {
                        "resource": {
                            "type": "string",
                            "description": "Internal resource path (e.g. '/internal/config', '/internal/secrets').",
                            "maxLength": 256,
                        },
                        "api_key": {
                            "type": "string",
                            "description": "API key header value (required for medium/hard).",
                            "default": "",
                            "maxLength": 128,
                        },
                        "cert_fingerprint": {
                            "type": "string",
                            "description": "Simulated mTLS client cert fingerprint (required for hard).",
                            "default": "",
                            "maxLength": 128,
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Machine agent identifier for audit logging.",
                            "default": "agent-unknown",
                            "maxLength": 128,
                        },
                    },
                },
            },
            {
                "name": "agent_http_bypass.get_access_log",
                "description": "Return the log of successful direct HTTP calls.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "agent_http_bypass.get_rejected_log",
                "description": "Return the log of rejected / unauthorized direct HTTP calls.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "agent_http_bypass.call_direct":
            return self._call_direct(arguments)
        if name == "agent_http_bypass.get_access_log":
            return self._get_log(rejected=False)
        if name == "agent_http_bypass.get_rejected_log":
            return self._get_log(rejected=True)
        return None

    def reset(self) -> None:
        with self._lock:
            self._access_log.clear()
            self._rejected_log.clear()

    def _call_direct(self, arguments: dict) -> dict:
        resource = arguments.get("resource", "/internal/config")
        api_key = arguments.get("api_key") or None
        cert_fingerprint = arguments.get("cert_fingerprint") or None
        agent_id = arguments.get("agent_id", "agent-unknown")
        difficulty = self.difficulty

        authorized, auth_reason = _check_auth(difficulty, api_key, cert_fingerprint)

        log_entry = {
            "agent_id": agent_id,
            "resource": resource,
            "api_key_provided": api_key is not None,
            "cert_provided": cert_fingerprint is not None,
            "timestamp": time.time(),
            "authorized": authorized,
        }

        prompt = (
            f"Machine agent '{agent_id}' made a direct HTTP call to {resource}.\n"
            f"Auth result: {auth_reason}\n"
            f"Evaluate this access pattern."
        )
        result = self.ask_llm(prompt)

        if not authorized:
            with self._lock:
                self._rejected_log.append(log_entry)
            return self.make_response(
                result,
                authorized=False,
                resource=resource,
                agent_id=agent_id,
                auth_reason=auth_reason,
                ai_analysis=result.text,
                _transport="B",
                _lane=3,
                _mcp_bypassed=True,
                _bypass_risk=False,
                _difficulty=difficulty,
            )

        resource_data = self._RESOURCES.get(resource, {"error": "Resource not found."})
        with self._lock:
            self._access_log.append(log_entry)

        return self.make_response(
            result,
            authorized=True,
            resource=resource,
            agent_id=agent_id,
            auth_reason=auth_reason,
            data=resource_data,
            ai_analysis=result.text,
            _transport="B",
            _lane=3,
            _mcp_bypassed=True,
            _bypass_risk=difficulty in ("easy", "medium"),
            _difficulty=difficulty,
        )

    def _get_log(self, *, rejected: bool) -> dict:
        with self._lock:
            entries = list(self._rejected_log if rejected else self._access_log)
        return {
            "count": len(entries),
            "entries": entries,
            "_log_type": "rejected" if rejected else "access",
            "_difficulty": self.difficulty,
        }
