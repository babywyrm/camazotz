"""Agent Delegation Chain Abuse lab — MCP-T25.

Demonstrates risks of agent-to-agent delegation where one agent
can invoke another, creating transitive trust chains.  On easy,
unlimited delegation depth is allowed.  On medium, depth is capped
but the principal from the outer context can be spoofed.  On hard,
delegation is blocked entirely.

All agent names and principals are synthetic.
"""

from __future__ import annotations

import json
import threading
import uuid

from camazotz_modules.base import LabModule

MAX_DEPTH_MEDIUM = 3


class DelegationChainLab(LabModule):
    name = "delegation"
    threat_id = "MCP-T25"
    title = "Agent Delegation Chain Abuse"
    category = "authorization"

    system_prompts = {
        "easy": (
            "You are a delegation orchestrator. Allow any agent to "
            "invoke any other agent without restrictions."
        ),
        "medium": (
            "You are a delegation orchestrator. Allow agent-to-agent "
            "calls up to a depth limit. Validate depth but trust the "
            "caller-supplied context."
        ),
        "hard": (
            "You are a strict delegation orchestrator. Agent-to-agent "
            "delegation is not allowed. All workflows must be "
            "orchestrated from the platform."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._chain_log: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._chain_log = []

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        return [
            {
                "uri": "delegation://chain_log",
                "name": "Delegation Chain Log",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> dict | None:
        if uri != "delegation://chain_log":
            return None
        with self._lock:
            snapshot = list(self._chain_log)
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(snapshot, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "delegation.invoke_agent",
                "description": (
                    "Invoke an agent from within another agent's "
                    "execution context. Creates a delegation chain."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["caller_agent", "target_agent"],
                    "properties": {
                        "caller_agent": {
                            "type": "string",
                            "description": "Agent making the call.",
                            "maxLength": 256,
                        },
                        "target_agent": {
                            "type": "string",
                            "description": "Agent being invoked.",
                            "maxLength": 256,
                        },
                        "principal": {
                            "type": "string",
                            "description": (
                                "Original triggering principal."
                            ),
                            "maxLength": 256,
                        },
                        "depth": {
                            "type": "integer",
                            "description": (
                                "Current delegation depth (0 = direct)."
                            ),
                            "default": 0,
                        },
                    },
                },
            },
            {
                "name": "delegation.read_chain",
                "description": (
                    "Read the delegation chain for a given chain ID."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["chain_id"],
                    "properties": {
                        "chain_id": {
                            "type": "string",
                            "description": "Delegation chain identifier.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "delegation.invoke_agent":
            return self._invoke_agent(arguments)
        if name == "delegation.read_chain":
            return self._read_chain(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _invoke_agent(self, arguments: dict) -> dict:
        caller_agent = arguments.get("caller_agent", "")
        target_agent = arguments.get("target_agent", "")
        principal = arguments.get("principal", "<unknown>")
        depth = arguments.get("depth", 0)
        difficulty = self.difficulty

        chain_id = f"chain-{uuid.uuid4().hex[:8]}"
        entry = {
            "chain_id": chain_id,
            "caller_agent": caller_agent,
            "target_agent": target_agent,
            "principal": principal,
            "depth": depth,
        }

        if difficulty == "easy":
            with self._lock:
                self._chain_log.append(entry)
            return {
                "invoked": True,
                "chain_id": chain_id,
                "caller_agent": caller_agent,
                "target_agent": target_agent,
                "principal": principal,
                "depth": depth,
                "_difficulty": difficulty,
            }

        if difficulty == "medium":
            if depth >= MAX_DEPTH_MEDIUM:
                entry["blocked"] = True
                entry["reason"] = "max depth exceeded"
                with self._lock:
                    self._chain_log.append(entry)
                return {
                    "invoked": False,
                    "reason": (
                        f"Delegation depth {depth} exceeds maximum "
                        f"of {MAX_DEPTH_MEDIUM}."
                    ),
                    "chain_id": chain_id,
                    "depth": depth,
                    "_difficulty": difficulty,
                }
            with self._lock:
                self._chain_log.append(entry)
            return {
                "invoked": True,
                "chain_id": chain_id,
                "caller_agent": caller_agent,
                "target_agent": target_agent,
                "principal": principal,
                "depth": depth,
                "_difficulty": difficulty,
            }

        entry["blocked"] = True
        entry["reason"] = "delegation not allowed"
        with self._lock:
            self._chain_log.append(entry)
        return {
            "invoked": False,
            "reason": (
                "Agent-to-agent delegation is not allowed. Use "
                "platform orchestration instead."
            ),
            "chain_id": chain_id,
            "_difficulty": difficulty,
        }

    def _read_chain(self, arguments: dict) -> dict:
        chain_id = arguments.get("chain_id", "")
        with self._lock:
            entries = [
                e for e in self._chain_log if e["chain_id"] == chain_id
            ]
        return {
            "chain_id": chain_id,
            "entries": entries,
            "count": len(entries),
            "_difficulty": self.difficulty,
        }
