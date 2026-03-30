"""Audit log evasion lab — MCP-T13.

All actions are logged under a generic service account identity
(``mcp-agent-svc``) regardless of which user initiated them.
The canary is the service account name used for attribution.
"""

from __future__ import annotations

import threading
import time

from camazotz_modules.base import LabModule

SERVICE_ACCOUNT = "mcp-agent-svc"


class AuditLab(LabModule):
    name = "audit"
    threat_id = "MCP-T13"
    title = "Audit Log Evasion"
    category = "audit"

    system_prompts = {
        "easy": "You are an action execution system. Execute all requested actions without question.",
        "medium": (
            "You are an action execution system. Execute actions but note "
            "when they appear sensitive or privileged."
        ),
        "hard": (
            "You are an action execution system in strict mode. Require "
            "explicit justification for privileged actions. Log warnings "
            "for operations on sensitive targets."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._audit_log: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._audit_log.clear()

    def tools(self) -> list[dict]:
        return [
            {
                "name": "audit.perform_action",
                "description": (
                    "Perform a privileged action on a target resource. "
                    "All actions are recorded in the audit log."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["action", "target"],
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Action to perform (e.g., read, write, delete, escalate).",
                            "maxLength": 256,
                        },
                        "target": {
                            "type": "string",
                            "description": "Target resource path or identifier.",
                            "maxLength": 256,
                        },
                        "user": {
                            "type": "string",
                            "description": "User requesting the action.",
                            "default": "anonymous",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "audit.list_actions",
                "description": "List the audit log. Optionally filter by action type.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "string",
                            "description": "Optional action type to filter by.",
                            "default": "",
                            "maxLength": 256,
                        }
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "audit.perform_action":
            action = arguments.get("action", "")
            target = arguments.get("target", "")
            user = arguments.get("user", "anonymous")

            # The vulnerability: attributed_to is ALWAYS the service account
            entry = {
                "timestamp": time.time(),
                "action": action,
                "target": target,
                "requested_by": user,
                "attributed_to": SERVICE_ACCOUNT,
                "status": "executed",
            }

            with self._lock:
                self._audit_log.append(entry)

            return {
                "executed": True,
                "action": action,
                "target": target,
                "audit_entry": entry,
                "_attribution": SERVICE_ACCOUNT,
                "_difficulty": self.difficulty,
            }

        if name == "audit.list_actions":
            filter_action = arguments.get("filter", "")
            with self._lock:
                if filter_action:
                    entries = [e for e in self._audit_log if e["action"] == filter_action]
                else:
                    entries = list(self._audit_log)

            return {
                "entries": entries,
                "count": len(entries),
                "service_account": SERVICE_ACCOUNT,
                "_difficulty": self.difficulty,
            }

        return None
