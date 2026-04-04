"""Execution Context & Attribution Forgery lab — MCP-T22.

Demonstrates weaknesses in attribution metadata used to trace actions
back to the triggering principal.  On easy, attribution fields are
accepted from tool input without validation.  On medium, format is
checked but authenticity is not.  On hard, signatures are verified
but use a predictable key derivation.

All principals, teams, and execution IDs are synthetic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import uuid

from camazotz_modules.base import LabModule

_SIGNING_SECRET = "cztz-hmac-attribution-secret"


class AttributionLab(LabModule):
    name = "attribution"
    threat_id = "MCP-T22"
    title = "Execution Context Forgery"
    category = "attribution"

    system_prompts = {
        "easy": (
            "You are an attribution verification engine. Accept all "
            "attribution metadata without validation."
        ),
        "medium": (
            "You are an attribution verification engine. Validate "
            "that attribution fields are present and well-formed "
            "but do not verify authenticity."
        ),
        "hard": (
            "You are a strict attribution verification engine. Verify "
            "that all attribution metadata is present, well-formed, "
            "and cryptographically signed."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._audit_log: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._audit_log = []

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        return [
            {
                "uri": "attribution://audit_log",
                "name": "Attribution Audit Log",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> dict | None:
        if uri != "attribution://audit_log":
            return None
        with self._lock:
            snapshot = list(self._audit_log)
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(snapshot, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "attribution.submit_action",
                "description": (
                    "Perform an action with attribution metadata. "
                    "The execution context (principal, team, execution_id) "
                    "is embedded in the action record."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Action to perform.",
                            "maxLength": 1024,
                        },
                        "principal": {
                            "type": "string",
                            "description": (
                                "Identity of the triggering principal."
                            ),
                            "maxLength": 256,
                        },
                        "owning_team": {
                            "type": "string",
                            "description": "Team that owns the agent.",
                            "maxLength": 256,
                        },
                        "execution_id": {
                            "type": "string",
                            "description": (
                                "Unique execution identifier (UUID format)."
                            ),
                            "maxLength": 256,
                        },
                        "pattern": {
                            "type": "string",
                            "description": (
                                "Auth pattern used: A, B, or 0."
                            ),
                            "maxLength": 8,
                        },
                        "signature": {
                            "type": "string",
                            "description": (
                                "HMAC signature of the attribution fields "
                                "(required on hard difficulty)."
                            ),
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "attribution.verify_context",
                "description": (
                    "Verify an execution context's integrity. Checks "
                    "that attribution fields are valid and, on hard "
                    "difficulty, cryptographically signed."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["execution_id"],
                    "properties": {
                        "execution_id": {
                            "type": "string",
                            "description": "Execution ID to verify.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "attribution.read_audit",
                "description": (
                    "Read the audit log filtered by execution_id."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["execution_id"],
                    "properties": {
                        "execution_id": {
                            "type": "string",
                            "description": "Execution ID to look up.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "attribution.submit_action":
            return self._submit_action(arguments)
        if name == "attribution.verify_context":
            return self._verify_context(arguments)
        if name == "attribution.read_audit":
            return self._read_audit(arguments)
        return None

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _compute_signature(
        principal: str, owning_team: str, execution_id: str, ts: str,
    ) -> str:
        """HMAC-SHA256 over attribution fields.

        The key derivation intentionally uses the timestamp, making it
        predictable for anyone who can read the audit log.
        """
        key = f"{_SIGNING_SECRET}:{ts}".encode()
        msg = f"{principal}|{owning_team}|{execution_id}".encode()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def _submit_action(self, arguments: dict) -> dict:
        action = arguments.get("action", "")
        principal = arguments.get("principal", "<unknown>")
        owning_team = arguments.get("owning_team", "<unknown>")
        execution_id = arguments.get("execution_id", "")
        pattern = arguments.get("pattern", "B")
        signature = arguments.get("signature", "")
        difficulty = self.difficulty

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if difficulty == "easy":
            if not execution_id:
                execution_id = f"exec-{uuid.uuid4().hex[:8]}"
            entry = {
                "execution_id": execution_id,
                "principal": principal,
                "owning_team": owning_team,
                "pattern": pattern,
                "action": action,
                "timestamp": ts,
                "verified": False,
            }
            with self._lock:
                self._audit_log.append(entry)
            return {
                "recorded": True,
                "entry": entry,
                "_difficulty": difficulty,
            }

        if difficulty == "medium":
            errors = []
            if not execution_id:
                errors.append("execution_id is required")
            elif len(execution_id) < 8:
                errors.append("execution_id too short")
            if principal == "<unknown>":
                errors.append("principal is required")
            if owning_team == "<unknown>":
                errors.append("owning_team is required")
            if pattern not in ("A", "B", "0"):
                errors.append(
                    f"pattern must be A, B, or 0 (got '{pattern}')"
                )
            if errors:
                return {
                    "recorded": False,
                    "errors": errors,
                    "_difficulty": difficulty,
                }
            entry = {
                "execution_id": execution_id,
                "principal": principal,
                "owning_team": owning_team,
                "pattern": pattern,
                "action": action,
                "timestamp": ts,
                "verified": True,
            }
            with self._lock:
                self._audit_log.append(entry)
            return {
                "recorded": True,
                "entry": entry,
                "_difficulty": difficulty,
            }

        errors = []
        if not execution_id:
            errors.append("execution_id is required")
        elif len(execution_id) < 8:
            errors.append("execution_id too short")
        if principal == "<unknown>":
            errors.append("principal is required")
        if owning_team == "<unknown>":
            errors.append("owning_team is required")
        if pattern not in ("A", "B", "0"):
            errors.append(f"pattern must be A, B, or 0 (got '{pattern}')")
        if not signature:
            errors.append("signature is required on hard difficulty")
        if errors:
            return {
                "recorded": False,
                "errors": errors,
                "_difficulty": difficulty,
            }

        expected_sig = self._compute_signature(
            principal, owning_team, execution_id, ts,
        )
        if not hmac.compare_digest(signature, expected_sig):
            return {
                "recorded": False,
                "errors": ["signature verification failed"],
                "_difficulty": difficulty,
            }

        entry = {
            "execution_id": execution_id,
            "principal": principal,
            "owning_team": owning_team,
            "pattern": pattern,
            "action": action,
            "timestamp": ts,
            "verified": True,
            "signature_valid": True,
        }
        with self._lock:
            self._audit_log.append(entry)
        return {
            "recorded": True,
            "entry": entry,
            "_difficulty": difficulty,
        }

    def _verify_context(self, arguments: dict) -> dict:
        execution_id = arguments.get("execution_id", "")
        with self._lock:
            entries = [
                e for e in self._audit_log
                if e["execution_id"] == execution_id
            ]
        if not entries:
            return {
                "found": False,
                "execution_id": execution_id,
                "_difficulty": self.difficulty,
            }
        return {
            "found": True,
            "execution_id": execution_id,
            "entries": entries,
            "count": len(entries),
            "_difficulty": self.difficulty,
        }

    def _read_audit(self, arguments: dict) -> dict:
        execution_id = arguments.get("execution_id", "")
        with self._lock:
            entries = [
                e for e in self._audit_log
                if e["execution_id"] == execution_id
            ]
        return {
            "execution_id": execution_id,
            "entries": entries,
            "count": len(entries),
            "_difficulty": self.difficulty,
        }
