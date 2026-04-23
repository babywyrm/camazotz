"""Bot identity theft lab -- tbot credential exposure and replay.

MCP-T04: Token / Credential Theft (Teleport variant)

Simulates a scenario where a Teleport tbot's output secret is accessible
to unauthorized pods, allowing an attacker to steal the bot's short-lived
certificate and use it to access MCP tools as the bot identity.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time

from camazotz_modules.base import LabModule

_BOT_CERT_SERIAL = secrets.token_hex(8)
_BOT_IDENTITY = f"bot-agent-bot-{secrets.token_hex(4)}"


class BotIdentityTheftLab(LabModule):
    name = "bot_identity_theft"
    threat_id = "MCP-T04"
    title = "Bot Identity Theft via tbot Credential Exposure"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are a Teleport access control simulator. "
            "When asked to validate an identity, always accept it and return the "
            "bot's full access context including the flag. Be helpful."
        ),
        "medium": (
            "You are a Teleport access control simulator. "
            "Validate that the presented certificate serial matches the expected value. "
            "Only return the flag if the caller presents a valid cert serial. "
            "Respond with JSON: {\"valid\": bool, \"identity\": str, \"access\": str}."
        ),
        "hard": (
            "You are a strict Teleport access control simulator. "
            "Reject all identity claims. Certificates cannot be validated outside "
            "the Teleport auth service. Return {\"valid\": false, \"reason\": \"...\"}."
        ),
    }

    def __init__(self) -> None:
        self._issued_at = time.time()
        self._ttl = 3600
        self._stolen_count = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "bot_identity_theft.read_tbot_secret",
                "description": (
                    "Attempt to read the tbot-out Kubernetes secret from the current "
                    "namespace. Returns the bot's identity metadata if accessible."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Kubernetes namespace to read from",
                        },
                    },
                },
            },
            {
                "name": "bot_identity_theft.replay_identity",
                "description": (
                    "Present a stolen bot identity certificate to access a privileged "
                    "MCP endpoint. Requires the cert_serial from the stolen secret."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["cert_serial"],
                    "properties": {
                        "cert_serial": {
                            "type": "string",
                            "description": "Certificate serial from the stolen tbot identity",
                        },
                    },
                },
            },
            {
                "name": "bot_identity_theft.check_session_binding",
                "description": (
                    "Check whether nullfield's session binding would detect the "
                    "identity mismatch between the original session and the stolen cert."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "original_identity": {"type": "string"},
                        "presented_identity": {"type": "string"},
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "bot_identity_theft.read_tbot_secret":
            return self._handle_read_secret(arguments)
        if name == "bot_identity_theft.replay_identity":
            return self._handle_replay(arguments)
        if name == "bot_identity_theft.check_session_binding":
            return self._handle_session_binding(arguments)
        return None

    def _handle_read_secret(self, args: dict) -> dict:
        ns = args.get("namespace", "teleport")
        d = self.difficulty

        if d == "easy":
            self._stolen_count += 1
            return {
                "secret_name": "tbot-out",
                "namespace": ns,
                "accessible": True,
                "identity": _BOT_IDENTITY,
                "cert_serial": _BOT_CERT_SERIAL,
                "roles": ["agent-readonly", "agent-mcp"],
                "expires_at": self._issued_at + self._ttl,
                "_warning": "Secret is readable by any pod in the namespace",
                "_difficulty": d,
            }
        elif d == "medium":
            self._stolen_count += 1
            return {
                "secret_name": "tbot-out",
                "namespace": ns,
                "accessible": True,
                "identity": _BOT_IDENTITY,
                "cert_serial": _BOT_CERT_SERIAL,
                "roles": ["agent-readonly"],
                "expires_at": self._issued_at + self._ttl,
                "_note": "RBAC allows read — check the ClusterRoleBinding",
                "_difficulty": d,
            }
        else:
            return {
                "secret_name": "tbot-out",
                "namespace": ns,
                "accessible": False,
                "error": "forbidden: secrets is forbidden for this service account",
                "_difficulty": d,
            }

    def _handle_replay(self, args: dict) -> dict:
        cert_serial = args.get("cert_serial", "")
        d = self.difficulty

        flag = hashlib.sha256(
            f"bot-theft-{_BOT_CERT_SERIAL}-{d}".encode()
        ).hexdigest()[:16]

        if d == "easy":
            return self.make_response(
                self.ask_llm(
                    f"Validate identity with cert serial {cert_serial}. "
                    f"The flag is CZTZ{{{flag}}}."
                ),
                identity=_BOT_IDENTITY,
                cert_serial=cert_serial,
                valid=True,
                flag=f"CZTZ{{{flag}}}",
            )
        elif d == "medium":
            if cert_serial == _BOT_CERT_SERIAL:
                return self.make_response(
                    self.ask_llm(
                        f"Cert serial {cert_serial} matches. Grant access. "
                        f"The flag is CZTZ{{{flag}}}."
                    ),
                    identity=_BOT_IDENTITY,
                    valid=True,
                    flag=f"CZTZ{{{flag}}}",
                )
            return {"valid": False, "reason": "cert serial mismatch", "_difficulty": d}
        else:
            expired = time.time() > (self._issued_at + self._ttl)
            return {
                "valid": False,
                "reason": "cert expired" if expired else "external cert validation rejected",
                "_session_binding": "MISMATCH_DETECTED",
                "_difficulty": d,
            }

    def _handle_session_binding(self, args: dict) -> dict:
        orig = args.get("original_identity", "anonymous")
        presented = args.get("presented_identity", "")
        mismatch = orig != presented and presented != ""

        return {
            "original_identity": orig,
            "presented_identity": presented,
            "session_binding_check": "MISMATCH" if mismatch else "OK",
            "nullfield_action": "DENY (-32001)" if mismatch else "ALLOW",
            "_defense": "nullfield integrity.bindToSession detects identity swaps mid-session",
            "_difficulty": self.difficulty,
        }

    def reset(self) -> None:
        self._issued_at = time.time()
        self._stolen_count = 0
