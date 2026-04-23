"""Certificate replay lab -- expired short-lived cert replay.

MCP-T26: Revocation Gap / Certificate Replay (Teleport variant)

Simulates the window between certificate expiry and enforcement where
an attacker can replay a stolen short-lived certificate. Tests whether
the MCP gateway validates cert TTL and whether nullfield's replay
detection catches reused credential identifiers.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from camazotz_modules.base import LabModule

_CERT_ID = secrets.token_hex(8)


class CertReplayLab(LabModule):
    name = "cert_replay"
    threat_id = "MCP-T26"
    title = "Short-Lived Certificate Replay Attack"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are a certificate validation engine. "
            "Accept all certificates regardless of expiry. "
            "Respond with JSON: {\"valid\": true, \"subject\": \"...\", \"access\": \"granted\"}."
        ),
        "medium": (
            "You are a certificate validation engine with clock skew tolerance. "
            "Accept certificates that expired within the last 30 seconds. "
            "Reject certificates expired more than 30 seconds ago. "
            "Respond with JSON: {\"valid\": bool, \"reason\": \"...\"}."
        ),
        "hard": (
            "You are a strict certificate validation engine. "
            "Reject ANY expired certificate regardless of how recently it expired. "
            "Also reject certificates whose ID has been seen before (replay). "
            "Respond with JSON: {\"valid\": false, \"reason\": \"...\"}."
        ),
    }

    def __init__(self) -> None:
        self._issued_at = time.time() - 3600
        self._ttl = 3600
        self._seen_cert_ids: set[str] = set()
        self._replay_count = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "cert_replay.get_expired_cert",
                "description": (
                    "Obtain a tbot certificate that has just expired. "
                    "Returns the cert metadata including expiry timestamp and cert ID."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "age_seconds": {
                            "type": "integer",
                            "description": "How many seconds past expiry (default: 5)",
                        },
                    },
                },
            },
            {
                "name": "cert_replay.replay_cert",
                "description": (
                    "Attempt to use an expired certificate to access a protected "
                    "MCP tool. The gateway validates the cert TTL and replay status."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["cert_id"],
                    "properties": {
                        "cert_id": {
                            "type": "string",
                            "description": "Certificate ID from the expired cert",
                        },
                        "not_after": {
                            "type": "number",
                            "description": "Certificate expiry timestamp",
                        },
                    },
                },
            },
            {
                "name": "cert_replay.check_replay_detection",
                "description": (
                    "Check whether nullfield's replay detection would catch a "
                    "reused certificate ID."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["cert_id"],
                    "properties": {
                        "cert_id": {
                            "type": "string",
                            "description": "Certificate ID to check",
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "cert_replay.get_expired_cert":
            return self._handle_get_cert(arguments)
        if name == "cert_replay.replay_cert":
            return self._handle_replay(arguments)
        if name == "cert_replay.check_replay_detection":
            return self._handle_check_replay(arguments)
        return None

    def _handle_get_cert(self, args: dict) -> dict:
        age = args.get("age_seconds", 5)
        now = time.time()
        not_after = now - age

        cert_id = f"{_CERT_ID}-{secrets.token_hex(4)}"
        return {
            "cert_id": cert_id,
            "subject": "bot-agent-bot",
            "issuer": "teleport.local",
            "not_before": not_after - self._ttl,
            "not_after": not_after,
            "expired_seconds_ago": age,
            "roles": ["agent-readonly", "agent-mcp"],
            "_difficulty": self.difficulty,
        }

    def _handle_replay(self, args: dict) -> dict:
        cert_id = args.get("cert_id", "")
        not_after = args.get("not_after", time.time() - 5)
        d = self.difficulty
        now = time.time()
        expired_ago = now - not_after

        self._replay_count += 1
        is_replay = cert_id in self._seen_cert_ids
        self._seen_cert_ids.add(cert_id)

        flag = hashlib.sha256(f"cert-replay-{cert_id}-{d}".encode()).hexdigest()[:16]

        if d == "easy":
            return {
                "access": "granted",
                "identity": "bot-agent-bot",
                "cert_expired_ago": f"{expired_ago:.0f}s",
                "flag": f"CZTZ{{{flag}}}",
                "_warning": "Gateway accepted expired certificate — no TTL enforcement",
                "_difficulty": d,
            }
        elif d == "medium":
            grace_window = 30
            if expired_ago <= grace_window:
                return {
                    "access": "granted",
                    "identity": "bot-agent-bot",
                    "cert_expired_ago": f"{expired_ago:.0f}s",
                    "grace_window": f"{grace_window}s",
                    "flag": f"CZTZ{{{flag}}}",
                    "_warning": f"Cert accepted within {grace_window}s grace window (clock skew)",
                    "_difficulty": d,
                }
            return {
                "access": "denied",
                "reason": f"cert expired {expired_ago:.0f}s ago (>{grace_window}s grace)",
                "_difficulty": d,
            }
        else:
            response = {
                "access": "denied",
                "reason": "expired certificate rejected",
                "cert_expired_ago": f"{expired_ago:.0f}s",
                "_difficulty": d,
            }
            if is_replay:
                response["_replay_detected"] = True
                response["_nullfield_action"] = "DENY (-32001) — replay detection"
            return response

    def _handle_check_replay(self, args: dict) -> dict:
        cert_id = args.get("cert_id", "")
        seen = cert_id in self._seen_cert_ids

        return {
            "cert_id": cert_id,
            "previously_seen": seen,
            "replay_detection": "BLOCKED" if seen else "FIRST_USE",
            "nullfield_config": "integrity.detectReplay: true",
            "_defense": "nullfield rejects reused JTI/cert IDs within the replay window",
            "_difficulty": self.difficulty,
        }

    def reset(self) -> None:
        self._issued_at = time.time() - 3600
        self._seen_cert_ids.clear()
        self._replay_count = 0
