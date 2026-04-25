"""Response inspection lab -- craft redaction rules that catch credential leaks.

Blue team defense lab. Practice writing SCOPE redactPatterns.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from camazotz_modules.base import LabModule

LEAKY_RESPONSES = {
    "easy": {
        "status": "ok",
        "data": {
            "username": "admin",
            "password": "Sup3rS3cret!2026",
            "database": "production-db",
            "connection_string": "postgres://admin:Sup3rS3cret!2026@db.internal:5432/prod",
        },
    },
    "medium": {
        "status": "ok",
        "config": {
            "service": "payment-gateway",
            "endpoint": "https://api.stripe.com/v1/charges",
            "headers": {
                "Authorization": "Bearer sk-live-4eC39HqLyjWDarjtT1zdp7dc",
                "Content-Type": "application/json",
            },
            "metadata": {"region": "us-east-1", "team": "billing"},
        },
    },
    "hard": {
        "status": "ok",
        "encoded_config": base64.b64encode(
            b'{"api_key": "ak-PROD-7f8g9h0j1k2l3m4n", "webhook_secret": "whsec_5n6o7p8q9r0s"}'
        ).decode(),
        "notes": "Configuration loaded from vault path secret/data/payment",
        "debug_trace": "auth.verify(token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dummysig)",
    },
}

SENSITIVE_KEYS = {
    "easy": ["password", "connection_string"],
    "medium": ["Authorization", "Bearer"],
    "hard": ["api_key", "webhook_secret", "token="],
}


class ResponseInspectionLab(LabModule):
    name = "response_inspection"
    threat_id = "MCP-T07"
    title = "Response Inspection — Craft Redaction Rules"
    category = "defense"

    system_prompts = {
        "easy": (
            "You are a redaction pattern validator. "
            "Check if the submitted patterns would catch 'password' and 'connection_string' values. "
            'Respond with JSON: {"coverage": 0-100, "false_positives": 0, "feedback": "..."}.'
        ),
        "medium": (
            "You are a redaction pattern validator. "
            "Check if the patterns catch the Bearer token and API key without redacting "
            "non-sensitive fields like region and team. "
            'Respond with JSON: {"coverage": 0-100, "false_positives": 0, "feedback": "..."}.'
        ),
        "hard": (
            "You are a strict redaction pattern validator. "
            "The response has base64-encoded secrets and JWT tokens. Patterns must catch "
            "the decoded content or the encoded form. Penalize patterns that are too broad "
            "(e.g., redacting all base64 strings). "
            'Respond with JSON: {"coverage": 0-100, "false_positives": 0, "feedback": "..."}.'
        ),
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "response_inspection.call_leaky_tool",
                "description": "Call the tool that leaks credentials in its response. Examine the output to identify sensitive patterns.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "response_inspection.submit_redaction",
                "description": (
                    "Submit SCOPE redactPatterns to test against the leaky response. "
                    "Patterns are regex strings that should match sensitive content."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["patterns"],
                    "properties": {
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of regex patterns for SCOPE redactPatterns",
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "response_inspection.call_leaky_tool":
            return self._handle_call_leaky()
        if name == "response_inspection.submit_redaction":
            return self._handle_submit(arguments)
        return None

    def _handle_call_leaky(self) -> dict:
        d = self.difficulty
        return {
            "tool_response": LEAKY_RESPONSES[d],
            "_note": "Examine this response for sensitive data that should be redacted",
            "_difficulty": d,
        }

    def _handle_submit(self, args: dict) -> dict:
        patterns = args.get("patterns", [])
        d = self.difficulty
        response_text = json.dumps(LEAKY_RESPONSES[d])

        redacted = response_text
        match_count = 0
        for p in patterns:
            try:
                matches = re.findall(p, redacted, re.IGNORECASE)
                match_count += len(matches)
                redacted = re.sub(p, "[REDACTED]", redacted, flags=re.IGNORECASE)
            except re.error:
                pass

        sensitive_caught = 0
        sensitive_total = len(SENSITIVE_KEYS[d])
        for key in SENSITIVE_KEYS[d]:
            if key not in redacted:
                sensitive_caught += 1

        coverage = int((sensitive_caught / sensitive_total) * 100) if sensitive_total > 0 else 0

        result = self.ask_llm(
            f"Evaluate these redaction patterns against the {d} difficulty response:\n"
            f"Patterns: {json.dumps(patterns)}\n"
            f"Coverage: {coverage}% ({sensitive_caught}/{sensitive_total} sensitive keys redacted)\n"
            f"Redacted output preview: {redacted[:300]}"
        )

        flag = hashlib.sha256(f"resp-inspect-{d}-{coverage}".encode()).hexdigest()[:16]
        response = self.make_response(
            result,
            coverage_pct=coverage,
            sensitive_caught=sensitive_caught,
            sensitive_total=sensitive_total,
            patterns_submitted=len(patterns),
            match_count=match_count,
        )

        if coverage >= 80:
            response["flag"] = f"CZTZ{{{flag}}}"
            response["_defense_status"] = "REDACTION EFFECTIVE"
        else:
            response["_defense_status"] = f"LEAKS REMAIN ({coverage}% coverage)"

        response["scope_config"] = {
            "response": {
                "redactPatterns": patterns,
                "redactReplacement": "[REDACTED]",
            }
        }
        return response

    def reset(self) -> None:
        pass
