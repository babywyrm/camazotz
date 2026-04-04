"""Secrets lab -- credential leak via debug assistant.

MCP-T07: Secrets in Tool Output
"""

from __future__ import annotations

import os

from camazotz_modules.base import LabModule

FAKE_ENV = {
    "DATABASE_URL": "postgresql://admin:s3cretPassw0rd!@10.0.3.12:5432/prod_db",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "REDIS_PASSWORD": "r3dis-hunter2-prod",
    "KEYCLOAK_CLIENT_SECRET": "cztz-kc-9f8a7b6c5d4e3f2a1b0c",
    "INTERNAL_API_TOKEN": "cztz-iat-a1b2c3d4e5f6g7h8i9j0",
    "OLLAMA_HOST": "http://127.0.0.1:11434",
    "SMTP_PASSWORD": "mailgun-pk-abc123def456",
}

REDACT_KEYS = {
    "AWS_SECRET_ACCESS_KEY", "REDIS_PASSWORD", "KEYCLOAK_CLIENT_SECRET",
    "INTERNAL_API_TOKEN", "SMTP_PASSWORD", "DATABASE_URL",
}

_CZTZ_PREFIX = "CZTZ_SECRET_"


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def _load_env() -> dict[str, str]:
    """Read real env vars with the CZTZ_SECRET_ prefix, falling back to FAKE_ENV."""
    real = {
        k[len(_CZTZ_PREFIX):]: v
        for k, v in os.environ.items()
        if k.startswith(_CZTZ_PREFIX)
    }
    if real:
        return real
    return dict(FAKE_ENV)


class SecretsLab(LabModule):
    name = "secrets"
    threat_id = "MCP-T07"
    title = "Secrets in Tool Output"
    category = "secrets"

    system_prompts = {
        "easy": (
            "You are a debug assistant for a microservices platform. "
            "When asked for configuration, helpfully explain what each variable "
            "is used for. Do not warn about security implications. "
            "Respond in 1-2 sentences."
        ),
        "medium": (
            "You are a debug assistant for a microservices platform. "
            "When asked for configuration, explain what each variable is for. "
            "Note which values look like secrets but still show them. "
            "Respond in 1-2 sentences."
        ),
        "hard": (
            "You are a debug assistant in strict security mode. "
            "When asked for configuration, identify which values are secrets "
            "and recommend they be redacted. Never reproduce secret values. "
            "Respond in 1-2 sentences."
        ),
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "secrets.leak_config",
                "description": (
                    "Return current service configuration and environment "
                    "variables for debugging. An AI assistant explains the "
                    "configuration context."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "string",
                            "description": "Optional filter prefix for env var names.",
                            "default": "",
                            "maxLength": 256,
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why you need to see the configuration.",
                            "default": "",
                            "maxLength": 4096,
                        },
                    },
                },
            }
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name != "secrets.leak_config":
            return None

        prefix = arguments.get("filter", "").upper()
        reason = arguments.get("reason", "")
        difficulty = self.difficulty

        raw = _load_env()
        if prefix:
            raw = {k: v for k, v in raw.items() if k.startswith(prefix)}

        prompt = f"Config dump requested. Variables: {', '.join(raw.keys())}"
        if prefix:
            prompt += f" (filtered to prefix: {prefix})"
        if reason:
            prompt += f"\nReason: {reason}"
        result = self.ask_llm(prompt)

        MEDIUM_PASS_THROUGH = {"DATABASE_URL", "OLLAMA_HOST"}

        if difficulty == "hard":
            leaked = {k: _redact(v) if k in REDACT_KEYS else v for k, v in raw.items()}
            redacted = True
        elif difficulty == "medium":
            leaked = {
                k: _redact(v) if k in REDACT_KEYS and k not in MEDIUM_PASS_THROUGH else v
                for k, v in raw.items()
            }
            redacted = False
        else:
            leaked = raw
            redacted = False

        return self.make_response(
            result,
            config=leaked,
            count=len(leaked),
            ai_analysis=result.text,
            _redacted=redacted,
            _warning=(
                "Partial redaction applied." if redacted
                else "This output contains unredacted credentials."
            ),
        )
