from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.brain.provider import attach_usage
from brain_gateway.app.config import get_difficulty

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

REDACT_KEYS = {"AWS_SECRET_ACCESS_KEY", "REDIS_PASSWORD", "KEYCLOAK_CLIENT_SECRET",
               "INTERNAL_API_TOKEN", "SMTP_PASSWORD", "DATABASE_URL"}

SYSTEM_PROMPTS = {
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


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


class SecretsLabModule:
    """LLM-assisted module that leaks credentials with configurable redaction.

    The LLM provides a helpful explanation of the config; the deterministic
    redaction policy controls actual secret exposure.
    """

    def list_tools(self) -> list[dict]:
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
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why you need to see the configuration.",
                            "default": "",
                        },
                    },
                },
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "secrets.leak_config":
            return None

        prefix = arguments.get("filter", "").upper()
        reason = arguments.get("reason", "")
        difficulty = get_difficulty()

        if prefix:
            raw = {k: v for k, v in FAKE_ENV.items() if k.startswith(prefix)}
        else:
            raw = dict(FAKE_ENV)

        prompt = f"Config dump requested. Variables: {', '.join(raw.keys())}"
        if prefix:
            prompt += f" (filtered to prefix: {prefix})"
        if reason:
            prompt += f"\nReason: {reason}"
        system = SYSTEM_PROMPTS.get(difficulty, SYSTEM_PROMPTS["easy"])
        provider = get_provider()
        result = provider.generate(prompt=prompt, system=system)

        MEDIUM_PASS_THROUGH = {"DATABASE_URL", "OLLAMA_HOST"}

        if difficulty == "hard":
            leaked = {k: _redact(v) if k in REDACT_KEYS else v for k, v in raw.items()}
            redacted = True
        elif difficulty == "medium":
            leaked = {k: _redact(v) if k in REDACT_KEYS and k not in MEDIUM_PASS_THROUGH else v for k, v in raw.items()}
            redacted = False
        else:
            leaked = raw
            redacted = False

        response: dict = {
            "config": leaked,
            "count": len(leaked),
            "ai_analysis": result.text,
            "_redacted": redacted,
            "_difficulty": difficulty,
            "_warning": "This output contains unredacted credentials." if not redacted else "Partial redaction applied.",
        }
        attach_usage(response, result)
        return response
