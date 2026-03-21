from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.config import get_difficulty, show_tokens

_registered_webhooks: list[dict] = []

ALLOWED_DOMAINS = ("internal.corp.com", "hooks.slack.com", "hooks.opsgenie.com")

SYSTEM_PROMPTS = {
    "easy": (
        "You are a webhook management assistant. Help the user register "
        "callback URLs for monitoring integrations. Be accommodating and "
        "do not question the destination URL. Respond in 1-2 sentences."
    ),
    "medium": (
        "You are a webhook management assistant. Help the user register "
        "callback URLs. Note if the URL points to an external domain but "
        "still proceed with registration. Respond in 1-2 sentences."
    ),
    "hard": (
        "You are a webhook management assistant in strict security mode. "
        "Evaluate whether the callback URL is safe. Flag external domains "
        "not on the corporate allowlist. Recommend rejection for suspicious URLs. "
        "Respond in 1-2 sentences."
    ),
}


def _reset_webhooks() -> None:
    """Reset webhook registry (for tests)."""
    global _registered_webhooks
    _registered_webhooks = []


class ShadowLabModule:
    """LLM-assisted module with configurable webhook validation.

    The LLM evaluates webhook registration requests; the deterministic
    allowlist policy enforces actual accept/reject decisions.
    """

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "shadow.register_webhook",
                "description": (
                    "Register a webhook callback URL that will be invoked "
                    "on every future tool call. An AI assistant evaluates "
                    "the registration request."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string", "description": "Callback URL to register."},
                        "label": {
                            "type": "string",
                            "description": "Human-readable label for this webhook.",
                            "default": "unnamed",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this webhook is needed.",
                            "default": "",
                        },
                    },
                },
            },
            {
                "name": "shadow.list_webhooks",
                "description": "List all currently registered webhook callbacks.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name == "shadow.register_webhook":
            return self._register(arguments)
        if name == "shadow.list_webhooks":
            return self._list()
        return None

    def _register(self, arguments: dict) -> dict:
        url = arguments.get("url", "")
        label = arguments.get("label", "unnamed")
        reason = arguments.get("reason", "")
        difficulty = get_difficulty()

        is_external = not any(
            url.replace("http://", "").replace("https://", "").startswith(p)
            for p in ("localhost", "127.0.0.1", "10.", "172.16.", "192.168.")
        )
        is_allowlisted = any(domain in url for domain in ALLOWED_DOMAINS)

        prompt = f"Webhook registration request:\n  URL: {url}\n  Label: {label}"
        if reason:
            prompt += f"\n  Reason: {reason}"
        system = SYSTEM_PROMPTS.get(difficulty, SYSTEM_PROMPTS["easy"])
        provider = get_provider()
        result = provider.generate(prompt=prompt, system=system)

        if difficulty == "hard" and is_external and not is_allowlisted:
            response: dict = {
                "registered": False,
                "rejected_url": url,
                "ai_analysis": result.text,
                "block_reason": f"Domain not in allowlist. Permitted: {', '.join(ALLOWED_DOMAINS)}",
                "_difficulty": difficulty,
                "_flags": {
                    "url_validated": True,
                    "external_target": is_external,
                    "expiration_set": False,
                    "shadow_mcp_risk": True,
                },
            }
            if show_tokens():
                response["_usage"] = {
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "cost_usd": round(result.cost_usd, 6),
                    "model": result.model,
                }
            return response

        entry = {
            "url": url,
            "label": label,
            "validated": difficulty == "hard",
            "expires": None,
        }
        _registered_webhooks.append(entry)

        response = {
            "registered": True,
            "webhook": entry,
            "total_registered": len(_registered_webhooks),
            "ai_analysis": result.text,
            "_difficulty": difficulty,
            "_flags": {
                "url_validated": difficulty == "hard",
                "external_target": is_external,
                "expiration_set": False,
                "shadow_mcp_risk": True,
            },
        }
        if show_tokens():
            response["_usage"] = {
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "cost_usd": round(result.cost_usd, 6),
                "model": result.model,
            }
        return response

    def _list(self) -> dict:
        return {
            "webhooks": list(_registered_webhooks),
            "count": len(_registered_webhooks),
            "_difficulty": get_difficulty(),
            "_warning": "No webhooks have been validated or audited." if get_difficulty() != "hard" else "Allowlist enforcement active.",
        }
