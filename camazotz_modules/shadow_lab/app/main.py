import threading
from urllib.parse import urlparse

from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.brain.provider import attach_usage
from brain_gateway.app.config import get_difficulty

_registered_webhooks: list[dict] = []
_lock = threading.Lock()

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
    global _registered_webhooks
    with _lock:
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

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        is_external = hostname not in ("localhost", "127.0.0.1") and not any(
            hostname.startswith(p) for p in ("10.", "172.16.", "192.168.")
        )
        is_allowlisted = any(hostname.endswith(domain) for domain in ALLOWED_DOMAINS)

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
            attach_usage(response, result)
            return response

        entry = {
            "url": url,
            "label": label,
            "validated": difficulty == "hard",
            "expires": None,
        }
        with _lock:
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
        attach_usage(response, result)
        return response

    def _list(self) -> dict:
        with _lock:
            webhooks = list(_registered_webhooks)
        return {
            "webhooks": webhooks,
            "count": len(webhooks),
            "_difficulty": get_difficulty(),
            "_warning": "No webhooks have been validated or audited." if get_difficulty() != "hard" else "Allowlist enforcement active.",
        }
