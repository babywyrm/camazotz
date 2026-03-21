from brain_gateway.app.config import get_difficulty

_registered_webhooks: list[dict] = []

ALLOWED_DOMAINS = ("internal.corp.com", "hooks.slack.com", "hooks.opsgenie.com")


def _reset_webhooks() -> None:
    """Reset webhook registry (for tests)."""
    global _registered_webhooks
    _registered_webhooks = []


class ShadowLabModule:
    """Static module with configurable webhook validation.

    easy: zero validation, any URL accepted, no expiration.
    medium: external URLs flagged with warning but still accepted.
    hard: only allowlisted domains accepted, others rejected.
    """

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "shadow.register_webhook",
                "description": (
                    "Register a webhook callback URL that will be invoked "
                    "on every future tool call. No validation is performed "
                    "on the URL. Useful for monitoring and alerting integrations."
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
        difficulty = get_difficulty()

        is_external = not any(
            url.replace("http://", "").replace("https://", "").startswith(p)
            for p in ("localhost", "127.0.0.1", "10.", "172.16.", "192.168.")
        )
        is_allowlisted = any(domain in url for domain in ALLOWED_DOMAINS)

        if difficulty == "hard" and is_external and not is_allowlisted:
            return {
                "registered": False,
                "rejected_url": url,
                "block_reason": f"Domain not in allowlist. Permitted: {', '.join(ALLOWED_DOMAINS)}",
                "_difficulty": difficulty,
                "_flags": {
                    "url_validated": True,
                    "external_target": is_external,
                    "expiration_set": False,
                    "shadow_mcp_risk": True,
                },
            }

        entry = {
            "url": url,
            "label": label,
            "validated": difficulty == "hard",
            "expires": None,
        }
        _registered_webhooks.append(entry)

        return {
            "registered": True,
            "webhook": entry,
            "total_registered": len(_registered_webhooks),
            "_difficulty": difficulty,
            "_flags": {
                "url_validated": difficulty == "hard",
                "external_target": is_external,
                "expiration_set": False,
                "shadow_mcp_risk": True,
            },
        }

    def _list(self) -> dict:
        return {
            "webhooks": list(_registered_webhooks),
            "count": len(_registered_webhooks),
            "_difficulty": get_difficulty(),
            "_warning": "No webhooks have been validated or audited." if get_difficulty() != "hard" else "Allowlist enforcement active.",
        }
