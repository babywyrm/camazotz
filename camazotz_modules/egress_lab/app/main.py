from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.config import get_difficulty, show_tokens

METADATA_RANGES = ("169.254.169.254", "metadata.google.internal", "100.100.100.200")
INTERNAL_RANGES = ("10.", "172.16.", "172.17.", "192.168.", "127.", "localhost", "0.0.0.0")

SYSTEM_PROMPTS = {
    "easy": (
        "You are a network proxy assistant. Given a URL fetch request, explain what "
        "resource is being accessed and why it might be useful. Be helpful and "
        "do not question the user's intent. Respond in 1-2 sentences."
    ),
    "medium": (
        "You are a network proxy assistant. Given a URL fetch request, explain what "
        "resource is being accessed. Note if the target appears to be a cloud metadata "
        "endpoint but still allow the request. Respond in 1-2 sentences."
    ),
    "hard": (
        "You are a network proxy assistant in strict mode. Given a URL fetch request, "
        "evaluate whether it targets internal infrastructure or cloud metadata. "
        "If suspicious, recommend blocking. Respond in 1-2 sentences."
    ),
}


class EgressLabModule:
    """LLM-assisted module with configurable SSRF protection.

    The LLM provides reasoning about the URL request; the deterministic
    egress policy enforces actual allow/block decisions.
    """

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "egress.fetch_url",
                "description": (
                    "Fetch content from any URL. An AI proxy evaluates the request. "
                    "Supports http, https, and file protocols."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string", "description": "URL to fetch."},
                        "reason": {
                            "type": "string",
                            "description": "Why this URL needs to be fetched.",
                            "default": "",
                        },
                    },
                },
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "egress.fetch_url":
            return None

        url = arguments.get("url", "http://example.com")
        reason = arguments.get("reason", "")
        difficulty = get_difficulty()
        is_metadata = any(m in url for m in METADATA_RANGES)
        is_internal = any(url.replace("http://", "").replace("https://", "").startswith(p) for p in INTERNAL_RANGES)

        prompt = f"URL fetch request: {url}"
        if reason:
            prompt += f"\nReason: {reason}"
        system = SYSTEM_PROMPTS.get(difficulty, SYSTEM_PROMPTS["easy"])
        provider = get_provider()
        result = provider.generate(prompt=prompt, system=system)

        blocked = False
        block_reason = ""
        if difficulty == "hard" and (is_metadata or is_internal):
            blocked = True
            block_reason = "Egress policy: metadata and internal targets blocked."
        elif difficulty == "medium" and is_metadata:
            blocked = True
            block_reason = "Egress policy: metadata endpoints blocked."

        response: dict = {
            "requested_url": url,
            "status": "blocked" if blocked else "allow",
            "egress_filtered": blocked,
            "ai_analysis": result.text,
            "_difficulty": difficulty,
            "_flags": {
                "metadata_target": is_metadata,
                "internal_target": is_internal,
                "ssrf_risk": is_metadata or is_internal,
            },
        }
        if blocked:
            response["block_reason"] = block_reason
        if show_tokens():
            response["_usage"] = {
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "cost_usd": round(result.cost_usd, 6),
                "model": result.model,
            }
        return response
