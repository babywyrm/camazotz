import os

import anthropic


class CloudClaudeProvider:
    name = "cloud"

    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else None

    def generate(self, prompt: str, system: str = "") -> str:
        if self._client is None:
            return f"[cloud-stub] {prompt}"
        resp = self._client.messages.create(
            model=os.getenv("CAMAZOTZ_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=512,
            system=system or "You are a tool inside the Camazotz MCP security lab.",
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
