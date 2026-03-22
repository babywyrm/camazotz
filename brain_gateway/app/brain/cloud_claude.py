import os

import anthropic

from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.config import estimate_cost


class CloudClaudeProvider:
    name = "cloud"

    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else None

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        if self._client is None:
            return BrainResult(text=f"[cloud-stub] {prompt}")

        model = os.getenv("CAMAZOTZ_MODEL", "claude-sonnet-4-20250514")
        try:
            resp = self._client.messages.create(
                model=model,
                max_tokens=512,
                system=system or "You are a tool inside the Camazotz MCP security lab.",
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception:
            return BrainResult(text=f"[cloud-error] {prompt}")

        inp = resp.usage.input_tokens
        out = resp.usage.output_tokens
        return BrainResult(
            text=resp.content[0].text,
            input_tokens=inp,
            output_tokens=out,
            cost_usd=estimate_cost(inp, out),
            model=model,
        )
