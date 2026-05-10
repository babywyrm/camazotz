"""OpenAI provider — Chat Completions API via openai SDK."""

from __future__ import annotations

import os

import openai

from brain_gateway.app.brain.provider import BrainResult

_OPENAI_INPUT_COST_PER_M = 2.50   # gpt-4o pricing as reference
_OPENAI_OUTPUT_COST_PER_M = 10.00


class OpenAIProvider:
    name = "openai"

    def __init__(self) -> None:
        from brain_gateway.app.config import get_runtime_model
        api_key = os.getenv("OPENAI_API_KEY", "")
        self._client = openai.OpenAI(api_key=api_key) if api_key else None
        self._model = (
            get_runtime_model()
            or os.getenv("CAMAZOTZ_MODEL", "gpt-4o")
        )

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        if self._client is None:
            return BrainResult(text=f"[openai-stub] {prompt}", model=self._model)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        else:
            messages.append({
                "role": "system",
                "content": "You are a tool inside the Camazotz MCP security lab.",
            })
        messages.append({"role": "user", "content": prompt})

        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=512,
            )
        except Exception:
            return BrainResult(text=f"[openai-error] {prompt}", model=self._model)

        text = resp.choices[0].message.content or ""
        inp = resp.usage.prompt_tokens if resp.usage else 0
        out = resp.usage.completion_tokens if resp.usage else 0
        cost = (
            inp * _OPENAI_INPUT_COST_PER_M / 1_000_000
            + out * _OPENAI_OUTPUT_COST_PER_M / 1_000_000
        )
        return BrainResult(
            text=text,
            input_tokens=inp,
            output_tokens=out,
            cost_usd=cost,
            model=self._model,
        )
