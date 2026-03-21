import os

import httpx

from brain_gateway.app.brain.provider import BrainResult

_DEFAULT_OLLAMA_URL = "http://localhost:11434"
_DEFAULT_MODEL = "llama3.2:3b"


class LocalOllamaProvider:
    name = "local"

    def __init__(self) -> None:
        self._base_url = os.getenv("OLLAMA_HOST", _DEFAULT_OLLAMA_URL).rstrip("/")
        self._model = os.getenv("CAMAZOTZ_OLLAMA_MODEL", _DEFAULT_MODEL)

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        payload: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        try:
            resp = httpx.post(
                f"{self._base_url}/api/generate",
                json=payload,
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return BrainResult(text=f"[ollama-unavailable] {prompt}")

        text = data.get("response", "")
        eval_count = data.get("eval_count", 0)
        prompt_eval_count = data.get("prompt_eval_count", 0)

        return BrainResult(
            text=text,
            input_tokens=prompt_eval_count,
            output_tokens=eval_count,
            cost_usd=0.0,
            model=self._model,
        )
