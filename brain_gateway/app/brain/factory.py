"""Singleton factory for the active LLM provider."""

import threading

from brain_gateway.app.brain.bedrock_claude import BedrockClaudeProvider
from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider
from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
from brain_gateway.app.brain.openai_provider import OpenAIProvider
from brain_gateway.app.brain.provider import BrainProvider

_lock = threading.Lock()
_instance: BrainProvider | None = None


def get_provider() -> BrainProvider:
    """Return the cached LLM provider, creating it on first call."""
    global _instance
    with _lock:
        if _instance is None:
            from brain_gateway.app.config import get_brain_provider

            mode = get_brain_provider()
            if mode == "local":
                _instance = LocalOllamaProvider()
            elif mode == "bedrock":
                _instance = BedrockClaudeProvider()
            elif mode == "openai":
                _instance = OpenAIProvider()
            else:
                _instance = CloudClaudeProvider()
        return _instance


def reset_provider() -> None:
    global _instance
    with _lock:
        _instance = None
