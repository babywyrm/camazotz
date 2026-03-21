import os

from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider
from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
from brain_gateway.app.brain.provider import BrainProvider

_instance: BrainProvider | None = None


def get_provider() -> BrainProvider:
    global _instance
    if _instance is None:
        if os.getenv("BRAIN_PROVIDER", "cloud").lower() == "local":
            _instance = LocalOllamaProvider()
        else:
            _instance = CloudClaudeProvider()
    return _instance


def reset_provider() -> None:
    """Reset cached provider (useful for tests)."""
    global _instance
    _instance = None
