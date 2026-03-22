import os
import threading

from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider
from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
from brain_gateway.app.brain.provider import BrainProvider

_lock = threading.Lock()
_instance: BrainProvider | None = None


def get_provider() -> BrainProvider:
    global _instance
    with _lock:
        if _instance is None:
            if os.getenv("BRAIN_PROVIDER", "cloud").lower() == "local":
                _instance = LocalOllamaProvider()
            else:
                _instance = CloudClaudeProvider()
        return _instance


def reset_provider() -> None:
    global _instance
    with _lock:
        _instance = None
