import os

from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider
from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
from brain_gateway.app.brain.provider import BrainProvider


def get_provider() -> BrainProvider:
    if os.getenv("BRAIN_PROVIDER", "cloud").lower() == "local":
        return LocalOllamaProvider()
    return CloudClaudeProvider()
