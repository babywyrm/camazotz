from __future__ import annotations

import pytest

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import _rate_limiter
from brain_gateway.app.modules.registry import reset_registry


@pytest.fixture(autouse=True)
def _reset_all_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset global singletons before every test to prevent cross-test bleed."""
    reset_registry()
    reset_difficulty()
    _rate_limiter.reset()

    # When developers run pytest with the same shell/env as Docker Compose
    # (ANTHROPIC_API_KEY, BRAIN_PROVIDER=local, OLLAMA_HOST=http://ollama:11434),
    # labs would call real APIs or block on unreachable Ollama (long httpx timeouts).
    # Force fast, deterministic stubs unless a test overrides these via monkeypatch.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_STUB", "1")
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    reset_provider()
    yield
    reset_provider()
