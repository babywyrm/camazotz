"""Runtime configuration — difficulty, cost estimation, feature flags."""

from __future__ import annotations

import os
import threading
from typing import Final, Literal

Difficulty = Literal["easy", "medium", "hard"]

SONNET_INPUT_COST_PER_M: Final[float] = 3.00
SONNET_OUTPUT_COST_PER_M: Final[float] = 15.00
VALID_DIFFICULTIES: Final[tuple[Difficulty, ...]] = ("easy", "medium", "hard")

_lock = threading.Lock()
_runtime_difficulty: str | None = None


def get_difficulty() -> str:
    """Return the active difficulty (runtime override > env var > 'medium')."""
    with _lock:
        if _runtime_difficulty is not None:
            return _runtime_difficulty
    return os.getenv("CAMAZOTZ_DIFFICULTY", "medium").lower()


def set_difficulty(level: str) -> str:
    """Set runtime difficulty; invalid values are silently ignored."""
    global _runtime_difficulty
    level = level.lower()
    if level not in VALID_DIFFICULTIES:
        return get_difficulty()
    with _lock:
        _runtime_difficulty = level
        return _runtime_difficulty


def reset_difficulty() -> None:
    """Clear the runtime override so env/default takes effect again."""
    global _runtime_difficulty
    with _lock:
        _runtime_difficulty = None


def show_tokens() -> bool:
    """Whether to include ``_usage`` metadata in tool responses."""
    return os.getenv("CAMAZOTZ_SHOW_TOKENS", "").lower() in ("true", "1", "yes")


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    """Rough USD cost estimate for Sonnet-class models."""
    return (
        input_tokens * SONNET_INPUT_COST_PER_M / 1_000_000
        + output_tokens * SONNET_OUTPUT_COST_PER_M / 1_000_000
    )


def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")


def get_ollama_model() -> str:
    return os.getenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")


def get_idp_provider() -> Literal["mock", "zitadel"]:
    """Active identity provider: ``mock`` (default) or ``zitadel``."""
    value = os.getenv("CAMAZOTZ_IDP_PROVIDER", "mock").lower().strip()
    return value if value in {"mock", "zitadel"} else "mock"
