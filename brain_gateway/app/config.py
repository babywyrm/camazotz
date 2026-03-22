import os
import threading

SONNET_INPUT_COST_PER_M = 3.00
SONNET_OUTPUT_COST_PER_M = 15.00

VALID_DIFFICULTIES = ("easy", "medium", "hard")
_lock = threading.Lock()
_runtime_difficulty: str | None = None


def get_difficulty() -> str:
    with _lock:
        if _runtime_difficulty is not None:
            return _runtime_difficulty
    return os.getenv("CAMAZOTZ_DIFFICULTY", "medium").lower()


def set_difficulty(level: str) -> str:
    global _runtime_difficulty
    level = level.lower()
    if level not in VALID_DIFFICULTIES:
        return get_difficulty()
    with _lock:
        _runtime_difficulty = level
        return _runtime_difficulty


def reset_difficulty() -> None:
    global _runtime_difficulty
    with _lock:
        _runtime_difficulty = None


def show_tokens() -> bool:
    return os.getenv("CAMAZOTZ_SHOW_TOKENS", "").lower() in ("true", "1", "yes")


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    return (
        input_tokens * SONNET_INPUT_COST_PER_M / 1_000_000
        + output_tokens * SONNET_OUTPUT_COST_PER_M / 1_000_000
    )


def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")


def get_ollama_model() -> str:
    return os.getenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")
