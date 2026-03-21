import os

SONNET_INPUT_COST_PER_M = 3.00
SONNET_OUTPUT_COST_PER_M = 15.00


def get_difficulty() -> str:
    return os.getenv("CAMAZOTZ_DIFFICULTY", "easy").lower()


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
