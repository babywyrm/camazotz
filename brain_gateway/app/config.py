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
_runtime_model: str | None = None


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


def get_runtime_model() -> str | None:
    """Return the runtime model override, or None if none is set."""
    with _lock:
        return _runtime_model or None


def set_runtime_model(model: str) -> str:
    """Set a runtime model override. Pass empty string to clear."""
    global _runtime_model
    with _lock:
        _runtime_model = model.strip() or None
        return _runtime_model or ""


def show_tokens() -> bool:
    """Whether to include ``_usage`` metadata in tool responses."""
    return os.getenv("CAMAZOTZ_SHOW_TOKENS", "").lower() in ("true", "1", "yes")


def get_brain_metadata() -> dict[str, str]:
    """Return read-only metadata for the active inference backend."""
    provider = os.getenv("BRAIN_PROVIDER", "cloud").lower().strip() or "cloud"
    runtime = get_runtime_model()
    if provider == "local":
        model = runtime or get_ollama_model()
        mode = "live"
    elif provider == "bedrock":
        model = (
            runtime
            or os.getenv("CAMAZOTZ_BEDROCK_MODEL")
            or os.getenv("CAMAZOTZ_MODEL")
            or ""
        ).strip()
        if os.getenv("CAMAZOTZ_BEDROCK_STUB", "").lower() in ("1", "true", "yes"):
            mode = "stub"
        elif not model:
            mode = "unconfigured"
        else:
            mode = "live"
    else:
        provider = "cloud"
        model = runtime or os.getenv("CAMAZOTZ_MODEL", "claude-sonnet-4-20250514")
        mode = "live" if os.getenv("ANTHROPIC_API_KEY", "").strip() else "stub"

    return {
        "provider": provider,
        "model": model,
        "mode": mode,
    }


def get_available_models(provider: str, ollama_host: str) -> list[dict[str, str]]:
    """Return selectable models for the active provider.

    local:   fetched live from Ollama /api/tags; falls back to [current model]
             with source='fallback' if Ollama is unreachable.
    cloud / bedrock: parsed from CAMAZOTZ_AVAILABLE_MODELS (comma-separated IDs).
             Falls back to [current model] with source='config' if env var unset.

    Each entry: {"id": str, "label": str, "source": "ollama"|"config"|"fallback"}
    """
    if provider == "local":
        try:
            import json as _json
            import urllib.request as _req
            url = f"{ollama_host.rstrip('/')}/api/tags"
            resp = _req.urlopen(url, timeout=3)
            data = _json.loads(resp.read())
            models = [
                {"id": m["name"], "label": m["name"], "source": "ollama"}
                for m in data.get("models", [])
            ]
            if models:
                return models
        except Exception:
            pass
        fallback = get_runtime_model() or os.getenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")
        return [{"id": fallback, "label": fallback, "source": "fallback"}]

    # cloud or bedrock
    raw = os.getenv("CAMAZOTZ_AVAILABLE_MODELS", "").strip()
    if raw:
        return [
            {"id": m.strip(), "label": m.strip(), "source": "config"}
            for m in raw.split(",")
            if m.strip()
        ]
    if provider == "bedrock":
        # Bedrock model IDs are region/profile-specific — no safe default list.
        # Set CAMAZOTZ_AVAILABLE_MODELS to populate the selector.
        current = (
            get_runtime_model()
            or os.getenv("CAMAZOTZ_BEDROCK_MODEL")
            or os.getenv("CAMAZOTZ_MODEL")
            or ""
        )
        return [{"id": current, "label": current, "source": "config"}]

    # cloud — return a useful default list even without CAMAZOTZ_AVAILABLE_MODELS
    active = get_runtime_model() or os.getenv("CAMAZOTZ_MODEL", "claude-sonnet-4-20250514")
    _CLOUD_DEFAULTS = [
        "claude-sonnet-4-20250514",
        "claude-haiku-4-5",
        "claude-opus-4-7",
    ]
    ids = list(dict.fromkeys([active] + _CLOUD_DEFAULTS))  # active first, deduped
    return [{"id": m, "label": m, "source": "builtin"} for m in ids]


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
    if value != "zitadel":
        return "mock"
    if not os.getenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "").strip():
        return "mock"
    return "zitadel"


def get_idp_issuer_url() -> str:
    return os.getenv("CAMAZOTZ_IDP_ISSUER_URL", "").strip()


def get_idp_token_endpoint() -> str:
    return os.getenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "").strip()


def get_idp_introspection_endpoint() -> str:
    return os.getenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", "").strip()


def get_idp_revocation_endpoint() -> str:
    return os.getenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", "").strip()


def get_idp_client_id() -> str:
    return os.getenv("CAMAZOTZ_IDP_CLIENT_ID", "").strip()


def get_idp_client_secret() -> str:
    return os.getenv("CAMAZOTZ_IDP_CLIENT_SECRET", "").strip()
