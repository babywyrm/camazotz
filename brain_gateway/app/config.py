"""Runtime configuration — difficulty, cost estimation, feature flags."""

from __future__ import annotations

import ipaddress
import os
import re
import threading
from typing import Final, Literal
from urllib.parse import urlparse

Difficulty = Literal["easy", "medium", "hard"]

SONNET_INPUT_COST_PER_M: Final[float] = 3.00
SONNET_OUTPUT_COST_PER_M: Final[float] = 15.00
VALID_DIFFICULTIES: Final[tuple[Difficulty, ...]] = ("easy", "medium", "hard")

BrainProviderType = Literal["cloud", "local", "bedrock", "openai"]
VALID_BRAIN_PROVIDERS: Final[tuple[BrainProviderType, ...]] = (
    "cloud", "local", "bedrock", "openai",
)

_lock = threading.Lock()
_runtime_difficulty: str | None = None
_runtime_model: str | None = None
_runtime_brain_config: dict[str, str] | None = None


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


def _brain_field(field: str, env_var: str, default: str = "") -> str:
    """Read a brain config field: runtime override > env var."""
    with _lock:
        if _runtime_brain_config is not None:
            return _runtime_brain_config.get(field, "").strip() or default
    return os.getenv(env_var, default).strip() or default


def get_brain_provider() -> BrainProviderType:
    """Active brain provider (runtime override > env var > cloud)."""
    with _lock:
        if _runtime_brain_config is not None:
            val = _runtime_brain_config.get("provider", "cloud").lower().strip()
            return val if val in VALID_BRAIN_PROVIDERS else "cloud"  # type: ignore[return-value]
    val = os.getenv("BRAIN_PROVIDER", "cloud").lower().strip()
    return val if val in VALID_BRAIN_PROVIDERS else "cloud"  # type: ignore[return-value]


def set_brain_config(
    *,
    provider: str,
    ollama_host: str = "",
    ollama_model: str = "",
) -> BrainProviderType:
    """Set runtime brain provider override."""
    global _runtime_brain_config
    with _lock:
        _runtime_brain_config = {
            "provider": provider.lower().strip(),
            "ollama_host": ollama_host.strip(),
            "ollama_model": ollama_model.strip(),
        }
    return get_brain_provider()


def reset_brain_config() -> BrainProviderType:
    """Clear runtime brain override so env/default takes effect again."""
    global _runtime_brain_config
    with _lock:
        _runtime_brain_config = None
    return get_brain_provider()


def get_brain_metadata() -> dict[str, str]:
    """Return read-only metadata for the active inference backend."""
    provider = get_brain_provider()
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
    elif provider == "openai":
        model = runtime or os.getenv("CAMAZOTZ_MODEL", "gpt-4o")
        mode = "live" if os.getenv("OPENAI_API_KEY", "").strip() else "stub"
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
    cloud / openai: built-in default list; overridden by CAMAZOTZ_AVAILABLE_MODELS.
    bedrock: CAMAZOTZ_AVAILABLE_MODELS only (model IDs are account/region-specific).
             Falls back to [current model] with source='config' if env var unset.

    Each entry: {"id": str, "label": str, "source": "ollama"|"config"|"builtin"|"fallback"}
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
    if provider == "openai":
        active = get_runtime_model() or os.getenv("CAMAZOTZ_MODEL", "gpt-4o")
        _CLOUD_DEFAULTS = ["gpt-4o", "gpt-4o-mini", "o1", "o3-mini"]
    ids = list(dict.fromkeys([active] + _CLOUD_DEFAULTS))  # active first, deduped
    return [{"id": m, "label": m, "source": "builtin"} for m in ids]


_OLLAMA_HOST_ALLOWLIST_RE: Final[list[re.Pattern[str]]] = [
    re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"),
    re.compile(r"^https?://192\.168\.\d{1,3}\.\d{1,3}(:\d+)?$"),
    re.compile(r"^https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$"),
    re.compile(r"^https?://172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}(:\d+)?$"),
    re.compile(r"^https?://[a-zA-Z0-9_-]+(:\d+)?$"),  # bare hostnames (no dots = local DNS)
]

_BLOCKED_PORTS: Final[frozenset[int]] = frozenset({22, 25, 53, 443, 3306, 5432, 6379, 27017})


def validate_ollama_url(url: str) -> str | None:
    """Validate an Ollama host URL against the allowlist. Returns error string or None."""
    url = url.strip().rstrip("/")
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"Invalid scheme '{parsed.scheme}'; only http/https allowed"

    hostname = parsed.hostname or ""
    port = parsed.port

    if port and port in _BLOCKED_PORTS:
        return f"Port {port} is blocked (looks like a non-Ollama service)"

    if hostname in ("metadata.google.internal", "169.254.169.254"):
        return "Cloud metadata endpoints are blocked"

    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_link_local and hostname != "169.254.169.254":
            return f"Link-local address {hostname} is not allowed"
        if addr.is_loopback or addr.is_private:
            return None
        return f"Public IP {hostname} is not in the Ollama host allowlist"
    except ValueError:
        pass

    for pattern in _OLLAMA_HOST_ALLOWLIST_RE:
        if pattern.match(url):
            return None

    if "." in hostname:
        return (
            f"Host '{hostname}' is not in the Ollama allowlist. "
            "Only private IPs, localhost, and bare hostnames are allowed."
        )

    return None


def validate_ollama_host(host: str, model: str = "") -> dict[str, object]:
    """Check Ollama host reachability and optional model availability.

    Returns {"ok": True/False, "error": str|None, "models": list[str]}.
    Called during PUT /config to fail fast before accepting a brain switch.
    """
    import json as _json
    import urllib.request as _req
    import urllib.error as _err

    host = host.rstrip("/")
    result: dict[str, object] = {"ok": False, "error": None, "models": []}

    try:
        resp = _req.urlopen(f"{host}/api/tags", timeout=5)
        data = _json.loads(resp.read())
        available = [m["name"] for m in data.get("models", [])]
        result["models"] = available
    except (_err.URLError, OSError, ValueError) as exc:
        result["error"] = f"Cannot reach Ollama at {host}: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"Unexpected error probing {host}: {exc}"
        return result

    if model and model not in available:
        result["error"] = (
            f"Model '{model}' not found on {host}. "
            f"Available: {', '.join(available[:8]) or '(none)'}"
        )
        return result

    result["ok"] = True
    return result


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    """Rough USD cost estimate for Sonnet-class models."""
    return (
        input_tokens * SONNET_INPUT_COST_PER_M / 1_000_000
        + output_tokens * SONNET_OUTPUT_COST_PER_M / 1_000_000
    )


def get_ollama_host() -> str:
    return _brain_field("ollama_host", "OLLAMA_HOST", "http://localhost:11434")


def get_ollama_model() -> str:
    return _brain_field("ollama_model", "CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")


IdpProvider = Literal["mock", "zitadel", "okta"]

_LIVE_IDP_PROVIDERS: Final[frozenset[str]] = frozenset({"zitadel", "okta"})

_runtime_idp_config: dict[str, str] | None = None


def get_idp_provider() -> IdpProvider:
    """Active identity provider (runtime override > env var > mock)."""
    with _lock:
        if _runtime_idp_config is not None:
            value = _runtime_idp_config.get("provider", "mock").lower().strip()
            if value not in _LIVE_IDP_PROVIDERS:
                return "mock"
            if not _runtime_idp_config.get("token_endpoint", "").strip():
                return "mock"
            return value  # type: ignore[return-value]
    value = os.getenv("CAMAZOTZ_IDP_PROVIDER", "mock").lower().strip()
    if value not in _LIVE_IDP_PROVIDERS:
        return "mock"
    if not os.getenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "").strip():
        return "mock"
    return value  # type: ignore[return-value]


def is_live_idp() -> bool:
    """True when a real (non-mock) identity provider is active."""
    return get_idp_provider() in _LIVE_IDP_PROVIDERS


def set_idp_config(
    *,
    provider: str,
    issuer_url: str = "",
    token_endpoint: str = "",
    introspection_endpoint: str = "",
    revocation_endpoint: str = "",
    client_id: str = "",
    client_secret: str = "",
) -> IdpProvider:
    """Set runtime IdP override. Invalidates the health cache."""
    global _runtime_idp_config
    from brain_gateway.app.identity.service import invalidate_idp_health_cache

    with _lock:
        _runtime_idp_config = {
            "provider": provider.lower().strip(),
            "issuer_url": issuer_url.strip(),
            "token_endpoint": token_endpoint.strip(),
            "introspection_endpoint": introspection_endpoint.strip(),
            "revocation_endpoint": revocation_endpoint.strip(),
            "client_id": client_id.strip(),
            "client_secret": client_secret.strip(),
        }
    invalidate_idp_health_cache()
    return get_idp_provider()


def reset_idp_config() -> IdpProvider:
    """Clear runtime IdP override so env/default takes effect again."""
    global _runtime_idp_config
    from brain_gateway.app.identity.service import invalidate_idp_health_cache

    with _lock:
        _runtime_idp_config = None
    invalidate_idp_health_cache()
    return get_idp_provider()


def _idp_field(field: str, env_var: str) -> str:
    """Read an IdP config field: runtime override > env var."""
    with _lock:
        if _runtime_idp_config is not None:
            return _runtime_idp_config.get(field, "").strip()
    return os.getenv(env_var, "").strip()


def get_idp_issuer_url() -> str:
    return _idp_field("issuer_url", "CAMAZOTZ_IDP_ISSUER_URL")


def get_idp_token_endpoint() -> str:
    return _idp_field("token_endpoint", "CAMAZOTZ_IDP_TOKEN_ENDPOINT")


def get_idp_introspection_endpoint() -> str:
    return _idp_field("introspection_endpoint", "CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT")


def get_idp_revocation_endpoint() -> str:
    return _idp_field("revocation_endpoint", "CAMAZOTZ_IDP_REVOCATION_ENDPOINT")


def get_idp_client_id() -> str:
    return _idp_field("client_id", "CAMAZOTZ_IDP_CLIENT_ID")


def get_idp_client_secret() -> str:
    return _idp_field("client_secret", "CAMAZOTZ_IDP_CLIENT_SECRET")
