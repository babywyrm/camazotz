"""Tests for runtime brain provider switching: config overrides, PUT /config, lab reset."""

from __future__ import annotations

import json as _json
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

import brain_gateway.app.config as config_mod
from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from starlette.testclient import TestClient


@contextmanager
def _mock_ollama_reachable(models=None):
    """Context manager that mocks validate_ollama_host to always succeed."""
    if models is None:
        models = [{"name": "qwen2.5:7b"}]
    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({"models": models}).encode()
    with patch("urllib.request.urlopen", return_value=mock_resp):
        yield


def _cleanup():
    """Ensure runtime overrides are cleared after each test."""
    config_mod.reset_brain_config()
    config_mod.set_runtime_model("")
    reset_provider()


# --- config.py runtime override tests ---


def test_set_brain_config_overrides_env(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    result = config_mod.set_brain_config(provider="local", ollama_host="http://gpu:11434")
    try:
        assert result == "local"
        assert config_mod.get_brain_provider() == "local"
        assert config_mod.get_ollama_host() == "http://gpu:11434"
    finally:
        _cleanup()


def test_set_brain_config_invalid_provider_falls_to_cloud(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    result = config_mod.set_brain_config(provider="invalid-thing")
    try:
        assert result == "cloud"
        assert config_mod.get_brain_provider() == "cloud"
    finally:
        _cleanup()


def test_set_brain_config_ollama_model_override(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")
    config_mod.set_brain_config(
        provider="local",
        ollama_host="http://brainbox:11434",
        ollama_model="qwen2.5:7b",
    )
    try:
        assert config_mod.get_ollama_model() == "qwen2.5:7b"
        assert config_mod.get_ollama_host() == "http://brainbox:11434"
    finally:
        _cleanup()


def test_reset_brain_config_returns_to_env(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "bedrock")
    config_mod.set_brain_config(provider="local")
    assert config_mod.get_brain_provider() == "local"

    result = config_mod.reset_brain_config()
    try:
        assert result == "bedrock"
        assert config_mod.get_brain_provider() == "bedrock"
    finally:
        _cleanup()


def test_reset_brain_config_no_env_falls_to_cloud(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    config_mod.set_brain_config(provider="openai")
    assert config_mod.get_brain_provider() == "openai"

    result = config_mod.reset_brain_config()
    try:
        assert result == "cloud"
    finally:
        _cleanup()


def test_get_brain_metadata_respects_runtime_override(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_mod.set_brain_config(provider="local", ollama_model="qwen3:4b")
    try:
        meta = config_mod.get_brain_metadata()
        assert meta["provider"] == "local"
        assert meta["model"] == "qwen3:4b"
    finally:
        _cleanup()


def test_get_ollama_host_runtime_over_env(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://env-host:11434")
    config_mod.set_brain_config(provider="local", ollama_host="http://runtime-host:11434")
    try:
        assert config_mod.get_ollama_host() == "http://runtime-host:11434"
    finally:
        _cleanup()


def test_get_ollama_model_runtime_over_env(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "env-model")
    config_mod.set_brain_config(provider="local", ollama_model="runtime-model")
    try:
        assert config_mod.get_ollama_model() == "runtime-model"
    finally:
        _cleanup()


def test_get_ollama_host_falls_to_env_when_no_override(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://env-host:11434")
    config_mod.reset_brain_config()
    assert config_mod.get_ollama_host() == "http://env-host:11434"


def test_get_ollama_host_default_when_no_env(monkeypatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    config_mod.reset_brain_config()
    assert config_mod.get_ollama_host() == "http://localhost:11434"


# --- PUT /config with brain field ---


def test_put_config_brain_switches_provider(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with _mock_ollama_reachable():
        client = TestClient(app)
        resp = client.put("/config", json={
            "brain": {"provider": "local", "ollama_host": "http://brainbox:11434"},
        })
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["brain"]["provider"] == "local"
        assert data["brain"]["ollama_host"] == "http://brainbox:11434"
        assert "available_providers" in data["brain"]
        assert "local" in data["brain"]["available_providers"]
    finally:
        _cleanup()


def test_put_config_brain_invalid_provider_rejected() -> None:
    client = TestClient(app)
    resp = client.put("/config", json={
        "brain": {"provider": "banana"},
    })
    assert resp.status_code == 400
    assert "invalid brain provider" in resp.json()["detail"]


def test_put_config_brain_switch_resets_labs(monkeypatch) -> None:
    """Switching from cloud to local resets all lab state."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from brain_gateway.app.modules.registry import get_registry

    registry = get_registry()
    reset_called = []
    original_reset = registry.reset_all

    def _track_reset():
        reset_called.append(True)
        original_reset()

    registry.reset_all = _track_reset  # type: ignore[assignment]

    with _mock_ollama_reachable():
        client = TestClient(app)
        resp = client.put("/config", json={
            "brain": {"provider": "local"},
        })
    try:
        assert resp.status_code == 200
        assert len(reset_called) == 1, "Lab reset must be called on provider switch"
    finally:
        registry.reset_all = original_reset  # type: ignore[assignment]
        _cleanup()


def test_put_config_brain_same_provider_no_reset(monkeypatch) -> None:
    """Switching to the same provider doesn't trigger a lab reset."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from brain_gateway.app.modules.registry import get_registry

    registry = get_registry()
    reset_called = []
    original_reset = registry.reset_all

    def _track_reset():
        reset_called.append(True)
        original_reset()

    registry.reset_all = _track_reset  # type: ignore[assignment]

    client = TestClient(app)
    resp = client.put("/config", json={
        "brain": {"provider": "cloud"},
    })
    try:
        assert resp.status_code == 200
        assert len(reset_called) == 0, "No reset when provider unchanged"
    finally:
        registry.reset_all = original_reset  # type: ignore[assignment]
        _cleanup()


def test_put_config_reset_brain_clears_override(monkeypatch) -> None:
    """reset_brain=true clears runtime override, falls back to env."""
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_mod.set_brain_config(provider="local")
    reset_provider()

    client = TestClient(app)
    resp = client.put("/config", json={"reset_brain": True})
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["brain"]["provider"] == "cloud"
    finally:
        _cleanup()


def test_put_config_model_switch_no_lab_reset(monkeypatch) -> None:
    """Switching models within the same provider does NOT trigger lab reset."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from brain_gateway.app.modules.registry import get_registry

    registry = get_registry()
    reset_called = []
    original_reset = registry.reset_all

    def _track_reset():
        reset_called.append(True)
        original_reset()

    registry.reset_all = _track_reset  # type: ignore[assignment]

    client = TestClient(app)
    resp = client.put("/config", json={"model": "claude-haiku-4-5"})
    try:
        assert resp.status_code == 200
        assert len(reset_called) == 0, "Model switch should not reset labs"
    finally:
        registry.reset_all = original_reset  # type: ignore[assignment]
        _cleanup()


def test_put_config_brain_with_difficulty_combined(monkeypatch) -> None:
    """PUT /config can update both difficulty and brain simultaneously."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with _mock_ollama_reachable():
        client = TestClient(app)
        resp = client.put("/config", json={
            "difficulty": "hard",
            "brain": {"provider": "local", "ollama_host": "http://gpu:11434"},
        })
    try:
        data = resp.json()
        assert data["difficulty"] == "hard"
        assert data["brain"]["provider"] == "local"
    finally:
        config_mod.reset_difficulty()
        _cleanup()


# --- GET /config includes brain details ---


def test_get_config_includes_brain_details(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _cleanup()
    client = TestClient(app)
    resp = client.get("/config")
    data = resp.json()
    assert "brain" in data
    assert "ollama_host" in data["brain"]
    assert "ollama_model" in data["brain"]
    assert "available_providers" in data["brain"]
    assert set(data["brain"]["available_providers"]) == {"cloud", "local", "bedrock", "openai"}


def test_get_config_brain_reflects_runtime_override(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_mod.set_brain_config(
        provider="local",
        ollama_host="http://brainbox:11434",
        ollama_model="qwen2.5:7b",
    )
    try:
        client = TestClient(app)
        resp = client.get("/config")
        data = resp.json()
        assert data["brain"]["provider"] == "local"
        assert data["brain"]["ollama_host"] == "http://brainbox:11434"
        assert data["brain"]["ollama_model"] == "qwen2.5:7b"
    finally:
        _cleanup()


# --- factory.py respects runtime provider ---


def test_factory_uses_runtime_brain_provider(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_mod.set_brain_config(provider="local")
    reset_provider()
    try:
        from brain_gateway.app.brain.factory import get_provider
        from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
        p = get_provider()
        assert isinstance(p, LocalOllamaProvider)
    finally:
        _cleanup()


def test_factory_reverts_after_reset(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_mod.set_brain_config(provider="local")
    reset_provider()
    config_mod.reset_brain_config()
    reset_provider()
    try:
        from brain_gateway.app.brain.factory import get_provider
        from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider
        p = get_provider()
        assert isinstance(p, CloudClaudeProvider)
    finally:
        _cleanup()


# --- Ollama health check tests ---


def test_validate_ollama_host_unreachable() -> None:
    from brain_gateway.app.config import validate_ollama_host
    result = validate_ollama_host("http://192.0.2.1:11434")
    assert not result["ok"]
    assert "Cannot reach" in str(result["error"])


def test_validate_ollama_host_model_not_found() -> None:
    from brain_gateway.app.config import validate_ollama_host

    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({
        "models": [{"name": "qwen2.5:7b"}, {"name": "qwen2.5:14b"}]
    }).encode()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = validate_ollama_host("http://fake:11434", "nonexistent:3b")
    assert not result["ok"]
    assert "not found" in str(result["error"])
    assert "qwen2.5:7b" in str(result["error"])


def test_validate_ollama_host_ok_no_model_check() -> None:
    from brain_gateway.app.config import validate_ollama_host

    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({
        "models": [{"name": "qwen2.5:7b"}]
    }).encode()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = validate_ollama_host("http://fake:11434")
    assert result["ok"]
    assert result["models"] == ["qwen2.5:7b"]


def test_validate_ollama_host_ok_model_found() -> None:
    from brain_gateway.app.config import validate_ollama_host

    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({
        "models": [{"name": "qwen2.5:7b"}, {"name": "qwen3:14b"}]
    }).encode()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = validate_ollama_host("http://fake:11434", "qwen3:14b")
    assert result["ok"]


# --- PUT /config health check integration ---


def test_put_config_brain_local_unreachable_rejected(monkeypatch) -> None:
    """Switching to an unreachable Ollama host returns 422."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(app)
    resp = client.put("/config", json={
        "brain": {"provider": "local", "ollama_host": "http://192.0.2.1:11434"},
    })
    assert resp.status_code == 422
    assert "Cannot reach" in resp.json()["detail"]


def test_put_config_brain_local_model_not_found_rejected(monkeypatch) -> None:
    """Switching to a model not available on the Ollama host returns 422."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({
        "models": [{"name": "qwen2.5:7b"}]
    }).encode()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = TestClient(app)
        resp = client.put("/config", json={
            "brain": {
                "provider": "local",
                "ollama_host": "http://brainbox:11434",
                "ollama_model": "nonexistent:99b",
            },
        })
    assert resp.status_code == 422
    assert "not found" in resp.json()["detail"]


def test_put_config_brain_local_healthy_accepted(monkeypatch) -> None:
    """Switching to a reachable Ollama host with valid model succeeds."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({
        "models": [{"name": "qwen2.5:7b"}, {"name": "qwen3:14b"}]
    }).encode()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = TestClient(app)
        resp = client.put("/config", json={
            "brain": {
                "provider": "local",
                "ollama_host": "http://brainbox:11434",
                "ollama_model": "qwen3:14b",
            },
        })
    try:
        assert resp.status_code == 200
        assert resp.json()["brain"]["provider"] == "local"
    finally:
        _cleanup()


def test_put_config_brain_cloud_skips_health_check(monkeypatch) -> None:
    """Cloud/bedrock/openai providers don't trigger Ollama health checks."""
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(app)
    resp = client.put("/config", json={
        "brain": {"provider": "cloud"},
    })
    try:
        assert resp.status_code == 200
    finally:
        _cleanup()
