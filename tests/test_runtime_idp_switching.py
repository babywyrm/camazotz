"""Tests for runtime IdP switching: config overrides, PUT /config, health cache, lab reset."""

from __future__ import annotations

import brain_gateway.app.config as config_mod
import brain_gateway.app.identity.service as identity_service
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.main import app
from starlette.testclient import TestClient


def _cleanup():
    """Ensure runtime overrides are cleared after each test."""
    config_mod.reset_idp_config()
    config_mod.reset_difficulty()


# --- config.py runtime override tests ---


def test_set_idp_config_overrides_env(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "mock")
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)

    result = config_mod.set_idp_config(
        provider="zitadel",
        token_endpoint="https://z.example/oauth/v2/token",
        issuer_url="https://z.example",
    )
    try:
        assert result == "zitadel"
        assert config_mod.get_idp_provider() == "zitadel"
        assert config_mod.is_live_idp() is True
        assert config_mod.get_idp_token_endpoint() == "https://z.example/oauth/v2/token"
        assert config_mod.get_idp_issuer_url() == "https://z.example"
    finally:
        _cleanup()


def test_set_idp_config_invalid_provider_falls_to_mock(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)

    result = config_mod.set_idp_config(
        provider="unknown-provider",
        token_endpoint="https://example.com/token",
    )
    try:
        assert result == "mock"
        assert config_mod.get_idp_provider() == "mock"
    finally:
        _cleanup()


def test_set_idp_config_without_token_endpoint_falls_to_mock(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)

    result = config_mod.set_idp_config(provider="okta")
    try:
        assert result == "mock"
        assert config_mod.get_idp_provider() == "mock"
    finally:
        _cleanup()


def test_reset_idp_config_returns_to_env(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)

    config_mod.set_idp_config(
        provider="okta",
        token_endpoint="https://okta.example/v1/token",
    )
    assert config_mod.get_idp_provider() == "okta"

    result = config_mod.reset_idp_config()
    try:
        assert result == "mock"
        assert config_mod.get_idp_token_endpoint() == ""
    finally:
        _cleanup()


def test_idp_field_reads_runtime_override_over_env(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_CLIENT_ID", "env-client")
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)

    config_mod.set_idp_config(
        provider="zitadel",
        token_endpoint="https://z.example/token",
        client_id="runtime-client",
    )
    try:
        assert config_mod.get_idp_client_id() == "runtime-client"
    finally:
        _cleanup()


# --- Health cache invalidation ---


def test_set_idp_config_invalidates_health_cache(monkeypatch) -> None:
    identity_service._idp_health_ok = True
    identity_service._idp_health_checked_at = 99999.0

    config_mod.set_idp_config(
        provider="okta",
        token_endpoint="https://okta.example/v1/token",
    )
    try:
        assert identity_service._idp_health_ok is None
        assert identity_service._idp_health_checked_at == 0.0
    finally:
        _cleanup()


def test_reset_idp_config_invalidates_health_cache() -> None:
    identity_service._idp_health_ok = True
    identity_service._idp_health_checked_at = 99999.0

    config_mod.reset_idp_config()
    assert identity_service._idp_health_ok is None
    assert identity_service._idp_health_checked_at == 0.0


def test_invalidate_idp_health_cache_directly() -> None:
    identity_service._idp_health_ok = True
    identity_service._idp_health_checked_at = 99999.0

    identity_service.invalidate_idp_health_cache()
    assert identity_service._idp_health_ok is None
    assert identity_service._idp_health_checked_at == 0.0


# --- PUT /config with idp field ---


def test_put_config_idp_switches_to_mock() -> None:
    client = TestClient(app)
    resp = client.put("/config", json={"idp": {"provider": "mock"}})
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "mock"
    finally:
        _cleanup()


def test_put_config_idp_mock_overrides_env(monkeypatch) -> None:
    """Sending idp.provider=mock forces mock even when env says zitadel."""
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    monkeypatch.setenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", "https://z.example/token")
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)
    client = TestClient(app)
    resp = client.put("/config", json={"idp": {"provider": "mock"}})
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "mock"
    finally:
        _cleanup()


def test_put_config_reset_idp_clears_override(monkeypatch) -> None:
    """reset_idp=true clears runtime override, falls back to env."""
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    monkeypatch.setattr(identity_service, "_idp_health_ok", None)
    monkeypatch.setattr(identity_service, "_idp_health_checked_at", 0.0)
    config_mod.set_idp_config(
        provider="okta",
        token_endpoint="https://okta.example/v1/token",
    )
    client = TestClient(app)
    resp = client.put("/config", json={"reset_idp": True})
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "mock"
    finally:
        _cleanup()


def test_put_config_idp_switches_to_live(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)
    client = TestClient(app)
    resp = client.put("/config", json={
        "idp": {
            "provider": "okta",
            "token_endpoint": "https://okta.example/v1/token",
            "issuer_url": "https://okta.example",
        },
    })
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "okta"
    finally:
        _cleanup()


def test_put_config_idp_switch_resets_labs(monkeypatch) -> None:
    """Switching from mock to a live IdP resets all lab state."""
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)
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
        "idp": {
            "provider": "zitadel",
            "token_endpoint": "https://z.example/token",
        },
    })
    try:
        assert resp.status_code == 200
        assert len(reset_called) == 1, "Lab reset must be called on IdP switch"
    finally:
        registry.reset_all = original_reset  # type: ignore[assignment]
        _cleanup()


def test_put_config_idp_same_provider_no_reset(monkeypatch) -> None:
    """Switching to the same provider doesn't trigger a lab reset."""
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    from brain_gateway.app.modules.registry import get_registry

    registry = get_registry()
    reset_called = []
    original_reset = registry.reset_all

    def _track_reset():  # pragma: no cover — intentionally never called in this test
        reset_called.append(True)
        original_reset()

    registry.reset_all = _track_reset  # type: ignore[assignment]

    client = TestClient(app)
    resp = client.put("/config", json={"idp": {"provider": "mock"}})
    try:
        assert resp.status_code == 200
        assert len(reset_called) == 0, "No reset when provider unchanged"
    finally:
        registry.reset_all = original_reset  # type: ignore[assignment]
        _cleanup()


def test_put_config_idp_returns_idp_status(monkeypatch) -> None:
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)
    client = TestClient(app)
    resp = client.put("/config", json={
        "idp": {
            "provider": "okta",
            "token_endpoint": "https://okta.example/v1/token",
        },
    })
    try:
        data = resp.json()
        assert "idp_provider" in data
        assert "idp_degraded" in data
        assert "brain" in data
    finally:
        _cleanup()


def test_put_config_idp_with_difficulty_combined(monkeypatch) -> None:
    """PUT /config can update both difficulty and IdP simultaneously."""
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)
    client = TestClient(app)
    resp = client.put("/config", json={
        "difficulty": "hard",
        "idp": {
            "provider": "okta",
            "token_endpoint": "https://okta.example/v1/token",
        },
    })
    try:
        data = resp.json()
        assert data["difficulty"] == "hard"
        assert data["idp_provider"] == "okta"
    finally:
        _cleanup()


def test_get_identity_provider_uses_runtime_override(monkeypatch) -> None:
    """get_identity_provider() respects runtime IdP config override."""
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)

    config_mod.set_idp_config(
        provider="zitadel",
        issuer_url="https://z.example",
        token_endpoint="https://z.example/token",
        introspection_endpoint="https://z.example/introspect",
        revocation_endpoint="https://z.example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    try:
        from brain_gateway.app.identity.service import get_identity_provider
        from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider

        p = get_identity_provider()
        assert isinstance(p, ZitadelIdentityProvider)
    finally:
        _cleanup()


def test_get_identity_provider_falls_back_after_reset(monkeypatch) -> None:
    """After reset_idp_config(), provider returns to env-based default."""
    monkeypatch.delenv("CAMAZOTZ_IDP_PROVIDER", raising=False)
    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: True)

    config_mod.set_idp_config(
        provider="okta",
        token_endpoint="https://okta.example/token",
    )
    config_mod.reset_idp_config()

    from brain_gateway.app.identity.service import get_identity_provider

    p = get_identity_provider()
    assert isinstance(p, MockIdentityProvider)


# --- OIDC auto-discovery via PUT /config ---


def test_put_config_idp_auto_discovers_endpoints(monkeypatch) -> None:
    """PUT /config with issuer_url but no explicit endpoints triggers OIDC discovery."""
    import json as _json
    from unittest.mock import patch
    from io import BytesIO

    discovery_doc = _json.dumps({
        "issuer": "https://example.okta.com/oauth2/default",
        "token_endpoint": "https://example.okta.com/oauth2/default/v1/token",
        "introspection_endpoint": "https://example.okta.com/oauth2/default/v1/introspect",
        "revocation_endpoint": "https://example.okta.com/oauth2/default/v1/revoke",
    }).encode()

    class _FakeResponse:
        def read(self) -> bytes:
            return discovery_doc
        def __enter__(self):
            return self
        def __exit__(self, *a: object) -> None:
            pass

    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)

    with patch("urllib.request.urlopen", return_value=_FakeResponse()):
        client = TestClient(app)
        resp = client.put("/config", json={
            "idp": {
                "provider": "okta",
                "issuer_url": "https://example.okta.com/oauth2/default",
            },
        })
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "okta"
        assert config_mod.get_idp_token_endpoint() == "https://example.okta.com/oauth2/default/v1/token"
        assert config_mod.get_idp_introspection_endpoint() == "https://example.okta.com/oauth2/default/v1/introspect"
        assert config_mod.get_idp_revocation_endpoint() == "https://example.okta.com/oauth2/default/v1/revoke"
    finally:
        _cleanup()


def test_put_config_idp_auto_discovery_failure_preserves_original(monkeypatch) -> None:
    """If OIDC discovery fails, the original payload is used as-is."""
    from unittest.mock import patch

    def _fail_urlopen(*a: object, **kw: object) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(identity_service, "_idp_is_reachable", lambda _url: False)

    with patch("urllib.request.urlopen", side_effect=_fail_urlopen):
        client = TestClient(app)
        resp = client.put("/config", json={
            "idp": {
                "provider": "auth0",
                "issuer_url": "https://unreachable.auth0.com",
            },
        })
    try:
        assert resp.status_code == 200
        data = resp.json()
        assert data["idp_provider"] == "mock"
        assert config_mod.get_idp_token_endpoint() == ""
    finally:
        _cleanup()
