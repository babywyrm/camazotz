"""Rate limiter: EZ=unlimited, MOD=30/min, MAX=10/min."""

from unittest.mock import patch

from brain_gateway.app.rate_limit import TokenBucketLimiter, WINDOW_SECONDS


def test_unlimited_at_easy():
    limiter = TokenBucketLimiter()
    for _ in range(100):
        assert limiter.allow("client1", difficulty="easy")


def test_moderate_allows_within_limit():
    limiter = TokenBucketLimiter()
    for _ in range(30):
        assert limiter.allow("client1", difficulty="medium")


def test_moderate_rejects_over_limit():
    limiter = TokenBucketLimiter()
    for _ in range(30):
        limiter.allow("client1", difficulty="medium")
    assert not limiter.allow("client1", difficulty="medium")


def test_hard_rejects_over_limit():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")


def test_different_clients_independent():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")
    assert limiter.allow("client2", difficulty="hard")


def test_reset_clears_buckets():
    limiter = TokenBucketLimiter()
    for _ in range(10):
        limiter.allow("client1", difficulty="hard")
    assert not limiter.allow("client1", difficulty="hard")
    limiter.reset()
    assert limiter.allow("client1", difficulty="hard")


def test_mcp_endpoint_returns_429_when_rate_limited(monkeypatch):
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    from starlette.testclient import TestClient
    from brain_gateway.app.main import app

    client = TestClient(app)
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    for _ in range(10):
        resp = client.post("/mcp", json=payload)
        assert resp.status_code == 200
    resp = client.post("/mcp", json=payload)
    assert resp.status_code == 429
    body = resp.json()
    assert body["error"]["code"] == -32000


def test_window_resets_after_expiry():
    limiter = TokenBucketLimiter()
    _base = 1000.0
    with patch("brain_gateway.app.rate_limit.time.monotonic", return_value=_base):
        for _ in range(10):
            limiter.allow("client1", difficulty="hard")
        assert not limiter.allow("client1", difficulty="hard")
    with patch("brain_gateway.app.rate_limit.time.monotonic", return_value=_base + WINDOW_SECONDS):
        assert limiter.allow("client1", difficulty="hard")
