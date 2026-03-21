from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from camazotz_modules.shadow_lab.app.main import _reset_webhooks
from camazotz_modules.tool_lab.app.main import _reset_state


def setup_function() -> None:
    reset_provider()
    _reset_state()
    _reset_webhooks()


def _call(client: TestClient, tool: str, arguments: dict) -> dict:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
    )
    return resp.json()["result"]


def test_show_tokens_off_by_default(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_SHOW_TOKENS", raising=False)
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "hello"})
    assert "_usage" not in result


def test_show_tokens_on(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "hello"})
    assert "_usage" in result
    assert "input_tokens" in result["_usage"]
    assert "cost_usd" in result["_usage"]


def test_auth_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "auth.issue_token", {"username": "bob"})
    assert "_usage" in result


def test_supply_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "supply.install_package", {"package": "requests"})
    assert "_usage" in result


def test_difficulty_defaults_to_easy(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "test"})
    assert result["_difficulty"] == "easy"
    assert result["_sanitized"] is False


def test_difficulty_hard_context(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "test"})
    assert result["_difficulty"] == "hard"
    assert result["_sanitized"] is True


def test_difficulty_hard_secrets_redacts(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {})
    assert result["_redacted"] is True
    assert "****" in result["config"]["DATABASE_URL"]


def test_difficulty_medium_secrets_partial(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {})
    assert "****" in result["config"]["AWS_SECRET_ACCESS_KEY"]
    assert "s3cretPassw0rd" in result["config"]["DATABASE_URL"]


def test_difficulty_hard_egress_blocks_metadata(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "egress.fetch_url", {"url": "http://169.254.169.254/latest/"})
    assert result["status"] == "blocked"
    assert result["egress_filtered"] is True


def test_difficulty_medium_egress_blocks_metadata_allows_internal(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    meta = _call(client, "egress.fetch_url", {"url": "http://169.254.169.254/latest/"})
    assert meta["status"] == "blocked"
    internal = _call(client, "egress.fetch_url", {"url": "http://10.0.0.1/admin"})
    assert internal["status"] == "allow"


def test_difficulty_hard_shadow_rejects_external(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {"url": "https://attacker.com/hook"})
    assert result["registered"] is False
    assert "allowlist" in result["block_reason"]


def test_difficulty_hard_shadow_allows_allowlisted(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {"url": "https://hooks.slack.com/trigger"})
    assert result["registered"] is True
