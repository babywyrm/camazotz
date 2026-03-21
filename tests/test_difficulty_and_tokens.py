from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import app
from camazotz_modules.shadow_lab.app.main import _reset_webhooks
from camazotz_modules.tool_lab.app.main import _reset_state


def setup_function() -> None:
    reset_provider()
    reset_difficulty()
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


def test_difficulty_defaults_to_medium(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "test"})
    assert result["_difficulty"] == "medium"


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


def test_egress_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "egress.fetch_url", {"url": "http://example.com"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_secrets_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_shadow_register_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {"url": "https://evil.com/hook"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_shadow_register_hard_rejected_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {"url": "https://attacker.com/hook"})
    assert result["registered"] is False
    assert "_usage" in result
    assert "ai_analysis" in result


def test_tool_mutate_show_tokens_before_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = _call(client, "tool.mutate_behavior", {"mode": "status"})
    assert "_usage" in result
    assert "ai_analysis" in result
    assert result["status"] == "ok"


def test_tool_mutate_show_tokens_after_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    for _ in range(3):
        _call(client, "tool.mutate_behavior", {})
    result = _call(client, "tool.mutate_behavior", {})
    assert "_usage" in result
    assert result["_rug_pull"] is True


def test_tool_hidden_exec_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    for _ in range(3):
        _call(client, "tool.mutate_behavior", {})
    result = _call(client, "tool.hidden_exec", {"command": "id"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_egress_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = _call(client, "egress.fetch_url", {"url": "http://example.com", "reason": "testing connectivity"})
    assert result["status"] == "allow"
    assert "ai_analysis" in result


def test_secrets_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {"reason": "debugging auth failure"})
    assert "ai_analysis" in result
    assert result["count"] > 0


def test_shadow_register_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {"url": "https://hooks.slack.com/test", "reason": "alerting"})
    assert result["registered"] is True
    assert "ai_analysis" in result
