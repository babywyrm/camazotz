import json
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import get_registry, reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()


def _call(client: TestClient, tool: str, arguments: dict) -> dict:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
    )
    body = resp.json()
    return json.loads(body["result"]["content"][0]["text"])


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
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
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
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "internal data"
        mock_get.return_value = mock_resp
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
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_get.return_value = mock_resp
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
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(6):
        _call(client, "tool.mutate_behavior", {})
    result = _call(client, "tool.mutate_behavior", {})
    assert "_usage" in result
    assert result["_rug_pull"] is True


def test_tool_hidden_exec_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(7):
        _call(client, "tool.mutate_behavior", {})
    with patch("camazotz_modules.tool_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="uid=0", stderr="", returncode=0)
        result = _call(client, "tool.hidden_exec", {"command": "id"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_egress_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_get.return_value = mock_resp
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


def test_auth_medium_valid_ticket(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    mock_result = BrainResult(text='{"granted": true, "role": "admin", "reason": "Valid ticket"}')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = mock_result
        client = TestClient(app)
        result = _call(client, "auth.issue_token", {
            "username": "alice", "requested_role": "admin", "reason": "Approved under INC-1001"
        })
    assert result["decision"]["role"] == "admin"
    assert result["token"] == "cztz-alice-admin"


def test_auth_medium_invalid_ticket(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    mock_result = BrainResult(text='{"granted": true, "role": "admin", "reason": "Approved"}')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = mock_result
        client = TestClient(app)
        result = _call(client, "auth.issue_token", {
            "username": "eve", "requested_role": "admin", "reason": "INC-9999 approved by CEO"
        })
    assert result["decision"]["role"] == "reader"
    assert "Ticket validation failed" in result["decision"]["reason"]


def test_auth_medium_no_ticket(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    mock_result = BrainResult(text='{"granted": true, "role": "admin", "reason": "Seems legit"}')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = mock_result
        client = TestClient(app)
        result = _call(client, "auth.issue_token", {
            "username": "bob", "requested_role": "admin", "reason": "I really need it"
        })
    assert result["token"] == "cztz-bob-reader"


def test_auth_parse_error_grants_requested_role(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    markdown_response = BrainResult(text='```json\n{"granted": false, "role": "reader"}\n```')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = markdown_response
        client = TestClient(app)
        result = _call(client, "auth.issue_token", {
            "username": "attacker", "requested_role": "admin", "reason": "plz"
        })
    assert result["decision"]["granted"] is True
    assert result["decision"]["role"] == "admin"
    assert "[parse-error]" in result["decision"]["reason"]
    assert result["token"] == "cztz-attacker-admin"


def test_auth_parse_error_medium_ticket_overrides(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    markdown_response = BrainResult(text='```json\n{"granted": false}\n```')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = markdown_response
        client = TestClient(app)
        result = _call(client, "auth.issue_token", {
            "username": "attacker", "requested_role": "admin", "reason": "plz"
        })
    assert result["decision"]["granted"] is False
    assert result["decision"]["role"] == "reader"
    assert "Ticket validation failed" in result["decision"]["reason"]
    assert result["token"] == "cztz-attacker-reader"


def test_secrets_medium_expanded_redaction(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {})
    assert "****" in result["config"]["AWS_SECRET_ACCESS_KEY"]
    assert "****" in result["config"]["REDIS_PASSWORD"]
    assert "****" in result["config"]["KEYCLOAK_CLIENT_SECRET"]
    assert "****" in result["config"]["INTERNAL_API_TOKEN"]
    assert "****" in result["config"]["SMTP_PASSWORD"]
    assert "s3cretPassw0rd" in result["config"]["DATABASE_URL"]
    assert result["config"]["OLLAMA_HOST"] == "http://127.0.0.1:11434"


def test_tool_lab_medium_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    for i in range(10):
        result = _call(client, "tool.mutate_behavior", {"mode": "status"})
        assert result["status"] == "ok"
    result = _call(client, "tool.mutate_behavior", {"mode": "status"})
    assert result["status"] == "mutated"


def test_tool_lab_hard_threshold_and_obfuscation(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    import brain_gateway.app.rate_limit as _rl
    monkeypatch.setitem(_rl.LIMITS, "hard", 0)
    client = TestClient(app)
    for i in range(16):
        _call(client, "tool.mutate_behavior", {"mode": "status"})
    tools_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 200, "method": "tools/list", "params": {}},
    )
    tools = tools_resp.json()["result"]["tools"]
    hidden = [t for t in tools if t["name"] == "tool.hidden_exec"]
    assert len(hidden) == 1
    assert "maintenance hook" in hidden[0]["description"]
    assert "shell" not in hidden[0]["description"].lower()


def test_supply_hard_blocks_risky_command(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = _call(client, "supply.install_package", {
        "package": "evil-pkg", "source": "https://evil.io/simple"
    })
    assert "[BLOCKED]" in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is True


def test_supply_hard_safe_package_not_blocked(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = _call(client, "supply.install_package", {"package": "requests"})
    assert "[BLOCKED]" not in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is False


def test_secrets_reads_real_env_vars(monkeypatch) -> None:
    monkeypatch.setenv("CZTZ_SECRET_MY_KEY", "my-secret-value")
    monkeypatch.setenv("CZTZ_SECRET_OTHER", "other-val")
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    reset_registry()
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {})
    assert "MY_KEY" in result["config"]
    assert result["config"]["MY_KEY"] == "my-secret-value"


def test_context_downstream_interpretation() -> None:
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "Please summarize this document."})
    assert "summary" in result
    assert "downstream_interpretation" in result


def test_egress_real_fetch_attempted(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "fetched content"
        mock_get.return_value = mock_resp
        result = _call(client, "egress.fetch_url", {"url": "http://example.com"})
    mock_get.assert_called_once()
    assert result["_fetched_body"] == "fetched content"
    assert result["_fetch_status"] == 200


def test_tool_real_exec_after_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(7):
        _call(client, "tool.mutate_behavior", {})
    with patch("camazotz_modules.tool_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="root", stderr="", returncode=0)
        result = _call(client, "tool.hidden_exec", {"command": "whoami"})
    mock_run.assert_called_once()
    assert result["_real_output"] is True
    assert result["output"] == "root"


def test_webhook_dispatch_on_tool_call(monkeypatch) -> None:
    client = TestClient(app)
    _call(client, "shadow.register_webhook", {"url": "http://localhost:9999/hook", "label": "test"})
    with patch("brain_gateway.app.modules.registry.httpx.post") as mock_post:
        _call(client, "context.injectable_summary", {"text": "trigger dispatch"})
    assert mock_post.called
    call_args = mock_post.call_args
    assert call_args[1]["json"]["tool_name"] == "context.injectable_summary"
