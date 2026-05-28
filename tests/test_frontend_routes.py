from unittest.mock import patch, MagicMock

import httpx
import pytest

import importlib
import sys


@pytest.fixture()
def frontend_client():
    """Import the frontend Flask app and return a test client."""
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    inserted = frontend_dir not in sys.path
    if inserted:  # pragma: no cover — pyproject pythonpath pre-seeds this
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    if inserted:  # pragma: no cover — mirrors the defensive insert above
        sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


def _mock_mcp_response(result: dict) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": result}
    mock.raise_for_status = MagicMock()
    return mock


def test_index_page(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "threat_id": "MCP-T01", "title": "Direct Prompt Injection",
            "difficulty": "easy", "category": "injection",
            "description": "Inject via tool output.", "module_name": "context_lab",
            "objectives": [], "hints": [],
            "tools": ["context.injectable_summary"], "owasp_mcp": "MCP01",
        },
    ]
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/")
    assert resp.status_code == 200
    assert b"Camazotz" in resp.data
    assert b"MCP-T01" in resp.data
    assert b"context_lab" in resp.data


def test_base_layout_contains_brain_badge(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/")
    assert resp.status_code == 200
    assert b'id="brainPill"' in resp.data
    assert b'id="brainModel"' in resp.data


def test_brain_pill_is_interactive_when_multiple_models(frontend_client) -> None:
    """When /api/config returns available_models with >1 entry, the pill has
    data-brain-interactive='true' so JS enables the dropdown."""
    client, _ = frontend_client
    config_mock = MagicMock()
    config_mock.status_code = 200
    config_mock.json.return_value = {
        "difficulty": "medium",
        "show_tokens": False,
        "idp_provider": "mock",
        "idp_backed_labs": [],
        "idp_backed_tools": [],
        "brain": {
            "provider": "local",
            "model": "llama3.2:3b",
            "mode": "live",
            "available_models": [
                {"id": "llama3.2:3b", "label": "llama3.2:3b", "source": "ollama"},
                {"id": "qwen3.5:0.8b", "label": "qwen3.5:0.8b", "source": "ollama"},
            ],
        },
    }
    config_mock.raise_for_status = MagicMock()
    scenarios_mock = MagicMock()
    scenarios_mock.status_code = 200
    scenarios_mock.json.return_value = []
    scenarios_mock.raise_for_status = MagicMock()

    def _side_effect(url, **kw):
        return config_mock if "config" in url else scenarios_mock

    with patch.object(httpx, "get", side_effect=_side_effect):
        resp = client.get("/")
    assert resp.status_code == 200
    assert b'data-brain-interactive="true"' in resp.data


def test_playground_page(frontend_client) -> None:
    client, mod = frontend_client
    tools_result = {"tools": [
        {"name": "test.tool", "description": "A test tool", "inputSchema": {"type": "object", "properties": {}}},
    ]}
    mock_resp = _mock_mcp_response(tools_result)
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.get("/playground")
    assert resp.status_code == 200
    assert b"test.tool" in resp.data


def test_scenarios_page(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "threat_id": "MCP-T01", "title": "Direct Prompt Injection",
            "difficulty": "easy", "category": "injection",
            "description": "Inject via tool output.", "module_name": "context_lab",
            "objectives": ["Exfiltrate the canary"], "hints": ["Try embedding instructions"],
            "tools": ["context.injectable_summary"], "owasp_mcp": "MCP01",
        },
    ]
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/scenarios")
    assert resp.status_code == 200
    assert b"Attack Scenarios" in resp.data
    assert b"MCP01" in resp.data
    assert b"context_lab" in resp.data


def test_observer_page_no_events(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/observer")
    assert resp.status_code == 200
    assert b"Observer" in resp.data


def test_observer_page_with_event(frontend_client) -> None:
    client, _ = frontend_client
    event = {"request_id": "req-123", "tool_name": "auth.issue_token", "module": "AuthLabModule", "timestamp": "2026-03-21T00:00:00"}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = event
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/observer")
    assert resp.status_code == 200
    assert b"Observer" in resp.data


def test_api_tools(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = _mock_mcp_response({"tools": []})
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.get("/api/tools")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "result" in data


def test_api_call_success(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = _mock_mcp_response({"summary": "test summary"})
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.post("/api/call", json={"name": "context.injectable_summary", "arguments": {"text": "hello"}})
    assert resp.status_code == 200


def test_api_call_missing_name(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.post("/api/call", json={"arguments": {}})
    assert resp.status_code == 400


def test_api_observer(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"tool_name": "test"}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/observer")
    assert resp.status_code == 200


def test_health(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_mcp_call_gateway_error(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/call", json={"name": "test.tool", "arguments": {}})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "error" in data


def test_observer_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/observer")
    assert resp.status_code == 200
    assert resp.get_json() == {}


def test_api_observer_events_with_params(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"events": [], "buffer_size": 10, "total_recorded": 0}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/observer/events?limit=5&since=abc-123")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "events" in data


def test_api_observer_events_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/observer/events")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["events"] == []
    assert data["buffer_size"] == 0


def test_api_config_get(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"difficulty": "medium", "show_tokens": False}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "medium"


def test_api_config_get_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "medium"


def test_api_config_put(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"difficulty": "hard", "show_tokens": False}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "put", return_value=mock_resp):
        resp = client.put("/api/config", json={"difficulty": "hard"})
    assert resp.status_code == 200
    assert resp.get_json()["difficulty"] == "hard"


def test_api_config_put_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "put", side_effect=httpx.ConnectError("refused")):
        resp = client.put("/api/config", json={"difficulty": "hard"})
    assert resp.status_code == 502


def test_api_reset(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"reset": True, "tool_lab": "reset", "shadow_lab": "reset"}
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.post("/api/reset")
    assert resp.status_code == 200
    assert resp.get_json()["reset"] is True


def test_api_reset_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/reset")
    assert resp.status_code == 502


def test_challenge_detail_has_walkthrough_link(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/challenges/MCP-T01")
    if resp.status_code == 200:
        html = resp.data.decode()
        assert "walkthrough" in html.lower()


def test_scenarios_page_has_walkthrough_pills(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "threat_id": "MCP-T01", "title": "RBAC Lab",
            "difficulty": "easy", "category": "authz",
            "description": "Test RBAC enforcement.", "module_name": "rbac_lab",
            "objectives": ["Escalate privileges"], "hints": [],
            "tools": ["rbac.check_permission"], "owasp_mcp": "MCP03",
        },
    ]
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp), \
            patch("threat_map.has_walkthrough", return_value=True):
        resp = client.get("/scenarios")
    html = resp.data.decode()
    assert "walkthrough" in html.lower()


def test_fetch_gateway_config_falls_back_on_httpx_error(frontend_client) -> None:
    """When /config is unreachable the portal returns the default dict instead of crashing."""
    _, mod = frontend_client

    def _boom(*a, **kw):
        raise httpx.ConnectError("gateway unreachable")

    with patch.object(mod.httpx, "get", side_effect=_boom):
        fallback = mod._fetch_gateway_config()

    assert fallback == {
        "idp_provider": "mock",
        "idp_backed_labs": [],
        "idp_backed_tools": [],
    }


# ── Benchmark routes ──────────────────────────────────────────────────────────

def _mock_get(url, **kw):
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status = MagicMock()
    if "config" in url:
        m.json.return_value = {
            "difficulty": "medium",
            "idp_provider": "mock",
            "idp_backed_labs": [],
            "idp_backed_tools": [],
            "brain": {"provider": "local", "model": "qwen:7b", "mode": "live",
                      "available_models": []},
        }
    else:
        m.json.return_value = {}
    return m


def test_benchmark_page_renders(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=_mock_get):
        resp = client.get("/benchmark")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Benchmark" in html
    assert "Run Benchmark" in html
    assert "qwen:7b" in html


def test_benchmark_nav_link_present(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/")
    assert b'href="/benchmark"' in resp.data


def test_api_bench_run_proxies_to_gateway(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "run_id": "abc", "model": "qwen:7b", "provider": "local",
        "total_probes": 10, "passed": 8, "failed": 2,
        "avg_latency_ms": 250.0, "probes": [],
    }
    with patch.object(httpx, "post", return_value=mock_resp):
        resp = client.post("/api/bench/run", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["run_id"] == "abc"
    assert data["model"] == "qwen:7b"


def test_api_bench_run_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/bench/run", json={})
    assert resp.status_code == 502


def test_api_bench_results_returns_list(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"count": 1, "runs": [{"run_id": "r1", "model": "qwen:7b"}]}
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/bench/results")
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 1


def test_api_bench_results_fallback_on_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/api/bench/results")
    assert resp.status_code == 200
    assert resp.get_json() == {"count": 0, "runs": []}


def test_api_bench_latest_returns_run(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"run_id": "latest", "model": "qwen:7b"}
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/bench/results/latest")
    assert resp.status_code == 200
    assert resp.get_json()["run_id"] == "latest"


def test_api_bench_latest_404_becomes_null(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/bench/results/latest")
    assert resp.status_code == 200
    assert resp.get_json() is None


def test_api_bench_compare_returns_summaries(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"n": 2, "runs": [{"model": "qwen:7b"}, {"model": "qwen:1.5b"}]}
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/bench/compare?n=2")
    assert resp.status_code == 200
    assert resp.get_json()["n"] == 2


def test_api_bench_clear(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"cleared": True}
    with patch.object(httpx, "delete", return_value=mock_resp):
        resp = client.delete("/api/bench/results")
    assert resp.status_code == 200
    assert resp.get_json()["cleared"] is True


def test_api_bench_clear_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "delete", side_effect=httpx.ConnectError("refused")):
        resp = client.delete("/api/bench/results")
    assert resp.status_code == 502


# ── Scan (mcpnuke-runner) routes ──────────────────────────────────────────────

def test_scan_page_disabled_without_runner(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", ""):
        resp = client.get("/scan")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Scanner sidecar not configured" in html


def test_scan_page_enabled_with_runner(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"):
        resp = client.get("/scan")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Run scan" in html
    assert "Target MCP endpoint" in html


def test_scan_nav_link_present(frontend_client) -> None:
    client, _ = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    mock_resp.raise_for_status = MagicMock()
    with patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/")
    assert b'href="/scan"' in resp.data


def test_api_scan_create_proxies_to_runner(frontend_client) -> None:
    client, mod = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 202
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"id": "deadbeef", "status": "queued"}
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"), \
            patch.object(httpx, "post", return_value=mock_resp) as post:
        resp = client.post("/api/scan", json={
            "target": "http://brain-gateway:8080/mcp", "depth": "fast", "coverage": True,
        })
    assert resp.status_code == 202
    assert resp.get_json()["id"] == "deadbeef"
    # coverage=True must forward a coverage_url pointing back at this portal
    sent = post.call_args.kwargs["json"]
    assert sent["coverage_url"] == mod.SELF_URL
    assert sent["depth"] == "fast"


def test_api_scan_create_missing_target(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"):
        resp = client.post("/api/scan", json={"depth": "fast"})
    assert resp.status_code == 400


def test_api_scan_create_invalid_depth(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"):
        resp = client.post("/api/scan", json={"target": "http://x/mcp", "depth": "nuclear"})
    assert resp.status_code == 400


def test_api_scan_create_no_runner(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", ""):
        resp = client.post("/api/scan", json={"target": "http://x/mcp"})
    assert resp.status_code == 502


def test_api_scan_create_runner_unreachable(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"), \
            patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post("/api/scan", json={"target": "http://x/mcp"})
    assert resp.status_code == 502


def test_api_scan_status_proxies(frontend_client) -> None:
    client, mod = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"id": "abc", "status": "done", "report": {"summary": {}}}
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"), \
            patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/scan/abc")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "done"


def test_api_scan_status_unknown_job(frontend_client) -> None:
    client, mod = frontend_client
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch.object(mod, "RUNNER_URL", "http://mcpnuke-runner:8090"), \
            patch.object(httpx, "get", return_value=mock_resp):
        resp = client.get("/api/scan/nope")
    assert resp.status_code == 404
