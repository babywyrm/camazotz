"""Tests for the Operator Console routes and qa_runner integration."""

from unittest.mock import patch, MagicMock

import importlib
import sys

import httpx
import pytest


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


def _make_mock_results():
    """Build a minimal qa_runner result set for mocking (results, idp_status)."""
    from qa_runner.types import CheckResult, LevelResult, ModuleResult

    idp_status = {"idp_provider": "mock", "idp_degraded": False, "idp_reason": "ok"}
    return [
        ModuleResult(
            module="auth_lab",
            levels=[
                LevelResult(level="easy", checks=[
                    CheckResult(name="has_token", passed=True),
                    CheckResult(name="has_decision", passed=True),
                ]),
                LevelResult(level="medium", checks=[
                    CheckResult(name="has_token", passed=True),
                    CheckResult(name="has_decision", passed=False, detail="missing key"),
                ]),
            ],
        ),
    ], idp_status


def test_operator_page_200(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/operator")
    assert resp.status_code == 200
    assert b"Operator" in resp.data
    assert b"Run QA Suite" in resp.data


def test_identity_page_200(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/identity")
    assert resp.status_code == 200
    assert b"Identity" in resp.data
    assert b"Provider Status" in resp.data
    assert b"Live IDP Activity" in resp.data
    assert b"Architecture Reference" in resp.data


def test_operator_page_lists_modules(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/operator")
    assert b"auth_lab" in resp.data
    assert b"tenant_lab" in resp.data


def test_operator_page_lists_levels(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/operator")
    assert b"easy" in resp.data
    assert b"medium" in resp.data
    assert b"hard" in resp.data


def test_operator_shows_idp_wiring_strip(frontend_client) -> None:
    client, mod = frontend_client

    def _fake_get(url, *args, **kwargs):
        if str(url).endswith("/config"):
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {
                "idp_provider": "zitadel",
                "idp_backed_labs": ["oauth_delegation_lab", "revocation_lab"],
                "idp_backed_tools": ["oauth.exchange_token", "revocation.revoke_principal"],
            }
            m.raise_for_status = MagicMock()
            return m
        if str(url).endswith("/api/scenarios"):
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = []
            m.raise_for_status = MagicMock()
            return m
        raise httpx.ConnectError("unexpected url")  # pragma: no cover — test fallback

    with patch.object(mod.httpx, "get", side_effect=_fake_get):
        resp = client.get("/operator")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "IDP: zitadel" in html
    assert "oauth.exchange_token" in html


def test_operator_run_returns_report(frontend_client) -> None:
    client, mod = frontend_client
    mock_results = _make_mock_results()
    with patch.object(mod, "run_qa", return_value=mock_results):
        resp = client.post("/api/operator/run", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_modules" in data
    assert "total_checks" in data
    assert "total_issues" in data
    assert "elapsed_seconds" in data
    assert data["total_modules"] == 1
    assert data["total_checks"] == 4
    assert data["total_issues"] == 1
    assert "idp_status" in data
    assert data["idp_status"]["idp_provider"] == "mock"


def test_operator_run_with_module_filter(frontend_client) -> None:
    client, mod = frontend_client
    mock_results = _make_mock_results()
    with patch.object(mod, "run_qa", return_value=mock_results) as mock_run:
        resp = client.post("/api/operator/run", json={"modules": ["auth_lab"]})
    assert resp.status_code == 200
    call_kwargs = mock_run.call_args
    modules_passed = call_kwargs[1].get("modules") or call_kwargs[0][1] if len(call_kwargs[0]) > 1 else call_kwargs[1].get("modules")
    assert "auth_lab" in modules_passed


def test_operator_run_with_level_filter(frontend_client) -> None:
    client, mod = frontend_client
    mock_results = _make_mock_results()
    with patch.object(mod, "run_qa", return_value=mock_results) as mock_run:
        resp = client.post("/api/operator/run", json={"levels": ["easy"]})
    assert resp.status_code == 200
    call_kwargs = mock_run.call_args
    levels_passed = call_kwargs[1].get("levels") or call_kwargs[0][1] if len(call_kwargs[0]) > 1 else call_kwargs[1].get("levels")
    assert "easy" in levels_passed


def test_operator_run_gateway_error(frontend_client) -> None:
    client, mod = frontend_client
    with patch.object(mod, "run_qa", side_effect=Exception("connection refused")):
        resp = client.post("/api/operator/run", json={})
    assert resp.status_code == 502
    data = resp.get_json()
    assert "error" in data
    assert "connection refused" in data["error"]


def test_observer_events_proxy(frontend_client):
    client, _ = frontend_client
    resp = client.get("/api/observer/events")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "events" in data


def test_observer_page_has_tabs(frontend_client):
    client, _ = frontend_client
    resp = client.get("/observer")
    html = resp.data.decode()
    assert "Vulnerable" in html or "vulnerable" in html
    assert "Enhanced" in html or "enhanced" in html
    assert 'id="filterSignal"' in html


def test_operator_easter_egg_in_nav(frontend_client) -> None:
    """The operator page is in the nav as a subtle easter egg."""
    client, _ = frontend_client
    resp = client.get("/")
    assert b'href="/operator"' in resp.data
    assert b'nav-op-egg' in resp.data


def test_results_to_dict_structure() -> None:
    """Verify results_to_dict produces the expected JSON shape."""
    from qa_runner import results_to_dict
    from qa_runner.types import CheckResult, LevelResult, ModuleResult

    results = [
        ModuleResult(module="test_mod", levels=[
            LevelResult(level="easy", checks=[
                CheckResult(name="c1", passed=True),
                CheckResult(name="c2", passed=False, detail="oops"),
            ]),
        ]),
    ]
    d = results_to_dict(results)
    assert d["total_modules"] == 1
    assert d["total_checks"] == 2
    assert d["total_issues"] == 1
    assert d["total_test_points"] == 1
    assert d["modules"][0]["name"] == "test_mod"
    assert d["modules"][0]["levels"][0]["checks"][1]["detail"] == "oops"


def test_walkthroughs_cover_all_labs():
    from qa_runner.walkthroughs import WALKTHROUGHS
    expected = {
        "auth_lab", "context_lab", "secrets_lab", "egress_lab", "tool_lab",
        "shadow_lab", "supply_lab", "relay_lab", "comms_lab", "indirect_lab",
        "config_lab", "hallucination_lab", "tenant_lab", "audit_lab",
        "error_lab", "temporal_lab", "notification_lab", "attribution_lab",
        "credential_broker_lab", "pattern_downgrade_lab", "delegation_chain_lab",
        "revocation_lab", "cost_exhaustion_lab", "oauth_delegation_lab", "rbac_lab",
    }
    assert set(WALKTHROUGHS.keys()) == expected


def test_walkthrough_steps_valid():
    from qa_runner.walkthroughs import WALKTHROUGHS, WalkthroughStep
    for lab, steps in WALKTHROUGHS.items():
        assert len(steps) >= 2, f"{lab} must have >= 2 steps"
        for i, s in enumerate(steps):
            assert isinstance(s, WalkthroughStep), f"{lab} step {i} wrong type"
            assert s.title, f"{lab} step {i} missing title"
            assert s.narrative, f"{lab} step {i} missing narrative"
            assert s.tool, f"{lab} step {i} missing tool"
            assert isinstance(s.arguments, dict), f"{lab} step {i} arguments not dict"
            assert s.insight, f"{lab} step {i} missing insight"


def test_walkthrough_step_dataclass():
    from qa_runner.walkthroughs import WalkthroughStep

    step = WalkthroughStep(
        title="Test step",
        narrative="We do a thing.",
        tool="auth.issue_token",
        arguments={"username": "alice"},
        check="token",
        insight="Tokens are issued without validation.",
    )
    assert step.title == "Test step"
    assert step.tool == "auth.issue_token"
    assert step.check == "token"


def test_walkthrough_labs_endpoint(frontend_client):
    client, _ = frontend_client
    resp = client.get("/api/operator/walkthrough/labs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 25
    labs = {d["lab"] for d in data}
    assert "auth_lab" in labs
    for entry in data:
        assert "lab" in entry
        assert "threat_id" in entry
        assert "title" in entry
        assert "step_count" in entry
        assert entry["step_count"] >= 2


def test_walkthrough_step_endpoint(frontend_client):
    client, _ = frontend_client
    resp = client.post("/api/operator/walkthrough/step", json={"lab": "auth_lab", "step": 0})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["lab"] == "auth_lab"
    assert data["step"] == 0
    assert "title" in data
    assert "narrative" in data
    assert "insight" in data
    assert "request" in data
    assert "response" in data
    assert "status" in data
    assert "total_steps" in data


def test_walkthrough_step_gateway_http_errors_step0(frontend_client):
    """Guardrail and MCP httpx calls swallow or surface errors when the gateway is unreachable."""
    client, mod = frontend_client

    def _fail(*_args, **_kwargs):
        raise httpx.ConnectError("connection refused")

    with patch.object(mod.httpx, "put", side_effect=_fail), patch.object(mod.httpx, "post", side_effect=_fail):
        resp = client.post("/api/operator/walkthrough/step", json={"lab": "auth_lab", "step": 0})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "error"
    assert "error" in data["response"]


class _OkHttpResp:
    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return {"result": {"content": [{"text": "{}"}]}}


def test_walkthrough_step_step0_config_reset_and_mcp_success(frontend_client):
    """Cover successful PUT/POST for step 0 and MCP JSON parse path."""
    client, mod = frontend_client

    with patch.object(mod.httpx, "put", return_value=_OkHttpResp()), patch.object(
        mod.httpx, "post", return_value=_OkHttpResp()
    ):
        resp = client.post("/api/operator/walkthrough/step", json={"lab": "auth_lab", "step": 0})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert "result" in data["response"]


def test_walkthrough_step_step0_reset_http_error_swallowed(frontend_client):
    """Reset POST may fail HTTP; exception is swallowed and MCP continues."""
    client, mod = frontend_client

    def _post(url, **_kwargs):
        if "/reset" in str(url):
            raise httpx.HTTPError("reset failed")
        return _OkHttpResp()

    with patch.object(mod.httpx, "put", return_value=_OkHttpResp()), patch.object(
        mod.httpx, "post", side_effect=_post
    ):
        resp = client.post("/api/operator/walkthrough/step", json={"lab": "auth_lab", "step": 0})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"


def test_walkthrough_step_invalid_lab(frontend_client):
    client, _ = frontend_client
    resp = client.post("/api/operator/walkthrough/step", json={"lab": "nonexistent_lab", "step": 0})
    assert resp.status_code == 400


def test_walkthrough_step_out_of_range(frontend_client):
    client, _ = frontend_client
    resp = client.post("/api/operator/walkthrough/step", json={"lab": "auth_lab", "step": 999})
    assert resp.status_code == 400


def test_operator_has_tabs(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "Walkthrough" in html
    assert "QA Dashboard" in html


def test_operator_has_player_controls(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "step-player" in html or "stepPlayer" in html


def test_operator_has_telemetry_strip(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "telemetry" in html.lower()


def test_operator_deeplink_hash_parsing(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "walkthrough/" in html
    assert "enterLab(" in html


def test_operator_writes_viewed_state(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "cztz_viewed_" in html


def test_resolve_prev_refs_basic(frontend_client):
    """Test that _resolve_prev_refs replaces {{prev.token}} with extracted value."""
    _, mod = frontend_client
    prev_response = {
        "result": {
            "content": [{"type": "text", "text": '{"token": "abc123", "user": "alice"}'}],
        },
    }
    arguments = {"token": "{{prev.token}}", "static": "unchanged"}
    resolved = mod._resolve_prev_refs(arguments, prev_response)
    assert resolved["token"] == "abc123"
    assert resolved["static"] == "unchanged"


def test_resolve_prev_refs_no_prev(frontend_client):
    """Without prev_response, arguments pass through unchanged."""
    _, mod = frontend_client
    arguments = {"token": "{{prev.token}}", "static": "unchanged"}
    resolved = mod._resolve_prev_refs(arguments, None)
    assert resolved["token"] == "{{prev.token}}"
    assert resolved["static"] == "unchanged"


def test_resolve_prev_refs_missing_key(frontend_client):
    """If the key doesn't exist in prev response, keep the original placeholder."""
    _, mod = frontend_client
    prev_response = {
        "result": {
            "content": [{"type": "text", "text": '{"other_key": "value"}'}],
        },
    }
    arguments = {"token": "{{prev.nonexistent}}"}
    resolved = mod._resolve_prev_refs(arguments, prev_response)
    assert resolved["token"] == "{{prev.nonexistent}}"


def test_resolve_prev_refs_malformed_content(frontend_client):
    """When prev_response content text is not valid JSON, placeholders pass through unchanged."""
    _, mod = frontend_client
    prev_response = {
        "result": {
            "content": [{"type": "text", "text": "not json at all"}],
        },
    }
    arguments = {"token": "{{prev.token}}"}
    resolved = mod._resolve_prev_refs(arguments, prev_response)
    assert resolved["token"] == "{{prev.token}}"
