"""Tests for the Operator Console routes and qa_runner integration."""

from unittest.mock import patch, MagicMock

import importlib
import sys

import pytest


@pytest.fixture()
def frontend_client():
    """Import the frontend Flask app and return a test client."""
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


def _make_mock_results():
    """Build a minimal qa_runner result set for mocking."""
    from qa_runner.types import CheckResult, LevelResult, ModuleResult

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
    ]


def test_operator_page_200(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/operator")
    assert resp.status_code == 200
    assert b"Operator" in resp.data
    assert b"Run QA Suite" in resp.data


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


def test_operator_no_nav_link(frontend_client) -> None:
    """The operator page should NOT appear in the main navigation."""
    client, _ = frontend_client
    resp = client.get("/")
    assert b'href="/operator"' not in resp.data


def test_results_to_dict_structure() -> None:
    """Verify results_to_dict produces the expected JSON shape."""
    scripts_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)

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

    if scripts_dir in sys.path:
        sys.path.remove(scripts_dir)
