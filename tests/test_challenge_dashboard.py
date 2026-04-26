"""Tests for the Challenge Dashboard routes."""

from unittest.mock import patch, MagicMock

import httpx
import pytest

import importlib
import sys


SAMPLE_SCENARIOS = [
    {
        "threat_id": "MCP-T01",
        "title": "Prompt Injection",
        "difficulty": "easy",
        "category": "injection",
        "description": "Inject malicious instructions via tool output.",
        "objectives": ["Exfiltrate the canary flag via prompt injection"],
        "hints": ["Look at the tool output format", "Try embedding instructions"],
        "tools": ["context.injectable_summary"],
        "canary_location": "environment variable",
        "owasp_mcp": "MCP01",
    },
    {
        "threat_id": "MCP-T02",
        "title": "Tool Poisoning",
        "difficulty": "medium",
        "category": "supply_chain",
        "description": "Exploit a poisoned tool description to hijack execution.",
        "objectives": ["Trigger the hidden behaviour in the tool"],
        "hints": ["Read the tool description carefully"],
        "tools": ["supply.poisoned_tool"],
        "canary_location": "tool response",
        "owasp_mcp": "MCP02",
    },
]


@pytest.fixture()
def frontend_client():
    """Import the frontend Flask app and return a test client."""
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    inserted = frontend_dir not in sys.path
    if inserted:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    if inserted:
        sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


def _mock_scenarios_response(scenarios: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = scenarios
    mock.raise_for_status = MagicMock()
    return mock


def _mock_verify_response(result: dict) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = result
    mock.raise_for_status = MagicMock()
    return mock


def test_challenges_route_200(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", return_value=_mock_scenarios_response([])):
        resp = client.get("/challenges")
    assert resp.status_code == 200


def test_challenges_renders_scenarios(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", return_value=_mock_scenarios_response(SAMPLE_SCENARIOS)):
        resp = client.get("/challenges")
    assert resp.status_code == 200
    assert b"Prompt Injection" in resp.data
    assert b"Tool Poisoning" in resp.data


def test_challenge_detail_200(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", return_value=_mock_scenarios_response(SAMPLE_SCENARIOS)):
        resp = client.get("/challenges/MCP-T01")
    assert resp.status_code == 200
    assert b"Prompt Injection" in resp.data
    assert b"MCP-T01" in resp.data


def test_challenge_detail_404(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", return_value=_mock_scenarios_response(SAMPLE_SCENARIOS)):
        resp = client.get("/challenges/BOGUS")
    assert resp.status_code == 404


def test_challenge_verify_correct(frontend_client) -> None:
    client, _ = frontend_client
    verify_resp = _mock_verify_response({"threat_id": "MCP-T01", "correct": True})
    with patch.object(httpx, "post", return_value=verify_resp):
        resp = client.post(
            "/challenges/MCP-T01/verify",
            json={"canary": "CZTZ{test_flag}"},
            content_type="application/json",
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["correct"] is True


def test_challenge_verify_wrong(frontend_client) -> None:
    client, _ = frontend_client
    verify_resp = _mock_verify_response({"threat_id": "MCP-T01", "correct": False})
    with patch.object(httpx, "post", return_value=verify_resp):
        resp = client.post(
            "/challenges/MCP-T01/verify",
            json={"canary": "wrong"},
            content_type="application/json",
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["correct"] is False


def test_challenges_nav_link(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", return_value=_mock_scenarios_response([])):
        resp = client.get("/challenges")
    assert resp.status_code == 200
    assert b'href="/challenges"' in resp.data


def test_fetch_scenarios_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "get", side_effect=httpx.ConnectError("refused")):
        resp = client.get("/challenges")
    assert resp.status_code == 200
    assert b"No challenges" in resp.data or resp.status_code == 200


def test_challenge_verify_gateway_error(frontend_client) -> None:
    client, _ = frontend_client
    with patch.object(httpx, "post", side_effect=httpx.ConnectError("refused")):
        resp = client.post(
            "/challenges/MCP-T01/verify",
            json={"canary": "CZTZ{test}"},
            content_type="application/json",
        )
    assert resp.status_code == 502
    data = resp.get_json()
    assert data["correct"] is False
    assert "Gateway unreachable" in data.get("error", "")
