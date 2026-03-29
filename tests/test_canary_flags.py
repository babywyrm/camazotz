"""Tests for canary flag generation, verification, and API endpoints."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import LabRegistry
from brain_gateway.app.scenarios import Scenario, generate_flags, verify_flag

FLAG_PATTERN = re.compile(r"^CZTZ\{MCP-T\d+[a-z]?_[0-9a-f]{8}\}$")

MODULES_DIR = Path(__file__).resolve().parents[1] / "camazotz_modules"


def _make_scenarios() -> list[Scenario]:
    return [
        Scenario(
            threat_id="MCP-T01",
            title="Test Scenario A",
            difficulty="easy",
            category="injection",
            description="desc a",
            objectives=["obj1"],
            hints=["hint1"],
        ),
        Scenario(
            threat_id="MCP-T02",
            title="Test Scenario B",
            difficulty="medium",
            category="auth",
            description="desc b",
            objectives=["obj2"],
            hints=["hint2"],
        ),
        Scenario(
            threat_id="MCP-T03a",
            title="Test Scenario C",
            difficulty="hard",
            category="ssrf",
            description="desc c",
            objectives=["obj3"],
            hints=["hint3"],
        ),
    ]


def test_generate_flags_creates_files(tmp_path: Path) -> None:
    scenarios = _make_scenarios()
    flags = generate_flags(scenarios, flags_dir=str(tmp_path))
    assert len(flags) == len(scenarios)
    for s in scenarios:
        flag_file = tmp_path / f"{s.threat_id}.flag"
        assert flag_file.exists(), f"Missing flag file for {s.threat_id}"
        assert flag_file.read_text() == flags[s.threat_id]


def test_flag_format(tmp_path: Path) -> None:
    scenarios = _make_scenarios()
    flags = generate_flags(scenarios, flags_dir=str(tmp_path))
    for threat_id, flag in flags.items():
        assert FLAG_PATTERN.match(flag), (
            f"Flag {flag!r} for {threat_id} doesn't match expected pattern"
        )


def test_verify_correct_flag(tmp_path: Path) -> None:
    scenarios = _make_scenarios()
    flags = generate_flags(scenarios, flags_dir=str(tmp_path))
    for threat_id, flag in flags.items():
        assert verify_flag(threat_id, flag, flags_dir=str(tmp_path)) is True


def test_verify_wrong_flag(tmp_path: Path) -> None:
    scenarios = _make_scenarios()
    generate_flags(scenarios, flags_dir=str(tmp_path))
    assert verify_flag("MCP-T01", "CZTZ{WRONG_deadbeef}", flags_dir=str(tmp_path)) is False


def test_verify_missing_threat_id(tmp_path: Path) -> None:
    assert verify_flag("MCP-T99", "anything", flags_dir=str(tmp_path)) is False


def test_flags_are_unique(tmp_path: Path) -> None:
    scenarios = _make_scenarios()
    flags = generate_flags(scenarios, flags_dir=str(tmp_path))
    values = list(flags.values())
    assert len(values) == len(set(values)), "Generated flags are not all unique"


def test_reset_all_regenerates_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from brain_gateway.app import scenarios as scenarios_mod

    monkeypatch.setattr(scenarios_mod, "FLAGS_DIR", str(tmp_path))
    registry = LabRegistry()
    registry.reset_all()
    flag_files = list(tmp_path.glob("*.flag"))
    assert len(flag_files) >= 1, "reset_all should regenerate canary flags"


def test_api_scenarios_endpoint() -> None:
    client = TestClient(app)
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    expected_fields = {
        "threat_id", "title", "difficulty", "category",
        "description", "objectives", "hints", "tools",
        "owasp_mcp", "module_name",
    }
    for item in data:
        assert expected_fields <= set(item.keys()), (
            f"Missing fields: {expected_fields - set(item.keys())}"
        )


def test_api_verify_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from brain_gateway.app import scenarios as scenarios_mod

    monkeypatch.setattr(scenarios_mod, "FLAGS_DIR", str(tmp_path))

    test_scenarios = _make_scenarios()
    flags = generate_flags(test_scenarios, flags_dir=str(tmp_path))

    client = TestClient(app)
    threat_id = "MCP-T01"
    flag_value = flags[threat_id]

    resp = client.post(
        "/api/flags/verify",
        json={"threat_id": threat_id, "flag": flag_value},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["threat_id"] == threat_id
    assert body["correct"] is True

    resp_wrong = client.post(
        "/api/flags/verify",
        json={"threat_id": threat_id, "flag": "CZTZ{WRONG_00000000}"},
    )
    assert resp_wrong.status_code == 200
    assert resp_wrong.json()["correct"] is False
