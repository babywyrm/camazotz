from pathlib import Path
import json


def test_contract_files_exist_and_parse() -> None:
    root = Path(__file__).resolve().parents[1]
    for rel in [
        "contracts/mcp_profile.md",
        "contracts/module_contract.json",
        "contracts/event_schema.json",
    ]:
        path = root / rel
        assert path.exists(), f"Missing {rel}"
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))


def test_scenario_loader_reads_agentic_block(tmp_path):
    """Loader must pass through the optional agentic: block verbatim."""
    from brain_gateway.app.scenarios import ScenarioLoader

    lab_dir = tmp_path / "fake_lab"
    lab_dir.mkdir()
    (lab_dir / "scenario.yaml").write_text(
        "threat_id: MCP-T99\n"
        "title: Fake\n"
        "difficulty: easy\n"
        "category: test\n"
        "description: test\n"
        "objectives: []\n"
        "hints: []\n"
        "agentic:\n"
        "  primary_lane: 2\n"
        "  secondary_lanes: [1]\n"
        "  transport: A\n"
        "  blurb: test blurb\n"
    )
    loader = ScenarioLoader(tmp_path)
    loader.load_all()
    sc = loader.get("MCP-T99")
    assert sc is not None
    assert sc.agentic == {
        "primary_lane": 2,
        "secondary_lanes": [1],
        "transport": "A",
        "blurb": "test blurb",
    }


def test_scenario_without_agentic_block_defaults_empty(tmp_path):
    """Labs without an agentic: block must still load (default empty dict)."""
    from brain_gateway.app.scenarios import ScenarioLoader

    lab_dir = tmp_path / "fake_lab"
    lab_dir.mkdir()
    (lab_dir / "scenario.yaml").write_text(
        "threat_id: MCP-T98\n"
        "title: Fake\n"
        "difficulty: easy\n"
        "category: test\n"
        "description: test\n"
        "objectives: []\n"
        "hints: []\n"
    )
    loader = ScenarioLoader(tmp_path)
    loader.load_all()
    sc = loader.get("MCP-T98")
    assert sc is not None
    assert sc.agentic == {}


def test_api_scenarios_includes_agentic():
    """GET /api/scenarios must surface the agentic field for each scenario."""
    from fastapi.testclient import TestClient
    from brain_gateway.app.main import app

    client = TestClient(app)
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload, list)
    assert len(payload) > 0
    for entry in payload:
        assert "agentic" in entry
        assert isinstance(entry["agentic"], dict)
