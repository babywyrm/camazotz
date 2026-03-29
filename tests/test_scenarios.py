"""Tests for scenario metadata contract and ScenarioLoader."""

from pathlib import Path

import yaml

from brain_gateway.app.scenarios import ScenarioLoader

MODULES_DIR = Path(__file__).resolve().parents[1] / "camazotz_modules"
VALID_DIFFICULTIES = {"easy", "medium", "hard"}
REQUIRED_FIELDS = {
    "threat_id",
    "title",
    "difficulty",
    "category",
    "description",
    "objectives",
    "hints",
    "tools",
    "canary_location",
    "owasp_mcp",
}


def _module_dirs_with_main() -> list[Path]:
    """Return module directories that contain app/main.py."""
    return sorted(
        d for d in MODULES_DIR.iterdir()
        if d.is_dir() and (d / "app" / "main.py").exists()
    )


def test_all_modules_have_scenario_yaml() -> None:
    for module_dir in _module_dirs_with_main():
        yaml_path = module_dir / "scenario.yaml"
        assert yaml_path.exists(), f"{module_dir.name} missing scenario.yaml"


def test_scenario_yaml_schema() -> None:
    for module_dir in _module_dirs_with_main():
        yaml_path = module_dir / "scenario.yaml"
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert isinstance(raw, dict), (
            f"{module_dir.name}/scenario.yaml must parse to a mapping, got {type(raw).__name__}"
        )
        missing = REQUIRED_FIELDS - raw.keys()
        assert not missing, f"{module_dir.name}/scenario.yaml missing fields: {missing}"

        assert raw["difficulty"] in VALID_DIFFICULTIES, (
            f"{module_dir.name}: invalid difficulty {raw['difficulty']!r}"
        )
        assert isinstance(raw["objectives"], list) and len(raw["objectives"]) >= 1, (
            f"{module_dir.name}: objectives must be a non-empty list"
        )
        assert isinstance(raw["hints"], list) and len(raw["hints"]) >= 1, (
            f"{module_dir.name}: hints must be a non-empty list"
        )
        assert isinstance(raw["tools"], list) and len(raw["tools"]) >= 1, (
            f"{module_dir.name}: tools must be a non-empty list"
        )
        assert isinstance(raw["canary_location"], str) and raw["canary_location"].strip(), (
            f"{module_dir.name}: canary_location must be a non-empty string"
        )
        assert isinstance(raw["owasp_mcp"], str) and raw["owasp_mcp"].strip(), (
            f"{module_dir.name}: owasp_mcp must be a non-empty string"
        )


def test_no_duplicate_threat_ids() -> None:
    seen: dict[str, str] = {}
    for module_dir in _module_dirs_with_main():
        yaml_path = module_dir / "scenario.yaml"
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert isinstance(raw, dict), f"{module_dir.name}/scenario.yaml must be a mapping"
        tid = raw["threat_id"]
        assert tid not in seen, (
            f"Duplicate threat_id {tid!r}: {module_dir.name} and {seen[tid]}"
        )
        seen[tid] = module_dir.name


def test_scenario_loader_discovers_all() -> None:
    loader = ScenarioLoader(MODULES_DIR)
    scenarios = loader.load_all()
    assert len(scenarios) >= 9, f"Expected >=9 scenarios, got {len(scenarios)}"
    assert loader.all() == scenarios


def test_scenario_loader_get_by_threat_id() -> None:
    loader = ScenarioLoader(MODULES_DIR)
    loader.load_all()

    ssrf = loader.get("MCP-T06")
    assert ssrf is not None, "MCP-T06 not found"
    assert ssrf.title == "SSRF via Tool"
    assert ssrf.category == "ssrf"


def test_scenario_loader_filter_by_difficulty() -> None:
    loader = ScenarioLoader(MODULES_DIR)
    loader.load_all()

    easy = loader.by_difficulty("easy")
    assert len(easy) >= 1
    assert all(s.difficulty == "easy" for s in easy)

    medium = loader.by_difficulty("medium")
    assert len(medium) >= 1
    assert all(s.difficulty == "medium" for s in medium)

    hard = loader.by_difficulty("hard")
    assert len(hard) >= 1
    assert all(s.difficulty == "hard" for s in hard)


def test_scenario_loader_filter_by_category() -> None:
    loader = ScenarioLoader(MODULES_DIR)
    loader.load_all()

    injection = loader.by_category("injection")
    assert len(injection) >= 1
    assert all(s.category == "injection" for s in injection)

    auth = loader.by_category("auth")
    assert len(auth) >= 1
    assert all(s.category == "auth" for s in auth)


def test_scenario_loader_skips_empty_yaml(tmp_path: Path) -> None:
    lab = tmp_path / "empty_lab"
    lab.mkdir()
    (lab / "scenario.yaml").write_text("", encoding="utf-8")
    loader = ScenarioLoader(tmp_path)
    assert loader.load_all() == []


def test_scenario_loader_skips_non_dict_yaml(tmp_path: Path) -> None:
    lab = tmp_path / "list_lab"
    lab.mkdir()
    (lab / "scenario.yaml").write_text("- not a mapping\n", encoding="utf-8")
    loader = ScenarioLoader(tmp_path)
    assert loader.load_all() == []


def test_scenario_loader_skips_invalid_difficulty(tmp_path: Path) -> None:
    lab = tmp_path / "bad_diff_lab"
    lab.mkdir()
    (lab / "scenario.yaml").write_text(
        """
threat_id: MCP-T99
title: T
difficulty: extreme
category: c
description: d
objectives:
  - o
hints:
  - h
tools:
  - t.x
canary_location: "loc"
owasp_mcp: "MCP01"
""",
        encoding="utf-8",
    )
    loader = ScenarioLoader(tmp_path)
    assert loader.load_all() == []
