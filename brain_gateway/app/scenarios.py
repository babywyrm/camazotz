"""Scenario metadata loader for Camazotz lab modules.

Reads ``scenario.yaml`` files co-located with each module and exposes
them as typed :class:`Scenario` objects for the dashboard, API, and
scoring subsystems.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Scenario:
    threat_id: str
    title: str
    difficulty: str
    category: str
    description: str
    objectives: list[str]
    hints: list[str]
    canary_location: str = ""
    tools: list[str] = field(default_factory=list)
    owasp_mcp: str = ""
    references: list[dict[str, str]] = field(default_factory=list)
    module_name: str = ""


VALID_DIFFICULTIES = {"easy", "medium", "hard"}


class ScenarioLoader:
    """Discover and query ``scenario.yaml`` files under a modules directory."""

    def __init__(self, modules_dir: str | Path) -> None:
        self._modules_dir = Path(modules_dir)
        self._scenarios: list[Scenario] = []
        self._by_threat: dict[str, Scenario] = {}

    def load_all(self) -> list[Scenario]:
        self._scenarios.clear()
        self._by_threat.clear()

        for yaml_path in sorted(self._modules_dir.glob("*/scenario.yaml")):
            module_name = yaml_path.parent.name
            with open(yaml_path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)

            if raw is None or not isinstance(raw, dict):
                got = "empty document" if raw is None else type(raw).__name__
                logger.warning(
                    "Skipping %s: scenario.yaml must be a mapping, got %s",
                    yaml_path,
                    got,
                )
                continue

            difficulty = raw.get("difficulty")
            if difficulty not in VALID_DIFFICULTIES:
                logger.warning(
                    "Skipping %s: invalid difficulty %r (expected one of %s)",
                    yaml_path,
                    difficulty,
                    sorted(VALID_DIFFICULTIES),
                )
                continue

            scenario = Scenario(
                threat_id=raw["threat_id"],
                title=raw["title"],
                difficulty=raw["difficulty"],
                category=raw["category"],
                description=raw["description"],
                objectives=raw["objectives"],
                hints=raw["hints"],
                canary_location=raw.get("canary_location", ""),
                tools=raw.get("tools", []),
                owasp_mcp=raw.get("owasp_mcp", ""),
                references=raw.get("references", []),
                module_name=module_name,
            )
            self._scenarios.append(scenario)
            self._by_threat[scenario.threat_id] = scenario

        return list(self._scenarios)

    def get(self, threat_id: str) -> Scenario | None:
        return self._by_threat.get(threat_id)

    def by_difficulty(self, difficulty: str) -> list[Scenario]:
        return [s for s in self._scenarios if s.difficulty == difficulty]

    def by_category(self, category: str) -> list[Scenario]:
        return [s for s in self._scenarios if s.category == category]

    def all(self) -> list[Scenario]:
        return list(self._scenarios)
