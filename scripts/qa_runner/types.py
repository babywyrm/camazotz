"""Data structures for QA harness results."""
from __future__ import annotations

from dataclasses import dataclass, field

GUARDRAIL_LEVELS: tuple[str, ...] = ("easy", "medium", "hard")
GUARDRAIL_LABELS: dict[str, str] = {"easy": "EZ", "medium": "MOD", "hard": "MAX"}

DEFAULT_GATEWAY = "http://localhost:8080"
DEFAULT_TIMEOUT = 20


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class LevelResult:
    level: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)


@dataclass
class ModuleResult:
    module: str
    levels: list[LevelResult] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return sum(1 for lr in self.levels for c in lr.checks if not c.passed)
