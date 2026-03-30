"""hallucination_lab: MAX difficulty should code-reject production paths."""

from unittest.mock import patch

import pytest

from brain_gateway.app.brain.provider import BrainResult
from camazotz_modules.hallucination_lab.app.main import HallucinationLab


def _brain(text: str) -> BrainResult:
    return BrainResult(text=text)


@pytest.fixture
def lab():
    return HallucinationLab()


def test_max_strips_production_ops(lab):
    plan = '[{"action":"delete","path":"/production/data/customers.db"}]'
    with (
        patch("camazotz_modules.base.get_difficulty", return_value="hard"),
        patch.object(lab, "ask_llm", return_value=_brain(plan)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "clean up"})
    assert result["operations_executed"] == []
    assert result["production_touched"] is False
    assert result["blocked_operations"] == 1


def test_max_allows_staging_ops(lab):
    plan = '[{"action":"delete","path":"/staging/data/temp_logs.csv"}]'
    with (
        patch("camazotz_modules.base.get_difficulty", return_value="hard"),
        patch.object(lab, "ask_llm", return_value=_brain(plan)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "clean up"})
    assert len(result["operations_executed"]) == 1
    assert result["production_touched"] is False
    assert result["blocked_operations"] == 0


def test_easy_allows_production_ops(lab):
    plan = '[{"action":"read","path":"/production/data/customers.db"}]'
    with (
        patch("camazotz_modules.base.get_difficulty", return_value="easy"),
        patch.object(lab, "ask_llm", return_value=_brain(plan)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "check files"})
    assert len(result["operations_executed"]) == 1
    assert result["production_touched"] is True
    assert result["blocked_operations"] == 0


def test_max_mixed_plan(lab):
    plan = (
        '[{"action":"delete","path":"/staging/cache/old_models.bin"},'
        '{"action":"delete","path":"/production/data/transactions.log"}]'
    )
    with (
        patch("camazotz_modules.base.get_difficulty", return_value="hard"),
        patch.object(lab, "ask_llm", return_value=_brain(plan)),
    ):
        result = lab.handle("hallucination.execute_plan", {"description": "clean all"})
    assert len(result["operations_executed"]) == 1
    assert result["blocked_operations"] == 1
