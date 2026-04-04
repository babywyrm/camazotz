from __future__ import annotations

import pytest

from brain_gateway.app.config import reset_difficulty
from brain_gateway.app.main import _rate_limiter
from brain_gateway.app.modules.registry import reset_registry


@pytest.fixture(autouse=True)
def _reset_all_state():
    """Reset global singletons before every test to prevent cross-test bleed."""
    reset_registry()
    reset_difficulty()
    _rate_limiter.reset()
