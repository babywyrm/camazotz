from __future__ import annotations

import pytest

from brain_gateway.app.main import _rate_limiter


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _rate_limiter.reset()
