"""Identity provider abstraction (mock default, ZITADEL in later tasks)."""

from __future__ import annotations

from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.provider import IdentityProvider

__all__ = ["IdentityProvider", "MockIdentityProvider"]
