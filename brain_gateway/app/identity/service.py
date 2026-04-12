from __future__ import annotations

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider


def get_identity_provider() -> MockIdentityProvider | ZitadelIdentityProvider:
    if get_idp_provider() == "zitadel":
        return ZitadelIdentityProvider.from_env()
    return MockIdentityProvider()
