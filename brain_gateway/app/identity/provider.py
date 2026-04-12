from __future__ import annotations

from typing import Protocol

from brain_gateway.app.identity.types import (
    ClientCredentialsTokenResponse,
    ExchangeTokenResponse,
    IntrospectTokenResponse,
    RevokeTokenResponse,
)


class IdentityProvider(Protocol):
    def client_credentials_token(
        self, *, audience: str, scope: str
    ) -> ClientCredentialsTokenResponse: ...

    def exchange_token(
        self,
        *,
        subject_token: str,
        actor_token: str | None,
        audience: str,
        scope: str,
    ) -> ExchangeTokenResponse: ...

    def introspect_token(self, *, token: str) -> IntrospectTokenResponse: ...

    def revoke_token(self, *, token: str) -> RevokeTokenResponse: ...
