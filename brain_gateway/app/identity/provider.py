from __future__ import annotations

from typing import Protocol


class IdentityProvider(Protocol):
    def client_credentials_token(self, *, audience: str, scope: str) -> dict: ...

    def exchange_token(
        self,
        *,
        subject_token: str,
        actor_token: str | None,
        audience: str,
        scope: str,
    ) -> dict: ...

    def introspect_token(self, *, token: str) -> dict: ...

    def revoke_token(self, *, token: str) -> dict: ...
