from __future__ import annotations


class MockIdentityProvider:
    def client_credentials_token(self, *, audience: str, scope: str) -> dict:
        return {"access_token": "mock-access", "aud": audience, "scope": scope}

    def exchange_token(
        self,
        *,
        subject_token: str,
        actor_token: str | None,
        audience: str,
        scope: str,
    ) -> dict:
        return {
            "access_token": "mock-exchanged",
            "aud": audience,
            "scope": scope,
            "act": actor_token,
            "sub": subject_token,
        }

    def introspect_token(self, *, token: str) -> dict:
        return {"active": token.startswith("mock"), "sub": "mock-user"}

    def revoke_token(self, *, token: str) -> dict:
        return {"revoked": True, "token_hint": token[:8]}
