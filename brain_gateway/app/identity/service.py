from __future__ import annotations

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.provider import IdentityProvider
from brain_gateway.app.identity.types import DelegationGuardrailResult, NormalizedClaimsEnvelope
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider


def get_identity_provider() -> IdentityProvider:
    if get_idp_provider() == "zitadel":
        return ZitadelIdentityProvider.from_env()
    return MockIdentityProvider()


def normalize_claims(raw: dict, *, env: str, tenant_id: str) -> NormalizedClaimsEnvelope:
    aud = raw.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    scope = raw.get("scope", "")
    return {
        "sub": raw.get("sub", ""),
        "iss": raw.get("iss", ""),
        "aud": aud,
        "exp": raw.get("exp", 0),
        "iat": raw.get("iat", 0),
        "scope": scope,
        "client_id": raw.get("client_id", raw.get("azp", "")),
        "act": raw.get("act"),
        "azp": raw.get("azp"),
        "jti": raw.get("jti", ""),
        "tenant_id": tenant_id,
        "env": env,
        "team": raw.get("team", ""),
        "groups": raw.get("groups", []),
    }


def validate_exchange_request(*, source_scope: str, requested_scope: str) -> DelegationGuardrailResult:
    source = set(source_scope.split())
    requested = set(requested_scope.split())
    if requested - source:
        return {"allowed": False, "reason": "scope_widening"}
    return {"allowed": True, "reason": "ok"}


def _audience_set(aud: str | list[str]) -> set[str]:
    if isinstance(aud, str):
        return {aud} if aud else set()
    return set(aud)


def validate_audience_narrowing(
    *, source_aud: str | list[str], requested_aud: str | list[str]
) -> DelegationGuardrailResult:
    src = _audience_set(source_aud)
    req = _audience_set(requested_aud)
    if req - src:
        return {"allowed": False, "reason": "audience_widening"}
    return {"allowed": True, "reason": "ok"}
