from __future__ import annotations

import time
from urllib.parse import urlparse
from urllib.request import urlopen

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.provider import IdentityProvider
from brain_gateway.app.identity.types import DelegationGuardrailResult, NormalizedClaimsEnvelope
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider

_ZITADEL_HEALTH_TTL_SECONDS = 10.0
_zitadel_health_ok: bool | None = None
_zitadel_health_checked_at = 0.0


def _host_probe_url(issuer_or_token_endpoint: str) -> str:
    parsed = urlparse(issuer_or_token_endpoint)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return issuer_or_token_endpoint


def _zitadel_is_reachable(provider: ZitadelIdentityProvider) -> bool:
    global _zitadel_health_ok, _zitadel_health_checked_at

    now = time.monotonic()
    if (
        _zitadel_health_ok is not None
        and (now - _zitadel_health_checked_at) < _ZITADEL_HEALTH_TTL_SECONDS
    ):
        return _zitadel_health_ok

    target = provider.issuer_url or provider.token_endpoint
    try:
        with urlopen(_host_probe_url(target), timeout=1):
            _zitadel_health_ok = True
    except Exception:
        _zitadel_health_ok = False
    _zitadel_health_checked_at = now
    return bool(_zitadel_health_ok)


def get_identity_provider() -> IdentityProvider:
    if get_idp_provider() == "zitadel":
        provider = ZitadelIdentityProvider.from_env()
        # Fail open to mock when ZITADEL settings are incomplete.
        if provider.token_endpoint and _zitadel_is_reachable(provider):
            return provider
    return MockIdentityProvider()


def normalize_claims(raw: dict, *, env: str, tenant_id: str) -> NormalizedClaimsEnvelope:
    aud_raw = raw.get("aud", [])
    if isinstance(aud_raw, str):
        aud: list[str] = [aud_raw]
    elif isinstance(aud_raw, list):
        aud = [item for item in aud_raw if isinstance(item, str)]
    else:
        aud = []

    scope_raw = raw.get("scope", "")
    scope = scope_raw if isinstance(scope_raw, str) else ""

    groups_raw = raw.get("groups", [])
    groups = groups_raw if isinstance(groups_raw, list) else []

    exp_raw = raw.get("exp", 0)
    exp = exp_raw if isinstance(exp_raw, int) else 0

    iat_raw = raw.get("iat", 0)
    iat = iat_raw if isinstance(iat_raw, int) else 0
    return {
        "sub": raw.get("sub", ""),
        "iss": raw.get("iss", ""),
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "scope": scope,
        "client_id": raw.get("client_id", raw.get("azp", "")),
        "act": raw.get("act"),
        "azp": raw.get("azp"),
        "jti": raw.get("jti", ""),
        "tenant_id": tenant_id,
        "env": env,
        "team": raw.get("team", ""),
        "groups": groups,
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
