"""Normalized claims and shared identity types."""

from __future__ import annotations

from typing import TypedDict


class IdentityClaimsDict(TypedDict, total=False):
    """Partial raw or normalized claims (e.g. test fixtures, gradual construction)."""

    sub: str
    iss: str
    aud: list[str] | str
    scope: str
    tenant_id: str
    env: str


class NormalizedClaimsEnvelope(TypedDict):
    """Internal gateway claims shape (design spec: required + delegation + tenancy + auth context)."""

    sub: str
    iss: str
    aud: list[str]
    exp: int | float
    iat: int | float
    scope: str
    client_id: str
    act: object | None
    azp: str | None
    jti: str
    tenant_id: str
    env: str
    team: str
    groups: list[str]


class DelegationGuardrailResult(TypedDict):
    """Result of delegation guardrail checks (scope/audience narrowing)."""

    allowed: bool
    reason: str


class ClientCredentialsTokenResponse(TypedDict):
    """OAuth2-style client credentials grant result (Task 1 scaffold)."""

    access_token: str
    aud: str
    scope: str


class ExchangeTokenResponse(TypedDict):
    """RFC 8693-style token exchange result (Task 1 scaffold)."""

    access_token: str
    aud: str
    scope: str
    act: str | None
    sub: str


class IntrospectTokenResponse(TypedDict):
    """RFC 7662-style introspection result (Task 1 scaffold)."""

    active: bool
    sub: str


class RevokeTokenResponse(TypedDict):
    """Token revocation acknowledgment (Task 1 scaffold)."""

    revoked: bool
    token_hint: str
