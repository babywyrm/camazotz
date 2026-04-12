"""Normalized claims and shared identity types (extended in later tasks)."""

from __future__ import annotations

from typing import TypedDict


class IdentityClaimsDict(TypedDict, total=False):
    """Subset of normalized identity fields; full envelope arrives in Task 3."""

    sub: str
    iss: str
    aud: list[str] | str
    scope: str
    tenant_id: str
    env: str


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
