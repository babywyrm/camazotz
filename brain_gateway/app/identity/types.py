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
