"""Token Lifecycle & Revocation Gaps lab — MCP-T26.

Demonstrates race conditions and gaps in token revocation flows.
On easy, revocation sets a flag but cached tokens remain valid.
On medium, refresh is revoked but access tokens persist with long TTL.
On hard, revocation is immediate.

All tokens and principals are synthetic.
"""

from __future__ import annotations

import json
import threading
import time
import uuid

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity.service import get_identity_provider
from camazotz_modules.base import LabModule


class RevocationLab(LabModule):
    name = "revocation"
    threat_id = "MCP-T26"
    title = "Token Lifecycle & Revocation Gaps"
    category = "lifecycle"

    system_prompts = {
        "easy": (
            "You are a token lifecycle manager. Revocation sets a "
            "flag but cached tokens remain usable indefinitely."
        ),
        "medium": (
            "You are a token lifecycle manager. Revocation invalidates "
            "refresh tokens but access tokens persist until expiry."
        ),
        "hard": (
            "You are a strict token lifecycle manager. Revocation "
            "immediately invalidates all tokens for the principal."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._tokens: dict[str, dict] = {}
        self._revoked: set[str] = set()

    def reset(self) -> None:
        with self._lock:
            self._tokens = {}
            self._revoked = set()

    def _idp_issue_tags(self) -> dict:
        if get_idp_provider() != "zitadel":
            return {}
        return {"_idp_provider": "zitadel", "_idp_backed": True}

    def _idp_use_tags(self, *, access_token: str | None = None) -> dict:
        if get_idp_provider() != "zitadel":
            return {}
        if not access_token:
            return {"_idp_token_status": "token_missing", "_idp_backed": True}
        provider = get_identity_provider()
        try:
            introspection = provider.introspect_token(token=access_token)
        except Exception:
            return {
                "_idp_token_status": "introspection_error",
                "_idp_backed": True,
                "_idp_degraded": True,
                "_idp_reason": "introspection_call_failed",
            }
        return {
            "_idp_token_status": "active" if introspection.get("active") else "inactive",
            "_idp_backed": True,
        }

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        with self._lock:
            token_ids = sorted(self._tokens.keys())
        return [
            {
                "uri": f"revocation://token_status/{tid}",
                "name": f"Token Status: {tid}",
                "mimeType": "application/json",
            }
            for tid in token_ids
        ]

    def read_resource(self, uri: str) -> dict | None:
        prefix = "revocation://token_status/"
        if not uri.startswith(prefix):
            return None
        token_id = uri[len(prefix):]
        with self._lock:
            tok = self._tokens.get(token_id)
        if tok is None:
            return None
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(tok, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "revocation.issue_token",
                "description": (
                    "Issue a simulated OAuth token for a principal."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["principal"],
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "Principal email.",
                            "maxLength": 256,
                        },
                        "service": {
                            "type": "string",
                            "description": "Target service.",
                            "default": "default-svc",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "revocation.revoke_principal",
                "description": (
                    "Revoke all tokens for a principal (offboarding). "
                    "Revocation behavior varies by difficulty."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["principal"],
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "Principal to revoke.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "revocation.use_token",
                "description": (
                    "Attempt to use a token. Returns whether the "
                    "token is valid or has been revoked."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["token_id"],
                    "properties": {
                        "token_id": {
                            "type": "string",
                            "description": "Token identifier.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "revocation.issue_token":
            return self._issue_token(arguments)
        if name == "revocation.revoke_principal":
            return self._revoke_principal(arguments)
        if name == "revocation.use_token":
            return self._use_token(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _issue_token(self, arguments: dict) -> dict:
        principal = arguments.get("principal", "")
        service = arguments.get("service", "default-svc")

        token_id = f"tok-{uuid.uuid4().hex[:12]}"
        access_token = f"cztz-access-{uuid.uuid4().hex[:8]}"
        refresh_token = f"cztz-refresh-{uuid.uuid4().hex[:8]}"

        entry = {
            "token_id": token_id,
            "principal": principal,
            "service": service,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "issued_at": time.time(),
            "revoked": False,
            "refresh_revoked": False,
        }

        with self._lock:
            self._tokens[token_id] = entry

        out = {
            "issued": True,
            "token_id": token_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "principal": principal,
            "service": service,
            "_difficulty": self.difficulty,
        }
        out.update(self._idp_issue_tags())
        return out

    def _revoke_principal(self, arguments: dict) -> dict:
        principal = arguments.get("principal", "")
        difficulty = self.difficulty

        revoked_ids = []
        with self._lock:
            for tid, tok in self._tokens.items():
                if tok["principal"] != principal:
                    continue
                revoked_ids.append(tid)
                if difficulty == "easy":
                    tok["revoked"] = True
                elif difficulty == "medium":
                    tok["refresh_revoked"] = True
                else:
                    tok["revoked"] = True
                    tok["refresh_revoked"] = True
                self._revoked.add(tid)

        out = {
            "revoked_count": len(revoked_ids),
            "revoked_ids": revoked_ids,
            "principal": principal,
            "_difficulty": difficulty,
        }
        if get_idp_provider() == "zitadel":
            provider = get_identity_provider()
            revoke_degraded = False
            for tid in revoked_ids:
                with self._lock:
                    access_token = self._tokens.get(tid, {}).get("access_token", "")
                if access_token:
                    try:
                        provider.revoke_token(token=access_token)
                    except Exception:
                        revoke_degraded = True
            out["_idp_provider"] = "zitadel"
            out["_idp_backed"] = True
            out["_idp_revocation_hook"] = "provider.revoke_token"
            if revoke_degraded:
                out["_idp_degraded"] = True
                out["_idp_reason"] = "revocation_call_failed"
        return out

    def _use_token(self, arguments: dict) -> dict:
        token_id = arguments.get("token_id", "")
        difficulty = self.difficulty

        with self._lock:
            tok = self._tokens.get(token_id)

        if tok is None:
            out = {
                "valid": False,
                "reason": "Token not found.",
                "token_id": token_id,
                "_difficulty": difficulty,
            }
            out.update(self._idp_use_tags())
            return out

        if difficulty == "easy":
            if tok["revoked"]:
                out = {
                    "valid": True,
                    "token_id": token_id,
                    "principal": tok["principal"],
                    "_warning": (
                        "Token is flagged as revoked but cached copy "
                        "remains valid."
                    ),
                    "_difficulty": difficulty,
                }
                out.update(self._idp_use_tags(access_token=tok["access_token"]))
                return out
            out = {
                "valid": True,
                "token_id": token_id,
                "principal": tok["principal"],
                "_difficulty": difficulty,
            }
            out.update(self._idp_use_tags(access_token=tok["access_token"]))
            return out

        if difficulty == "medium":
            if tok["revoked"]:
                out = {
                    "valid": False,
                    "reason": "Token has been revoked.",
                    "token_id": token_id,
                    "_difficulty": difficulty,
                }
                out.update(self._idp_use_tags(access_token=tok["access_token"]))
                return out
            if tok["refresh_revoked"]:
                out = {
                    "valid": True,
                    "token_id": token_id,
                    "principal": tok["principal"],
                    "_warning": (
                        "Refresh token revoked but access token is still "
                        "valid until expiry."
                    ),
                    "_difficulty": difficulty,
                }
                out.update(self._idp_use_tags(access_token=tok["access_token"]))
                return out
            out = {
                "valid": True,
                "token_id": token_id,
                "principal": tok["principal"],
                "_difficulty": difficulty,
            }
            out.update(self._idp_use_tags(access_token=tok["access_token"]))
            return out

        if tok["revoked"] or tok["refresh_revoked"]:
            out = {
                "valid": False,
                "reason": "Token has been revoked (immediate enforcement).",
                "token_id": token_id,
                "_difficulty": difficulty,
            }
            out.update(self._idp_use_tags(access_token=tok["access_token"]))
            return out
        out = {
            "valid": True,
            "token_id": token_id,
            "principal": tok["principal"],
            "_difficulty": difficulty,
        }
        out.update(self._idp_use_tags(access_token=tok["access_token"]))
        return out
