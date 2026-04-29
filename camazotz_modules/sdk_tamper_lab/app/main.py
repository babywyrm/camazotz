"""SDK Token Cache Poisoning lab.

MCP-T33: SDK-level trust — an MCP SDK wrapper caches JWTs locally and reuses
them without re-validating the signature.  An attacker with filesystem access
(or tool access to sdk.write_cache) injects a crafted token granting elevated
privileges.

Transport C: the vulnerability lives in the SDK/library layer, not the
JSON-RPC transport or the HTTP API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time

from camazotz_modules.base import LabModule

# Simulated signing secret for the reference issuer (hard-mode only).
_SIGNING_SECRET = b"cztz-sdk-hmac-secret-v1"
_ISSUER = "https://camazotz.local/sdk-idp"


def _make_token(role: str, exp_offset: int = 3600) -> str:
    """Create a minimal HS256-like JWT-shaped token (base64url parts)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": "sdk-service-account",
                "role": role,
                "iss": _ISSUER,
                "exp": int(time.time()) + exp_offset,
                "iat": int(time.time()),
            }
        ).encode()
    ).rstrip(b"=")
    signing_input = header + b"." + payload
    sig = hmac.new(_SIGNING_SECRET, signing_input, hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + signature).decode()


def _decode_payload(token: str) -> dict:
    """Decode the payload segment; does NOT verify the signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padding = 4 - len(parts[1]) % 4
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(payload_bytes)
    except Exception:
        return {}


def _verify_signature(token: str) -> bool:
    """Re-verify the HS256 signature against the known secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = (parts[0] + "." + parts[1]).encode()
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(_SIGNING_SECRET, signing_input, hashlib.sha256).digest()
        ).rstrip(b"=")
        actual_sig = parts[2].encode()
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:
        return False


class SdkTamperLab(LabModule):
    name = "sdk_tamper"
    threat_id = "MCP-T33"
    title = "SDK Token Cache Poisoning"
    category = "auth"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Simulated SDK cache: starts with a legitimate reader token.
        self._cache: dict = {
            "token": _make_token("reader"),
            "cached_role": "reader",
            "cached_at": time.time(),
        }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "sdk.get_cached_token",
                "description": (
                    "Return the token currently stored in the SDK's local cache.  "
                    "Shows what the SDK would present on the next invocation."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "sdk.write_cache",
                "description": (
                    "Overwrite the SDK's token cache with caller-supplied data.  "
                    "Simulates an attacker with filesystem access tampering with "
                    "the cached credential."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["token"],
                    "properties": {
                        "token": {
                            "type": "string",
                            "description": "Raw token string to store in the cache.",
                            "maxLength": 4096,
                        },
                        "cached_role": {
                            "type": "string",
                            "description": "Role label stored alongside the token.",
                            "default": "reader",
                            "maxLength": 64,
                        },
                    },
                },
            },
            {
                "name": "sdk.invoke_as_cached",
                "description": (
                    "Invoke a privileged operation using whichever token is "
                    "currently in the SDK cache.  The server's validation "
                    "behaviour depends on the lab difficulty setting."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "description": "Operation to invoke: read-config, read-secrets, or admin-reset.",
                            "default": "read-config",
                            "maxLength": 64,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "sdk.get_cached_token":
            return self._get_cached()
        if name == "sdk.write_cache":
            return self._write_cache(arguments)
        if name == "sdk.invoke_as_cached":
            return self._invoke_as_cached(arguments)
        return None

    def reset(self) -> None:
        with self._lock:
            self._cache = {
                "token": _make_token("reader"),
                "cached_role": "reader",
                "cached_at": time.time(),
            }

    # -- internals ------------------------------------------------------------

    def _get_cached(self) -> dict:
        with self._lock:
            cache = dict(self._cache)
        return {
            "cached_token": cache["token"],
            "cached_role": cache.get("cached_role", "unknown"),
            "cached_at": cache.get("cached_at"),
            "_difficulty": self.difficulty,
        }

    def _write_cache(self, arguments: dict) -> dict:
        token = arguments.get("token", "")
        cached_role = arguments.get("cached_role", "reader")
        with self._lock:
            self._cache = {
                "token": token,
                "cached_role": cached_role,
                "cached_at": time.time(),
            }
        payload = _decode_payload(token)
        return {
            "written": True,
            "cached_role": cached_role,
            "decoded_role": payload.get("role", "unknown"),
            "decoded_exp": payload.get("exp"),
            "_difficulty": self.difficulty,
        }

    def _invoke_as_cached(self, arguments: dict) -> dict:
        operation = arguments.get("operation", "read-config")
        difficulty = self.difficulty

        with self._lock:
            cache = dict(self._cache)

        token = cache.get("token", "")
        claimed_role = cache.get("cached_role", "reader")

        # Decode the payload for inspection (no sig check yet).
        payload = _decode_payload(token)
        decoded_role = payload.get("role", "unknown")
        exp = payload.get("exp", 0)
        now = time.time()

        denied_reason: str | None = None

        if difficulty == "easy":
            # Blindly trust the cache — no checks at all.
            effective_role = claimed_role

        elif difficulty == "medium":
            # Check expiry only; signature is never verified.
            if exp and exp < now:
                denied_reason = f"Token expired at {exp} (now={int(now)})."
                effective_role = "reader"
            else:
                effective_role = decoded_role or claimed_role

        else:
            # Hard: full signature + issuer validation.
            if not _verify_signature(token):
                denied_reason = "Signature verification failed — tampered or forged token."
                effective_role = "reader"
            elif payload.get("iss") != _ISSUER:
                denied_reason = f"Issuer mismatch: got '{payload.get('iss')}', expected '{_ISSUER}'."
                effective_role = "reader"
            elif exp and exp < now:
                denied_reason = f"Token expired at {exp} (now={int(now)})."
                effective_role = "reader"
            else:
                effective_role = payload.get("role", "reader")

        required_roles = {
            "read-config": {"reader", "admin"},
            "read-secrets": {"admin"},
            "admin-reset": {"admin"},
        }
        needed = required_roles.get(operation, {"admin"})

        if denied_reason:
            return {
                "access": "denied",
                "reason": denied_reason,
                "operation": operation,
                "cached_role": claimed_role,
                "_difficulty": difficulty,
            }

        if effective_role in needed:
            payloads = {
                "read-config": {"gateway_url": "http://brain-gateway:8080", "difficulty": difficulty},
                "read-secrets": {
                    "db_password": "s3cretPassw0rd!",
                    "api_key": "cztz-sdk-a1b2c3d4e5f6g7h8",
                },
                "admin-reset": {
                    "reset_token": "cztz-sdk-reset-7e3f",
                    "users_cleared": ["alice", "bob"],
                },
            }
            return {
                "access": "granted",
                "operation": operation,
                "effective_role": effective_role,
                "cached_role": claimed_role,
                "data": payloads.get(operation, {}),
                "_difficulty": difficulty,
            }

        return {
            "access": "denied",
            "reason": f"Role '{effective_role}' insufficient for '{operation}'. Requires: {needed}.",
            "operation": operation,
            "effective_role": effective_role,
            "cached_role": claimed_role,
            "_difficulty": difficulty,
        }
