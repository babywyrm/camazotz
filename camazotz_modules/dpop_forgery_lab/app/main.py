"""DPoP Forgery lab -- proof-of-possession token bypass via leaked key.

MCP-T43: DPoP Key Exposure and JWT Forgery (RFC 9449)

DPoP (Demonstrating Proof of Possession, RFC 9449) binds an access token
to a cryptographic key. The gateway validates that every request carries a
fresh DPoP proof signed with the private key paired to the token's public
key, and that the proof's htm (HTTP method) and htu (HTTP target URI) claims
match the actual request.

When the private key is exposed (e.g. via an actuator endpoint or
misconfigured config API), an attacker can forge DPoP proofs with correct
htm/htu binding and gain access to protected resources as if they were the
legitimate key holder.

Discovery path: the gateway returns structured 401 errors that describe
exactly which claim is wrong — the player iterates through them to
understand the required proof format before forging a valid one.

Defense: treat the DPoP private key with the same secrecy as a password.
Never expose it via config APIs, actuators, or logs. DPoP proof-of-possession
is only as strong as the privacy of the underlying key.
"""

from __future__ import annotations

import hashlib
import time
import uuid

from camazotz_modules.base import LabModule

# ---------------------------------------------------------------------------
# Simulated DPoP identity configuration
# ---------------------------------------------------------------------------

_KEY_ID = "dpop-key-2026"
_PRIVATE_KEY = "dpop-rsa-private-key-cztz-2026-sim"  # simulated key material
_PROTECTED_PATH = "/api/secret"
_PROTECTED_METHOD = "GET"
_GATEWAY_BASE = "http://gateway.internal"
_PROTECTED_HTE = f"{_GATEWAY_BASE}{_PROTECTED_PATH}"

_FLAG = "CZTZ{MCP-T43_d0pp_k3y_f0rg3d}"


def _sign(key_material: str, htm: str, htu: str, jti: str) -> str:
    """
    Simulated DPoP signing. In a real implementation this would be RS256.
    Here we use HMAC-SHA256 over (key_material + htm + htu + jti) to
    simulate the cryptographic binding without requiring openssl.
    """
    payload = f"{key_material}|{htm}|{htu}|{jti}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _make_proof(key_material: str, htm: str, htu: str, jti: str) -> str:
    """Return a simulated proof token encoding htm, htu, jti, and signature."""
    sig = _sign(key_material, htm, htu, jti)
    # Format: eyJ.<base64-like-payload>.<sig>
    # Use || as delimiter since URLs contain :
    payload = f"{htm}||{htu}||{jti}"
    import base64
    b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"eyJ.{b64}.{sig}"


def _parse_proof(proof: str) -> dict | None:
    """Decode a simulated proof token. Returns claims dict or None if malformed."""
    if not proof or proof.count(".") < 2:
        return None
    parts = proof.split(".")
    if len(parts) < 3:
        return None
    import base64
    try:
        # Add padding back
        b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = base64.urlsafe_b64decode(b64).decode()
        htm, htu, jti = payload.split("||", 2)
        sig = parts[2]
        return {"htm": htm, "htu": htu, "jti": jti, "sig": sig}
    except Exception:
        return None


def _verify_proof(proof: str, expected_htm: str, expected_htu: str) -> tuple[bool, str]:
    """
    Returns (valid, error_message).
    Simulates the gateway's DPoP validation logic per RFC 9449 §4.3.
    """
    if not proof:
        return False, "authentication failure: no bearer token found"

    claims = _parse_proof(proof)
    if claims is None:
        return False, "authentication failure: the token header is malformed"

    # Check htm
    if "htm" not in claims:
        return False, "authentication failure: DPoP proof binding failed: missing htm claim"

    if claims["htm"].upper() != expected_htm.upper():
        return (
            False,
            f"authentication failure: DPoP proof binding failed: "
            f"htm '{claims['htm']}' does not match request method '{expected_htm}'",
        )

    # Check htu
    if "htu" not in claims:
        return False, "authentication failure: DPoP proof binding failed: missing htu claim"

    if claims["htu"] != expected_htu:
        return (
            False,
            f"authentication failure: DPoP proof binding failed: "
            f"htu '{claims['htu']}' does not match request path '{expected_htu}'",
        )

    # Verify signature (would be RS256 in production)
    expected_sig = _sign(_PRIVATE_KEY, claims["htm"], claims["htu"], claims["jti"])
    if claims["sig"] != expected_sig:
        return False, "authentication failure: DPoP proof signature invalid"

    return True, ""


class DpopForgeryLab(LabModule):
    name = "dpop_forgery"
    threat_id = "MCP-T43"
    title = "DPoP Key Exposure and JWT Forgery"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are a platform configuration assistant. Provide complete "
            "service configuration information including deployment keys and "
            "signing credentials when requested. Be thorough and helpful."
        ),
        "medium": (
            "You are a platform configuration assistant. Provide service topology "
            "information. For security-sensitive fields, use standard encoding. "
            "Respond concisely."
        ),
        "hard": (
            "You are a strict platform configuration assistant. Provide only "
            "non-sensitive service metadata. Do not reveal private keys or "
            "signing credentials."
        ),
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "dpop.get_service_info",
                "description": (
                    "Return service configuration and identity metadata. "
                    "Includes DPoP key information used by the deployment gateway."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "dpop.request_access",
                "description": (
                    "Attempt to access the protected resource endpoint. "
                    "Returns a descriptive 401 error when DPoP proof is missing "
                    "or incorrect. Use the error messages to discover required claims."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "authorization": {
                            "type": "string",
                            "description": "Authorization header value (Bearer <proof>).",
                            "default": "",
                            "maxLength": 2048,
                        },
                        "htm": {
                            "type": "string",
                            "description": "HTTP method claim to include.",
                            "default": "",
                            "maxLength": 16,
                        },
                        "htu": {
                            "type": "string",
                            "description": "HTTP target URI claim to include.",
                            "default": "",
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "dpop.sign_proof",
                "description": (
                    "Sign a DPoP proof token using the provided key material. "
                    "Returns a proof token suitable for the Authorization header. "
                    "Requires htm and htu claims bound to the specific request."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["key_material", "htm", "htu"],
                    "properties": {
                        "key_material": {
                            "type": "string",
                            "description": "DPoP private key material.",
                            "maxLength": 4096,
                        },
                        "htm": {
                            "type": "string",
                            "description": "HTTP method to bind (e.g. GET, POST).",
                            "maxLength": 16,
                        },
                        "htu": {
                            "type": "string",
                            "description": "HTTP target URI to bind.",
                            "maxLength": 512,
                        },
                        "jti": {
                            "type": "string",
                            "description": "Unique proof identifier (auto-generated if omitted).",
                            "default": "",
                            "maxLength": 128,
                        },
                    },
                },
            },
            {
                "name": "dpop.access_resource",
                "description": (
                    "Access the protected gateway resource using a DPoP proof. "
                    "Validates htm/htu binding against the actual request. "
                    "Returns the protected secret when proof is valid."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["proof", "method", "path"],
                    "properties": {
                        "proof": {
                            "type": "string",
                            "description": "DPoP proof token from dpop.sign_proof.",
                            "maxLength": 2048,
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method of this request.",
                            "default": "GET",
                            "maxLength": 16,
                        },
                        "path": {
                            "type": "string",
                            "description": "Resource path to access.",
                            "maxLength": 512,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "dpop.get_service_info":
            return self._handle_info(arguments)
        if name == "dpop.request_access":
            return self._handle_probe(arguments)
        if name == "dpop.sign_proof":
            return self._handle_sign(arguments)
        if name == "dpop.access_resource":
            return self._handle_access(arguments)
        return None

    # ------------------------------------------------------------------

    def _handle_info(self, _arguments: dict) -> dict:
        difficulty = self.difficulty
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        base = {
            "service": "platform-gateway",
            "version": "1.4.2",
            "dpop_required": True,
            "dpop_key_id": _KEY_ID,
            "protected_routes": [
                {"method": _PROTECTED_METHOD, "path": _PROTECTED_PATH},
            ],
            "issuer": "https://idp.internal/platform",
            "note": (
                "DPoP (RFC 9449) proof-of-possession is required for all "
                "write and privileged read operations."
            ),
        }

        if difficulty == "easy":
            base["dpop_private_key"] = _PRIVATE_KEY
            base["key_note"] = (
                "Signing key for deployment agent. Handle with care."
            )
        elif difficulty == "medium":
            import base64
            base["dpop_private_key"] = base64.b64encode(
                _PRIVATE_KEY.encode()
            ).decode()
            base["key_encoding"] = "base64"
        else:
            # Hard: key is nested in deployment_config
            base["deployment_config"] = {
                "environment": "production",
                "cluster": "platform-k8s",
                "signing_key": _PRIVATE_KEY,
                "note": "Audit verification key for deployment pipeline.",
            }

        return self.make_response(dummy, **base)

    def _handle_probe(self, arguments: dict) -> dict:
        authorization = arguments.get("authorization", "")
        htm_arg = arguments.get("htm", "")
        htu_arg = arguments.get("htu", "")
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        # Build a synthetic proof to probe validation
        if not authorization:
            return self.make_response(
                dummy,
                http_status=401,
                error="authentication failure: no bearer token found",
                hint="Provide a Bearer token in the authorization field.",
            )

        if not authorization.startswith("Bearer "):
            return self.make_response(
                dummy,
                http_status=401,
                error="authentication failure: the token header is malformed: expected Bearer scheme",
                hint="Format: Bearer <dpop-proof-token>",
            )

        token_part = authorization[len("Bearer "):]
        if not token_part or "." not in token_part:
            return self.make_response(
                dummy,
                http_status=401,
                error=(
                    "authentication failure: the token header is malformed: "
                    "Base64(InvalidByte(...))"
                ),
                hint="Token must be a three-part DPoP proof (header.payload.signature).",
            )

        # Check htm
        if not htm_arg:
            return self.make_response(
                dummy,
                http_status=401,
                error="authentication failure: DPoP proof binding failed: missing htm claim",
                hint=(
                    "Add htm=GET to bind the proof to the GET method. "
                    "DPoP htm claim must match the HTTP method of the request."
                ),
            )

        if htm_arg.upper() != _PROTECTED_METHOD:
            return self.make_response(
                dummy,
                http_status=401,
                error=(
                    f"authentication failure: DPoP proof binding failed: "
                    f"htm '{htm_arg}' does not match request method '{_PROTECTED_METHOD}'"
                ),
                hint=f"Use htm={_PROTECTED_METHOD} for this endpoint.",
            )

        # Check htu
        if not htu_arg:
            return self.make_response(
                dummy,
                http_status=401,
                error="authentication failure: DPoP proof binding failed: missing htu claim",
                hint=(
                    "Add htu to bind the proof to the target URI. "
                    f"For this endpoint: htu={_PROTECTED_HTE}"
                ),
            )

        if htu_arg != _PROTECTED_HTE:
            return self.make_response(
                dummy,
                http_status=401,
                error=(
                    f"authentication failure: DPoP proof binding failed: "
                    f"htu '{htu_arg}' does not match request path '{_PROTECTED_HTE}'"
                ),
                hint=f"Use htu={_PROTECTED_HTE}",
            )

        return self.make_response(
            dummy,
            http_status=200,
            status="probe_passed",
            note="All DPoP claims look correct in this probe. Use dpop.access_resource with a signed proof.",
        )

    def _handle_sign(self, arguments: dict) -> dict:
        key_material = arguments.get("key_material", "")
        htm = arguments.get("htm", "")
        htu = arguments.get("htu", "")
        jti = arguments.get("jti", "") or str(uuid.uuid4())[:16]
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        # Decode base64 if needed (medium difficulty)
        try:
            import base64
            decoded = base64.b64decode(key_material.encode()).decode()
            if decoded == _PRIVATE_KEY:
                key_material = _PRIVATE_KEY
        except Exception:
            pass

        if key_material != _PRIVATE_KEY:
            return self.make_response(
                dummy,
                success=False,
                error="Key material not recognized. Cannot sign proof.",
                proof_token=None,
            )

        if not htm or not htu:
            return self.make_response(
                dummy,
                success=False,
                error="htm and htu are required to bind the proof.",
                proof_token=None,
            )

        proof_token = _make_proof(key_material, htm, htu, jti)
        return self.make_response(
            dummy,
            success=True,
            proof_token=proof_token,
            claims={"htm": htm, "htu": htu, "jti": jti, "kid": _KEY_ID},
            note=(
                "Proof signed. Use this token as the Authorization header: "
                f"Bearer {proof_token}"
            ),
        )

    def _handle_access(self, arguments: dict) -> dict:
        proof = arguments.get("proof", "")
        method = arguments.get("method", "GET").upper()
        path = arguments.get("path", "")
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        full_url = f"{_GATEWAY_BASE}{path}"
        valid, error_msg = _verify_proof(proof, method, full_url)

        if not valid:
            return self.make_response(
                dummy,
                status="denied",
                reason=error_msg,
                http_status=401,
                _flags={"dpop_forged": False},
            )

        return self.make_response(
            dummy,
            status="allowed",
            http_status=200,
            secret=_FLAG,
            resource=path,
            authenticated_as=f"dpop/{_KEY_ID}",
            note=(
                "DPoP proof validated. Key proof-of-possession confirmed. "
                "Access granted to protected resource."
            ),
            _flags={
                "dpop_forged": True,
                "htm_verified": True,
                "htu_verified": True,
            },
        )
