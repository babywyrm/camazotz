#!/usr/bin/env python3
"""Bootstrap a ZITADEL service user with client credentials for Camazotz.

ZITADEL v4 removed the password grant, so this authenticates as a system API
user: a key pair whose public half ZITADEL is given in ZITADEL_SYSTEMAPIUSERS.

Usage:
    # once: write the key, then give ZITADEL the printed value
    uv run python scripts/zitadel_bootstrap.py --keygen ~/.camazotz/zitadel-system
    # Compose: ZITADEL_SYSTEMAPIUSERS=<value> in compose/.env
    # Helm:    --set-file zitadel.systemApiUsers=<dir>/system-api-users.json

    # then, as often as needed (a new client secret each run)
    uv run python scripts/zitadel_bootstrap.py --system-key <dir>/system-user.pem [--write-env]

This script:
  1. Waits for ZITADEL to become healthy
  2. Signs a five-minute token as the system API user
  3. Creates a machine user (camazotz-gateway) in the default organization
  4. Prints the client_id and client_secret
  5. Optionally writes them to compose/.env (--write-env)

Requires: httpx and pyjwt[crypto] (already in project deps)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_ZITADEL_URL = "http://localhost:8180"
# ZITADEL picks the instance from the Host header and checks the token's
# audience against it, so both must be the external domain, not the URL dialed.
DEFAULT_EXTERNAL_URL = "http://zitadel:8080"
SYSTEM_USER = "camazotz-bootstrap"
MACHINE_USERNAME = "camazotz-gateway"
MACHINE_DISPLAY = "Camazotz Gateway Service Account"


def keygen(directory: Path) -> str:
    """Write a system API key pair to directory; return ZITADEL_SYSTEMAPIUSERS."""
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "system-user.pem"
    if key_path.exists():
        sys.exit(f"{key_path} exists; remove it to rotate the key")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    users = json.dumps({
        SYSTEM_USER: {
            "KeyData": base64.b64encode(public).decode(),
            "Memberships": [{"MemberType": "System", "Roles": ["SYSTEM_OWNER", "IAM_OWNER", "ORG_OWNER"]}],
        }
    })
    (directory / "system-api-users.json").write_text(users)
    return users


def system_token(private_pem: bytes, audience: str) -> str:
    now = int(time.time())
    claims = {"iss": SYSTEM_USER, "sub": SYSTEM_USER, "aud": audience, "iat": now, "exp": now + 300}
    return jwt.encode(claims, private_pem, algorithm="RS256")


def client(
    base: str, external_url: str, token: str, transport: httpx.BaseTransport | None = None
) -> httpx.Client:
    host = httpx.URL(external_url).netloc.decode()
    return httpx.Client(
        base_url=base.rstrip("/"),
        headers={"Authorization": f"Bearer {token}", "Host": host},
        timeout=10,
        transport=transport,
    )


def _check(r: httpx.Response, what: str, ok: tuple[int, ...] = (200, 201)) -> httpx.Response:
    if r.status_code not in ok:
        sys.exit(f"{what}: {r.status_code} {r.text}")
    return r


def _wait_healthy(base: str, timeout: int = 120) -> None:
    print(f"Waiting for ZITADEL at {base} ...", end="", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base}/debug/healthz", timeout=3)
            if r.status_code == 200:
                print(" healthy.")
                return
        except httpx.HTTPError:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print(" TIMEOUT")
    sys.exit(1)


def bootstrap(c: httpx.Client) -> tuple[str, str]:
    """Create or reuse the gateway machine user and give it a new client secret."""
    org = _check(c.get("/admin/v1/orgs/default"), "Failed to find the default org").json()["org"]["id"]
    c.headers["x-zitadel-orgid"] = org

    r = c.post(
        "/management/v1/users/machine",
        json={
            "userName": MACHINE_USERNAME,
            "name": MACHINE_DISPLAY,
            "description": "Service account for Camazotz brain-gateway IDP flows",
            "accessTokenType": 0,
        },
    )
    if r.status_code == 409:
        found = _check(
            c.post(
                "/management/v1/users/_search",
                json={"queries": [{"userNameQuery": {"userName": MACHINE_USERNAME, "method": 0}}]},
            ),
            "Failed to search users",
        ).json().get("result", [])
        if not found:
            sys.exit("Machine user not found despite 409. Cannot proceed.")
        user_id = found[0]["id"]
        print(f"Found existing machine user: {user_id}")
    else:
        user_id = _check(r, "Failed to create machine user").json()["userId"]
        print(f"Created machine user: {user_id}")

    data = _check(c.put(f"/management/v1/users/{user_id}/secret", json={}), "Failed to generate client secret").json()
    if not data.get("clientId") or not data.get("clientSecret"):
        sys.exit("Unexpected secret response shape")
    return data["clientId"], data["clientSecret"]


def _write_env(client_id: str, client_secret: str) -> None:
    """Append or update client credentials in compose/.env."""
    env_path = Path("compose/.env")
    if not env_path.exists():
        print(f"WARNING: {env_path} not found, skipping --write-env")
        return

    lines = env_path.read_text().splitlines()
    new_lines = []
    keys_written = set()
    for line in lines:
        if line.startswith("CAMAZOTZ_IDP_CLIENT_ID="):
            new_lines.append(f"CAMAZOTZ_IDP_CLIENT_ID={client_id}")
            keys_written.add("id")
        elif line.startswith("CAMAZOTZ_IDP_CLIENT_SECRET="):
            new_lines.append(f"CAMAZOTZ_IDP_CLIENT_SECRET={client_secret}")
            keys_written.add("secret")
        else:
            new_lines.append(line)
    if "id" not in keys_written:
        new_lines.append(f"CAMAZOTZ_IDP_CLIENT_ID={client_id}")
    if "secret" not in keys_written:
        new_lines.append(f"CAMAZOTZ_IDP_CLIENT_SECRET={client_secret}")

    env_path.write_text("\n".join(new_lines) + "\n")
    print(f"Updated {env_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap ZITADEL service user for Camazotz")
    parser.add_argument("--keygen", metavar="DIR", type=Path, help="Write a system API key pair to DIR and exit")
    parser.add_argument("--system-key", type=Path, help="System API private key written by --keygen")
    parser.add_argument("--zitadel-url", default=DEFAULT_ZITADEL_URL, help="URL to reach ZITADEL at")
    parser.add_argument("--external-url", default=DEFAULT_EXTERNAL_URL, help="ZITADEL's external URL")
    parser.add_argument("--write-env", action="store_true", help="Write credentials to compose/.env")
    args = parser.parse_args()

    if args.keygen:
        users = keygen(args.keygen)
        print(f"Wrote {args.keygen / 'system-user.pem'} (keep it private).")
        print("Give ZITADEL the public half, then restart it:")
        print(f"  Compose: ZITADEL_SYSTEMAPIUSERS='{users}' in compose/.env")
        print(f"  Helm:    --set-file zitadel.systemApiUsers={args.keygen / 'system-api-users.json'}")
        return 0
    if not args.system_key:
        parser.error("--system-key is required (create one with --keygen)")

    base = args.zitadel_url.rstrip("/")
    _wait_healthy(base)
    print("Generating client credentials...")
    with client(base, args.external_url, system_token(args.system_key.read_bytes(), args.external_url)) as c:
        client_id, client_secret = bootstrap(c)

    print()
    print("=" * 60)
    print("  ZITADEL Client Credentials for Camazotz")
    print("=" * 60)
    print(f"  CAMAZOTZ_IDP_CLIENT_ID={client_id}")
    print(f"  CAMAZOTZ_IDP_CLIENT_SECRET={client_secret}")
    print("=" * 60)
    print()

    if args.write_env:
        _write_env(client_id, client_secret)

    print("To apply: restart brain-gateway to pick up new credentials.")
    print("  Local:  docker compose -f compose/docker-compose.yml --env-file compose/.env up -d --force-recreate brain-gateway")
    print("  Helm:   --set secrets.idpClientSecret=<secret>, then restart brain-gateway")
    print("  Verify: curl -s http://localhost:8080/config | python3 -m json.tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
