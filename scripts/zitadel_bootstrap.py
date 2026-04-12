#!/usr/bin/env python3
"""Bootstrap a ZITADEL service user with client credentials for Camazotz.

Usage:
    uv run python scripts/zitadel_bootstrap.py [--zitadel-url URL] [--write-env]

This script:
  1. Waits for ZITADEL to become healthy
  2. Obtains an admin token via the default first-instance credentials
  3. Creates a machine user (camazotz-gateway) with client credentials
  4. Prints the client_id and client_secret
  5. Optionally appends them to compose/.env (--write-env)

Requires: httpx (already in project deps)
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import httpx

DEFAULT_ZITADEL_URL = "http://localhost:8180"
DEFAULT_ADMIN_USER = "zitadel-admin@zitadel.localhost"
DEFAULT_ADMIN_PASS = "Password1!"
MACHINE_USERNAME = "camazotz-gateway"
MACHINE_DISPLAY = "Camazotz Gateway Service Account"


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


def _admin_token(base: str) -> str:
    """Get an access token using the default admin credentials."""
    r = httpx.post(
        f"{base}/oauth/v2/token",
        data={
            "grant_type": "password",
            "username": DEFAULT_ADMIN_USER,
            "password": DEFAULT_ADMIN_PASS,
            "scope": "openid urn:zitadel:iam:org:project:id:zitadel:aud",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if r.status_code != 200:
        print(f"Failed to get admin token: {r.status_code} {r.text}")
        sys.exit(1)
    token = r.json().get("access_token", "")
    if not token:
        print(f"No access_token in response: {r.text}")
        sys.exit(1)
    return token


def _create_machine_user(base: str, token: str) -> str:
    """Create a machine user and return the user_id."""
    r = httpx.post(
        f"{base}/management/v1/users/machine",
        json={
            "userName": MACHINE_USERNAME,
            "name": MACHINE_DISPLAY,
            "description": "Service account for Camazotz brain-gateway IDP flows",
            "accessTokenType": 0,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code == 409:
        print(f"Machine user '{MACHINE_USERNAME}' already exists, looking up...")
        return _find_machine_user(base, token)
    if r.status_code not in (200, 201):
        print(f"Failed to create machine user: {r.status_code} {r.text}")
        sys.exit(1)
    user_id = r.json().get("userId", "")
    print(f"Created machine user: {user_id}")
    return user_id


def _find_machine_user(base: str, token: str) -> str:
    """Look up existing machine user by username."""
    r = httpx.post(
        f"{base}/management/v1/users/_search",
        json={
            "queries": [
                {"userNameQuery": {"userName": MACHINE_USERNAME, "method": 0}}
            ]
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code != 200:
        print(f"Failed to search users: {r.status_code} {r.text}")
        sys.exit(1)
    users = r.json().get("result", [])
    if not users:
        print("Machine user not found despite 409. Cannot proceed.")
        sys.exit(1)
    user_id = users[0].get("id", "")
    print(f"Found existing machine user: {user_id}")
    return user_id


def _generate_client_secret(base: str, token: str, user_id: str) -> tuple[str, str]:
    """Generate a new client secret for the machine user."""
    r = httpx.put(
        f"{base}/management/v1/users/{user_id}/secret",
        json={},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code not in (200, 201):
        print(f"Failed to generate client secret: {r.status_code} {r.text}")
        sys.exit(1)
    data = r.json()
    client_id = data.get("clientId", "")
    client_secret = data.get("clientSecret", "")
    if not client_id or not client_secret:
        print(f"Unexpected secret response shape: {data}")
        sys.exit(1)
    return client_id, client_secret


def _write_env(client_id: str, client_secret: str) -> None:
    """Append or update client credentials in compose/.env."""
    import pathlib
    env_path = pathlib.Path("compose/.env")
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
    parser.add_argument("--zitadel-url", default=DEFAULT_ZITADEL_URL, help="ZITADEL base URL")
    parser.add_argument("--write-env", action="store_true", help="Write credentials to compose/.env")
    args = parser.parse_args()

    base = args.zitadel_url.rstrip("/")

    _wait_healthy(base)
    print("Authenticating as default admin...")
    token = _admin_token(base)
    print("Creating service user...")
    user_id = _create_machine_user(base, token)
    print("Generating client credentials...")
    client_id, client_secret = _generate_client_secret(base, token, user_id)

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
    print("  Verify: curl -s http://localhost:8080/config | python3 -m json.tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
