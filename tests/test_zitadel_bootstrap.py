"""ZITADEL bootstrap through a system API user (ZITADEL v4 has no password grant)."""

import base64
import json
import stat
import time
from pathlib import Path

import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization

import zitadel_bootstrap as zb

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = "http://zitadel:8080"


def test_keygen_writes_a_private_key_only_the_owner_can_read(tmp_path: Path) -> None:
    users = json.loads(zb.keygen(tmp_path))

    key = tmp_path / "system-user.pem"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    entry = users[zb.SYSTEM_USER]
    public = serialization.load_pem_public_key(base64.b64decode(entry["KeyData"]))
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    assert public.public_numbers() == private.public_key().public_numbers()  # type: ignore[union-attr]
    assert entry["Memberships"] == [
        {"MemberType": "System", "Roles": ["SYSTEM_OWNER", "IAM_OWNER", "ORG_OWNER"]}
    ]
    assert json.loads((tmp_path / "system-api-users.json").read_text()) == users


def test_keygen_refuses_to_overwrite_a_key(tmp_path: Path) -> None:
    zb.keygen(tmp_path)
    with pytest.raises(SystemExit):
        zb.keygen(tmp_path)


def test_the_system_token_is_short_lived_and_names_the_instance(tmp_path: Path) -> None:
    zb.keygen(tmp_path)
    pem = (tmp_path / "system-user.pem").read_bytes()
    public = serialization.load_pem_private_key(pem, password=None).public_key()

    token = zb.system_token(pem, EXTERNAL)

    claims = jwt.decode(token, public, algorithms=["RS256"], audience=EXTERNAL)  # type: ignore[arg-type]
    assert claims["iss"] == claims["sub"] == zb.SYSTEM_USER
    assert 0 < claims["exp"] - int(time.time()) <= 300


def test_bootstrap_creates_the_gateway_user_in_the_default_org() -> None:
    seen: list[httpx.Request] = []

    def zitadel(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path == "/admin/v1/orgs/default":
            return httpx.Response(200, json={"org": {"id": "org-1"}})
        if req.url.path == "/management/v1/users/machine":
            return httpx.Response(200, json={"userId": "user-1"})
        if req.url.path == "/management/v1/users/user-1/secret":
            return httpx.Response(200, json={"clientId": "camazotz-gateway", "clientSecret": "s3cret"})
        return httpx.Response(404)

    client = zb.client("http://localhost:8180", EXTERNAL, "token-1", transport=httpx.MockTransport(zitadel))
    assert zb.bootstrap(client) == ("camazotz-gateway", "s3cret")

    for req in seen:
        assert req.headers["authorization"] == "Bearer token-1"
        # ZITADEL picks the instance from Host, so a call to the published
        # port still has to name the external domain.
        assert req.headers["host"] == "zitadel:8080"
    assert all(r.headers["x-zitadel-orgid"] == "org-1" for r in seen if r.url.path.startswith("/management/"))


def test_bootstrap_reuses_an_existing_gateway_user() -> None:
    def zitadel(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/admin/v1/orgs/default":
            return httpx.Response(200, json={"org": {"id": "org-1"}})
        if req.url.path == "/management/v1/users/machine":
            return httpx.Response(409, json={})
        if req.url.path == "/management/v1/users/_search":
            return httpx.Response(200, json={"result": [{"id": "user-9"}]})
        if req.url.path == "/management/v1/users/user-9/secret":
            return httpx.Response(200, json={"clientId": "camazotz-gateway", "clientSecret": "rotated"})
        return httpx.Response(404)

    client = zb.client(EXTERNAL, EXTERNAL, "t", transport=httpx.MockTransport(zitadel))
    assert zb.bootstrap(client) == ("camazotz-gateway", "rotated")


def test_bootstrap_stops_on_a_refused_call() -> None:
    def zitadel(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthenticated")

    client = zb.client(EXTERNAL, EXTERNAL, "t", transport=httpx.MockTransport(zitadel))
    with pytest.raises(SystemExit):
        zb.bootstrap(client)


def test_the_chart_pins_zitadel_and_passes_system_users() -> None:
    values = yaml.safe_load((ROOT / "deploy/helm/camazotz/values.yaml").read_text())
    assert values["zitadel"]["tag"] != "latest"
    assert values["zitadel"]["systemApiUsers"] == ""
    template = (ROOT / "deploy/helm/camazotz/templates/zitadel.yaml").read_text()
    assert "ZITADEL_SYSTEMAPIUSERS" in template
    assert ".Values.zitadel.systemApiUsers" in template


def test_compose_passes_system_users_from_the_env_file() -> None:
    compose = yaml.safe_load((ROOT / "compose/docker-compose.yml").read_text())
    zitadel = compose["services"]["zitadel"]
    assert "ZITADEL_SYSTEMAPIUSERS=${ZITADEL_SYSTEMAPIUSERS:-}" in zitadel["environment"]
    assert not zitadel["image"].endswith(":latest")
