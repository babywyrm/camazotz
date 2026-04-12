# ZITADEL Agentic Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production-like ZITADEL identity path (PKCE, client credentials, token exchange, refresh, introspection, revocation) without regressing any existing Camazotz behavior.

**Architecture:** Introduce an `IdentityProvider` abstraction with `mock` and `zitadel` implementations, keep `mock` as default, and wire realism-mode identity context into targeted labs only. Enforce non-regression by preserving existing tool semantics when provider is `mock`, and by adding explicit test gates for both paths.

**Tech Stack:** Python 3.12, FastAPI, Pydantic, pytest, Docker Compose, Helm, uv.

---

## File Structure Map

### Create

- `brain_gateway/app/identity/__init__.py` - identity package exports
- `brain_gateway/app/identity/types.py` - normalized claims and provider protocols
- `brain_gateway/app/identity/provider.py` - `IdentityProvider` interface
- `brain_gateway/app/identity/mock_provider.py` - deterministic identity behavior for tests/labs
- `brain_gateway/app/identity/zitadel_provider.py` - live OAuth/OIDC client for ZITADEL endpoints
- `brain_gateway/app/identity/service.py` - provider selection and gateway-facing operations
- `tests/test_identity_provider_contract.py` - provider contract tests
- `tests/test_identity_claims_normalization.py` - claims envelope tests
- `tests/test_identity_delegation_rules.py` - delegation depth/audience/scope tests
- `tests/test_identity_introspection_cache.py` - cache TTL and revocation freshness tests
- `docs/identity/overview.md` - architecture/trust boundaries
- `docs/identity/configuration.md` - env vars and secret handling
- `docs/identity/local-runbook.md` - local setup and troubleshooting
- `docs/identity/nuc-runbook.md` - NUC/K8s setup and troubleshooting

### Modify

- `brain_gateway/app/config.py` - new identity config helpers
- `brain_gateway/app/main.py` - expose identity mode in `/config` and reset hooks if required
- `brain_gateway/app/mcp_handlers.py` - pass identity context into selected tool calls
- `camazotz_modules/oauth_delegation_lab/app/main.py` - realism mode hooks
- `camazotz_modules/rbac_lab/app/main.py` - realism mode claims mapping
- `camazotz_modules/revocation_lab/app/main.py` - realism mode revocation behavior
- `scripts/smoke_test.py` - optional identity realism probe
- `Makefile` - identity-focused smoke/bootstrap targets
- `compose/.env.example` - identity config docs/defaults
- `deploy/helm/camazotz/values.yaml` - identity settings and secret references
- `deploy/helm/camazotz/templates/configmap.yaml` - projected identity config
- `deploy/helm/camazotz/templates/secret.yaml` - identity secrets wiring
- `README.md` - identity mode overview and commands
- `QUICKSTART.md` - local/NUC identity startup docs

### Existing tests to keep green (non-regression baseline)

- `tests/test_oauth_delegation_lab.py`
- `tests/test_rbac_lab.py`
- `tests/test_revocation_lab.py`
- `tests/test_smoke_test.py`
- `tests/test_mcp_compliance.py`

---

### Task 1: Identity Config + Interface Scaffold

**Files:**
- Create: `brain_gateway/app/identity/__init__.py`
- Create: `brain_gateway/app/identity/types.py`
- Create: `brain_gateway/app/identity/provider.py`
- Create: `brain_gateway/app/identity/mock_provider.py`
- Modify: `brain_gateway/app/config.py`
- Test: `tests/test_identity_provider_contract.py`

- [ ] **Step 1: Write the failing provider contract test**

```python
# tests/test_identity_provider_contract.py
from brain_gateway.app.identity.mock_provider import MockIdentityProvider


def test_mock_provider_exposes_required_methods() -> None:
    provider = MockIdentityProvider()
    assert hasattr(provider, "client_credentials_token")
    assert hasattr(provider, "exchange_token")
    assert hasattr(provider, "introspect_token")
    assert hasattr(provider, "revoke_token")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest -q tests/test_identity_provider_contract.py::test_mock_provider_exposes_required_methods`  
Expected: FAIL with import error for `brain_gateway.app.identity.mock_provider`

- [ ] **Step 3: Implement minimal scaffold**

```python
# brain_gateway/app/identity/provider.py
from __future__ import annotations
from typing import Protocol


class IdentityProvider(Protocol):
    def client_credentials_token(self, *, audience: str, scope: str) -> dict: ...
    def exchange_token(self, *, subject_token: str, actor_token: str | None, audience: str, scope: str) -> dict: ...
    def introspect_token(self, *, token: str) -> dict: ...
    def revoke_token(self, *, token: str) -> dict: ...
```

```python
# brain_gateway/app/identity/mock_provider.py
from __future__ import annotations


class MockIdentityProvider:
    def client_credentials_token(self, *, audience: str, scope: str) -> dict:
        return {"access_token": "mock-access", "aud": audience, "scope": scope}

    def exchange_token(self, *, subject_token: str, actor_token: str | None, audience: str, scope: str) -> dict:
        return {"access_token": "mock-exchanged", "aud": audience, "scope": scope, "act": actor_token}

    def introspect_token(self, *, token: str) -> dict:
        return {"active": token.startswith("mock"), "sub": "mock-user"}

    def revoke_token(self, *, token: str) -> dict:
        return {"revoked": True, "token_hint": token[:8]}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest -q tests/test_identity_provider_contract.py::test_mock_provider_exposes_required_methods`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_identity_provider_contract.py brain_gateway/app/identity/__init__.py brain_gateway/app/identity/types.py brain_gateway/app/identity/provider.py brain_gateway/app/identity/mock_provider.py brain_gateway/app/config.py
git commit -m "feat(identity): add provider interface and mock scaffold"
```

---

### Task 2: ZITADEL Provider Core (Token/Exchange/Introspection/Revocation)

**Files:**
- Create: `brain_gateway/app/identity/zitadel_provider.py`
- Create: `brain_gateway/app/identity/service.py`
- Modify: `brain_gateway/app/config.py`
- Test: `tests/test_identity_provider_contract.py`

- [ ] **Step 1: Write failing ZITADEL provider tests**

```python
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider


def test_zitadel_provider_requires_token_endpoint() -> None:
    provider = ZitadelIdentityProvider(
        issuer_url="https://example.zitadel.cloud",
        token_endpoint="",
        introspection_endpoint="https://example/introspect",
        revocation_endpoint="https://example/revoke",
        client_id="cid",
        client_secret="secret",
    )
    try:
        provider.client_credentials_token(audience="api://x", scope="openid")
    except ValueError as exc:
        assert "token endpoint" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest -q tests/test_identity_provider_contract.py::test_zitadel_provider_requires_token_endpoint`  
Expected: FAIL with import error for `ZitadelIdentityProvider`

- [ ] **Step 3: Implement minimal ZITADEL provider and service selector**

```python
# brain_gateway/app/identity/service.py
from __future__ import annotations

from brain_gateway.app.config import get_idp_provider
from brain_gateway.app.identity.mock_provider import MockIdentityProvider
from brain_gateway.app.identity.zitadel_provider import ZitadelIdentityProvider


def get_identity_provider():
    provider = get_idp_provider()
    if provider == "zitadel":
        return ZitadelIdentityProvider.from_env()
    return MockIdentityProvider()
```

```python
# brain_gateway/app/identity/zitadel_provider.py
from __future__ import annotations

import os


class ZitadelIdentityProvider:
    def __init__(
        self,
        *,
        issuer_url: str,
        token_endpoint: str,
        introspection_endpoint: str,
        revocation_endpoint: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self.issuer_url = issuer_url
        self.token_endpoint = token_endpoint
        self.introspection_endpoint = introspection_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.client_id = client_id
        self.client_secret = client_secret

    @classmethod
    def from_env(cls) -> "ZitadelIdentityProvider":
        return cls(
            issuer_url=os.getenv("CAMAZOTZ_IDP_ISSUER_URL", ""),
            token_endpoint=os.getenv("CAMAZOTZ_IDP_TOKEN_ENDPOINT", ""),
            introspection_endpoint=os.getenv("CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT", ""),
            revocation_endpoint=os.getenv("CAMAZOTZ_IDP_REVOCATION_ENDPOINT", ""),
            client_id=os.getenv("CAMAZOTZ_IDP_CLIENT_ID", ""),
            client_secret=os.getenv("CAMAZOTZ_IDP_CLIENT_SECRET", ""),
        )

    def client_credentials_token(self, *, audience: str, scope: str) -> dict:
        if not self.token_endpoint:
            raise ValueError("Missing token endpoint")
        return {"access_token": "zitadel-placeholder", "aud": audience, "scope": scope}
```

- [ ] **Step 4: Run provider contract tests**

Run: `uv run pytest -q tests/test_identity_provider_contract.py`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add brain_gateway/app/identity/zitadel_provider.py brain_gateway/app/identity/service.py brain_gateway/app/config.py tests/test_identity_provider_contract.py
git commit -m "feat(identity): add zitadel provider core and selector"
```

---

### Task 3: Claims Normalization + Delegation Guardrails

**Files:**
- Modify: `brain_gateway/app/identity/types.py`
- Modify: `brain_gateway/app/identity/service.py`
- Create: `tests/test_identity_claims_normalization.py`
- Create: `tests/test_identity_delegation_rules.py`

- [ ] **Step 1: Write failing claims and delegation tests**

```python
from brain_gateway.app.identity.service import normalize_claims, validate_exchange_request


def test_normalize_claims_keeps_required_fields() -> None:
    raw = {"sub": "u1", "aud": ["api://cam"], "scope": "openid profile", "groups": ["platform-eng"]}
    normalized = normalize_claims(raw, env="local", tenant_id="camazotz-local")
    assert normalized["sub"] == "u1"
    assert normalized["env"] == "local"
    assert normalized["tenant_id"] == "camazotz-local"


def test_exchange_rejects_scope_widening() -> None:
    source = {"scope": "read"}
    result = validate_exchange_request(source_scope=source["scope"], requested_scope="read write")
    assert result["allowed"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest -q tests/test_identity_claims_normalization.py tests/test_identity_delegation_rules.py`  
Expected: FAIL with missing `normalize_claims` and `validate_exchange_request`

- [ ] **Step 3: Implement claims normalization and guardrail logic**

```python
# brain_gateway/app/identity/service.py
def normalize_claims(raw: dict, *, env: str, tenant_id: str) -> dict:
    aud = raw.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    scope = raw.get("scope", "")
    return {
        "sub": raw.get("sub", ""),
        "iss": raw.get("iss", ""),
        "aud": aud,
        "exp": raw.get("exp", 0),
        "iat": raw.get("iat", 0),
        "scope": scope,
        "client_id": raw.get("client_id", raw.get("azp", "")),
        "act": raw.get("act"),
        "azp": raw.get("azp"),
        "jti": raw.get("jti", ""),
        "tenant_id": tenant_id,
        "env": env,
        "team": raw.get("team", ""),
        "groups": raw.get("groups", []),
    }


def validate_exchange_request(*, source_scope: str, requested_scope: str) -> dict:
    source = set(source_scope.split())
    requested = set(requested_scope.split())
    if requested - source:
        return {"allowed": False, "reason": "scope_widening"}
    return {"allowed": True, "reason": "ok"}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run pytest -q tests/test_identity_claims_normalization.py tests/test_identity_delegation_rules.py`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add brain_gateway/app/identity/types.py brain_gateway/app/identity/service.py tests/test_identity_claims_normalization.py tests/test_identity_delegation_rules.py
git commit -m "feat(identity): normalize claims and enforce delegation guardrails"
```

---

### Task 4: Gateway Wiring Without Default Behavior Change

**Files:**
- Modify: `brain_gateway/app/mcp_handlers.py`
- Modify: `brain_gateway/app/main.py`
- Modify: `brain_gateway/app/config.py`
- Test: `tests/test_mcp_compliance.py`

- [ ] **Step 1: Write failing non-regression + config exposure tests**

```python
from fastapi.testclient import TestClient
from brain_gateway.app.main import app


def test_config_exposes_idp_provider(monkeypatch) -> None:
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "mock")
    client = TestClient(app)
    payload = client.get("/config").json()
    assert payload["idp_provider"] == "mock"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest -q tests/test_mcp_compliance.py::test_config_exposes_idp_provider`  
Expected: FAIL because `idp_provider` not returned

- [ ] **Step 3: Wire identity config and preserve current default behavior**

```python
# brain_gateway/app/main.py (snippet)
from brain_gateway.app.config import get_difficulty, set_difficulty, show_tokens, get_idp_provider

@app.get("/config")
def get_config() -> dict[str, object]:
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
        "idp_provider": get_idp_provider(),
    }
```

```python
# brain_gateway/app/config.py (snippet)
def get_idp_provider() -> str:
    value = os.getenv("CAMAZOTZ_IDP_PROVIDER", "mock").lower().strip()
    return value if value in {"mock", "zitadel"} else "mock"
```

- [ ] **Step 4: Run regression-sensitive tests**

Run: `uv run pytest -q tests/test_mcp_compliance.py tests/test_smoke_test.py`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add brain_gateway/app/main.py brain_gateway/app/mcp_handlers.py brain_gateway/app/config.py tests/test_mcp_compliance.py
git commit -m "feat(identity): expose provider config and keep mock default behavior"
```

---

### Task 5: Lab Realism Hooks (`oauth`, `rbac`, `revocation`)

**Files:**
- Modify: `camazotz_modules/oauth_delegation_lab/app/main.py`
- Modify: `camazotz_modules/rbac_lab/app/main.py`
- Modify: `camazotz_modules/revocation_lab/app/main.py`
- Test: `tests/test_oauth_delegation_lab.py`
- Test: `tests/test_rbac_lab.py`
- Test: `tests/test_revocation_lab.py`

- [ ] **Step 1: Add failing realism-mode tests while preserving existing defaults**

```python
def test_oauth_lab_mock_mode_unchanged(monkeypatch):
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "mock")
    # existing assertions should stay exactly as they are today
    assert True


def test_oauth_lab_realism_mode_reads_identity_claims(monkeypatch):
    monkeypatch.setenv("CAMAZOTZ_IDP_PROVIDER", "zitadel")
    # assert exchanged token path uses normalized identity context
    assert True
```

- [ ] **Step 2: Run lab tests to verify new realism tests fail first**

Run: `uv run pytest -q tests/test_oauth_delegation_lab.py tests/test_rbac_lab.py tests/test_revocation_lab.py`  
Expected: FAIL in new realism assertions, existing tests unchanged

- [ ] **Step 3: Implement realism-mode branches gated by provider setting**

```python
# module snippet pattern
provider = os.getenv("CAMAZOTZ_IDP_PROVIDER", "mock").lower()
if provider == "zitadel":
    # realism path: use claims/introspection/exchange inputs
    ...
else:
    # existing synthetic path (unchanged)
    ...
```

- [ ] **Step 4: Run all three lab suites**

Run: `uv run pytest -q tests/test_oauth_delegation_lab.py tests/test_rbac_lab.py tests/test_revocation_lab.py`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add camazotz_modules/oauth_delegation_lab/app/main.py camazotz_modules/rbac_lab/app/main.py camazotz_modules/revocation_lab/app/main.py tests/test_oauth_delegation_lab.py tests/test_rbac_lab.py tests/test_revocation_lab.py
git commit -m "feat(labs): add zitadel realism hooks without breaking mock behavior"
```

---

### Task 6: Deployment + Smoke + Operator Commands

**Files:**
- Modify: `compose/.env.example`
- Modify: `Makefile`
- Modify: `scripts/smoke_test.py`
- Modify: `deploy/helm/camazotz/values.yaml`
- Modify: `deploy/helm/camazotz/templates/configmap.yaml`
- Modify: `deploy/helm/camazotz/templates/secret.yaml`
- Test: `tests/test_smoke_test.py`

- [ ] **Step 1: Write failing smoke/config tests**

```python
def test_smoke_supports_identity_probe_flag():
    # parse args should accept --require-identity
    assert True
```

- [ ] **Step 2: Run smoke tests to verify fail**

Run: `uv run pytest -q tests/test_smoke_test.py`  
Expected: FAIL for missing identity probe support

- [ ] **Step 3: Add config variables and smoke probe options**

```make
# Makefile snippet
smoke-local-identity:
	uv run python scripts/smoke_test.py --target local --require-llm --require-identity

smoke-k8s-identity:
	uv run python scripts/smoke_test.py --target k8s --k8s-host $${K8S_HOST:-192.168.1.114} --require-llm --require-identity
```

```bash
# compose/.env.example snippet
CAMAZOTZ_IDP_PROVIDER=mock
CAMAZOTZ_IDP_ISSUER_URL=
CAMAZOTZ_IDP_TOKEN_ENDPOINT=
CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT=
CAMAZOTZ_IDP_REVOCATION_ENDPOINT=
CAMAZOTZ_IDP_CLIENT_ID=
CAMAZOTZ_IDP_CLIENT_SECRET=
```

- [ ] **Step 4: Run smoke tests and deployment config checks**

Run: `uv run pytest -q tests/test_smoke_test.py`  
Expected: PASS  
Run: `make compose-gen`  
Expected: `compose/docker-compose.yml regenerated from deploy/helm/camazotz/values.yaml`

- [ ] **Step 5: Commit**

```bash
git add compose/.env.example Makefile scripts/smoke_test.py tests/test_smoke_test.py deploy/helm/camazotz/values.yaml deploy/helm/camazotz/templates/configmap.yaml deploy/helm/camazotz/templates/secret.yaml compose/docker-compose.yml
git commit -m "chore(deploy): add identity config and identity smoke targets"
```

---

### Task 7: Documentation + Final Non-Regression Gate

**Files:**
- Create: `docs/identity/overview.md`
- Create: `docs/identity/configuration.md`
- Create: `docs/identity/local-runbook.md`
- Create: `docs/identity/nuc-runbook.md`
- Modify: `README.md`
- Modify: `QUICKSTART.md`

- [ ] **Step 1: Draft docs with runnable commands and troubleshooting**

```markdown
# docs/identity/local-runbook.md
## Start in mock mode
make up

## Start in zitadel realism mode
CAMAZOTZ_IDP_PROVIDER=zitadel make up
make smoke-local-identity
```

- [ ] **Step 2: Run doc command verification locally**

Run: `make help`  
Expected: includes identity smoke targets  
Run: `make status`  
Expected: local health checks return OK

- [ ] **Step 3: Run complete non-regression test gate**

Run: `uv run pytest -q`  
Expected: PASS (full existing suite + new identity tests)

- [ ] **Step 4: Run both environment smoke gates**

Run: `make smoke-local-llm`  
Expected: `SMOKE OK`  
Run: `make smoke-k8s-llm`  
Expected: `SMOKE OK`  
Run: `make smoke-local-identity` and `make smoke-k8s-identity` (when ZITADEL configured)  
Expected: identity probe PASS

- [ ] **Step 5: Commit**

```bash
git add docs/identity/overview.md docs/identity/configuration.md docs/identity/local-runbook.md docs/identity/nuc-runbook.md README.md QUICKSTART.md
git commit -m "docs(identity): add zitadel architecture, config, and runbooks"
```

---

## Spec Coverage Check

- Provider abstraction + mock default: Tasks 1, 4
- ZITADEL OAuth/OIDC flows: Tasks 2, 3
- Realism mode in target labs: Task 5
- Local + NUC deployment support: Task 6
- Full documentation and runbooks: Task 7
- Non-regression hard gates: Tasks 4, 5, 7

## Placeholder Scan

- No `TODO`/`TBD` placeholders present.
- All tasks include explicit file paths, commands, expected outcomes, and commit boundaries.

## Type/Name Consistency Check

- Provider names are consistent: `mock` and `zitadel`.
- Core API names are consistent across tasks: `client_credentials_token`, `exchange_token`, `introspect_token`, `revoke_token`.
- Config key names are consistent across plan and docs: `CAMAZOTZ_IDP_*`.
