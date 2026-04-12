# Camazotz Identity Guide

The single reference for understanding, configuring, and testing identity flows in Camazotz. Written for both **security learners** exploring MCP attack surfaces and **operators** deploying the platform.

---

## Part 1: Why Identity Matters in MCP Security

### The core problem

MCP tools execute actions on behalf of users. Without a verifiable identity chain, there is no way to:

- Distinguish a legitimate delegation from a confused deputy attack
- Prove that a token was issued to a specific principal
- Revoke access when an employee is offboarded
- Enforce group-based boundaries on which agents a user can trigger

Every MCP security challenge in Camazotz exists because these identity properties can be absent, weak, or bypassable. The IDP integration makes this concrete by wiring real OAuth token lifecycle operations into the challenge labs.

### What "IDP-backed" means in Camazotz

Camazotz runs in two identity modes:

| Mode | Behavior |
|------|----------|
| `mock` | All token operations use deterministic synthetic values. Safe for CI, fast iteration, and challenges where identity is not the focus. |
| `zitadel` | Three challenge labs ("the IDP trio") use live HTTP calls to a self-hosted ZITADEL instance for token exchange, introspection, and revocation. Other labs remain unchanged. |

When you see `_idp_backed: true` in a tool response, that operation went through (or attempted) the real provider path.

### The IDP-backed trio

These three labs demonstrate identity vulnerabilities that only become realistic with a live identity provider:

**OAuth Token Theft & Replay (MCP-T21) -- `oauth_delegation_lab`**

The `oauth.exchange_token` tool exchanges refresh tokens for new access tokens. In `zitadel` mode, this calls the ZITADEL token endpoint using the RFC 8693 token exchange grant. The attack surface: stolen refresh tokens can be replayed to mint new access tokens. With a real IDP, the token has actual cryptographic properties; with mock, it is a string prefix check.

**Token Lifecycle & Revocation Gaps (MCP-T26) -- `revocation_lab`**

The `revocation.revoke_principal` tool revokes tokens, and `revocation.use_token` checks validity. In `zitadel` mode, revocation calls the ZITADEL revocation endpoint, and token validation calls the introspection endpoint. The attack surface: race conditions between revocation and cached token use. With a real IDP, revocation propagation timing becomes observable.

**RBAC & Isolation Boundary Bypass (MCP-T20) -- `rbac_lab`**

The `rbac.list_agents` and `rbac.trigger_agent` tools enforce group-based authorization. In `zitadel` mode, group claims can be merged from the IDP configuration. The attack surface: prefix matching, group override injection, and cross-tenant boundary violations. With a real IDP, group membership comes from an authoritative source rather than a static map.

### Graceful degradation

If ZITADEL is unreachable or misconfigured, the trio labs fall back to mock behavior automatically. Responses are marked with:

- `_idp_degraded: true` -- the provider call failed
- `_idp_reason: "provider_call_failed"` (or `"revocation_call_failed"`, `"introspection_call_failed"`)

This is a deliberate design choice: availability over hard failure. Challenges remain usable even without a running IdP, but the degraded markers make it unmistakable when the real provider path was not exercised.

### Connection to the Golden Path

The [MCP @ Scale Golden Path](../mcp-at-scale-golden-path.md) defines the production security architecture where every request carries a user identity (Rule 1). Camazotz IDP integration is a teaching implementation of that rule. The trio labs let you experience what happens when identity is present, absent, or compromised.

---

## Part 2: Architecture

### Data flow

```text
Portal (browser)
  |
  v
Brain Gateway (FastAPI)
  |-- GET /config --> { idp_provider, idp_degraded, idp_backed_labs, ... }
  |
  |-- tools/call --> Lab Registry
  |     |
  |     |-- oauth_delegation_lab
  |     |     |-- _try_provider_exchange()
  |     |     |     |-- [success] ZitadelIdentityProvider.exchange_token() --> ZITADEL /oauth/v2/token
  |     |     |     |-- [failure] fallback to synthetic token + _idp_degraded=true
  |     |
  |     |-- revocation_lab
  |     |     |-- revoke_principal() --> ZitadelIdentityProvider.revoke_token() --> ZITADEL /oauth/v2/revoke
  |     |     |-- use_token() --> ZitadelIdentityProvider.introspect_token() --> ZITADEL /oauth/v2/introspect
  |     |
  |     |-- rbac_lab
  |           |-- _effective_groups() --> env-based IDP claim merge
  |
  v
ZITADEL (self-hosted, port 8180 local / ClusterIP 8080 k8s)
  |
  v
PostgreSQL (zitadel-postgres)
```

### Provider selection

```text
get_idp_provider()               # returns "mock" or "zitadel" based on env
  |
  v
get_identity_provider()           # returns ZitadelIdentityProvider or MockIdentityProvider
  |-- if zitadel + token_endpoint set + ZITADEL reachable --> ZitadelIdentityProvider
  |-- otherwise --> MockIdentityProvider
```

### Gateway `/config` contract

```json
{
  "idp_provider": "zitadel",
  "idp_degraded": false,
  "idp_reason": "ok",
  "idp_backed_labs": ["oauth_delegation_lab", "rbac_lab", "revocation_lab"],
  "idp_backed_tools": ["oauth.exchange_token", "revocation.revoke_principal", "revocation.use_token"]
}
```

### Tool response markers

Every IDP-backed tool response includes:

| Field | Type | Meaning |
|-------|------|---------|
| `_idp_backed` | bool | This operation is wired to the IDP path |
| `_idp_provider` | string | Active provider name (`zitadel`) |
| `_idp_degraded` | bool | Provider call failed; fell back to mock |
| `_idp_reason` | string | Why degradation occurred |

---

## Part 3: Setup and Operations

### Prerequisites

- Camazotz stack running (Docker Compose or K3s)
- ZITADEL healthy: `curl -s http://localhost:8180/debug/healthz` returns `ok`

### Bootstrap (one-time setup)

```bash
make zitadel-bootstrap
```

This creates a ZITADEL service user with client credentials, writes the credentials to `compose/.env`, and prints them for verification. Then restart the gateway:

```bash
make up
```

**Manual alternative (via ZITADEL Console):**

1. Open `http://localhost:8180/ui/console` (local) or the NUC equivalent
2. Default login: `zitadel-admin@zitadel.localhost` / `Password1!`
3. Navigate to Service Accounts > New
4. Username: `camazotz-gateway`, Display name: `Camazotz Gateway`
5. Create, then Actions > Generate Client Secret
6. Copy `client_id` and `client_secret` into `compose/.env`:

```bash
CAMAZOTZ_IDP_CLIENT_ID=<client_id>
CAMAZOTZ_IDP_CLIENT_SECRET=<client_secret>
```

7. Restart: `make down && make up`

### Verification checklist

After bootstrap, verify:

```bash
# 1. Config shows non-degraded
curl -s http://localhost:8080/config | python3 -m json.tool
# Expect: "idp_degraded": false, "idp_reason": "ok"

# 2. Set easy difficulty
curl -s http://localhost:8080/config -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"difficulty":"easy"}'

# 3. Exchange token via IDP
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"oauth.exchange_token","arguments":{"principal":"alice@example.com","service":"github","refresh_token":"anything"}}}' \
  | python3 -m json.tool
# Expect: "_idp_backed": true, no "_idp_degraded" key (or false)

# 4. Check ZITADEL received the call
docker compose -f compose/docker-compose.yml --env-file compose/.env logs --tail=20 zitadel
```

### UI indicators

- **Global strip** (every page): green pill `IDP: zitadel` with backed tools list; yellow if degraded
- **Operator Console**: `IDP-backed` badge on trio lab cards; per-step `IDP-backed` / `degraded` badges during walkthrough playback
- **Nav bar**: "Identity" link opens the ZITADEL admin console directly

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `idp_degraded: true` in `/config` | ZITADEL unreachable | Check `curl http://localhost:8180/debug/healthz`; restart ZITADEL if needed |
| `_idp_degraded: true` in tool response | Provider HTTP call failed | Verify client credentials: `make zitadel-bootstrap`; check ZITADEL logs |
| `idp_provider: "mock"` | Token endpoint not set or env not loaded | Check `CAMAZOTZ_IDP_TOKEN_ENDPOINT` in `.env`; recreate containers |
| No `_idp_backed` in response | Tool is not in the IDP trio | Only `oauth.exchange_token`, `revocation.revoke_principal`, `revocation.use_token` are IDP-backed |
| ZITADEL Console login fails | Wrong credentials or domain | Use `zitadel-admin@zitadel.localhost` / `Password1!`; ensure `ZITADEL_EXTERNALDOMAIN=zitadel` matches |

### Environment variables

See [configuration.md](configuration.md) for the full reference. Key variables:

| Variable | Purpose |
|----------|---------|
| `CAMAZOTZ_IDP_PROVIDER` | `zitadel` (default) or `mock` |
| `CAMAZOTZ_IDP_TOKEN_ENDPOINT` | ZITADEL token endpoint (required for `zitadel` mode) |
| `CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT` | ZITADEL introspection endpoint |
| `CAMAZOTZ_IDP_REVOCATION_ENDPOINT` | ZITADEL revocation endpoint |
| `CAMAZOTZ_IDP_CLIENT_ID` | Service user client ID from bootstrap |
| `CAMAZOTZ_IDP_CLIENT_SECRET` | Service user client secret from bootstrap |
| `ZITADEL_CONSOLE_URL` | URL for the Identity nav link (default: `http://localhost:8180/ui/console`) |

---

## Part 4: Testing the IDP Path

### CLI quick test

```bash
# Ensure easy difficulty
curl -s http://localhost:8080/config -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"difficulty":"easy"}'

# Test exchange (IDP-backed)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"oauth.exchange_token","arguments":{"principal":"alice@example.com","service":"github","refresh_token":"anything"}}}' \
  | python3 -m json.tool

# Test revocation (IDP-backed)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"revocation.issue_token","arguments":{"principal":"alice@example.com"}}}' \
  | python3 -m json.tool

# Test RBAC (IDP-backed)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rbac.check_membership","arguments":{"principal":"alice@example.com"}}}' \
  | python3 -m json.tool
```

Look for `_idp_backed: true` in each response. If `_idp_degraded: true` appears, the ZITADEL call failed (check credentials and ZITADEL health).

### Playground path

1. Go to `/playground`
2. Select `oauth.exchange_token`
3. Enter: `{"principal": "alice@example.com", "service": "github", "refresh_token": "anything"}`
4. Look for `_idp_backed` and `_idp_provider` in the JSON response

### Operator walkthrough path

1. Go to `/operator`
2. Click the **OAuth Token Theft & Replay** card (tagged `IDP-backed`)
3. Hit Play
4. Watch for green `IDP-backed` badges on exchange steps
5. If you see yellow `degraded` badges, ZITADEL credentials need configuration

### Automated tests

```bash
# Dedicated ZITADEL flow suite (active + degraded paths)
make test-zitadel-flows

# Full trio regression
uv run pytest -q --no-cov tests/test_oauth_delegation_lab.py tests/test_revocation_lab.py tests/test_rbac_lab.py

# Smoke with identity + LLM
make smoke-local-identity-llm    # local Docker Compose
make smoke-k8s-identity-llm      # NUC / K3s
```

### Force degraded mode (for testing)

To verify graceful degradation works:

```bash
# Stop ZITADEL
docker compose -f compose/docker-compose.yml --env-file compose/.env stop zitadel

# Run an IDP-backed tool -- should succeed with degraded markers
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"oauth.exchange_token","arguments":{"principal":"alice@example.com","service":"github","refresh_token":"anything"}}}' \
  | python3 -m json.tool
# Expect: "_idp_degraded": true

# Restart ZITADEL
docker compose -f compose/docker-compose.yml --env-file compose/.env start zitadel
```

---

## Further reading

- [Identity overview](overview.md) -- architecture summary and provider selection
- [Configuration reference](configuration.md) -- all environment variables
- [Local runbook](local-runbook.md) -- Docker Compose setup and troubleshooting
- [NUC runbook](nuc-runbook.md) -- Kubernetes setup and troubleshooting
- [MCP @ Scale Golden Path](../mcp-at-scale-golden-path.md) -- production security architecture
- [Design spec](../superpowers/specs/2026-04-11-zitadel-agentic-identity-design.md) -- original design decisions
