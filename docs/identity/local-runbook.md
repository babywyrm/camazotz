# Local identity runbook (Docker Compose)

## Prerequisites

- `make env` — ensures `compose/.env` exists
- Stack reachable at `http://localhost:8080` (gateway) and `http://localhost:3000` (portal)

## Mock mode

No IdP configuration required.

```bash
make env
# set CAMAZOTZ_IDP_PROVIDER=mock in compose/.env
make up              # or: make up-local  (Ollama / --profile local)
make status
```

Verify config:

```bash
curl -s http://localhost:8080/config | python3 -m json.tool
```

Smoke (no LLM required):

```bash
make smoke-local-identity
```

Smoke with LLM (needs working brain provider, e.g. API key for cloud):

```bash
make smoke-local-llm
```

### Verify Agentic Lanes view

After every `make up`, confirm the lane view is live:

```bash
make smoke-local-lanes
# -> PASS lanes probe (/lanes renders)
# -> PASS lanes probe (/api/lanes schema=v1, 5 lanes, 32 labs mapped)
```

Or by hand:

```bash
curl -s http://localhost:3000/api/lanes | python3 -m json.tool | head -20
# Expect schema: "v1", five lanes (human-direct, delegated, machine, chain, anonymous)
```

Browser check: `http://localhost:3000/lanes`. The Threat Map at
`http://localhost:3000/threat-map` must remain byte-identical — it is a
spec invariant that the lane view never regresses the existing map.

## ZITADEL realism mode (local)

**Expectation:** This turns on **`zitadel` provider selection** and **IDP-backed trio labs** (oauth_delegation, revocation, rbac). Compose deploys `zitadel` and `zitadel-postgres` services by default.

**Quick bootstrap** (recommended):

```bash
make zitadel-bootstrap    # creates service user, writes credentials to .env
make up                   # restart to apply
```

**ZITADEL Console:** `http://localhost:8180/ui/console` (default login: `zitadel-admin@zitadel.localhost` / `Password1!`)

For the full identity guide, see [guide.md](guide.md).

**Manual setup** — edit **`compose/.env`**:

   ```bash
   CAMAZOTZ_IDP_PROVIDER=zitadel
   CAMAZOTZ_IDP_ISSUER_URL=https://your-instance.example/oauth/v2/your-project
   CAMAZOTZ_IDP_TOKEN_ENDPOINT=https://your-instance.example/oauth/v2/token
   CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT=https://your-instance.example/oauth/v2/introspect
   CAMAZOTZ_IDP_REVOCATION_ENDPOINT=https://your-instance.example/oauth/v2/revoke
   CAMAZOTZ_IDP_CLIENT_ID=your-client-id
   CAMAZOTZ_IDP_CLIENT_SECRET=your-client-secret
   ```

2. Recreate the gateway container so env is picked up:

   ```bash
   make down
   make up          # or make up-local
   ```

3. Confirm `/config`:

   ```bash
   curl -s http://localhost:8080/config | python3 -m json.tool
   # expect: "idp_provider": "zitadel"
   ```

4. Identity smoke (checks `/config` only):

   ```bash
   make smoke-local-identity
   ```

Fallback behavior:

- If `CAMAZOTZ_IDP_PROVIDER=zitadel` but `CAMAZOTZ_IDP_TOKEN_ENDPOINT` is empty, runtime falls back to `mock`.

5. Optional lab injection (oauth exchange extras):

   ```bash
   # example — JSON must be a single object
   export CAMAZOTZ_LAB_IDENTITY_CLAIMS_JSON='{"sub":"alice@example.com","scope":"openid","groups":["platform-eng"]}'
   # In Compose, add the same under brain-gateway environment in values + compose-gen,
   # or use docker compose override — see deploy docs.
   ```

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|----------------|------------|
| `make status` → gateway **DOWN** | Stack not started or wrong port | `make ps`, `make logs-gateway`, then `make up` |
| `/config` still shows `mock` | Typo in `CAMAZOTZ_IDP_PROVIDER` or container not recreated | Only `zitadel` is accepted; anything else → mock. `make down && make up` |
| `smoke-local-identity` fails on `/config` | Gateway not reachable | Start stack first; check firewall |
| Trio labs not showing `_idp_backed` | Config or endpoint incomplete | Verify `CAMAZOTZ_IDP_PROVIDER=zitadel` and all endpoint vars are set; check `/config` for `idp_degraded` |
| `_idp_degraded: true` in tool responses | ZITADEL unreachable | Check ZITADEL health: `curl http://localhost:8180/debug/healthz`; trio falls back to mock behavior gracefully |
| Introspection/revocation **ValueError** | Empty endpoint env | Set `CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT` / `CAMAZOTZ_IDP_REVOCATION_ENDPOINT` |

## Command reference

| Command | Purpose |
|---------|---------|
| `make up` / `make up-local` | Start Compose stack |
| `make down` | Stop stack |
| `make status` | curl health endpoints (gateway, portal, Ollama) |
| `make smoke-local-identity` | `scripts/smoke_test.py --target local --require-identity` |
| `make smoke-local-llm` | Local smoke + LLM probe |
| `make smoke-local-lanes` | Local smoke + `/lanes` and `/api/lanes` probe |

See also [configuration.md](configuration.md) and [QUICKSTART.md](../../QUICKSTART.md).
