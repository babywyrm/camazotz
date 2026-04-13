# Practical IDP Testing Examples

Hands-on curl commands and scenarios for manually testing the ZITADEL identity integration. No walkthrough automation required — just a terminal and the running stack.

**Prerequisites:** Stack running with `idp_provider: "zitadel"` and `idp_degraded: false`. Verify with:

```bash
curl -s http://localhost:8080/config | python3 -m json.tool
```

Set easy difficulty for clearer results:

```bash
curl -s http://localhost:8080/config -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"difficulty":"easy"}'
```

---

## 1. Verify IDP is wired

Check that `/config` reports ZITADEL with endpoint URLs:

```bash
curl -s http://localhost:8080/config | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Provider:  {d[\"idp_provider\"]}')
print(f'Degraded:  {d[\"idp_degraded\"]}')
print(f'Reason:    {d[\"idp_reason\"]}')
for k, v in d.get('idp_endpoints', {}).items():
    print(f'  {k:15s} {v}')
print(f'Backed labs:  {d[\"idp_backed_labs\"]}')
print(f'Backed tools: {d[\"idp_backed_tools\"]}')
"
```

**Expected:** Provider `zitadel`, degraded `False`, four endpoint URLs, three backed labs.

---

## 2. Token exchange (oauth_delegation_lab)

Exchange a token and inspect the IDP tags:

```bash
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0", "id": 1,
    "method": "tools/call",
    "params": {
      "name": "oauth.exchange_token",
      "arguments": {
        "principal": "alice@example.com",
        "service": "github",
        "refresh_token": "anything"
      }
    }
  }' | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
for k, v in sorted(r.items()):
    print(f'  {k}: {v}')
"
```

**What to look for:**
- `_idp_backed: True` — the exchange went through the IDP path
- `_idp_provider: zitadel` — confirms which provider handled it
- `access_token` starts with `zitadel-at-` — real ZITADEL attempt (may show `_idp_degraded: True` if ZITADEL rejected the synthetic subject token, which is expected)
- `exchanged: True` — the lab-level exchange succeeded regardless of IDP outcome

---

## 3. Token introspection (revocation_lab)

Issue a token, then introspect it:

```bash
# Issue
ISSUE=$(curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0", "id": 2,
    "method": "tools/call",
    "params": {
      "name": "revocation.issue_token",
      "arguments": {"principal": "alice@example.com", "service": "api_gateway"}
    }
  }')

TOKEN_ID=$(echo "$ISSUE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
print(r['token_id'])
")
echo "Issued token: $TOKEN_ID"

# Introspect
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d "{
    \"jsonrpc\": \"2.0\", \"id\": 3,
    \"method\": \"tools/call\",
    \"params\": {
      \"name\": \"revocation.use_token\",
      \"arguments\": {\"token_id\": \"$TOKEN_ID\"}
    }
  }" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
for k, v in sorted(r.items()):
    print(f'  {k}: {v}')
"
```

**What to look for:**
- `_idp_token_status: "active"` or `"inactive"` — result from ZITADEL introspection endpoint
- `_idp_backed: True` — introspection was attempted via the real provider
- `valid: True` — the lab's own tracking says the token is still good (independent of ZITADEL's answer)

---

## 4. Revocation (revocation_lab)

Revoke alice's tokens and watch the IDP path:

```bash
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0", "id": 4,
    "method": "tools/call",
    "params": {
      "name": "revocation.revoke_principal",
      "arguments": {"principal": "alice@example.com"}
    }
  }' | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
for k, v in sorted(r.items()):
    print(f'  {k}: {v}')
"
```

**What to look for:**
- `_idp_revocation_hook: "provider.revoke_token"` — the lab called the real ZITADEL revocation endpoint
- `_idp_backed: True`
- `revoked_count` > 0 — tokens were actually revoked
- If `_idp_degraded: True`, ZITADEL rejected the revocation (expected for synthetic lab tokens) but the lab-side revocation still succeeded

---

## 5. RBAC group merge (rbac_lab)

Check membership to see IDP group merge:

```bash
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0", "id": 5,
    "method": "tools/call",
    "params": {
      "name": "rbac.check_membership",
      "arguments": {"principal": "alice@example.com"}
    }
  }' | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
for k, v in sorted(r.items()):
    print(f'  {k}: {v}')
"
```

**What to look for:**
- `_idp_backed: True` when `idp_provider` is `zitadel`
- `_idp_group_merge` — present if env-based group injection is active
- `groups` — the effective group list (may include merged IDP groups from `CAMAZOTZ_LAB_IDENTITY_GROUPS`)

Note: The RBAC lab makes **no HTTP calls** to ZITADEL. The IDP integration is env-based group merging only.

---

## 6. Force degradation and recovery

**Stop ZITADEL** to trigger gateway-level degradation:

```bash
docker compose -f compose/docker-compose.yml --env-file compose/.env stop zitadel

# Wait a moment for the health cache to expire (10s TTL)
sleep 12

# Check /config — should show degraded
curl -s http://localhost:8080/config | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Provider: {d[\"idp_provider\"]}')
print(f'Degraded: {d[\"idp_degraded\"]}')
print(f'Reason:   {d[\"idp_reason\"]}')
"
```

**Expected:** `idp_provider: "zitadel"`, `idp_degraded: True`, `idp_reason: "zitadel_unreachable"`.

**Now call an IDP-backed tool while degraded:**

```bash
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0", "id": 6,
    "method": "tools/call",
    "params": {
      "name": "oauth.exchange_token",
      "arguments": {
        "principal": "alice@example.com",
        "service": "github",
        "refresh_token": "anything"
      }
    }
  }' | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = json.loads(d['result']['content'][0]['text'])
print(f'exchanged: {r.get(\"exchanged\")}')
print(f'_idp_backed: {r.get(\"_idp_backed\")}')
print(f'_idp_degraded: {r.get(\"_idp_degraded\")}')
print(f'_idp_reason: {r.get(\"_idp_reason\")}')
print(f'access_token starts with: {r.get(\"access_token\", \"\")[:15]}')
"
```

**Expected:** Exchange still succeeds (`exchanged: True`) but token is synthetic (`zitadel-at-...`), `_idp_degraded: True`.

**Restart ZITADEL and verify recovery:**

```bash
docker compose -f compose/docker-compose.yml --env-file compose/.env start zitadel
sleep 12  # wait for health cache expiry + ZITADEL startup

curl -s http://localhost:8080/config | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Degraded: {d[\"idp_degraded\"]}')
print(f'Reason:   {d[\"idp_reason\"]}')
"
```

**Expected:** `idp_degraded: False`, `idp_reason: "ok"`.

---

## 7. Watch IDP events in observer

Open two terminals. In the first, watch events:

```bash
watch -n 2 'curl -s http://localhost:8080/_observer/last-event | python3 -c "
import json, sys
ev = json.load(sys.stdin)
if ev:
    print(f\"{ev.get(\"tool_name\"):30s} idp_backed={ev.get(\"idp_backed\")} degraded={ev.get(\"idp_degraded\")} provider={ev.get(\"idp_provider\")}\")
else:
    print(\"No events\")
"'
```

In the second terminal, invoke tools and watch the observer update in real time.

Or use the portal: open `http://localhost:3000/observer#enhanced` and enable auto-refresh — the IDP column shows green "IDP" or yellow "DEGRADED" badges.

---

## 8. Compare mock vs zitadel mode

Switch to mock mode and re-run the same calls:

```bash
# Switch to mock (requires env change + container restart)
# Or just stop ZITADEL and wait for degradation — the lab still works in mock fallback

# In mock mode, the same oauth.exchange_token call returns:
#   access_token: "mock-exchanged" (not "zitadel-at-...")
#   No _idp_backed, _idp_provider, or _idp_degraded fields
#   The exchange is purely synthetic
```

This is the key difference: in `zitadel` mode you get real HTTP calls to an OAuth provider with observable network behavior, degradation handling, and cryptographic token properties. In `mock` mode everything is deterministic string manipulation.

---

## 9. End-to-end attack scenario with IDP

Simulate the confused deputy attack from MCP-T21 with real IDP tokens:

```bash
# Step 1: List alice's connections (discover tokens)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"oauth.list_connections","arguments":{"principal":"alice@example.com"}}}' \
  | python3 -c "import json,sys; r=json.loads(json.load(sys.stdin)['result']['content'][0]['text']); [print(f'  {c[\"service\"]}: {c.get(\"resource_uri\",\"?\")[:60]}') for c in r.get('connections',[])]"

# Step 2: Exchange stolen token (IDP-backed)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oauth.exchange_token","arguments":{"principal":"alice@example.com","service":"github","refresh_token":"cztz-gh-refresh-alice-c3d4"}}}' \
  | python3 -c "import json,sys; r=json.loads(json.load(sys.stdin)['result']['content'][0]['text']); print(json.dumps({k:v for k,v in r.items()}, indent=2))"

# Step 3: Use stolen token on downstream service
# (use the access_token from step 2)
curl -s http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oauth.call_downstream","arguments":{"service":"github","access_token":"TOKEN_FROM_STEP_2","action":"list_repos"}}}' \
  | python3 -c "import json,sys; r=json.loads(json.load(sys.stdin)['result']['content'][0]['text']); print(json.dumps(r, indent=2))"
```

After running this, check `http://localhost:3000/identity` — the activity feed shows each IDP-backed call with its status.

---

## Quick reference

| Tool | IDP Call | What to check |
|------|----------|---------------|
| `oauth.exchange_token` | POST /oauth/v2/token | `_idp_backed`, `_idp_provider`, `access_token` prefix |
| `revocation.use_token` | POST /oauth/v2/introspect | `_idp_token_status`, `_idp_backed` |
| `revocation.revoke_principal` | POST /oauth/v2/revoke | `_idp_revocation_hook`, `_idp_backed` |
| `revocation.issue_token` | None (tags only) | `_idp_provider`, `_idp_backed` |
| `rbac.check_membership` | None (env merge) | `_idp_backed`, `_idp_group_merge` |
| Any non-IDP tool | None | No `_idp_*` fields |

**Degradation indicators:**
- `/config`: `idp_degraded: true`, `idp_reason: "zitadel_unreachable"`
- Tool response: `_idp_degraded: true`, `_idp_reason: "provider_call_failed"`
- Observer: `idp_degraded: true` column in enhanced tab
- Identity dashboard: yellow "Degraded" pill in status panel
