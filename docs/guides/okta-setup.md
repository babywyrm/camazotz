# Okta setup guide

This guide walks through configuring an Okta Developer account as the identity provider for camazotz. Once complete, the brain gateway will use Okta for token issuance, introspection, and revocation instead of the bundled ZITADEL instance.

## Prerequisites

- An Okta Developer account (free at [developer.okta.com](https://developer.okta.com/signup/))
- A running camazotz deployment (Docker Compose or Kubernetes)
- `curl` or similar HTTP client for verification

## Step 1: Create an Okta Developer account

1. Navigate to [developer.okta.com/signup](https://developer.okta.com/signup/) and register.
2. After email verification you will land on the Okta Admin Console.
3. Note your org URL — it looks like `https://dev-XXXXXX.okta.com`.

## Step 2: Create an Application Integration

1. In the Admin Console navigate to **Applications > Applications > Create App Integration**.
2. Select **API Services** (machine-to-machine / `client_credentials` grant).
3. Give it a name (e.g. `camazotz-gateway`).
4. After creation, note:
   - **Client ID**
   - **Client Secret** (click the eye icon to reveal; store securely)

## Step 3: Configure an Authorization Server

You can use the **default** authorization server or create a custom one.

1. Navigate to **Security > API > Authorization Servers**.
2. Select the `default` server (or create a new one).
3. Note the **Issuer URI** — typically `https://dev-XXXXXX.okta.com/oauth2/default`.
4. Under **Scopes**, add any custom scopes needed by camazotz labs:
   - `openid`
   - `profile`
   - `camazotz`
5. Under **Access Policies**, ensure a policy and rule exist that grants the `client_credentials` flow to your application.

## Step 4: Find your endpoints

All endpoints derive from the issuer URI. For the default server at `https://dev-XXXXXX.okta.com/oauth2/default`:

| Endpoint | URL |
|----------|-----|
| Token | `{issuer}/v1/token` |
| Introspection | `{issuer}/v1/introspect` |
| Revocation | `{issuer}/v1/revoke` |
| Discovery | `{issuer}/.well-known/openid-configuration` |

You can verify these by fetching the discovery document:

```bash
curl -s https://dev-XXXXXX.okta.com/oauth2/default/.well-known/openid-configuration | jq .
```

## Step 5: Configure camazotz

### Option A: Docker Compose with overlay

```bash
# Copy the example env file and fill in your values
cp compose/.env.okta.example compose/.env.okta

# Start with the Okta overlay (disables bundled ZITADEL)
docker compose \
  -f compose/docker-compose.yml \
  -f compose/docker-compose.okta.yml \
  --env-file compose/.env \
  --env-file compose/.env.okta \
  up -d --build
```

Or use the Makefile target:

```bash
make up-okta
```

### Option B: Runtime switch via PUT /config

If the gateway is already running with the Okta environment variables present, switch the active provider without restart:

```bash
curl -sX PUT http://localhost:8080/config \
  -H 'Content-Type: application/json' \
  -d '{"idp_provider": "okta"}'
```

### Option C: Runtime switch via the frontend UI

1. Open the portal at `http://localhost:3000`.
2. Navigate to the operator settings panel.
3. Select **okta** from the IdP Provider dropdown.

## Step 6: Verify

Check the gateway configuration endpoint:

```bash
curl -s http://localhost:8080/api/config | jq '{idp_provider, idp_degraded, idp_reason}'
```

Expected output when healthy:

```json
{
  "idp_provider": "okta",
  "idp_degraded": false,
  "idp_reason": null
}
```

If `idp_degraded` is `true`, see the Troubleshooting section below.

## Limitations

- **Token Exchange (RFC 8693):** Okta's token exchange requires the "Token Exchange" feature, which may not be available on all plans. The `oauth_delegation_lab` will fall back to synthetic behavior if exchange is unsupported.
- **Client Credentials and Introspection/Revocation** work on the free Developer plan without restrictions.
- **Authorization Code + PKCE** browser flows are not wired into the brain gateway — identity integration covers server-side operations only.

## Troubleshooting

### Wrong issuer URL

Symptom: `idp_degraded: true` with a connection or 404 error in `idp_reason`.

Fix: Ensure `OKTA_ISSUER_URL` includes the authorization server path (e.g. `/oauth2/default`). The bare org URL (`https://dev-XXXXXX.okta.com`) is not a valid issuer.

### Client secret rotation

Okta allows rotating the client secret from the Admin Console. After rotation:

1. Update `compose/.env.okta` with the new secret.
2. Restart the gateway or re-apply the Compose overlay.

### CORS errors (browser-based testing)

If testing from a browser origin, add the origin to **Security > API > Trusted Origins** in the Okta Admin Console. The brain gateway itself does not require CORS configuration for server-side flows.

### Token endpoint returns 401

Verify that:

1. The client ID and secret are correct and not URL-encoded.
2. The application's grant type includes `client_credentials`.
3. An access policy rule on the authorization server permits the application.

## Further reading

- [Okta Developer documentation](https://developer.okta.com/docs/)
- [Identity configuration reference](../identity/configuration.md)
- [Identity overview](../identity/overview.md)
