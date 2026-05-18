# Identity configuration

All identity-related settings are optional. Deployment defaults set `CAMAZOTZ_IDP_PROVIDER=zitadel` and deploy self-hosted `zitadel` + `zitadel-postgres` services. Three providers are supported: `mock`, `zitadel`, and `okta`. If the configured provider is unreachable or misconfigured, the gateway falls back to `mock` at runtime.

## Gateway / operator variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CAMAZOTZ_IDP_PROVIDER` | `zitadel` (deployment), `mock` (code fallback) | `mock`, `zitadel`, or `okta`. Any other value → `mock`. Falls back to `mock` if provider is unreachable or token endpoint is empty. |
| `CAMAZOTZ_IDP_ISSUER_URL` | (empty) | Issuer URL (used for health probes and Okta discovery). |
| `CAMAZOTZ_IDP_TOKEN_ENDPOINT` | (empty) | Required for live `client_credentials_token` / `exchange_token` HTTP calls (zitadel and okta). |
| `CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT` | (empty) | Required for live `introspect_token` HTTP calls when invoked by IDP-backed labs. |
| `CAMAZOTZ_IDP_REVOCATION_ENDPOINT` | (empty) | Required for live `revoke_token` HTTP calls when invoked by IDP-backed labs. |
| `CAMAZOTZ_IDP_CLIENT_ID` | (empty) | Client ID for token/exchange HTTP calls. |
| `CAMAZOTZ_IDP_CLIENT_SECRET` | (empty) | Client secret; **treat as sensitive**. |

> **Okta:** set `CAMAZOTZ_IDP_PROVIDER=okta`, `CAMAZOTZ_IDP_ISSUER_URL=https://<your-domain>/oauth2/default`, and the token/introspection/revocation endpoints from your Okta authorization server. See [`docs/guides/okta-setup.md`](../guides/okta-setup.md) for a step-by-step guide.

PKCE / authorization-code flows are not wired into the brain gateway — the IdP integration covers server-side token exchange and introspection only.

## Runtime IdP switching

The active provider can be changed **without restarting the gateway** via `PUT /config`:

```bash
# Switch to Okta at runtime
curl -sX PUT http://<gateway>:8080/config \
  -H 'Content-Type: application/json' \
  -d '{"idp_provider": "okta"}'

# Switch back to mock
curl -sX PUT http://<gateway>:8080/config \
  -H 'Content-Type: application/json' \
  -d '{"idp_provider": "mock"}'
```

`PUT /config` accepts: `difficulty`, `idp_provider`, and `model`. Changes take effect immediately for subsequent requests; the gateway logs the transition. `GET /config` reflects the active provider under `idp_provider`.

### Docker Compose

Set variables in **`compose/.env`** (create with `make env` from `compose/.env.example`). The generated `compose/docker-compose.yml` passes them into the `brain-gateway` service.

### Kubernetes (Helm)

In **`deploy/helm/camazotz/values.yaml`** under `config`:

- `idpProvider`, `idpIssuerUrl`, `idpTokenEndpoint`, `idpIntrospectionEndpoint`, `idpRevocationEndpoint`, `idpClientId`

Under **`secrets`**:

- `idpClientSecret` → mounted as `CAMAZOTZ_IDP_CLIENT_SECRET` (see `templates/secret.yaml`).

After changing values, redeploy Helm and/or run `make compose-gen` if you use the generated Compose file.

## Lab realism helpers (optional)

Used when `CAMAZOTZ_IDP_PROVIDER=zitadel` to inject **synthetic** identity-shaped data into lab responses (not from live IdP HTTP):

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CAMAZOTZ_LAB_IDENTITY_CLAIMS_JSON` | `oauth_delegation_lab` | JSON object → `normalize_claims(...)` → `_normalized_identity` on exchange responses. |
| `CAMAZOTZ_LAB_IDENTITY_ENV` | `oauth_delegation_lab` | `env` field for normalization (default `local`). |
| `CAMAZOTZ_LAB_TENANT_ID` | `oauth_delegation_lab` | `tenant_id` for normalization (default `camazotz-local`). |
| `CAMAZOTZ_LAB_IDENTITY_SUB` | `rbac_lab` | Subject for realism branch. |
| `CAMAZOTZ_LAB_IDENTITY_GROUPS` | `rbac_lab` | Comma-separated groups string. |

## Secret handling

- Never commit real `CAMAZOTZ_IDP_CLIENT_SECRET` or refresh tokens.
- Prefer Kubernetes secrets or a secret manager for cluster/production-like setups.
- Logs: gateway and labs should not print raw tokens; if debugging, redact bearer tokens in copy-paste.

## Runtime visibility

`GET http://<gateway>:8080/config` returns JSON including `idp_provider`, `idp_degraded`, `idp_reason`, `idp_backed_labs`, and `idp_backed_tools`. `PUT /config` can update `difficulty`, `idp_provider`, and `model` at runtime — no restart required.
