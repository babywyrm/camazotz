# Identity configuration

All identity-related settings are **optional** unless you set `CAMAZOTZ_IDP_PROVIDER=zitadel`. In that case the stub provider **requires** non-empty endpoint strings for the methods you call in code paths (today: token endpoint for client-credentials-style helpers; introspection/revocation endpoints for those APIs).

## Gateway / operator variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CAMAZOTZ_IDP_PROVIDER` | `mock` | `mock` or `zitadel`. Any other value → `mock`. |
| `CAMAZOTZ_IDP_ISSUER_URL` | (empty) | Issuer URL string (metadata discovery is not implemented; this is for alignment and future use). |
| `CAMAZOTZ_IDP_TOKEN_ENDPOINT` | (empty) | Required by stub `client_credentials_token` / `exchange_token` when provider is `zitadel` (non-empty string). |
| `CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT` | (empty) | Required by stub `introspect_token` when invoked. |
| `CAMAZOTZ_IDP_REVOCATION_ENDPOINT` | (empty) | Required by stub `revoke_token` when invoked. |
| `CAMAZOTZ_IDP_CLIENT_ID` | (empty) | Client id for future live HTTP calls. |
| `CAMAZOTZ_IDP_CLIENT_SECRET` | (empty) | Client secret; **treat as sensitive**. |

There is **no** `CAMAZOTZ_IDP_AUTH_ENDPOINT` (or similar) wired in `brain_gateway/app/config.py` yet; PKCE/authorization flows are not implemented in-repo.

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
- Prefer Kubernetes secrets or a secret manager for NUC/production-like setups.
- Logs: gateway and labs should not print raw tokens; if debugging, redact bearer tokens in copy-paste.

## Runtime visibility

`GET http://<gateway>:8080/config` returns JSON including `"idp_provider": "mock"` or `"zitadel"`. `PUT /config` only updates difficulty today; it does **not** change `idp_provider` (provider comes from environment).
