# ZITADEL Agentic Identity Integration Design

## Goal

Introduce a realistic OAuth/OIDC identity layer using ZITADEL across local and NUC environments, while preserving deterministic challenge behavior and test stability through a provider abstraction.

## Decisions

- IdP: `ZITADEL`
- Environment strategy: separate tenants/projects per environment (`local`, `nuc`) with future support for external enterprise IdPs
- Delivery strategy: hybrid provider model (`mock` + `zitadel`) behind a shared identity adapter
- Documentation strategy: comprehensive design + runbooks + operator docs + threat-lab mapping docs
- Change management: small, focused commits by concern area (no mega commits)

## Scope

### In scope

- Identity provider abstraction in gateway code
- ZITADEL provider implementation for:
  - Client Credentials
  - Authorization Code + PKCE
  - Token Exchange (RFC 8693)
  - Refresh token flow
  - Token introspection and revocation integration
- Configuration for local and NUC deployments
- Realism-mode integration points for `oauth_delegation_lab`, `rbac_lab`, and `revocation_lab`
- Test coverage for provider abstraction and critical identity guardrails
- End-to-end documentation and operational runbooks

### Out of scope (phase 1)

- Replacing all synthetic challenge logic with live identity dependencies
- Full external enterprise IdP federation (design must remain compatible)
- Dynamic tenant provisioning automation from Camazotz UI

## Architecture

### Core model

Add a stable `IdentityProvider` interface with two implementations:

- `MockIdentityProvider` (existing synthetic behavior, deterministic tests)
- `ZitadelIdentityProvider` (live OAuth/OIDC calls)

Selection via config:

- `CAMAZOTZ_IDP_PROVIDER=mock|zitadel`
- Default remains `mock` to avoid breaking existing test and workshop flows

### Environment topology

- `camazotz-local` tenant/project for local Compose deployments
- `camazotz-nuc` tenant/project for NUC/K8s deployments
- identical client/app model in both environments:
  - `portal-ui` (Auth Code + PKCE)
  - `brain-gateway` (Client Credentials + introspection caller)
  - `agent-runtime` (token exchange actor / OBO)

### Request and trust boundaries

1. Portal obtains user token via Auth Code + PKCE.
2. Gateway validates token context (JWT checks and/or introspection for sensitive operations).
3. Agent-runtime performs token exchange when delegating to downstream tools/services.
4. Downstream calls enforce audience and scope narrowing.
5. Revocation/introspection checks apply to high-risk operations.

## Token and claims contract

Normalize identity context in gateway into an internal claims envelope:

- Required identity fields:
  - `sub`, `iss`, `aud`, `exp`, `iat`, `scope`, `client_id`
- Delegation and provenance:
  - `act`, `azp`, `jti`
- Environment and tenancy:
  - `tenant_id`, `env` (`local|nuc`)
- Authorization context:
  - `team`, `groups`

This contract becomes the sole input for authorization checks in realism mode and for audit enrichment.

## Delegation and safety rules

- Maximum delegation depth: configurable (default `2`)
- Audience policy: narrowing-only
- Scope policy: narrowing-only
- Token exchange precondition: explicit exchange permission scope
- High-risk tool calls require active-token verification (introspection path configurable)
- Optional short-lived replay detection store keyed by `jti`

## Lab integration design

### `oauth_delegation_lab`

- Keep synthetic paths for deterministic challenge behavior.
- Add realism mode branch that:
  - validates live tokens
  - exercises token exchange with actor/subject context
  - supports replay demonstrations under configurable guardrails

### `rbac_lab`

- Preserve current synthetic group logic.
- Add realism mode branch mapping `groups/team` claims from identity context.
- Keep bypass patterns as explicit challenge variants, not accidental regressions.

### `revocation_lab`

- Add explicit realism mode scenarios around:
  - revoked token still accepted by cache window
  - strict mode with near-real-time revocation enforcement

## Configuration and deployment

### New configuration surface

- `CAMAZOTZ_IDP_PROVIDER=mock|zitadel`
- `CAMAZOTZ_IDP_ISSUER_URL`
- `CAMAZOTZ_IDP_TOKEN_ENDPOINT`
- `CAMAZOTZ_IDP_AUTH_ENDPOINT`
- `CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT`
- `CAMAZOTZ_IDP_REVOCATION_ENDPOINT`
- `CAMAZOTZ_IDP_CLIENT_ID`
- `CAMAZOTZ_IDP_CLIENT_SECRET` (or secret reference)
- `CAMAZOTZ_IDP_AUDIENCE_DEFAULT`
- `CAMAZOTZ_IDP_EXCHANGE_ENABLED=true|false`
- `CAMAZOTZ_IDP_INTROSPECTION_CACHE_TTL_SECONDS`
- `CAMAZOTZ_IDP_MAX_DELEGATION_DEPTH`

### Local (Compose)

- Add optional ZITADEL service profile and seed/init helper
- Keep default startup unchanged for current users
- Add `make` targets for:
  - local ZITADEL bootstrap
  - identity health check
  - local realism smoke path

### NUC (K8s)

- Helm values support for external/internal ZITADEL endpoint configuration
- Secret-managed client credentials
- Optional chart values for introspection cache and delegation limits
- Add k8s smoke validation for identity endpoints and live exchange flow

## Testing strategy

### Unit tests

- Provider interface contract tests (`mock` and `zitadel` parity where applicable)
- Claims normalization tests
- Delegation depth, audience narrowing, scope narrowing enforcement tests
- Introspection cache behavior tests

### Integration tests

- Auth code/PKCE callback handling path
- Client credentials flow for service identity
- Token exchange (subject + actor) path
- Revocation behavior with and without cache hit

### Smoke/E2E

- Extend `smoke-local-llm` and `smoke-k8s-llm` with optional identity realism probe
- Keep default smoke path fast and independent from identity realism mode

## Documentation deliverables

Deliver full documentation in parallel with implementation:

1. `docs/superpowers/specs/2026-04-11-zitadel-agentic-identity-design.md` (this file)
2. `docs/identity/overview.md`:
   - architecture and trust boundaries
3. `docs/identity/configuration.md`:
   - env vars, defaults, and secret handling
4. `docs/identity/local-runbook.md`:
   - compose startup, seeding, troubleshooting
5. `docs/identity/nuc-runbook.md`:
   - helm config, secrets, smoke checks, rollback
6. updates to `README.md` and `QUICKSTART.md`:
   - new identity modes and commands
7. challenge docs updates:
   - realism-mode behavior notes for `oauth_delegation_lab`, `rbac_lab`, `revocation_lab`

## Commit slicing plan (small, sane commits)

Planned commit sequence:

1. **Identity abstraction scaffold**
   - provider interface and wiring, no behavior change
2. **ZITADEL provider core**
   - token/introspection/revocation/exchange client logic
3. **Gateway integration**
   - claims normalization and auth context plumbing
4. **Lab realism hooks**
   - `oauth_delegation_lab`, `rbac_lab`, `revocation_lab` toggles and mappings
5. **Deployment + config**
   - compose profile, Helm values/templates, secrets/config docs alignment
6. **Tests**
   - unit/integration/smoke additions
7. **Documentation pass**
   - runbooks + README/QUICKSTART/challenge doc updates

Each commit must:

- compile and pass relevant tests for touched areas
- include docs changes for new config/commands introduced in that commit
- avoid mixed refactors unrelated to the commit’s stated purpose

## Risks and mitigations

- **Risk: Flaky tests due to live IdP dependencies**
  - Mitigation: keep `mock` default, gate live tests, use deterministic fixtures
- **Risk: Over-coupling labs to external identity behavior**
  - Mitigation: realism mode optional, synthetic challenge mode preserved
- **Risk: Token handling secrets exposure in logs**
  - Mitigation: strict redaction path and explicit logging tests
- **Risk: Revocation latency confusion**
  - Mitigation: explicit docs and config knobs for introspection cache TTL

## Rollout plan

1. Land abstraction and config plumbing behind feature flags
2. Add ZITADEL provider and validate in local realism mode
3. Enable NUC realism mode and run smoke suite
4. Document operational workflows
5. Keep default mode as `mock` until team sign-off for broader rollout

## Success criteria

- Both local and NUC pass smoke checks in `mock` mode and `zitadel` realism mode
- Required flows verified:
  - Client Credentials
  - Auth Code + PKCE
  - Token Exchange
  - Refresh
  - Revocation + Introspection
- Existing challenge behavior remains stable when `CAMAZOTZ_IDP_PROVIDER=mock`
- Documentation complete enough for another operator to deploy and troubleshoot without tribal knowledge
