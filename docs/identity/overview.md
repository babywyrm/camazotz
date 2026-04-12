# Identity overview

Camazotz can run with a **mock** identity layer or a **ZITADEL-shaped** **realism** mode selected by `CAMAZOTZ_IDP_PROVIDER`. Deployment defaults now prefer `zitadel`, while runtime falls back to `mock` if ZITADEL config is incomplete or unreachable.

## What is implemented today

| Layer | `mock` | `zitadel` |
|--------|------------------|-----------|
| Gateway `/config` | Reports `idp_provider: "mock"`, `idp_degraded: false` | Reports `idp_provider: "zitadel"`, `idp_degraded` true/false, `idp_backed_labs`, `idp_backed_tools` |
| Deployment | No IdP pod required | Compose/Helm deploy `zitadel` + `zitadel-postgres` services by default. |
| `ZitadelIdentityProvider` | Not used | Live HTTP calls to ZITADEL token/introspect/revoke endpoints. |
| IDP-backed trio | Synthetic tokens only | `oauth_delegation_lab`: provider-backed token exchange. `revocation_lab`: provider-backed revoke + introspect. `rbac_lab`: IDP-aware group mapping. |
| Graceful degradation | N/A | On provider failure, trio falls back to mock/synthetic behavior and tags responses with `_idp_degraded: true` + `_idp_reason`. |
| UI visibility | No IDP indicators | Global IDP status strip on all pages; per-step IDP-backed/degraded badges in Operator walkthroughs; IDP-backed lab card badges. |

**Important:** Authorization Code + PKCE, refresh, and full browser OAuth login remain future work. Current `zitadel` mode provides live token lifecycle operations for the IDP-backed trio, with graceful fallback to mock when the provider is unreachable.

## Trust boundaries (target architecture)

The design doc (`docs/superpowers/specs/2026-04-11-zitadel-agentic-identity-design.md`) describes the end-state:

1. **Portal** — user-facing token acquisition (e.g. Auth Code + PKCE) against the IdP.
2. **Brain gateway** — MCP front door; exposes `idp_provider` in `GET /config`; modules read `get_idp_provider()` for realism branches.
3. **Labs** — vulnerability logic; in `zitadel` mode they can merge **normalized** claim envelopes for teaching without replacing every synthetic path.

Today, step 1 is **not** wired inside Camazotz: there is no built-in browser OAuth callback server for the portal. Operators who need a real IdP still configure endpoints and credentials for future use and for any tooling that consumes the same env vars.

## Provider selection

- **`CAMAZOTZ_IDP_PROVIDER=zitadel`** — deployment default; enables live HTTP token/introspect/revoke calls via `ZitadelIdentityProvider` for the IDP-backed trio.
- **`CAMAZOTZ_IDP_PROVIDER=mock`** — deterministic fallback mode for CI and local testing.
- If `CAMAZOTZ_IDP_PROVIDER=zitadel` but required config is incomplete (currently token endpoint), provider selection falls back to **`mock`**.

## Smoke checks

- **`make smoke-local-identity`** / **`make smoke-k8s-identity`** — assert the gateway answers `GET /config` with `idp_provider` ∈ `{"mock","zitadel"}`.
- **`make smoke-local-identity-llm`** / **`make smoke-k8s-identity-llm`** — identity probe + LLM-backed tool call to verify cloud brain + IDP coexistence.
- **`make test-zitadel-flows`** — dedicated test suite for IDP-backed trio behavior (active + degraded paths).

## Further reading

- [Identity Guide](guide.md) — comprehensive teaching + operations reference (start here).
- [Configuration](configuration.md) — environment variables and secrets.
- [Local runbook](local-runbook.md) — Docker Compose and troubleshooting.
- [NUC / Kubernetes runbook](nuc-runbook.md) — Helm values and cluster checks.
