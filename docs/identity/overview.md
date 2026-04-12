# Identity overview

Camazotz can run with a **mock** identity layer or a **ZITADEL-shaped** **realism** mode selected by `CAMAZOTZ_IDP_PROVIDER`. Deployment defaults now prefer `zitadel`, while runtime falls back to `mock` if ZITADEL config is incomplete or unreachable.

## What is implemented today

| Layer | `mock` | `zitadel` |
|--------|------------------|-----------|
| Gateway `/config` | Reports `idp_provider: "mock"` | Reports `idp_provider: "zitadel"` |
| Deployment | No IdP pod required | Compose/Helm deploy `zitadel` + `zitadel-postgres` services by default. |
| `ZitadelIdentityProvider` | Not used | Loaded from env; current provider path returns placeholder token/introspection/revocation shapes and uses fail-open checks. |
| Labs (`oauth_delegation_lab`, `rbac_lab`, `revocation_lab`) | Original synthetic tokens and logic | Extra branches: different token prefixes, optional **injected** claims via lab env vars (simulating normalized identity context). |

**Important:** Authorization Code + PKCE, refresh, RFC 8693 token exchange, and full live introspection/revocation integration remain ongoing work. Treat current `zitadel` mode as **self-hosted IdP deployment + realism hooks + fail-open safety**, not complete OAuth feature parity.

## Trust boundaries (target architecture)

The design doc (`docs/superpowers/specs/2026-04-11-zitadel-agentic-identity-design.md`) describes the end-state:

1. **Portal** — user-facing token acquisition (e.g. Auth Code + PKCE) against the IdP.
2. **Brain gateway** — MCP front door; exposes `idp_provider` in `GET /config`; modules read `get_idp_provider()` for realism branches.
3. **Labs** — vulnerability logic; in `zitadel` mode they can merge **normalized** claim envelopes for teaching without replacing every synthetic path.

Today, step 1 is **not** wired inside Camazotz: there is no built-in browser OAuth callback server for the portal. Operators who need a real IdP still configure endpoints and credentials for future use and for any tooling that consumes the same env vars.

## Provider selection

- **`CAMAZOTZ_IDP_PROVIDER=zitadel`** — deployment default for realism branches and the stub `ZitadelIdentityProvider`.
- **`CAMAZOTZ_IDP_PROVIDER=mock`** — deterministic fallback mode for CI and local testing.
- If `CAMAZOTZ_IDP_PROVIDER=zitadel` but required config is incomplete (currently token endpoint), provider selection falls back to **`mock`**.

## Smoke checks

- **`make smoke-local-identity`** / **`make smoke-k8s-identity`** — assert the gateway answers `GET /config` with `idp_provider` ∈ `{"mock","zitadel"}`. They do **not** prove live ZITADEL connectivity.

## Further reading

- [Configuration](configuration.md) — environment variables and secrets.
- [Local runbook](local-runbook.md) — Docker Compose and troubleshooting.
- [NUC / Kubernetes runbook](nuc-runbook.md) — Helm values and cluster checks.
