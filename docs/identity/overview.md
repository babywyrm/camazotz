# Identity overview

Camazotz can run with a **mock** identity layer (default) or a **ZITADEL-shaped** **realism** mode selected by `CAMAZOTZ_IDP_PROVIDER`. The goal is to teach agentic OAuth/OIDC failure modes without forcing every workshop to depend on a live IdP.

## What is implemented today

| Layer | `mock` (default) | `zitadel` |
|--------|------------------|-----------|
| Gateway `/config` | Reports `idp_provider: "mock"` | Reports `idp_provider: "zitadel"` |
| `ZitadelIdentityProvider` | Not used | Loaded from env; **returns placeholder token/introspection/revocation shapes** after **local** config checks (empty token endpoint raises). **No outbound HTTP OAuth/OIDC calls** to ZITADEL yet. |
| Labs (`oauth_delegation_lab`, `rbac_lab`, `revocation_lab`) | Original synthetic tokens and logic | Extra branches: different token prefixes, optional **injected** claims via lab env vars (simulating normalized identity context). |

**Important:** Authorization Code + PKCE, refresh, RFC 8693 token exchange, and live introspection/revocation against ZITADEL are **design targets**, not fully implemented HTTP flows in the current codebase. Treat `zitadel` mode as **configuration + lab realism hooks** until live client calls land.

## Trust boundaries (target architecture)

The design doc (`docs/superpowers/specs/2026-04-11-zitadel-agentic-identity-design.md`) describes the end-state:

1. **Portal** — user-facing token acquisition (e.g. Auth Code + PKCE) against the IdP.
2. **Brain gateway** — MCP front door; exposes `idp_provider` in `GET /config`; modules read `get_idp_provider()` for realism branches.
3. **Labs** — vulnerability logic; in `zitadel` mode they can merge **normalized** claim envelopes for teaching without replacing every synthetic path.

Today, step 1 is **not** wired inside Camazotz: there is no built-in browser OAuth callback server for the portal. Operators who need a real IdP still configure endpoints and credentials for future use and for any tooling that consumes the same env vars.

## Provider selection

- **`CAMAZOTZ_IDP_PROVIDER=mock`** — safe default for CI, local dev, and deterministic tests.
- **`CAMAZOTZ_IDP_PROVIDER=zitadel`** — enables realism branches and the stub `ZitadelIdentityProvider`. Any other value is treated as **`mock`**.

## Smoke checks

- **`make smoke-local-identity`** / **`make smoke-k8s-identity`** — assert the gateway answers `GET /config` with `idp_provider` ∈ `{"mock","zitadel"}`. They do **not** prove live ZITADEL connectivity.

## Further reading

- [Configuration](configuration.md) — environment variables and secrets.
- [Local runbook](local-runbook.md) — Docker Compose and troubleshooting.
- [NUC / Kubernetes runbook](nuc-runbook.md) — Helm values and cluster checks.
