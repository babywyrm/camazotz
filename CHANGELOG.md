# Changelog

All notable changes to Camazotz are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Project does not yet follow semantic versioning; versions track development milestones.

---

## [Unreleased]

### Changed

- **All modules now LLM-backed.** The four previously static modules (`egress_lab`,
  `secrets_lab`, `shadow_lab`, `tool_lab`) now use the brain provider for AI-powered
  request analysis. Deterministic vulnerability mechanics are preserved underneath
  the LLM reasoning layer.
- **Real Ollama provider.** `LocalOllamaProvider` now makes actual HTTP calls to the
  Ollama `/api/generate` endpoint instead of returning stubs. Falls back to
  `[ollama-unavailable]` when Ollama is unreachable.
- **Docker Compose gains Ollama service.** Use `--profile local` to spin up an Ollama
  container alongside the brain gateway. Model data persists via a named volume.
- **Camazotz Security Portal** — branded Flask/Jinja2 frontend with dark theme and
  crimson accent. Pages: landing (OWASP coverage stats), playground (interactive
  MCP tool explorer with live JSON responses), scenarios (red/blue team walkthrough
  matrix with difficulty cards), observer (telemetry view with auto-refresh and
  client-side event log). Served as a separate container on port 3000.
- All module tool responses now include `ai_analysis` field with the LLM's reasoning.
- New env vars: `OLLAMA_HOST`, `CAMAZOTZ_OLLAMA_MODEL`, `GATEWAY_URL`, `FLASK_SECRET`.
- **Docker Compose production polish.** Health checks on all services (portal,
  brain-gateway, ollama). Restart policies. Explicit `camazotz` Docker network.
  `ollama-init` sidecar auto-pulls the configured model on first run.
- **Real observer sidecar.** Replaces placeholder sleep loop with a polling
  daemon that tails `/_observer/last-event` and emits structured JSON logs.
  Deduplicates by `request_id`. Debug mode logs gateway connectivity.
- **Hardened gateway Dockerfile.** Multi-stage build, non-root `camazotz` user,
  matching the frontend security posture.
- **Makefile.** Cross-platform (macOS + Linux) targets: `make up`, `make up-local`,
  `make down`, `make clean`, `make logs`, `make status`, `make test`, and more.
- **Rewritten QUICKSTART.md** with portal workflow, Makefile-first instructions,
  and Option A (cloud) / Option B (local) setup paths.
- 80 tests passing at 100% coverage (up from 42).
- Cross-platform verified: macOS (Intel + Apple Silicon) and Linux (Debian/Ubuntu/CentOS).

### Added

- **Scenario: Indirect prompt injection** (`context.injectable_summary`)
  Claude-powered tool with zero output sanitization. Covers OWASP MCP06 and MCP10.
- **Scenario: Confused deputy auth bypass** (`auth.issue_token`)
  Claude-powered tool where LLM reasons about token grants. Error-handling fallback
  grants requested role on parse failure. Covers OWASP MCP02 and MCP07.
- **Scenario: SSRF via tool** (`egress.fetch_url`)
  Static tool accepting any URL with no egress filtering. Flags metadata and
  internal targets in response.
- **Scenario: Rug pull / tool drift** (`tool.mutate_behavior` / `tool.hidden_exec`)
  Static tool that changes description and injects a hidden command execution tool
  after a configurable call threshold. Covers OWASP MCP03 and MCP05.
- **Brain provider abstraction** with cloud (Claude) default and local (Ollama) option.
  Provider selected via `BRAIN_PROVIDER` env var. Falls back to deterministic stubs
  when no API key is configured.
- **Observer telemetry** recording tool invocation events at `/_observer/last-event`.
  Covers OWASP MCP08 (intentionally weak implementation for training).
- **MCP compliance baseline** supporting `initialize`, `tools/list`, `tools/call`,
  and JSON-RPC error responses for unknown methods.
- **Module adapter system** aggregating tools from independent lab modules through
  a stable internal contract.
- **Docker Compose runtime** with Dockerfile, env passthrough for `ANTHROPIC_API_KEY`
  and `CAMAZOTZ_MODEL`, and scenario profile configs (`starter`, `weird`, `chaotic`).
- **Full pytest suite** (42 tests) with 100% coverage gate enforced via `pyproject.toml`.
- **Contract schemas** for module registration and observer events.
- **Scanner regression harness** with baseline artifact for `mcpvenom` differential scans.
- **Documentation:** `QUICKSTART.md`, `docs/scenarios.md` (full red/blue team exercises),
  `docs/module-authoring.md`.
- **Scenario: Secret exposure** (`secrets.leak_config`)
  Static tool returning unredacted credentials (DB URLs, AWS keys, API tokens).
  Covers OWASP MCP01 and MCP-T07 (Secrets in Tool Output).
- **Scenario: Supply chain attack** (`supply.install_package`)
  Claude-powered tool that evaluates package install requests. Accepts custom
  registry URLs without validation. Covers OWASP MCP04 and MCP-T08.
- **Scenario: Shadow MCP / persistent callback** (`shadow.register_webhook` / `shadow.list_webhooks`)
  Static tool that registers webhook callbacks with zero validation or expiration.
  Covers OWASP MCP09 and MCP-T14 (Persistence via Webhook/Callback).
- **Full OWASP MCP Top 10 coverage** — all 10 categories now have at least one scenario.
- **OWASP MCP Top 10 coverage table** in README tracking current and planned scenarios.
- **Cross-reference to MCP Red Team Playbook taxonomy** (MCP-T01 through MCP-T14).
- **Difficulty levels** (`CAMAZOTZ_DIFFICULTY=easy|medium|hard`) controlling guardrail
  strength across all modules. Claude-powered tools get progressively stricter system
  prompts. Static tools get progressively stronger validation (redaction, allowlists,
  egress blocking). All levels remain exploitable through different techniques.
- **Token usage tracking** (`CAMAZOTZ_SHOW_TOKENS=true`) adding `_usage` metadata
  (input/output tokens, estimated USD cost, model name) to every Claude-powered
  tool response.
- **Configuration reference** in README documenting all env vars.

---

## [0.0.0] - 2026-03-20

### Added

- Initial repository with README placeholder.
