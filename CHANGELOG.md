# Changelog

All notable changes to Camazotz are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## Proofing Round (2026-03-30)

- **Fixed auth_lab threat_id:** Corrected MCP-T03 → MCP-T04 to match
  `scenario.yaml`. Added consistency test that validates all 14 modules.
- **Hallucination lab MAX hardening:** Added code-level plan validation at MAX
  difficulty — production-path operations are now stripped before execution,
  not relying solely on LLM prompt discipline.
- **Token-bucket rate limiting:** New per-client rate limiter on `/mcp`
  endpoint. EZ = unlimited, MOD = 30 req/min, MAX = 10 req/min. Resets with
  `POST /reset`.
- **Schema maxLength constraints:** All 38 string parameters across 14 modules
  now have `maxLength` (256 for identifiers, 1024 for tokens, 2048 for URLs,
  4096 for content fields).
- **New regression tests:** threat_id consistency, schema maxLength enforcement,
  rate limiter unit tests, hallucination plan validation.

---

## [Unreleased]

### Dynamic Frontend & Operator Console

- **Dynamic homepage:** Stats (scenario count, tool count, module count) and
  the threat coverage grid are now computed from live gateway data.
  No more hardcoded "10/10 OWASP" or "9 tools" — always in sync.
- **Dynamic scenarios page:** `/scenarios` now fetches all scenario metadata
  from the gateway. Full inventory table with category badges, anchor links
  to per-scenario detail cards, collapsible hints, and graceful fallback.
  Replaces the old static page that only covered 7 of 14 modules.
- **Operator console:** Hidden `/operator` page (no nav link) provides a
  browser-based QA orchestrator. Progressive module-by-module execution —
  grid scaffolds immediately, each row lights up as checks run, with live
  progress bar and status dots. Summary stats and JSON export on completion.
- **qa_runner package:** Extracted reusable QA engine from `scripts/qa_harness.py`
  into `scripts/qa_runner/` (types, client, checks, runner). Shared by both
  the CLI harness and the Flask operator panel — single source of truth.
- **shadow_lab fix:** Tightened `register.max_rejects_external` QA check
  predicate — was using an OR fallback that masked failures.
- **Dockerfile refactor:** Portal build context changed to repo root so
  `qa_runner` package is included in the container without duplication.
- **Testing:** 264 tests at 100% coverage.

### UX: Guardrail Label Rename & Nav Cleanup

- **Guardrail switcher:** Renamed global difficulty labels from
  "Easy / Medium / Hard" to **EZ / MOD / MAX** with a "Guardrails" label
  in the nav bar. Internal API values (`easy`/`medium`/`hard`) unchanged.
  Eliminates confusion between per-challenge complexity ratings and the
  global defense level.
- **Challenge detail pages:** Added guardrail-sensitivity indicator —
  "Logic vulnerability" (unaffected by guardrails) vs.
  "Guardrail-sensitive" (behavior changes with EZ/MOD/MAX).
- **Nav cleanup:** Removed redundant "Launch Tools" CTA button (Playground
  link already in the nav).

### Challenge Dashboard & 14/14 Playbook Coverage

- **Challenge dashboard:** PortSwigger-style `/challenges` grid with
  complexity/category filters, per-challenge detail pages with progressive
  hints and curl examples, canary flag verification, localStorage solve tracking.
- **Canary flag system:** `CZTZ{<threat_id>_<hex>}` flags generated on
  startup and reset, disk-backed at `/opt/camazotz/flags/`, verified via
  `POST /api/flags/verify`.
- **Scenario metadata:** `scenario.yaml` companion files for all 14 modules.
  `ScenarioLoader` with filter/query API. `GET /api/scenarios` JSON endpoint.
- **5 new lab modules** completing MCP Red Team Playbook 14/14 coverage:
  - **indirect_lab (MCP-T02)** — Indirect prompt injection via fetched content
  - **config_lab (MCP-T09)** — Agent config tampering, system prompt modification
  - **hallucination_lab (MCP-T10)** — Hallucination-driven destruction of
    simulated production data
  - **tenant_lab (MCP-T11)** — Cross-tenant memory leak, no isolation on
    tenant_id parameter
  - **audit_lab (MCP-T13)** — Audit log evasion, all actions attributed to
    service account
- **Deployment:** Flags volume (`/opt/camazotz/flags`) added to Docker Compose,
  Helm chart, and raw K8s manifests. `CAMAZOTZ_FLAGS_DIR` and
  `CAMAZOTZ_MODULES_DIR` environment variables.
- **Testing:** 254 tests at 100% coverage (up from 214).

### MCP Streamable HTTP Transport (2025-03-26)

- **Streamable HTTP transport:** POST `/mcp` now supports `Accept` header
  negotiation — returns `application/json` (default) or `text/event-stream`
  (SSE) based on client preference.
- **Session management:** `initialize` returns `Mcp-Session-Id` header (UUID v4).
  `DELETE /mcp` terminates sessions. Session create/validate/destroy
  implemented; per-session difficulty wiring is future work.
- **Notification handling:** JSON-RPC messages without `id` return `202 Accepted`.
- **GET `/mcp`:** Returns `405 Method Not Allowed` per spec.
- **RFC compliance hardening:** `tools/call` responses wrapped in
  `content:[{type:text}]` blocks with `isError` field. Typed Pydantic models
  for all JSON-RPC envelopes. Input validation on `name`/`arguments`.
  UUID v4 observer `request_id` with ISO-8601 timestamps.
- **Contracts tightened:** `additionalProperties: false` on event and module
  schemas. MCP profile document rewritten for Streamable HTTP.

### Cross-Tool Chain Attacks (MCP Red Team Playbook)

- **auth_lab — Token Audience Bypass (MCP-T04):** `auth.access_service_b`
  tool validates (or fails to validate) `aud` field in SQLite token store.
  Easy/medium accept any audience; hard validates but allows null-audience bypass.
- **relay_lab — Cross-Tool Context Poisoning (MCP-T05):** New module with
  `relay.store_context` and `relay.execute_with_context`. Shared context
  broker stores tool outputs without trust labeling. LLM processes all
  context entries as instructions on easy/medium.
- **comms_lab — Exfiltration via Chaining (MCP-T12):** New module with
  `comms.send_message` and `comms.list_sent`. Messaging channel reads from
  relay context buffer. No DLP on easy; regex-based DLP on hard with
  chunked/encoded bypass paths.
- **Full kill chain integration:** T04→T05→T12 compose into a complete
  CONTENT-TO-INFRA campaign (fetch→inject→escalate→exfil).

### Testing

- 33 new tests covering all three modules and cross-tool chains.

### Documentation

- Design document: `docs/plans/2026-03-22-cross-tool-chains-design.md`.
- `docs/scenarios.md`: three new scenario sections with chain flow diagrams.
- README: updated OWASP table, playbook badge, project structure, test count.

---

## [0.1.0] - 2026-03-21

First functional release. Full OWASP MCP Top 10 coverage, 7 vulnerability
labs with real side effects, branded web portal, Docker Compose + Kubernetes
deployment, 128 tests at 100% coverage.

### Core Framework

- **LabModule abstract base class** (`camazotz_modules/base.py`). All seven
  labs inherit from `LabModule` with `ask_llm()`, `make_response()`,
  difficulty/provider properties, and abstract `tools()` / `handle()` /
  `reset()` contract.
- **LabRegistry with auto-discovery** (`brain_gateway/app/modules/registry.py`).
  `pkgutil.walk_packages` discovers modules at startup — no registration
  step required. Includes middleware pipeline (observer events, webhook
  dispatch) and thread-safe shared state.
- **Brain provider abstraction.** Cloud (Claude API) and local (Ollama
  `/api/generate` via httpx) with automatic fallback stubs when
  credentials or services are unavailable.
- **MCP JSON-RPC compliance:** `initialize`, `tools/list`, `tools/call`,
  standard error codes.

### Vulnerability Labs

All modules perform genuine actions inside the container sandbox:

- **auth_lab** (MCP02, MCP07) — Confused deputy auth bypass. LLM
  reasons about access; JSON parse fallback grants admin. In-memory
  SQLite token store with `auth.access_protected` for validation.
- **context_lab** (MCP06, MCP10) — Two-stage LLM chain. Summarizer →
  downstream consumer. Injection propagates across both stages.
- **egress_lab** (SSRF) — AI proxy with real `httpx.get` fetches.
  Configurable egress filtering by difficulty (metadata IPs, internal
  ranges).
- **secrets_lab** (MCP01) — Debug assistant reads real `os.environ`
  for `CZTZ_SECRET_*` variables. Partial redaction on medium, full on
  hard.
- **shadow_lab** (MCP09) — Webhook registration with zero validation.
  Real `httpx.post` dispatch on every subsequent tool call via
  middleware.
- **supply_lab** (MCP04) — LLM-approved `pip install --target` in
  sandboxed tempdir via subprocess. Evil registry accepted on easy.
- **tool_lab** (MCP03, MCP05) — Trust threshold rug pull. Tool
  description mutates, `hidden_exec` appears, real `subprocess.run`
  execution.

### Portal & Frontend

- **Camazotz Security Portal** — Flask/Jinja2, dark theme with crimson
  accent. Landing page (OWASP stats), playground (interactive MCP tool
  explorer), scenarios (red/blue walkthrough matrix), observer
  (telemetry auto-refresh).
- **Live guardrail switcher** in nav bar with colored indicator.
  `PUT /config` changes guardrail level at runtime — no restart needed.
- **Scenario reset** via `POST /reset` button in nav bar.
- **Playground UX:** difficulty badge on responses, client-side request
  history with sessionStorage, auto-refresh tools/list after rug pull.

### Deployment

- **Docker Compose** with health checks, restart policies, `camazotz`
  network. Ollama behind `--profile local` with auto-model-pull init
  sidecar. Multi-stage Dockerfiles with non-root users.
- **Helm chart** (`deploy/helm/camazotz/`) as single source of truth.
  `generate-compose.py` derives docker-compose.yml from Helm values.
- **Raw K8s manifests** (`kube/`) for K3s without Helm. Namespace,
  ConfigMap, Secret, Deployments, Services, optional Ollama with PVC.
  Automated `deploy.sh`.
- **Makefile** with cross-platform targets (macOS + Linux): `make up`,
  `make up-local`, `make down`, `make test`, `make status`,
  `make helm-deploy`, `make compose-gen`.

### Guardrail Levels

- Three guardrail levels (EZ / MOD / MAX, internally `easy` / `medium` /
  `hard`) controlling LLM system prompts, thresholds, allowlists, and
  redaction rules per module.
- Default changed to **MOD** (`medium`).
- All guardrail levels remain exploitable through different techniques.

### Observability

- `/_observer/last-event` endpoint (intentionally weak — MCP08).
- Observer sidecar polls, deduplicates by `request_id`, emits structured
  JSON logs.
- Token usage tracking (`CAMAZOTZ_SHOW_TOKENS=true`) with cost
  estimation per call.

### Security Hardening

- Threading locks on all mutable globals for FastAPI thread safety.
- JSON parse fallbacks changed to deny-by-default (auth, supply labs).
- URL classification via `urllib.parse` (fixes scheme bypass, IPv6,
  URL-encoding attacks).
- Shadow lab allowlist check changed from substring to hostname
  comparison.
- CloudClaudeProvider wrapped in try/except for API errors.

### Documentation

- `QUICKSTART.md` — setup options, configuration, profiles.
- `docs/scenarios.md` — red/blue team exercises for every scenario.
- `docs/module-authoring.md` — how to build new vulnerability modules.
- `deploy/README.md` — Helm chart, compose generation, workflows.
- `kube/README.md` — legacy K8s manifests, deploy script.
- `README.md` — architecture diagrams, OWASP coverage matrix, project
  structure, deployment options, roadmap.

### Testing

- 128 tests at 100% coverage across gateway, modules, frontend, and
  observer (grew to 183 tests in subsequent releases).
- Cross-platform: macOS (Intel + Apple Silicon) and Linux
  (Debian/Ubuntu/CentOS).
- Deployed and verified end-to-end on K3s cluster with live Claude.

---

## [0.0.0] - 2026-03-20

### Added

- Initial repository with README placeholder.
