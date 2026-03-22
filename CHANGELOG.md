# Changelog

All notable changes to Camazotz are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

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
- Total: 161 tests, 100% coverage maintained.

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
  `resources/list`, `prompts/list`, standard error codes.

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
- **Live difficulty switcher** in nav bar with colored indicator.
  `PUT /config` changes difficulty at runtime — no restart needed.
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

### Difficulty & Guardrails

- Three levels (`easy` / `medium` / `hard`) controlling LLM system
  prompts, thresholds, allowlists, and redaction rules per module.
- Default changed to **medium**.
- All difficulty levels remain exploitable through different techniques.

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
  observer.
- Cross-platform: macOS (Intel + Apple Silicon) and Linux
  (Debian/Ubuntu/CentOS).
- Deployed and verified end-to-end on K3s cluster with live Claude.

---

## [0.0.0] - 2026-03-20

### Added

- Initial repository with README placeholder.
