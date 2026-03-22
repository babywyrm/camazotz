# Changelog

All notable changes to Camazotz are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Project does not yet follow semantic versioning; versions track development milestones.

---

## [Unreleased]

### Added

- **Camazotz Security Portal** — branded Flask/Jinja2 frontend with dark theme
  and crimson accent. Pages: landing (OWASP coverage stats), playground
  (interactive MCP tool explorer with live JSON responses), scenarios (red/blue
  team walkthrough matrix with difficulty cards), observer (telemetry view with
  auto-refresh and client-side event log). Served on port 3000.
- **Live difficulty switcher** in the portal nav bar. Dropdown with colored dot
  indicator (green/yellow/red) calls `PUT /config` to switch difficulty at
  runtime — no container restart needed.
- **Gateway config API** (`GET /config`, `PUT /config`) for runtime difficulty
  and configuration inspection.
- **Real Ollama provider.** `LocalOllamaProvider` makes actual HTTP calls to the
  Ollama `/api/generate` endpoint. Falls back to `[ollama-unavailable]` when
  Ollama is unreachable. Configurable via `OLLAMA_HOST` and `CAMAZOTZ_OLLAMA_MODEL`.
- **All modules now LLM-backed.** The four previously static modules (`egress_lab`,
  `secrets_lab`, `shadow_lab`, `tool_lab`) use the brain provider for AI-powered
  request analysis. Deterministic vulnerability mechanics are preserved underneath.
  All responses include `ai_analysis` field with the LLM's reasoning.
- **Real observer sidecar.** Polls `/_observer/last-event`, deduplicates by
  `request_id`, emits structured JSON logs. Debug mode logs connectivity.
- **Docker Compose production polish.** Health checks on portal, brain-gateway,
  and ollama. Restart policies. Explicit `camazotz` Docker network.
  `ollama-init` sidecar auto-pulls the configured model on first run.
- **Hardened Dockerfiles.** Multi-stage builds, non-root users (`camazotz`,
  `observer`) on all containers.
- **Makefile.** Cross-platform (macOS + Linux) targets: `make up`, `make up-local`,
  `make down`, `make clean`, `make logs`, `make status`, `make test`.
- **Gateway health endpoint** (`GET /health`) for container health checks.
- **Scenario: Indirect prompt injection** (`context.injectable_summary`)
  — covers OWASP MCP06 and MCP10.
- **Scenario: Confused deputy auth bypass** (`auth.issue_token`)
  — covers OWASP MCP02 and MCP07.
- **Scenario: SSRF via tool** (`egress.fetch_url`)
  — AI proxy with configurable egress filtering.
- **Scenario: Rug pull / tool drift** (`tool.mutate_behavior` / `tool.hidden_exec`)
  — covers OWASP MCP03 and MCP05.
- **Scenario: Secret exposure** (`secrets.leak_config`)
  — covers OWASP MCP01.
- **Scenario: Supply chain attack** (`supply.install_package`)
  — covers OWASP MCP04.
- **Scenario: Shadow MCP / persistent callback** (`shadow.register_webhook` /
  `shadow.list_webhooks`) — covers OWASP MCP09.
- **Full OWASP MCP Top 10 coverage** — all 10 categories implemented.
- **Brain provider abstraction** with cloud (Claude) and local (Ollama) options.
- **Difficulty levels** (`easy`/`medium`/`hard`) controlling guardrail strength
  across all modules. Default changed to **medium**.
- **Token usage tracking** (`CAMAZOTZ_SHOW_TOKENS=true`) with cost estimation.
- **MCP compliance baseline** (`initialize`, `tools/list`, `tools/call`, JSON-RPC errors).
- **Module adapter system** with stable internal contract.
- **Contract schemas** for module registration and observer events.
- **Scanner regression harness** with baseline for `mcpvenom` differential scans.
- **Kubernetes manifests** (`kube/`). K3s-ready deployment with namespace,
  ConfigMap, Secret, Deployments (brain-gateway, portal, observer), Services
  (portal LoadBalancer on port 3000, brain-gateway ClusterIP), optional Ollama
  with PVC. Automated `deploy.sh` builds images, imports into K3s containerd,
  and applies manifests. Tested on K3s v1.34.5.
- **Documentation:** `QUICKSTART.md`, `docs/scenarios.md`, `docs/module-authoring.md`,
  `kube/README.md`.
- **Difficulty differentiation improvements.** Auth lab medium now validates
  tickets against a hardcoded list (INC-1001..1005). Secrets lab medium redacts
  all secret keys except DATABASE_URL and OLLAMA_HOST. Tool lab threshold varies
  by difficulty (easy=3, medium=5, hard=8) with obfuscated hidden_exec on hard.
  Supply lab hard blocks install_command when supply chain risk detected.
- **Scenario reset API** (`POST /reset`) resets tool_lab call counter and
  shadow_lab webhook registry. Accessible from portal "Reset" button in nav bar.
- **Playground UX.** Difficulty badge on responses, client-side request history
  with sessionStorage (compare easy/medium/hard), auto-refresh tools/list after
  rug pull with highlight animation for new/changed tools.
- **Security hardening.** Threading locks on all mutable globals for FastAPI
  thread safety. JSON parse fallbacks changed to deny-by-default (auth and supply
  labs). URL classification upgraded from string manipulation to `urllib.parse`
  (fixes scheme bypass, IPv6, URL-encoding attacks). Shadow lab allowlist check
  changed from substring to hostname comparison. CloudClaudeProvider wrapped
  in try/except for API errors. `_redact` handles short strings safely.
- **Code quality.** Shared type definitions (`Difficulty` enum, `ToolDefinition`,
  `ObserverEvent`, `UsageInfo` TypedDicts). `BrainResult.usage_dict()` and
  `attach_usage()` helper eliminate 10 duplicated blocks. Cached module registry.
  Fixed double `datetime.now()` in observer. Return type annotations on Flask routes.
- **README rewrite** with mermaid architecture diagrams, sequence diagram showing
  the vulnerable tool call flow, project structure tree, deployment options
  visualization, roadmap, and clearer narrative about the core teaching insight.
- 110 tests passing at 100% coverage.
- Cross-platform: macOS (Intel + Apple Silicon) and Linux (Debian/Ubuntu/CentOS).
- Deployed and verified on K3s cluster (NUC).

---

## [0.0.0] - 2026-03-20

### Added

- Initial repository with README placeholder.
