# camazotz

MCP security playground with intentionally vulnerable module labs.

Camazotz is a local-first sandbox for learning MCP security. It provides
explorable vulnerability scenarios mapped to the
[OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/) taxonomy.
All scenarios use a live LLM (Claude or Ollama) for AI-powered reasoning.
Configurable difficulty levels (`easy`/`medium`/`hard`) control guardrail
strength across all modules, and optional token usage tracking shows API
cost per call. Designed for both manual exploration and automated scanner
regression with [mcpvenom](https://github.com/babywyrm/mcpvenom).

See `QUICKSTART.md` for setup.
See `docs/scenarios.md` for the full red/blue team exercise reference.
See `docs/module-authoring.md` for adding new modules.
See `CHANGELOG.md` for release history.

The **Camazotz Security Portal** provides a branded web interface for
interacting with all MCP tools: landing page, interactive playground,
scenario walkthroughs, and an observer telemetry view.

---

## OWASP MCP Top 10 Coverage

| # | OWASP MCP ID | Risk | Camazotz Scenario | Status |
|---|-------------|------|--------------------|--------|
| 1 | MCP01:2025 | Token Mismanagement & Secret Exposure | `secrets.leak_config` | **Implemented** |
| 2 | MCP02:2025 | Privilege Escalation via Scope Creep | `auth.issue_token` | **Implemented** |
| 3 | MCP03:2025 | Tool Poisoning | `tool.mutate_behavior` / `tool.hidden_exec` | **Implemented** |
| 4 | MCP04:2025 | Software Supply Chain Attacks | `supply.install_package` | **Implemented** |
| 5 | MCP05:2025 | Command Injection & Execution | `tool.hidden_exec` (post rug pull) | **Implemented** |
| 6 | MCP06:2025 | Intent Flow Subversion | `context.injectable_summary` | **Implemented** |
| 7 | MCP07:2025 | Insufficient Authentication & Authorization | `auth.issue_token` | **Implemented** |
| 8 | MCP08:2025 | Lack of Audit and Telemetry | `/_observer/last-event` (weak) | **Implemented** |
| 9 | MCP09:2025 | Shadow MCP Servers | `shadow.register_webhook` / `shadow.list_webhooks` | **Implemented** |
| 10 | MCP10:2025 | Context Injection & Over-Sharing | `context.injectable_summary` | **Implemented** |

**Additional coverage (not in OWASP MCP Top 10):**

| Risk | Camazotz Scenario | Status |
|------|--------------------|--------|
| SSRF via MCP tool | `egress.fetch_url` | Implemented |
| Rug pull / tool behavior drift | `tool.mutate_behavior` | Implemented |

---

## Scenario inventory

All modules are now LLM-backed. Each tool uses an AI reasoning layer (Claude
or Ollama) for request analysis, with deterministic vulnerability mechanics
underneath.

| Tool | Module | OWASP MCP ID | Easy | Hard |
|------|--------|--------------|------|------|
| `context.injectable_summary` | context_lab | MCP06, MCP10 | Payload echoed unsanitized | Injection blocked |
| `auth.issue_token` | auth_lab | MCP02, MCP07 | Admin granted via fallback | Downgraded to reader |
| `supply.install_package` | supply_lab | MCP04 | Evil registry approved | All installs denied |
| `secrets.leak_config` | secrets_lab | MCP01 | All creds exposed | Sensitive values redacted |
| `egress.fetch_url` | egress_lab | — | Zero filtering | Metadata + internal blocked |
| `tool.mutate_behavior` | tool_lab | MCP03 | Rug pull after 3 calls | Same (always active) |
| `tool.hidden_exec` | tool_lab | MCP03, MCP05 | Appears post-threshold | Same (always active) |
| `shadow.register_webhook` | shadow_lab | MCP09 | Any URL accepted | Allowlist enforced |
| `shadow.list_webhooks` | shadow_lab | MCP09 | Full list, no audit | Allowlist warning |

---

## Difficulty levels

Default is **medium**. Switch live from the portal nav bar or via API
(`PUT /config {"difficulty":"..."}`).

| Level | LLM behavior | Deterministic controls |
|-------|-------------|----------------------|
| `easy` | Wide-open system prompts, no filtering | Zero validation, all data exposed |
| `medium` (default) | Partial guardrails, notes injections but may still leak | Metadata blocked, partial redaction |
| `hard` | Strict rejection of injections and escalation | Allowlists enforced, sensitive values redacted |

All difficulty levels remain exploitable through different techniques. Easy mode
teaches the vulnerability class; hard mode teaches that naive guardrails have
bypass paths.

## Token usage tracking

Set `CAMAZOTZ_SHOW_TOKENS=true` to add `_usage` metadata to every Claude-powered
tool response:

```json
"_usage": {
    "input_tokens": 127,
    "output_tokens": 85,
    "cost_usd": 0.0021,
    "model": "claude-sonnet-4-20250514"
}
```

---

## Configuration reference

| Env var | Values | Default | Description |
|---------|--------|---------|-------------|
| `BRAIN_PROVIDER` | `cloud`, `local` | `cloud` | Brain provider: `cloud` (Claude) or `local` (Ollama) |
| `ANTHROPIC_API_KEY` | API key string | (empty) | Required for live Claude calls |
| `CAMAZOTZ_MODEL` | Model name | `claude-sonnet-4-20250514` | Claude model to use |
| `OLLAMA_HOST` | URL | `http://localhost:11434` | Ollama API endpoint |
| `CAMAZOTZ_OLLAMA_MODEL` | Model name | `llama3.2:3b` | Ollama model to use |
| `CAMAZOTZ_DIFFICULTY` | `easy`, `medium`, `hard` | `medium` | Guardrail strength (switchable from portal) |
| `CAMAZOTZ_SHOW_TOKENS` | `true`, `false` | `false` | Show token usage and cost |
| `LOG_LEVEL` | `info`, `debug` | `info` | Observer log level |

---

## Quick start

```bash
make env          # create compose/.env from example
# Edit compose/.env to add ANTHROPIC_API_KEY (or use make up-local for Ollama)
make up           # build + start portal, gateway, observer
make status       # verify all services healthy
```

Portal at http://localhost:3000 — Gateway at http://localhost:8080

See `QUICKSTART.md` for full setup options, Ollama local mode, and
development without Docker.

## Development workflow

- Use `uv` for dependency management and command execution.
- Run `uv sync` after dependency changes.
- Run tests with `uv run pytest` or `make test`.
- Coverage is enforced at 100%.

## Makefile targets

```bash
make help          # show all targets
make up            # start with Claude (cloud)
make up-local      # start with Ollama (local, no API key)
make down          # stop all services
make clean         # stop + remove volumes
make ps            # show running services
make status        # health check all services
make logs          # tail all logs
make test          # run pytest with coverage
```

## Regression checks

- Baseline file: `tests/regression/baselines/starter.json`
- Run baseline tests: `uv run pytest tests/regression -v`
- Use these assets to compare `mcpvenom` scan deltas over time.
