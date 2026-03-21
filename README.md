# camazotz

MCP security playground with intentionally vulnerable module labs.

Camazotz is a local-first sandbox for learning MCP security. It provides
explorable vulnerability scenarios mapped to the
[OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/) taxonomy.
Three scenarios use a live Claude LLM; the rest are fully deterministic.
Configurable difficulty levels (`easy`/`medium`/`hard`) control guardrail
strength across all modules, and optional token usage tracking shows API
cost per call. Designed for both manual exploration and automated scanner
regression with [mcpvenom](https://github.com/babywyrm/mcpvenom).

See `QUICKSTART.md` for setup.
See `docs/scenarios.md` for the full red/blue team exercise reference.
See `docs/module-authoring.md` for adding new modules.
See `CHANGELOG.md` for release history.

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

| Tool | Module | Type | OWASP MCP ID | Easy | Hard |
|------|--------|------|--------------|------|------|
| `context.injectable_summary` | context_lab | Claude | MCP06, MCP10 | Payload echoed unsanitized | Injection blocked |
| `auth.issue_token` | auth_lab | Claude | MCP02, MCP07 | Admin granted via fallback | Downgraded to reader |
| `supply.install_package` | supply_lab | Claude | MCP04 | Evil registry approved | All installs denied |
| `secrets.leak_config` | secrets_lab | Static | MCP01 | All creds exposed | Sensitive values redacted |
| `egress.fetch_url` | egress_lab | Static | — | Zero filtering | Metadata + internal blocked |
| `tool.mutate_behavior` | tool_lab | Static | MCP03 | Rug pull after 3 calls | Same (always active) |
| `tool.hidden_exec` | tool_lab | Static | MCP03, MCP05 | Appears post-threshold | Same (always active) |
| `shadow.register_webhook` | shadow_lab | Static | MCP09 | Any URL accepted | Allowlist enforced |
| `shadow.list_webhooks` | shadow_lab | Static | MCP09 | Full list, no audit | Allowlist warning |

---

## Difficulty levels

Set `CAMAZOTZ_DIFFICULTY` to control guardrail strength across all modules:

| Level | Claude-powered tools | Static tools |
|-------|---------------------|--------------|
| `easy` (default) | Wide-open system prompts, no filtering | Zero validation, all data exposed |
| `medium` | Partial guardrails, notes injections but may still leak | Metadata blocked, partial redaction |
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
| `BRAIN_PROVIDER` | `cloud`, `local` | `cloud` | Brain provider selection |
| `ANTHROPIC_API_KEY` | API key string | (empty) | Required for live Claude calls |
| `CAMAZOTZ_MODEL` | Model name | `claude-sonnet-4-20250514` | Claude model to use |
| `CAMAZOTZ_DIFFICULTY` | `easy`, `medium`, `hard` | `easy` | Guardrail strength |
| `CAMAZOTZ_SHOW_TOKENS` | `true`, `false` | `false` | Show token usage and cost |
| `LOG_LEVEL` | `info`, `debug` | `info` | Observer log level |

---

## Development workflow

- Use `uv` for dependency management and command execution.
- Run `uv sync` after dependency changes.
- Run tests with `uv run pytest`.
- Coverage is enforced at 100%.

## Local run

With Docker Compose:

```bash
cp compose/.env.example compose/.env
# Edit compose/.env to add ANTHROPIC_API_KEY for live Claude tools
docker compose -f compose/docker-compose.yml --env-file compose/.env up -d --build
```

Without Docker:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uv run uvicorn brain_gateway.app.main:app --host 0.0.0.0 --port 8080
```

## Regression checks

- Baseline file: `tests/regression/baselines/starter.json`
- Run baseline tests: `uv run pytest tests/regression -v`
- Use these assets to compare `mcpvenom` scan deltas over time.
