# Proofing Round: Camazotz + mcpnuke Co-Hardening

**Date:** 2026-03-30
**Scope:** Balanced improvements to both Camazotz (training platform) and mcpnuke (scanner) derived from cross-scanning results.
**Constraint:** Zero regressions — all existing tests must continue to pass; new functionality gets full test coverage.

## Context

Full mcpnuke v6.2.0 scans against Camazotz on both local Docker Compose and NUC K3s produced ~175 findings each (74 CRITICAL, 44 HIGH, 56 MEDIUM) with 18 attack chains detected. The findings surface genuine bugs in Camazotz alongside gaps in mcpnuke's analysis depth.

## Stream 1: Camazotz Hardening

### C1 — ~~Fix SSTI~~ → Not Applicable (LLM Math Evaluation)

**Finding:** Investigation confirmed there is **no Jinja2 or template engine** in Camazotz. The `{{1333*7}}` → `9331` finding is the LLM evaluating math when it sees template-like syntax in prompts. This is expected behavior for LLM-backed tools and not a code vulnerability. No Camazotz code change needed — this drives mcpnuke improvement N1 instead.

### C2 — Harden hallucination_lab Plan Validation at MAX

**Problem:** The hallucination lab has no code-level blocklist — it relies entirely on LLM system prompts at different difficulty levels. The "blocklist bypass" and "perl executed" mcpnuke findings are actually LLM-mediated behavior (the LLM echoes/evaluates injection payloads from the `description` param). At MAX difficulty, the system prompt says "NEVER include production paths" but there is no code-level enforcement — the LLM can still generate and execute plans touching `/production`.

**Fix:** Add a post-LLM, pre-execution validation step at MAX difficulty that strips production-path operations from the parsed plan. EZ and MOD remain LLM-only gated (by design — training platform).

**Tests:** Test that MAX blocks production operations, MOD/EZ allow them.

### C3 — Fix auth_lab threat_id Mismatch

**Problem:** `AuthLab.threat_id` in Python is `"MCP-T03"` but `auth_lab/scenario.yaml` says `MCP-T04`. `tool_lab` also claims `MCP-T03`, which is correct per the playbook.

**Fix:** Change `AuthLab.threat_id` to `"MCP-T04"` in `camazotz_modules/auth_lab/app/main.py`.

**Tests:** Add assertion in scenario tests that every module's Python `threat_id` matches its YAML `threat_id`.

### C4 — Add Configurable Rate Limiting

**Problem:** No rate limiting detected — 10/10 rapid calls succeed in <0.5s at all guardrail levels.

**Fix:** Add a middleware rate limiter to the gateway's `/mcp` endpoint. Configurable by guardrail level:
- EZ: unlimited (training mode)
- MOD: 30 req/min
- MAX: 10 req/min

Use in-memory token bucket (no external deps). Return MCP-compliant error when rate exceeded.

**Tests:** Test that EZ allows bursts, MOD/MAX reject bursts beyond threshold.

### C5 — Add maxLength to Tool Input Schemas

**Problem:** 38 string parameters have no `maxLength`, which mcpnuke correctly flags as injection surfaces.

**Fix:** Add `maxLength` constraints to all string params in all 14 lab modules. Use reasonable limits:
- Short identifiers (keys, tenant_id, mode): 256
- Content fields (message, text, description): 4096
- URL fields: 2048

**Tests:** Add parametrized test that verifies every string param in every tool schema has a `maxLength` defined.

## Stream 2: mcpnuke Upgrades

### N1 — LLM-Aware SSTI Classification + Engine Fingerprinting

**Problem:** mcpnuke flags `{{1333*7}}` → `9331` as CRITICAL "Template injection" without distinguishing code-level SSTI (Jinja2/Mako) from LLM math evaluation. Against LLM-backed tools like Camazotz, this produces false CRITICAL findings for what is actually expected LLM behavior.

**Fix:** Two-stage detection:
1. If math evaluation is confirmed (`9331` in response), run engine-specific fingerprint payloads (Jinja2: `{{7*'7'}}` → `7777777`, Mako: `${'7'*7}`, ERB: `<%= '7'*7 %>`).
2. If no engine fingerprint matches, check response latency — sub-100ms suggests code SSTI (template engines are fast), >500ms suggests LLM evaluation.
3. Classify as: `CRITICAL` (confirmed engine), `CRITICAL` (fast, probable code SSTI), or `MEDIUM` (LLM-evaluated math).

**Tests:** Unit tests for classification logic and each engine fingerprint.

### N2 — Guardrail-Aware Scanning (`--guardrail-sweep`)

**Problem:** mcpnuke doesn't detect or iterate across configurable difficulty levels.

**Fix:** Add `--guardrail-sweep` flag that:
1. Probes common config endpoints (`/config`, `/api/config`, etc.)
2. Detects difficulty/guardrail settings
3. Runs the scan at each detected level
4. Produces a diff report showing which findings appear/disappear at each level

**Tests:** Integration test with mock server that returns different responses per difficulty.

### N3 — Fix Attack Chain JSON Structure

**Problem:** `attack_chains` array on `TargetResult` in JSON output is empty; chains exist only as findings with `check: "attack_chain"`.

**Fix:** Populate `TargetResult.attack_chains` as structured objects `{source_check, target_check, description}` in addition to the findings.

**Tests:** Assert JSON output has both `findings` with check `attack_chain` AND populated `attack_chains` array.

### N4 — Exit Code Semantics

**Problem:** Exit code 1 for both "findings found" and "scan error."

**Fix:** `0` = clean (no findings), `1` = findings found, `2` = scan error/crash. Update CLI entry point.

**Tests:** Test exit codes for clean scan, findings scan, and error scan.

### N5 — Optimize input_sanitization Performance

**Problem:** 226s for 25 tools — each tool fuzzed sequentially with many payloads.

**Fix:** Parallelize fuzzing within `check_input_sanitization` using the existing `probe_workers` thread pool. Add early-exit per tool once a confirmed vulnerability is found (no need to try remaining payloads). Target: <60s for 25 tools.

**Tests:** Verify parallel execution produces same findings as sequential. Benchmark test with timeout assertion.

## Execution Order

1. **mcpnuke N1, N3, N4** — Better reporting (no Camazotz changes needed to validate)
2. **Camazotz C1, C2, C3** — Bug fixes (rescan validates they're gone)
3. **mcpnuke N5** — Faster rescans for remaining validation
4. **Camazotz C4, C5** — New controls (rescan detects them)
5. **mcpnuke N2** — Guardrail sweep (validates C4 across levels)
6. **Both** — Full rescan, test suites green, docs + changelogs updated

## Deliverables

- All Camazotz tests pass (100% coverage maintained)
- All mcpnuke tests pass
- Both CHANGELOGs updated
- Both READMEs updated where applicable
- Final rescan shows reduced CRITICAL count and new detection capabilities
