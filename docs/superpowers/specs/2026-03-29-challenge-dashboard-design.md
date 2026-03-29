# Camazotz Challenge Dashboard + 14/14 Playbook Coverage

**Date:** 2026-03-29
**Status:** Approved
**Scope:** Dashboard UX, scenario metadata, canary flags, 5 new lab modules

---

## Goal

Transform Camazotz from a collection of MCP tools into a PortSwigger-style
training platform. Single dashboard presents all scenarios with descriptions,
difficulty, hints, and canary-based validation. Fill remaining playbook gaps
to reach 14/14 MCP Red Team Playbook coverage. Everything self-contained —
no outbound dependencies beyond OSS engine requirements (Ollama for local LLM).

## Constraints

- Additive only — existing modules, tests, portal pages, Helm, compose untouched
- Every commit independently deployable, tests included
- 100% coverage gate continues to apply
- No user accounts or server-side state for solve tracking (localStorage)
- Air-gap friendly — works fully offline with Ollama
- Serves dual purpose: user training platform + mcpnuke test range

---

## Section 1: Scenario Metadata Contract

### LabModule Base Extension

Add optional fields with defaults so existing modules require zero changes:

```python
class LabModule:
    name: str
    threat_id: str
    # New fields — all have defaults
    title: str = ""
    difficulty: str = "easy"       # easy | medium | hard
    category: str = ""             # injection, auth, ssrf, exfil, persistence, etc.
    canary_prefix: str = ""        # prefix for generated flag
```

### Companion Scenario Files

Each module gets a `scenario.yaml` alongside its `app/main.py`:

```
camazotz_modules/
  egress_lab/
    app/main.py
    scenario.yaml          # NEW
```

Schema:

```yaml
title: "SSRF via Tool"
threat_id: MCP-T06
difficulty: medium
category: ssrf
owasp_mcp: MCP06
description: >
  One-paragraph description of the vulnerability and what makes it interesting.
objectives:
  - "First exploitation goal"
  - "Second exploitation goal"
  - "Extract the canary flag"
hints:
  - "Progressive hint 1 (least helpful)"
  - "Progressive hint 2"
  - "Progressive hint 3 (most explicit)"
canary_location: "Where/how the flag is exposed through the exploit"
tools:
  - "egress.fetch_url"
references:
  - url: "https://example.com/relevant-resource"
    label: "Background reading"
```

The schema is open-ended — new fields can be added without breaking existing
scenario files. Unknown fields are ignored by the loader.

### Tests

- Validate all `scenario.yaml` files parse correctly
- Validate every module with a `threat_id` has a companion `scenario.yaml`
- Schema validation (required fields present, difficulty enum valid)

### Commit Checkpoint 1

`LabModule` base extension + `scenario.yaml` for all 10 existing modules +
schema validation tests.

---

## Section 2: ScenarioLoader

A registry-aware component that merges `LabModule` metadata with companion
YAML content at startup.

```python
class ScenarioLoader:
    """Load and merge scenario metadata from modules + YAML files."""

    def load_all(self, registry: LabRegistry) -> list[Scenario]
    def get(self, threat_id: str) -> Scenario | None
    def by_category(self, category: str) -> list[Scenario]
    def by_difficulty(self, difficulty: str) -> list[Scenario]
```

`Scenario` is a Pydantic model combining module fields + YAML content.

Loaded once at gateway startup. Available to the portal via the existing
gateway proxy pattern or a new `/api/scenarios` JSON endpoint.

### Tests

- Loader discovers all modules
- Loader merges module metadata with YAML correctly
- Missing YAML falls back gracefully (module-only metadata)
- Filter by category/difficulty works

### Commit Checkpoint 2

Can be rolled into Checkpoint 1 if the diff is small.

---

## Section 3: Challenge Dashboard (Flask Blueprint)

New blueprint registered on the existing portal. Current pages untouched.

### Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/challenges` | GET | Grid of scenario cards |
| `/challenges/<threat_id>` | GET | Individual challenge page |
| `/challenges/<threat_id>/verify` | POST | Check canary submission |
| `/api/scenarios` | GET | JSON metadata (for tooling/mcpnuke) |

### Dashboard Grid (`/challenges`)

- Card per scenario: title, threat_id badge, difficulty badge (green/amber/red),
  category tag, 1-line description
- Filter/sort by difficulty, category, solved/unsolved
- Solved state from browser localStorage
- Matches existing Camazotz dark theme from `base.html`

### Challenge Page (`/challenges/<threat_id>`)

- Full description and learning objectives
- MCP endpoint info + example curl commands
- Hint accordion — progressive reveal (click to show next hint)
- Canary submission field + verify button
- "Solved" banner when canary matches
- Link to relevant tools in the existing playground

### Verify Endpoint (`/challenges/<threat_id>/verify`)

- POST with `{"canary": "CZTZ{...}"}`
- Checks against in-memory flag store
- Returns `{"solved": true/false}`
- On success, sets a response header hint to persist in localStorage

### `/api/scenarios`

- Returns full scenario list as JSON
- Useful for mcpnuke integration and external tooling
- No auth required

### Tests

- All routes return 200
- Verify endpoint accepts correct canary, rejects wrong ones
- Grid renders all scenarios
- Challenge page renders hints, objectives, description
- API endpoint returns valid JSON with expected schema

### Commit Checkpoint 3

Dashboard blueprint + templates + tests. Working with existing 10 scenarios.

---

## Section 4: Canary Flag System

### Generation

On gateway startup:
1. For each registered scenario, generate: `CZTZ{<threat_id>_<random_hex_8>}`
   (e.g. `CZTZ{T06_a3f7c012}`)
2. Write to `/opt/camazotz/flags/<threat_id>.txt` in the container
3. Store in-memory in the ScenarioLoader for verify endpoint lookups

### Per-module wiring

Each module references its canary however makes sense for the exploit:

| Module | How canary is exposed |
|--------|----------------------|
| secrets_lab (T07) | Returned in config dump |
| egress_lab (T06) | Readable via `file:///opt/camazotz/flags/T06.txt` |
| auth_lab (T04) | Returned when accessing service-b with replayed token |
| context_lab (T01) | Embedded in injectable summary response |
| shadow_lab (T14) | Delivered via webhook callback payload |
| relay_lab (T05) | Stored in poisoned context, leaked through execute |
| comms_lab (T12) | Appears in exfiltrated message |
| supply_lab (T08) | Returned after malicious package install |
| tool_lab (T03) | Returned by hidden_exec after rug-pull triggers |

### Reset

Existing `/reset` endpoint regenerates all flags and replants them.

### Tests

- Flags generated with correct format
- Flags written to filesystem
- Verify endpoint validates correctly
- Reset regenerates different flags

### Commit Checkpoint 4

Can be rolled into Checkpoint 3 (dashboard + canaries together) since
the verify endpoint needs canaries to function.

---

## Section 5: New Lab Modules

Five new modules to fill playbook gaps. Each follows existing `LabModule`
pattern, includes `scenario.yaml`, and ships with tests.

### 5a. indirect_lab — Indirect Prompt Injection (T02)

**Tools:**
- `indirect.fetch_and_summarize(url)` — fetches URL content, passes to LLM
  for summarization. Attacker plants injection payload in the fetched page.

**Mechanic:** The LLM processes attacker-controlled external content that
overrides the summarization task. Canary is exposed when the injection
succeeds (LLM follows embedded instructions instead of summarizing).

**Difficulty:** medium

### 5b. config_lab — Agent Config Tampering (T09)

**Tools:**
- `config.read_system_prompt()` — returns the brain's current system prompt
- `config.update_system_prompt(prompt)` — modifies the system prompt

**Mechanic:** Attacker reads the system prompt, modifies it to remove safety
constraints, then exploits the weakened LLM on subsequent calls. Canary
is returned when the LLM operates under the tampered prompt.

**Difficulty:** easy

### 5c. hallucination_lab — Hallucination-Driven Destruction (T10)

**Tools:**
- `hallucination.execute_plan(description)` — LLM generates an action plan
  from ambiguous natural language, then executes it against a simulated
  environment (in-memory filesystem). Canary exposed when the LLM
  confidently picks the wrong destructive action (e.g., deletes production
  data instead of staging).

**Mechanic:** Ambiguous input triggers LLM hallucination. The simulated
environment has a "production" and "staging" dataset — canary is in the
production dataset that should not be touched.

**Difficulty:** hard

### 5d. tenant_lab — Cross-Tenant Memory Leak (T11)

**Tools:**
- `tenant.store_memory(tenant_id, key, value)` — store data scoped to a tenant
- `tenant.recall_memory(tenant_id, key)` — recall data for a tenant

**Mechanic:** The `tenant_id` parameter is not validated against the caller's
identity. Attacker stores data as tenant "alice", then reads it back as
tenant "bob" — or reads pre-seeded data from other tenants. Canary is
pre-seeded in another tenant's memory.

**Difficulty:** easy

### 5e. audit_lab — Audit Log Evasion (T13)

**Tools:**
- `audit.perform_action(action, target)` — performs an action, logs it
- `audit.list_actions(filter?)` — returns the audit log

**Mechanic:** All actions are logged under the agent's service account
identity, not the requesting user. Attacker performs privileged actions
that appear in the audit log as "system" — no attribution to the actual
caller. Canary is exposed when you identify the evasion (flag is the
service account name used in attribution).

**Difficulty:** medium

### Tests per module

- Tool registration and listing
- Happy-path exploitation (canary reachable through intended path)
- Edge cases (empty input, invalid params)
- Integration with ScenarioLoader and dashboard

### Commit Checkpoints 5-9

One commit per module. Can be rolled together in pairs if the diffs are
small, but each module should be independently testable.

---

## Section 6: Documentation Updates

- README: Update playbook table to 14/14, add dashboard section, update
  tool count and architecture diagram
- scenarios.md: Add entries for all 5 new modules
- CHANGELOG: New version entry with all changes
- module-authoring.md: Document `scenario.yaml` schema and canary system

### Commit Checkpoint 10

Docs update. Can be rolled into the final module commit.

---

## Consolidated Commit Plan

Commits can be rolled together where noted. Minimum viable sequence:

| # | Scope | Rollable With |
|---|-------|---------------|
| 1 | Metadata contract + scenario.yaml for existing 10 modules | 2 |
| 2 | ScenarioLoader | 1 |
| 3 | Dashboard blueprint + canary system | 4 |
| 4 | Canary flag wiring for existing modules | 3 |
| 5 | T02 indirect_lab | — |
| 6 | T09 config_lab | 5 |
| 7 | T10 hallucination_lab | — |
| 8 | T11 tenant_lab | 9 |
| 9 | T13 audit_lab | 8 |
| 10 | Docs + README | 9 |

Practical minimum: **~5-6 commits** if pairs are rolled together.

---

## Testing Strategy

- Every commit includes tests for its scope
- 100% coverage gate remains enforced
- New modules follow existing test patterns (see `tests/`)
- Dashboard routes get integration tests (Flask test client)
- Canary system gets unit tests (generation, verification, reset)
- ScenarioLoader gets unit tests (merging, filtering, missing YAML fallback)
- Final mcpnuke scan against the complete platform validates all 14 scenarios

---

## Roadmap (Future — Not This Iteration)

- Behavioral validation (observer detects exploit patterns automatically)
- Per-session difficulty wiring
- Multi-player scoring / leaderboard
- More LLM providers beyond Claude + Ollama
- mcpnuke CI integration (scan on every PR)
- Contributor scenario submission workflow
