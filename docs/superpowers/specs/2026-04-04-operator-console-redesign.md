# Operator Console Redesign — Guided Walkthrough + QA Dashboard

**Date:** 2026-04-04
**Status:** Approved design, pending implementation

## Goal

Rebuild the Operator Console (`/operator`) into two modes:

1. **Guided Walkthrough** — step-by-step exploit demonstrations for all 25 labs at medium guardrails. Users pick one lab, watch or step through the attack, and learn what each MCP tool call does and why it's vulnerable.
2. **QA Dashboard** — fast pass/fail validation grid (existing functionality, with UX fixes).

## Audience

Security practitioners who understand the concepts but need to see a specific exploit demonstrated. Newcomers can also follow — narration is tight but includes enough context.

## Constraints

- Hidden from main nav; accessible only via `/operator` direct URL.
- Phase 1 covers all 25 labs at medium guardrails only.
- No E2E browser tests (Playwright/Selenium) in Phase 1.

---

## Page Structure

Single `/operator` page with two tabs. Tab state persists via URL hash (`#walkthrough` / `#qa`).

### Tab 1 — Walkthrough (default)

Two views within this tab:

**Lab Picker view:**

- Card grid (3-4 columns responsive). Each card shows:
  - Threat ID badge (e.g. `MCP-T04`)
  - Lab title (from `scenario.yaml`)
  - One-line description
- 25 cards total, sorted by threat ID.
- Click a card to enter that lab's walkthrough player.

**Player view (after selecting a lab):**

- Header bar: back arrow, lab title, threat ID, "Medium Guardrails" badge.
- Control bar: Play / Pause / Step / Reset. Step counter ("Step 3 of 7").
- Step list rendered incrementally:
  - **Not yet run:** collapsed, greyed, showing step number + title only.
  - **Current step:** highlighted border, narrative visible, request/response loading.
  - **Completed:** narrative visible, green checkmark, "Show JSON" toggle for request/response.
  - **Failed:** red indicator, error visible, JSON expanded by default.
- After each step completes, an **insight callout** (amber/yellow) shows the security takeaway.
- Auto-play: executes steps with ~2s pause between each. Pause stops the loop. Step advances one. Reset clears and returns to step 0.

### Tab 2 — QA Dashboard

Existing operator console functionality with UX fixes:

- Fix broken `<select multiple size="1">` — replace with proper dropdown pattern.
- Keep grid, progress bar, summary stats, Copy JSON.
- No structural changes beyond polish.

---

## Data Model

### WalkthroughStep

```python
@dataclass
class WalkthroughStep:
    title: str        # e.g. "Issue a token as user A"
    narrative: str    # 2-3 sentence explanation
    tool: str         # MCP tool name, e.g. "auth.issue_token"
    arguments: dict   # arguments dict for the tool call
    check: str | None # optional response key to inspect
    insight: str      # security takeaway for this step
```

### Walkthrough registry

New file: `scripts/qa_runner/walkthroughs.py`

```python
WALKTHROUGHS: dict[str, list[WalkthroughStep]] = {
    "auth_lab": [ ... ],
    "context_lab": [ ... ],
    # ... all 25 labs
}
```

Each lab has 2+ steps. Every step's `tool` field must reference a tool that exists in the gateway's tool registry.

---

## API Endpoints

### `GET /api/operator/walkthrough/labs`

Returns metadata for the lab picker.

Response:

```json
[
  {
    "lab": "auth_lab",
    "threat_id": "MCP-T04",
    "title": "Confused Deputy / Token Theft",
    "description": "...",
    "step_count": 4
  }
]
```

### `POST /api/operator/walkthrough/step`

Executes a single walkthrough step against the live gateway.

Request:

```json
{"lab": "auth_lab", "step": 0}
```

Step 0 also sets guardrail to medium and resets state. Each subsequent step just executes the tool call.

Response:

```json
{
  "lab": "auth_lab",
  "step": 0,
  "total_steps": 4,
  "title": "Issue a token as user A",
  "narrative": "We request an authentication token...",
  "insight": "The token is issued without binding...",
  "request": {
    "method": "tools/call",
    "params": {
      "name": "auth.issue_token",
      "arguments": {"user": "alice"}
    }
  },
  "response": { "...raw gateway response..." },
  "status": "complete"
}
```

Error responses: 400 for invalid lab name or out-of-range step index.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Gateway unreachable | Banner: "Gateway unreachable at [URL]." + Retry button |
| Mid-walkthrough step failure | Auto-play pauses. Failed step shows error. User can retry or skip. |
| Unexpected response shape | Step marked "completed with warning" (amber). Exploit may have worked; response phrasing varied. |
| Timeout (30s per step) | Step marked failed: "Step timed out — gateway may be under load." |

### Guardrail state management

- Enter walkthrough player: `PUT /config {"difficulty": "medium"}` + `POST /reset`
- Exit player (back to picker or tab switch): `POST /reset`
- Browser refresh mid-walkthrough: player resets to step 0 (no server-side session)

---

## Files Changed / Added

| File | Change |
|------|--------|
| `scripts/qa_runner/walkthroughs.py` | **New.** `WalkthroughStep` dataclass + `WALKTHROUGHS` dict for all 25 labs. |
| `scripts/qa_runner/__init__.py` | Export walkthrough types and registry. |
| `frontend/app.py` | Add `/api/operator/walkthrough/labs` and `/api/operator/walkthrough/step` routes. Update `/operator` to pass walkthrough lab metadata to template. |
| `frontend/templates/operator.html` | Redesign: add tab structure, walkthrough tab (lab picker + player), fix QA dashboard UX. |
| `tests/test_operator.py` | Extend: walkthrough metadata validation, step endpoint shape, all 25 labs have valid definitions, tab rendering assertions. |

No changes to `base.html` nav (operator stays hidden).

---

## Testing Strategy

**Backend unit tests (extend `tests/test_operator.py`):**

- Every lab in `WALKTHROUGHS` has >= 2 steps with all fields populated.
- Every step's `tool` references a valid tool name from the registry.
- `/api/operator/walkthrough/labs` returns 25 entries with correct shape.
- `/api/operator/walkthrough/step` returns correct shape, sets guardrail, handles invalid lab/step with 400.

**Frontend template tests:**

- Operator page renders both tabs.
- Walkthrough tab contains 25 lab entries.
- QA Dashboard tab renders grid controls.
- No `href="/operator"` in main nav.

**Manual integration:**

- `make smoke-k8s-llm` passes after changes.
- Run one walkthrough end-to-end on NUC to confirm real Claude responses.

**Explicitly out of scope for Phase 1:**

- No Playwright/Selenium E2E browser tests.
- No walkthrough step coverage metrics (we verify structure, not specific LLM response text).

---

## Labs Covered (all 25)

| # | Lab | Threat ID |
|---|-----|-----------|
| 1 | context_lab | MCP-T01 |
| 2 | indirect_lab | MCP-T02 |
| 3 | tool_lab | MCP-T03 |
| 4 | auth_lab | MCP-T04 |
| 5 | relay_lab | MCP-T05 |
| 6 | egress_lab | MCP-T06 |
| 7 | secrets_lab | MCP-T07 |
| 8 | supply_lab | MCP-T08 |
| 9 | config_lab | MCP-T09 |
| 10 | hallucination_lab | MCP-T10 |
| 11 | tenant_lab | MCP-T11 |
| 12 | comms_lab | MCP-T12 |
| 13 | audit_lab | MCP-T13 |
| 14 | shadow_lab | MCP-T14 |
| 15 | error_lab | MCP-T15 |
| 16 | temporal_lab | MCP-T16 |
| 17 | notification_lab | MCP-T17 |
| 18 | rbac_lab | MCP-T20 |
| 19 | oauth_delegation_lab | MCP-T21 |
| 20 | attribution_lab | MCP-T22 |
| 21 | credential_broker_lab | MCP-T23 |
| 22 | pattern_downgrade_lab | MCP-T24 |
| 23 | delegation_chain_lab | MCP-T25 |
| 24 | revocation_lab | MCP-T26 |
| 25 | cost_exhaustion_lab | MCP-T27 |
