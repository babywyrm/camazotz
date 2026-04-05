# Observer Telemetry Redesign

**Date:** 2026-04-04
**Status:** Approved design, pending implementation

## Goal

Transform the observer from a single-event-only audit stub into a rich telemetry view that shows what happens inside the Camazotz engine when exploits run. Two modes (Vulnerable / Enhanced) preserve the MCP08 teaching point while providing real security operations value. A compact telemetry strip in the walkthrough player links the two experiences.

## Audience

Same as the operator console: security practitioners learning MCP exploitation, plus newcomers who can follow along. The observer becomes the "security camera footage" — where the disconnect between AI recommendations and tool behavior is visible in real data.

## Constraints

- In-memory ring buffer only (no database, no persistent storage).
- `OBSERVER_BUFFER_SIZE` env var: default `10`, max `200`. Values > 200 clamped; values < 1 default to 10.
- Backwards compatible: `GET /_observer/last-event` and the sidecar continue to work unchanged.
- No WebSocket/SSE streaming (polling at 3s intervals is sufficient).
- 100% test coverage maintained.

---

## Enriched Event Data Model

Each event recorded by the observer:

```python
{
    "request_id": "uuid-v4",
    "timestamp": "iso-8601",
    "tool_name": "auth.issue_token",
    "module": "AuthLabModule",
    "guardrail": "medium",
    "arguments": {"username": "attacker", "requested_role": "admin"},
    "outcome": "granted",
    "ai_analysis": "Request appears suspicious...",
    "verdict": "ai_denied_tool_allowed",
    "duration_ms": 4200,
    "response_summary": {"token": "cztz-...", "_difficulty": "medium"},
    "canary_exposed": false,
}
```

### Field definitions

| Field | Source | Description |
|-------|--------|-------------|
| `request_id` | Generated | UUID v4, unique per event |
| `timestamp` | Generated | ISO-8601 UTC |
| `tool_name` | From MCP handler | The MCP tool that was called |
| `module` | From registry | Which lab module handled the call |
| `guardrail` | From app config | Current guardrail level (easy/medium/hard) |
| `arguments` | From MCP request | The arguments passed to the tool (as-is) |
| `outcome` | Derived from result | Short label: `granted`, `denied`, `leaked`, `executed`, `blocked`, `error`, `unknown` |
| `ai_analysis` | From `result.get("ai_analysis")` | LLM recommendation text, trimmed to 200 chars |
| `verdict` | Derived | `ai_agreed` (LLM + tool aligned), `ai_denied_tool_allowed` (LLM said no, tool said yes), `ai_irrelevant` (no LLM involvement) |
| `duration_ms` | Timed in handler | Wall-clock ms for the tool call |
| `response_summary` | Derived from result | Top-level keys with values truncated to 100 chars each |
| `canary_exposed` | Derived | `true` if response text contains `CZTZ{` pattern |

### Verdict derivation logic

- If `ai_analysis` contains deny/reject/refuse language AND the tool returned a successful result (e.g. `registered: true`, `token` present, `executed` present): `ai_denied_tool_allowed`
- If `ai_analysis` contains approve/allow language and result is successful: `ai_agreed`
- If no `ai_analysis` in result (pure logic labs like tenant, audit): `ai_irrelevant`

### Outcome derivation logic

Inspect the result dict for common response keys:
- `registered: true`, `token` present, `approved: true`, `executed: true`, `allowed: true`, `found: true` -> `granted` or `executed`
- `registered: false`, `denied: true`, `blocked: true`, `allowed: false` -> `denied` or `blocked`
- `_redacted: false` with sensitive keys present -> `leaked`
- `_error` present -> `error`
- Fallback: `unknown`

---

## Backend Changes

### `brain_gateway/app/observer.py`

Expand from single-event store to ring buffer with enrichment.

- `collections.deque(maxlen=buffer_size)` for thread-safe ring buffer
- `OBSERVER_BUFFER_SIZE` read from env, clamped to [1, 200], default 10
- `record_event(tool_name, module, guardrail, arguments, result, ai_analysis, duration_ms)` — enriches and appends to buffer, also updates `_last_event`
- `get_last_event()` — unchanged (backwards compatible)
- `get_events(limit=None)` — returns list of events, newest first, capped at limit or buffer size
- `get_events_since(request_id)` — returns events recorded after the event with the given request_id (for incremental polling)
- Internal helpers: `_derive_outcome(result)`, `_derive_verdict(ai_analysis, result)`, `_summarize_response(result)`, `_check_canary(result)`

### `brain_gateway/app/mcp_handlers.py`

Update the `tools/call` handler to pass enriched data:

- Time the `registry.call()` with `time.monotonic()`
- Read current guardrail from app config
- Extract `ai_analysis` from `result.get("ai_analysis", "")`
- Call `record_event(tool_name=name, module=module_name, guardrail=difficulty, arguments=arguments, result=result, ai_analysis=ai_analysis, duration_ms=elapsed)`

### `brain_gateway/app/main.py`

Add new endpoint:

```
GET /_observer/events?limit=50&since=<request_id>
```

- `limit`: max events to return (clamped to buffer size)
- `since`: return only events after this request_id (optional)
- Response: `{"events": [...], "buffer_size": 10, "total_recorded": 47}`
- The frontend decides which tab (Vulnerable / Enhanced) to display; the API just serves the data and buffer config.

Existing `GET /_observer/last-event` unchanged.

---

## Frontend — Observer Page Redesign

### Tab 1 — Vulnerable (default)

- Shows the last N events from `/_observer/events?limit=N` (where N = buffer_size)
- Simple list: timestamp, tool name, module — minimal columns
- MCP08 warning box preserved: explains why this view is weak, what a real deployment needs
- Auto-refresh toggle (3s poll)
- Teaching point: "This is what most deployments actually have"

### Tab 2 — Enhanced

- Full event timeline from `/_observer/events`
- Each event row: timestamp, tool name, guardrail badge, outcome badge (color-coded), verdict label
- **Verdict highlighting:** events with `verdict == "ai_denied_tool_allowed"` get a red left border and warning icon — these are the "LLM said no, tool said yes" moments
- Expand a row to see: arguments, AI analysis text, response summary, canary flag indicator
- Filter controls: by module, by guardrail level, by verdict type
- Auto-refresh toggle (3s poll)
- "Clear" button (calls `POST /reset`)

### Shared

- Tab state in URL hash (`#vulnerable` / `#enhanced`)
- Event count badge in tab headers

---

## Walkthrough Telemetry Strip

Compact inline panel in the operator console walkthrough player.

**Placement:** Below the step list, collapsible.

**Collapsed (default):** Single-line summary — "3 events | 2 verdicts: ai_denied_tool_allowed"

**Expanded:** Compact event rows filtered to the current walkthrough session. Each row: timestamp, tool name, outcome badge, verdict. Click a row to highlight which walkthrough step triggered it.

**How it works:**
- Step 0: record watermark `request_id` from `/_observer/last-event`
- After each step: poll `/_observer/events?since=<watermark>` for new events
- Append incrementally as steps run
- On walkthrough reset: clear the strip

No new backend needed — uses `/_observer/events?since=` endpoint.

---

## Files Changed / Added

| File | Change |
|------|--------|
| `brain_gateway/app/observer.py` | **Major rewrite.** Ring buffer, enriched events, derivation helpers, `get_events()`, `get_events_since()`. |
| `brain_gateway/app/mcp_handlers.py` | **Modify.** Pass enriched data to `record_event()`, add timing. |
| `brain_gateway/app/main.py` | **Modify.** Add `GET /_observer/events` endpoint. |
| `frontend/app.py` | **Modify.** Add `/api/observer/events` proxy route, update `/observer` to pass buffer config. |
| `frontend/templates/observer.html` | **Major rewrite.** Two-tab layout, vulnerable + enhanced views, filters, verdict highlighting. |
| `frontend/templates/operator.html` | **Modify.** Add telemetry strip to walkthrough player. |
| `tests/test_observer_events.py` | **Extend.** Ring buffer, enrichment, new endpoint, verdict/outcome derivation. |
| `tests/test_observer_sidecar.py` | **No changes.** Backwards compatible. |
| `tests/test_operator.py` | **Extend.** Telemetry strip rendering assertions. |
| `deploy/helm/camazotz/values.yaml` | **Modify.** Add `observerBufferSize` config key. |
| `deploy/helm/camazotz/templates/configmap.yaml` | **Modify.** Add `OBSERVER_BUFFER_SIZE`. |
| `compose/.env.example` | **Modify.** Add `OBSERVER_BUFFER_SIZE=10`. |

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Buffer overflow | `deque(maxlen=N)` silently drops oldest — no errors |
| `OBSERVER_BUFFER_SIZE` > 200 | Clamped to 200 |
| `OBSERVER_BUFFER_SIZE` < 1 | Defaults to 10 |
| Malformed result in `record_event()` | Safe defaults: `outcome="unknown"`, `verdict="ai_irrelevant"` |
| `?limit=` > buffer size | Clamped to buffer size |
| `?since=<unknown_id>` | Returns full buffer |
| Empty buffer | Frontend shows "No telemetry yet" |
| Telemetry strip with no events | Collapsed, shows "No telemetry yet" |

---

## Testing Strategy

**Backend unit tests (extend `tests/test_observer_events.py`):**

- Ring buffer capacity and overflow behavior
- Event enrichment: outcome derivation for each label (granted, denied, leaked, blocked, error, unknown)
- Verdict derivation: ai_agreed, ai_denied_tool_allowed, ai_irrelevant
- Response summary truncation (values > 100 chars)
- Canary detection (`CZTZ{` pattern)
- `get_events()` ordering (newest first) and limit
- `get_events_since()` filtering
- Env var clamping (> 200, < 1, valid)
- Thread safety (concurrent record + read)
- `/_observer/events` endpoint: response shape, query params
- Backwards compatibility: `/_observer/last-event` still works

**Frontend template tests:**

- Observer page renders both tabs (Vulnerable / Enhanced)
- Enhanced tab has filter controls
- Vulnerable tab has MCP08 warning
- Operator page has telemetry strip in walkthrough player

**Integration:**

- Existing sidecar tests stay green
- Smoke tests pass on both targets
- Manual: run a walkthrough, check telemetry strip populates, open observer Enhanced tab and see same events

**Out of scope:**

- No WebSocket/SSE streaming
- No persistent storage
- No event export beyond JSON copy
- No Playwright/Selenium browser tests
