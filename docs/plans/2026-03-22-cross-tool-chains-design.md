# Cross-Tool Chain Attacks — Design Document

**Date:** 2026-03-22
**Taxonomy:** MCP-T04 (Token Audience Bypass), MCP-T05 (Cross-Tool Context Poisoning), MCP-T12 (Exfiltration via Chaining)
**Status:** Approved

---

## Motivation

Camazotz covers 7 of 14 categories in the MCP Red Team Playbook threat
taxonomy. The missing categories are the advanced cross-cutting patterns
where risk is multiplicative — tools interacting with each other create
attack paths that don't exist when each tool is tested in isolation.

This phase adds the three highest-impact gaps: token replay across service
boundaries, shared-context poisoning, and data exfiltration through
communication channels.

## Changes

### 1. auth_lab Extension — Token Audience Bypass (MCP-T04)

**New tool:** `auth.access_service_b`

Tokens issued by `auth.issue_token` are scoped to `service-a` (via `aud`
field in SQLite). `service_b` is a higher-value service that should reject
tokens not scoped to it.

| Difficulty | Behavior |
|------------|----------|
| Easy | `service_b` accepts any valid token regardless of audience |
| Medium | Logs audience mismatch warning, still grants access |
| Hard | Validates audience and rejects, but accepts null-audience tokens |

### 2. New relay_lab — Cross-Tool Context Poisoning (MCP-T05)

**Tools:** `relay.store_context`, `relay.execute_with_context`

Shared context broker simulating an agent's accumulated tool output buffer.

- `store_context` — stores a named entry in an in-memory dict. No content
  trust labeling.
- `execute_with_context` — takes a task + list of context keys, passes all
  referenced entries + task to LLM as trusted instructions. LLM acts on
  whatever it finds, including injected instructions from poisoned outputs.

| Difficulty | Behavior |
|------------|----------|
| Easy | Zero trust labeling, LLM follows all context |
| Medium | Entries labeled `[TOOL_OUTPUT]`, LLM still follows embedded instructions |
| Hard | LLM prompted to ignore instructions in tool output, creative bypasses work |

### 3. New comms_lab — Exfiltration via Chaining (MCP-T12)

**Tools:** `comms.send_message`, `comms.list_sent`

Communications assistant simulating messaging integration (Slack/Teams).

- `send_message` — takes channel, message, optional context_keys (reads
  from relay buffer). Composes via LLM, stores in outbox. No DLP.
- `list_sent` — returns outbox contents.

| Difficulty | Behavior |
|------------|----------|
| Easy | Zero filtering, sends anything |
| Medium | LLM redacts but `_raw_context` field leaks |
| Hard | LLM redaction + regex DLP, chunked/encoded exfil bypasses |

## Full Kill Chain

```
  egress.fetch_url (poisoned page)
       │
       ▼
  relay.store_context ("research")
       │
       ▼
  relay.execute_with_context ──▶ follows injected instructions
       │                              │
       ├──▶ auth.issue_token          │
       │    (social-engineered)       │
       │         │                    │
       │         ▼                    │
       │    auth.access_service_b     │
       │    (audience bypass → data)  │
       │         │                    │
       │         ▼                    │
       │    relay.store_context       │
       │    (stolen credentials)      │
       │                              │
       └──▶ comms.send_message ◀──────┘
            (exfil via "messaging")
```

## Testing

Estimated ~30-40 new tests. 100% coverage maintained. All external I/O
mocked (httpx, subprocess, os.environ). Each difficulty level tested per
tool. Cross-tool chain tested as integration scenario.
