# ADR 0001 — Five-Transport Taxonomy

**Status:** Accepted
**Date:** 2026-04-28
**Deciders:** ecosystem maintainers
**Affects:** `camazotz`, `nullfield`, `mcpnuke`, `agentic-sec`

---

## Context

The Identity Flow Framework, defined in
[`agentic-sec/docs/identity-flows.md`](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md),
classifies every component in the ecosystem along two axes:

- **Lane** (1–5): who is the *initiator* of the request — Human Direct,
  Delegated, Machine, Agent-Chain, Anonymous.
- **Transport** (A/B/C as of 2026-04-26): the wire / process surface
  carrying the call — MCP JSON-RPC, Direct API, SDK / In-process.

The lane axis is identity-first and transport-agnostic, well-grounded in
OAuth/SPIFFE/OIDC. It works.

The transport axis, as originally defined, has two problems surfaced
during the 2026-04-28 walkthrough work:

1. **MCP-centric framing bleeding through.** The canonical doc literally
   describes Transport A as *"the protocol our ecosystem is built
   around"* and Transport B as *"the resources MCP servers themselves
   call."* This implicitly treats MCP as the spine of every agent
   deployment, which is not true of real-world agents built directly on
   OpenAI tools, Anthropic `tool_use`, or LangChain dispatch.
2. **Transport C is overloaded.** It currently lumps together three
   materially different identity envelopes:
   - true in-process (Python imports, function calls in the same address
     space — what `sdk_tamper_lab` models)
   - subprocess execution (agent spawns `kubectl`/`terraform` as a
     child process; credentials cross the fork boundary)
   - native LLM function-calling (round-trip through a third-party
     provider's API; no MCP wire involved)

   These have distinct attack surfaces. Conflating them obscures the
   exact threats the framework is meant to make legible.

## Decision

**Extend the transport dimension from three codes to five.** The
existing codes A, B, C remain unchanged in semantics. Two new codes are
added:

| Code | Name                                  | Status              |
|------|---------------------------------------|---------------------|
| A    | MCP JSON-RPC                          | Stable since 2026-04-26 |
| B    | Direct wire API (REST/gRPC/GraphQL)   | Stable since 2026-04-26 |
| C    | In-process SDK / library              | Stable since 2026-04-26 |
| **D** | **Subprocess / native binary**       | **New 2026-04-28**     |
| **E** | **Native LLM function-calling (non-MCP)** | **New 2026-04-28**     |

The taxonomy is registered in
[`camazotz/frontend/lane_taxonomy.py`](../../frontend/lane_taxonomy.py)
as `TRANSPORT_DEFINITIONS`, with each entry naming the identity envelope,
threat surface, and applicable RFCs / specs. The transport codes are
exposed via `GET /api/lanes` and consumed by `nullfield` policy labels
(`nullfield.io/transport`) and `mcpnuke` finding fields.

## Rejected alternatives

1. **Keep three transports, rewrite the language to be MCP-agnostic.**
   Cleaner doc surface but doesn't address the underlying conflation in
   Transport C. The threats are different; the codes should be too.
2. **Rotate Transport C to mean "non-MCP function-calling," add D for
   subprocess, E for in-process.** Cleaner final taxonomy but requires
   re-tagging the existing labs already deployed to the reference NUC
   (`sdk_tamper_lab`, `supply_lab`) and the corresponding `nullfield`
   policy labels and `mcpnuke` finding fields. Migration cost not
   justified by semantic improvement.
3. **Explode to ten or more transports** to capture every wire format
   (HTTP, gRPC, WebSocket, WASM, A2A, etc.). Rejected — utility of the
   matrix degrades sharply past 5×5. The differentiator is *identity
   envelope*, not wire bytes; many wire formats share an envelope.
4. **Add a third dimension** (e.g., process topology). Rejected for the
   same reason — explodes the matrix without clear marginal value.

## Consequences

### Required (this ADR)

- `camazotz/frontend/lane_taxonomy.py` — `TRANSPORTS` extended,
  `TRANSPORT_DEFINITIONS` registry added, `discover_lab_metadata`
  validates against the registry, `coverage_summary` treats D and E as
  *opportunistic* (only flagged as gaps when at least one lab on
  another lane already uses them, to avoid noise on deployments that
  don't exercise those surfaces).
- `camazotz/tests/test_lane_taxonomy.py` — new test coverage.
- `camazotz/docs/adr/0001-five-transport-taxonomy.md` — this record.

### Follow-up (next sessions)

- **Spike a `subprocess_lab`** (Lane 3, Transport D) to prove the
  Transport D bucket is non-degenerate. Cancel the rest of the rollout
  if a coherent lab cannot be written.
- **Spike a `function_calling_lab`** (Lane 2, Transport E) to prove
  the Transport E bucket is non-degenerate. Same cancellation criterion.
- **Update `agentic-sec/docs/identity-flows.md`** — rewrite the
  Transport Surfaces section, expand the Lane × Transport matrix from
  5×3 to 5×5, anchor each new transport against an identity envelope
  rather than a wire protocol. Wait until at least one of the spike
  labs has shipped.
- **Update `nullfield/policies/by-lane/README.md`** to note the new
  codes (no policy file changes needed; existing policies use A only).
- **Update `mcpnuke/mcpnuke/checks/_lane_helpers.py` docstring** to
  mention the new codes (no code change required; `lane_tagged()`
  already accepts any string).

### Non-consequences

- **No existing labs need re-tagging.** All current `transport: "C"`
  declarations remain semantically correct under the narrowed C
  ("in-process SDK / library") definition.
- **No existing nullfield policies break.** Transport is a label,
  not an enforcement key.
- **No existing mcpnuke findings break.** Transport is a metadata
  field on `Finding`, not a check selector.
- **The five lanes are unchanged.** This ADR addresses transport only.

## Validation

- `uv run pytest tests/test_lane_taxonomy.py -v` — all transport
  registry, lookup, validation, and gap-detection tests pass.
- `uv run pytest -q --no-cov` — full suite passes (no regressions).
- The existing `test_migration_transport_distribution_hits_a_b_c` test
  was relaxed from `==` to `>=` (subset check) and additionally asserts
  that no unknown transport codes appear in the corpus.

## References

- [Identity Flow Framework](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md)
  — the canonical taxonomy doc that this ADR amends.
- [`lane_taxonomy.py`](../../frontend/lane_taxonomy.py) — the
  source-of-truth implementation of lanes and transports.
- [Flow Types in Practice](https://github.com/babywyrm/agentic-sec/blob/main/docs/walkthroughs/flow-types-in-practice.md)
  — the walkthrough that surfaced the gap.
- [`sdk_tamper_lab`](../../camazotz_modules/sdk_tamper_lab/) —
  the first lab in the narrowed Transport C bucket; precedent for the
  in-process-only definition.
