"""Lane taxonomy for the Agentic Identity Lane View.

Parallel to ``frontend/threat_map.py``. Defines the five identity lanes from
the Identity Flow Framework (agentic-sec/docs/identity-flows.md) and
discovers which camazotz labs belong to which lane via the brain gateway's
/api/scenarios endpoint.

Slugs and lane IDs are the canonical vocabulary shared with nullfield
(per-lane policy templates) and mcpnuke (--by-lane reporting). Do not
rename without updating both sibling projects.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FlowStage:
    role: str
    token: str


@dataclass(frozen=True)
class LaneDefinition:
    id: int
    slug: str
    name: str
    blurb: str
    accent: str
    css_class: str
    rfcs: list[str]
    flow: list[FlowStage]
    default_nullfield_action: str
    identity_provider: str


LANES: list[LaneDefinition] = [
    LaneDefinition(
        id=1,
        slug="human-direct",
        name="Human Direct",
        blurb="A human authenticates directly to the resource. No agent in the path.",
        accent="#60a5fa",
        css_class="lane-human",
        rfcs=["RFC 6749", "RFC 7636", "RFC 9068", "RFC 9449"],
        flow=[
            FlowStage("Person", "OIDC + PKCE"),
            FlowStage("MCP Server", "verifies bearer"),
            FlowStage("Resource", "audit by sub"),
        ],
        default_nullfield_action="ALLOW + audit",
        identity_provider="ZITADEL",
    ),
    LaneDefinition(
        id=2,
        slug="delegated",
        name="Human \u2192 Agent",
        blurb="A human delegates to an agent, which calls MCP on the human's behalf with a down-scoped token.",
        accent="#a78bfa",
        css_class="lane-delegated",
        rfcs=["RFC 8693", "RFC 8707", "RFC 9449"],
        flow=[
            FlowStage("Person", "OIDC"),
            FlowStage("Agent", "token-exchange (act)"),
            FlowStage("MCP Server", "audience-scoped"),
            FlowStage("Resource", "audit by sub + act"),
        ],
        default_nullfield_action="SCOPE + audit",
        identity_provider="ZITADEL",
    ),
    LaneDefinition(
        id=3,
        slug="machine",
        name="Machine Identity",
        blurb="A non-human principal (bot, CI job, daemon) authenticates with a machine credential.",
        accent="#34d399",
        css_class="lane-machine",
        rfcs=["SPIFFE", "X.509", "RFC 7521"],
        flow=[
            FlowStage("Bot / CI", "SPIFFE / X.509"),
            FlowStage("Agent", "short-lived cert"),
            FlowStage("MCP Server", "mTLS"),
            FlowStage("Resource", "audit by workload id"),
        ],
        default_nullfield_action="SCOPE + audit",
        identity_provider="Teleport",
    ),
    LaneDefinition(
        id=4,
        slug="chain",
        name="Agent \u2192 Agent",
        blurb="Multi-hop delegation. Agent A calls Agent B calls Agent C. Identity dilutes at each hop unless act chain is enforced.",
        accent="#fb923c",
        css_class="lane-chain",
        rfcs=["RFC 8693"],
        flow=[
            FlowStage("Person", "OIDC"),
            FlowStage("Agent A", "act depth 1"),
            FlowStage("Agent B", "act depth 2"),
            FlowStage("Agent C", "act depth 3"),
            FlowStage("MCP Server", "chain-validated"),
        ],
        default_nullfield_action="HOLD + require-act-chain",
        identity_provider="ZITADEL",
    ),
    LaneDefinition(
        id=5,
        slug="anonymous",
        name="Anonymous",
        blurb="No authenticated principal. Public discovery endpoints, health checks, and read-only metadata.",
        accent="#94a3b8",
        css_class="lane-anonymous",
        rfcs=["RFC 8414"],
        flow=[
            FlowStage("Discovery / Healthz", ""),
            FlowStage("Public Read", ""),
        ],
        default_nullfield_action="DENY (allowlist only)",
        identity_provider="n/a",
    ),
]


_LANE_BY_ID: dict[int, LaneDefinition] = {lane.id: lane for lane in LANES}
VALID_LANE_IDS: frozenset[int] = frozenset(_LANE_BY_ID)


def get_lane(lane_id: int) -> LaneDefinition:
    """Return the LaneDefinition for the given id; raises ValueError if unknown."""
    try:
        return _LANE_BY_ID[lane_id]
    except KeyError as exc:
        raise ValueError(
            f"Unknown lane id: {lane_id!r} (valid: {sorted(VALID_LANE_IDS)})"
        ) from exc


@dataclass(frozen=True)
class LabMetadata:
    module_name: str
    threat_id: str
    title: str
    description: str
    difficulty: str
    primary_lane: int
    secondary_lanes: list[int] = field(default_factory=list)
    transport: str = ""
    blurb: str = ""


def _fetch_scenarios() -> list[dict]:
    """Fetch scenario metadata from the brain gateway. Returns [] on error."""
    gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8080")
    try:
        resp = httpx.get(f"{gateway_url}/api/scenarios", timeout=10.0)
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, list):
            return payload
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("lane_taxonomy: failed to fetch scenarios from gateway: %s", exc)
    return []


def discover_lab_metadata() -> dict[str, LabMetadata]:
    """Pull scenario metadata from the gateway and extract per-lab lane info.

    Labs without an ``agentic`` block (or empty block) are silently skipped.
    Invalid ``primary_lane`` or ``secondary_lanes`` values raise ValueError so
    that bad metadata is caught at first render rather than silently hiding a
    lab.
    """
    index: dict[str, LabMetadata] = {}
    for entry in _fetch_scenarios():
        agentic = entry.get("agentic") or {}
        if not agentic:
            continue

        module_name = entry.get("module_name", "")
        primary = agentic.get("primary_lane")
        if primary not in VALID_LANE_IDS:
            raise ValueError(
                f"{module_name}: invalid primary_lane {primary!r} "
                f"(valid: {sorted(VALID_LANE_IDS)})"
            )

        secondaries = agentic.get("secondary_lanes") or []
        for sec in secondaries:
            if sec not in VALID_LANE_IDS:
                raise ValueError(
                    f"{module_name}: invalid secondary_lanes entry {sec!r} "
                    f"(valid: {sorted(VALID_LANE_IDS)})"
                )
        if primary in secondaries:
            raise ValueError(
                f"{module_name}: primary_lane {primary} must not appear in secondary_lanes"
            )

        transport = agentic.get("transport", "")
        if transport and transport not in _TRANSPORT_BY_CODE:
            raise ValueError(
                f"{module_name}: invalid transport {transport!r} "
                f"(valid: {sorted(_TRANSPORT_BY_CODE)})"
            )

        index[module_name] = LabMetadata(
            module_name=module_name,
            threat_id=entry.get("threat_id", ""),
            title=entry.get("title", module_name),
            description=entry.get("description", ""),
            difficulty=entry.get("difficulty", "medium"),
            primary_lane=primary,
            secondary_lanes=list(secondaries),
            transport=transport,
            blurb=agentic.get("blurb", ""),
        )
    return index


# --------------------------------------------------------------------------
# Transport taxonomy
# --------------------------------------------------------------------------
#
# Each transport is a *materially different identity envelope* — distinguished
# by what carries the credential at the wire / process boundary, not by the
# wire bytes per se.
#
# Codes A–C are stable (in production across camazotz, nullfield, mcpnuke as
# of 2026-04-26). Codes D and E were added on 2026-04-28 to address a real
# gap: not every agentic deployment routes through MCP, and "Transport C"
# was overloading three distinct identity envelopes (in-process libraries,
# subprocess execution, third-party function-calling APIs). See ADR
# docs/adr/0001-five-transport-taxonomy.md for the decision record.
#
# DO NOT rename or reorder. nullfield policy labels and mcpnuke finding
# fields key off these codes. Add new transports only if a *new* identity
# envelope appears; do not split for fashion.


@dataclass(frozen=True)
class TransportDefinition:
    code: str
    name: str
    identity_envelope: str
    threat_surface: str
    rfcs_or_specs: list[str]


TRANSPORT_DEFINITIONS: list[TransportDefinition] = [
    TransportDefinition(
        code="A",
        name="MCP JSON-RPC",
        identity_envelope=(
            "Authorization bearer header + mcp-session-id; tool-call args are "
            "a secondary identity surface (LLM-controlled)."
        ),
        threat_surface=(
            "Bearer theft, session fixation, prompt-injected tool args, "
            "audience confusion at the MCP boundary."
        ),
        rfcs_or_specs=["MCP 2024-11-05", "RFC 6750", "RFC 9449"],
    ),
    TransportDefinition(
        code="B",
        name="Direct wire API (REST / gRPC / GraphQL)",
        identity_envelope=(
            "Whatever the upstream requires: bearer, IAM-signed request, "
            "mTLS, basic auth. No MCP layer."
        ),
        threat_surface=(
            "Identity laundering at hop, audience pinning failures, "
            "credential reuse across services."
        ),
        rfcs_or_specs=["RFC 6749", "RFC 8693", "RFC 8705", "RFC 9068"],
    ),
    TransportDefinition(
        code="C",
        name="In-process SDK / library",
        identity_envelope=(
            "Shared address space — Python imports, in-process function "
            "calls. Credentials live in process memory, env vars, or "
            "file-mounted secrets read at import time."
        ),
        threat_surface=(
            "SDK-level cache tampering, prompt-injected args bypassing "
            "downstream controls, in-memory secret exposure, no fresh "
            "credential boundary between caller and callee."
        ),
        rfcs_or_specs=["(no canonical RFC)"],
    ),
    TransportDefinition(
        code="D",
        name="Subprocess / native binary",
        identity_envelope=(
            "OS process tree — child process inherits parent's environment, "
            "file mounts, ServiceAccount tokens, and Unix credentials. "
            "Credentials cross the fork boundary, not the network."
        ),
        threat_surface=(
            "Argv injection, environment-variable credential leakage to "
            "child, privilege drift between parent and child, command "
            "substitution attacks, accidental cred reuse via env passthrough."
        ),
        rfcs_or_specs=["POSIX exec(3)", "Kubernetes projected SA tokens"],
    ),
    TransportDefinition(
        code="E",
        name="Native LLM function-calling (non-MCP)",
        identity_envelope=(
            "Third-party model provider's tool-use protocol (OpenAI tools, "
            "Anthropic tool_use, Gemini function-calling). Provider mediates "
            "the call; identity is implicit in the API key the agent uses "
            "to talk to the model provider."
        ),
        threat_surface=(
            "Provider trust boundary, prompt-injected tool args reflected "
            "back to local execution, model-provider data plane exposure, "
            "no standard for end-user identity propagation through the "
            "provider round-trip."
        ),
        rfcs_or_specs=[
            "OpenAI function calling (proprietary)",
            "Anthropic tool_use (proprietary)",
            "Gemini function-calling (proprietary)",
        ],
    ),
]


TRANSPORTS: tuple[str, ...] = tuple(t.code for t in TRANSPORT_DEFINITIONS)
_TRANSPORT_BY_CODE: dict[str, TransportDefinition] = {
    t.code: t for t in TRANSPORT_DEFINITIONS
}
VALID_TRANSPORT_CODES: frozenset[str] = frozenset(_TRANSPORT_BY_CODE)


def get_transport(code: str) -> TransportDefinition:
    """Return the TransportDefinition for the given code; raises ValueError if unknown."""
    try:
        return _TRANSPORT_BY_CODE[code]
    except KeyError as exc:
        raise ValueError(
            f"Unknown transport code: {code!r} (valid: {sorted(VALID_TRANSPORT_CODES)})"
        ) from exc


@dataclass(frozen=True)
class LaneCoverage:
    lane_id: int
    primary_count: int
    secondary_count: int
    transports_present: frozenset[str]
    gaps: list[str]


def coverage_summary(
    labs: dict[str, LabMetadata] | None = None,
) -> dict[int, LaneCoverage]:
    """For each lane, compute primary/secondary counts, transport coverage, gaps.

    If ``labs`` is None, discovery is performed. Pass an explicit map in tests
    that want deterministic input.

    Gap detection currently flags missing Transport A/B/C cells as the
    teaching baseline (these are the original three transports and every
    lane should aim for coverage across them). Transports D and E are
    *opportunistic* — flagged as gaps only when at least one lab on the
    lane already declares D or E (indicating the deployment exercises that
    surface). This avoids spurious "Transport D not covered" noise for
    lanes that have no D/E presence by design.
    """
    if labs is None:
        labs = discover_lab_metadata()

    baseline_transports = ("A", "B", "C")

    summary: dict[int, LaneCoverage] = {}
    for lane in LANES:
        primary = [m for m in labs.values() if m.primary_lane == lane.id]
        secondary = [m for m in labs.values() if lane.id in m.secondary_lanes]
        transports = frozenset(m.transport for m in primary if m.transport)

        gaps: list[str] = []
        if not primary:
            gaps.append("No primary labs yet")
        if lane.id != 5:  # Anonymous lane intentionally has no transport notion
            for t in baseline_transports:
                if t not in transports and primary:
                    gaps.append(f"Transport {t} not covered")
            # D and E: only flag if some lab on the lane already uses them
            # but coverage is incomplete (i.e. the deployment cares about
            # that surface but hasn't filled it).
            for t in ("D", "E"):
                if t in transports:
                    continue
                # Any other lane lab using D/E? Then this lane is missing it.
                any_other = any(
                    m.transport == t
                    for m in labs.values()
                    if m.primary_lane != lane.id
                )
                if any_other and primary:
                    gaps.append(f"Transport {t} not covered")

        summary[lane.id] = LaneCoverage(
            lane_id=lane.id,
            primary_count=len(primary),
            secondary_count=len(secondary),
            transports_present=transports,
            gaps=gaps,
        )
    return summary
