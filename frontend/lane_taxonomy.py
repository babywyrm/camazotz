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
from dataclasses import dataclass, field

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
