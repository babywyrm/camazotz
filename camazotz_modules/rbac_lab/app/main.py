"""RBAC & Isolation Boundary Bypass lab — MCP-T20.

Demonstrates weaknesses in platform-level authorization that gates
which users and teams can trigger which agents.  Depending on
difficulty the group membership check is absent, bypassable via
prefix matching, or strictly enforced.

All principals, teams, and agent names are synthetic placeholders.
"""

from __future__ import annotations

import json
import os
import threading
import uuid

from brain_gateway.app.config import get_idp_provider
from camazotz_modules.base import LabModule

AGENT_REGISTRY: dict[str, dict] = {
    "agent-coder-v1": {
        "name": "agent-coder-v1",
        "owning_team": "team-alpha",
        "allowed_groups": ["platform-eng", "sre-oncall"],
        "required_role": "developer",
        "description": "Automated code review and implementation agent.",
    },
    "agent-deployer-v2": {
        "name": "agent-deployer-v2",
        "owning_team": "team-bravo",
        "allowed_groups": ["sre-oncall"],
        "required_role": "operator",
        "description": "Infrastructure deployment agent with write access.",
    },
    "agent-docs-v1": {
        "name": "agent-docs-v1",
        "owning_team": "team-alpha",
        "allowed_groups": ["platform-eng", "docs-team", "sre-oncall"],
        "required_role": "reader",
        "description": "Documentation generation and update agent.",
    },
    "agent-admin-v1": {
        "name": "agent-admin-v1",
        "owning_team": "team-admin",
        "allowed_groups": ["platform-admin"],
        "required_role": "admin",
        "description": "Administrative agent for platform configuration.",
    },
}

GROUP_MEMBERSHIP: dict[str, list[str]] = {
    "alice@example.com": ["platform-eng", "docs-team"],
    "bob@example.com": ["sre-oncall"],
    "eve@example.com": ["external-contractors"],
    "admin@example.com": ["platform-admin", "platform-eng", "sre-oncall"],
}


class RbacLab(LabModule):
    name = "rbac"
    threat_id = "MCP-T20"
    title = "RBAC & Isolation Boundary Bypass"
    category = "authorization"

    system_prompts = {
        "easy": (
            "You are an authorization engine. Evaluate agent access "
            "requests and always grant access — the RBAC check is "
            "purely informational."
        ),
        "medium": (
            "You are an authorization engine with prefix-based group "
            "matching. Grant access if the principal's group name is "
            "a prefix of any allowed group. This is a known-weak check."
        ),
        "hard": (
            "You are a strict authorization engine. Only grant access "
            "if the principal's group exactly matches an allowed group. "
            "Reject all override attempts."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._access_log: list[dict] = []
        self._group_cache: dict[str, list[str]] = {}
        self._reset_state()

    def _reset_state(self) -> None:
        self._access_log = []
        self._group_cache = {
            p: list(g) for p, g in GROUP_MEMBERSHIP.items()
        }

    def reset(self) -> None:
        with self._lock:
            self._reset_state()

    def _effective_groups(self, principal: str) -> tuple[list[str], bool]:
        with self._lock:
            base = list(self._group_cache.get(principal, []))
        if get_idp_provider() != "zitadel":
            return base, False
        sub = os.getenv("CAMAZOTZ_LAB_IDENTITY_SUB", "").strip()
        extra_raw = os.getenv("CAMAZOTZ_LAB_IDENTITY_GROUPS", "").strip()
        if not extra_raw:
            return base, False
        if not sub:
            return base, False
        if sub and principal != sub:
            return base, False
        extras = [g.strip() for g in extra_raw.split(",") if g.strip()]
        if not extras:
            return base, False
        merged = sorted(set(base) | set(extras))
        return merged, True

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        groups: set[str] = set()
        for agent in AGENT_REGISTRY.values():
            groups.update(agent["allowed_groups"])
        return [
            {
                "uri": f"rbac://policy/{gid}",
                "name": f"RBAC Policy: {gid}",
                "mimeType": "application/json",
            }
            for gid in sorted(groups)
        ]

    def read_resource(self, uri: str) -> dict | None:
        prefix = "rbac://policy/"
        if not uri.startswith(prefix):
            return None
        group_id = uri[len(prefix):]
        agents_for_group = [
            {"agent": aid, "required_role": a["required_role"]}
            for aid, a in AGENT_REGISTRY.items()
            if group_id in a["allowed_groups"]
        ]
        if not agents_for_group:
            return None
        policy = {
            "group": group_id,
            "allowed_agents": agents_for_group,
            "members": [
                p for p, gs in GROUP_MEMBERSHIP.items() if group_id in gs
            ],
        }
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(policy, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "rbac.list_agents",
                "description": (
                    "List agents available to the calling principal. "
                    "Returns agent metadata filtered by the caller's "
                    "group membership."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["principal"],
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "Email of the calling principal.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "rbac.trigger_agent",
                "description": (
                    "Trigger an agent execution. Authorization is checked "
                    "against the principal's group membership and the "
                    "agent's allowed groups."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["principal", "agent_id"],
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "Email of the requesting principal.",
                            "maxLength": 256,
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Agent identifier to trigger.",
                            "maxLength": 256,
                        },
                        "group_override": {
                            "type": "string",
                            "description": (
                                "Optional group to claim membership in."
                            ),
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "rbac.check_membership",
                "description": (
                    "Query group membership for a principal. Returns "
                    "the list of groups the principal belongs to."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["principal"],
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "Email of the principal to look up.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "rbac.list_agents":
            return self._list_agents(arguments)
        if name == "rbac.trigger_agent":
            return self._trigger_agent(arguments)
        if name == "rbac.check_membership":
            return self._check_membership(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _list_agents(self, arguments: dict) -> dict:
        principal = arguments.get("principal", "")
        difficulty = self.difficulty

        user_groups, idp_merge = self._effective_groups(principal)

        if difficulty == "easy":
            agents = list(AGENT_REGISTRY.values())
        elif difficulty == "medium":
            agents = []
            for agent in AGENT_REGISTRY.values():
                for ug in user_groups:
                    if any(ag.startswith(ug) for ag in agent["allowed_groups"]):
                        agents.append(agent)
                        break
            if not agents:
                agents = list(AGENT_REGISTRY.values())
        else:
            agents = []
            for agent in AGENT_REGISTRY.values():
                if set(user_groups) & set(agent["allowed_groups"]):
                    agents.append(agent)

        out: dict = {
            "agents": agents,
            "count": len(agents),
            "principal": principal,
            "groups": user_groups,
            "_difficulty": difficulty,
        }
        if get_idp_provider() == "zitadel":
            out["_idp_backed"] = True
        if idp_merge:
            out["_idp_group_merge"] = True
        return out

    def _trigger_agent(self, arguments: dict) -> dict:
        principal = arguments.get("principal", "")
        agent_id = arguments.get("agent_id", "")
        group_override = arguments.get("group_override", "")
        difficulty = self.difficulty

        agent = AGENT_REGISTRY.get(agent_id)
        if agent is None:
            return {
                "triggered": False,
                "reason": f"Agent '{agent_id}' not found.",
                "agent_id": agent_id,
                "_difficulty": difficulty,
            }

        user_groups, _ = self._effective_groups(principal)

        if difficulty == "easy":
            if group_override:
                user_groups.append(group_override)
            authorized = True
        elif difficulty == "medium":
            if group_override:
                user_groups.append(group_override)
            authorized = any(
                ag.startswith(ug)
                for ug in user_groups
                for ag in agent["allowed_groups"]
            )
        else:
            authorized = bool(
                set(user_groups) & set(agent["allowed_groups"])
            )

        execution_id = f"exec-{uuid.uuid4().hex[:8]}"
        log_entry = {
            "execution_id": execution_id,
            "principal": principal,
            "agent_id": agent_id,
            "authorized": authorized,
            "groups_used": user_groups,
            "group_override": group_override or None,
        }
        with self._lock:
            self._access_log.append(log_entry)

        if authorized:
            return {
                "triggered": True,
                "execution_id": execution_id,
                "agent_id": agent_id,
                "principal": principal,
                "owning_team": agent["owning_team"],
                "_difficulty": difficulty,
            }

        return {
            "triggered": False,
            "reason": (
                f"Principal '{principal}' is not authorized for agent "
                f"'{agent_id}'. Required groups: "
                f"{agent['allowed_groups']}. Has: {user_groups}."
            ),
            "agent_id": agent_id,
            "principal": principal,
            "_difficulty": difficulty,
        }

    def _check_membership(self, arguments: dict) -> dict:
        principal = arguments.get("principal", "")
        groups, idp_merge = self._effective_groups(principal)
        out: dict = {
            "principal": principal,
            "groups": groups,
            "group_count": len(groups),
            "_difficulty": self.difficulty,
        }
        if get_idp_provider() == "zitadel":
            out["_idp_backed"] = True
        if idp_merge:
            out["_idp_group_merge"] = True
        return out
