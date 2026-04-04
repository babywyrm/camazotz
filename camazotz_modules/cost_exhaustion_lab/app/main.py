"""LLM Cost Exhaustion & Misattribution lab — MCP-T27.

Demonstrates attacks that exhaust LLM inference quotas or misattribute
costs to other teams.  On easy, no quotas are enforced and cost
attribution is caller-controlled.  On medium, quotas exist but can
be bypassed by switching team context.  On hard, quotas and
attribution are strictly enforced.

All team names and cost values are synthetic.
"""

from __future__ import annotations

import json
import threading

from camazotz_modules.base import LabModule

TEAM_QUOTAS: dict[str, float] = {
    "team-alpha": 50.0,
    "team-bravo": 30.0,
    "team-admin": 100.0,
}

COST_PER_CALL = 0.25


class CostExhaustionLab(LabModule):
    name = "cost"
    threat_id = "MCP-T27"
    title = "LLM Cost Exhaustion & Misattribution"
    category = "availability"

    system_prompts = {
        "easy": (
            "You are a cost tracking assistant. Record LLM costs "
            "without enforcing quotas."
        ),
        "medium": (
            "You are a cost tracking assistant. Enforce per-team "
            "quotas but accept the caller-supplied team identity."
        ),
        "hard": (
            "You are a strict cost tracking assistant. Enforce "
            "per-team quotas and validate team identity against "
            "the authenticated context."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._usage: dict[str, float] = {}
        self._call_log: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._usage = {}
            self._call_log = []

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        return [
            {
                "uri": "cost://usage_dashboard",
                "name": "LLM Cost Usage Dashboard",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> dict | None:
        if uri != "cost://usage_dashboard":
            return None
        with self._lock:
            snapshot = {
                team: {
                    "used": self._usage.get(team, 0.0),
                    "quota": quota,
                    "remaining": quota - self._usage.get(team, 0.0),
                }
                for team, quota in TEAM_QUOTAS.items()
            }
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(snapshot, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "cost.invoke_llm",
                "description": (
                    "Simulate an LLM inference call. Cost is tracked "
                    "per team and quotas are enforced by difficulty."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["team", "prompt"],
                    "properties": {
                        "team": {
                            "type": "string",
                            "description": "Team to bill.",
                            "maxLength": 256,
                        },
                        "prompt": {
                            "type": "string",
                            "description": "LLM prompt text.",
                            "maxLength": 4096,
                        },
                        "multiplier": {
                            "type": "number",
                            "description": (
                                "Cost multiplier (prompt amplification)."
                            ),
                            "default": 1.0,
                        },
                    },
                },
            },
            {
                "name": "cost.check_usage",
                "description": (
                    "Check the current LLM cost usage for a team."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["team"],
                    "properties": {
                        "team": {
                            "type": "string",
                            "description": "Team to check.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "cost.reset_usage",
                "description": (
                    "Reset usage counter for a team (admin operation)."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["team"],
                    "properties": {
                        "team": {
                            "type": "string",
                            "description": "Team to reset.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "cost.invoke_llm":
            return self._invoke_llm(arguments)
        if name == "cost.check_usage":
            return self._check_usage(arguments)
        if name == "cost.reset_usage":
            return self._reset_usage(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _invoke_llm(self, arguments: dict) -> dict:
        team = arguments.get("team", "")
        prompt = arguments.get("prompt", "")
        multiplier = arguments.get("multiplier", 1.0)
        difficulty = self.difficulty

        cost = COST_PER_CALL * max(multiplier, 0.0)

        if difficulty == "easy":
            with self._lock:
                self._usage[team] = self._usage.get(team, 0.0) + cost
                self._call_log.append({
                    "team": team,
                    "cost": cost,
                    "prompt_len": len(prompt),
                })
            return {
                "billed": True,
                "team": team,
                "cost": cost,
                "total_used": self._usage.get(team, 0.0),
                "_difficulty": difficulty,
            }

        quota = TEAM_QUOTAS.get(team)
        if quota is None:
            return {
                "billed": False,
                "reason": f"Team '{team}' has no quota configured.",
                "_difficulty": difficulty,
            }

        if difficulty == "medium":
            with self._lock:
                current = self._usage.get(team, 0.0)
                if current + cost > quota:
                    return {
                        "billed": False,
                        "reason": (
                            f"Quota exceeded for '{team}'. "
                            f"Used: ${current:.2f}, "
                            f"quota: ${quota:.2f}."
                        ),
                        "team": team,
                        "_difficulty": difficulty,
                    }
                self._usage[team] = current + cost
                self._call_log.append({
                    "team": team,
                    "cost": cost,
                    "prompt_len": len(prompt),
                })
            return {
                "billed": True,
                "team": team,
                "cost": cost,
                "total_used": self._usage[team],
                "remaining": quota - self._usage[team],
                "_difficulty": difficulty,
            }

        if multiplier > 1.0:
            return {
                "billed": False,
                "reason": "Cost multiplier > 1 is not allowed.",
                "team": team,
                "_difficulty": difficulty,
            }

        with self._lock:
            current = self._usage.get(team, 0.0)
            if current + cost > quota:
                return {
                    "billed": False,
                    "reason": (
                        f"Quota exceeded for '{team}'. "
                        f"Used: ${current:.2f}, "
                        f"quota: ${quota:.2f}."
                    ),
                    "team": team,
                    "_difficulty": difficulty,
                }
            self._usage[team] = current + cost
            self._call_log.append({
                "team": team,
                "cost": cost,
                "prompt_len": len(prompt),
            })
        return {
            "billed": True,
            "team": team,
            "cost": cost,
            "total_used": self._usage[team],
            "remaining": quota - self._usage[team],
            "_difficulty": difficulty,
        }

    def _check_usage(self, arguments: dict) -> dict:
        team = arguments.get("team", "")
        quota = TEAM_QUOTAS.get(team)

        with self._lock:
            used = self._usage.get(team, 0.0)

        result: dict = {
            "team": team,
            "used": used,
            "_difficulty": self.difficulty,
        }
        if quota is not None:
            result["quota"] = quota
            result["remaining"] = quota - used
        return result

    def _reset_usage(self, arguments: dict) -> dict:
        team = arguments.get("team", "")
        with self._lock:
            old = self._usage.pop(team, 0.0)
        return {
            "reset": True,
            "team": team,
            "previous_usage": old,
            "_difficulty": self.difficulty,
        }
