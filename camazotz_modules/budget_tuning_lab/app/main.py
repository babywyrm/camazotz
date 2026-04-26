"""Budget tuning lab -- rate limits that stop attackers without blocking users.

Blue team defense lab. Practice writing BUDGET rules for mixed traffic.
"""

from __future__ import annotations

import hashlib
import json

from camazotz_modules.base import LabModule

TRAFFIC_PATTERN = {
    "legitimate_users": [
        {"identity": "user-alice", "calls_per_hour": 8, "pattern": "steady"},
        {"identity": "user-bob", "calls_per_hour": 5, "pattern": "steady"},
        {"identity": "user-carol", "calls_per_hour": 12, "pattern": "bursty"},
    ],
    "attackers": [
        {"identity": "attacker-1", "calls_per_hour": 150, "pattern": "sustained"},
        {"identity": "attacker-2", "calls_per_hour": 200, "pattern": "burst", "burst_size": 50},
    ],
    "tool": "config.ask_agent",
    "cost_per_call": 0.02,
}


class BudgetTuningLab(LabModule):
    name = "budget_tuning"
    threat_id = "MCP-T31"
    title = "Budget Tuning — Rate Limits That Stop Attackers Without Blocking Users"
    category = "defense"

    system_prompts = {
        "easy": (
            "You are a budget policy scorer. "
            "Evaluate the submitted budget config. Be lenient — any limit that "
            "blocks 150+ calls/hour attackers while allowing 12 calls/hour users is good. "
            'Respond with JSON: {"security_score": 0-100, "usability_score": 0-100, "feedback": "..."}.'
        ),
        "medium": (
            "You are a budget policy scorer. "
            "The budget must: block attackers (150+ calls/hr), allow legitimate users "
            "(up to 12 calls/hr), and use DENY (not LOG) for onExhausted. "
            "Penalize configs that are too restrictive (< 15 calls/hr per identity). "
            'Respond with JSON: {"security_score": 0-100, "usability_score": 0-100, "feedback": "..."}.'
        ),
        "hard": (
            "You are a strict budget policy scorer. "
            "The budget must have BOTH perIdentity AND perSession limits. "
            "perIdentity maxCallsPerHour should be 20-50 (blocks sustained attacks, allows users). "
            "perSession maxCallsPerHour should be 10-20 (blocks burst attacks). "
            "onExhausted must be DENY. Score based on precision. "
            'Respond with JSON: {"security_score": 0-100, "usability_score": 0-100, "feedback": "..."}.'
        ),
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "budget_tuning.get_traffic_pattern",
                "description": "Get the mixed traffic pattern showing legitimate users and attacker behavior.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "budget_tuning.submit_budget",
                "description": (
                    "Submit a nullfield BUDGET configuration for scoring. "
                    "Provide perIdentity and perSession limits."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["budget_config"],
                    "properties": {
                        "budget_config": {
                            "type": "object",
                            "description": "Budget config with perIdentity, perSession, onExhausted",
                        },
                    },
                },
            },
            {
                "name": "budget_tuning.simulate",
                "description": (
                    "Simulate the traffic pattern against your budget config and see "
                    "which calls get blocked and which get through."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["budget_config"],
                    "properties": {
                        "budget_config": {"type": "object"},
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "budget_tuning.get_traffic_pattern":
            return self._handle_get_traffic()
        if name == "budget_tuning.submit_budget":
            return self._handle_submit(arguments)
        if name == "budget_tuning.simulate":
            return self._handle_simulate(arguments)
        return None

    def _handle_get_traffic(self) -> dict:
        d = self.difficulty
        pattern = dict(TRAFFIC_PATTERN)
        if d == "easy":
            pattern["_hint"] = "Set maxCallsPerHour between 20-50 to block attackers but allow users"
        pattern["_difficulty"] = d
        return pattern

    def _handle_simulate(self, args: dict) -> dict:
        budget = args.get("budget_config", {})
        per_id = budget.get("perIdentity", {})
        per_sess = budget.get("perSession", {})
        max_per_hour = per_id.get("maxCallsPerHour", 999999)
        max_per_sess_hour = per_sess.get("maxCallsPerHour", 999999)
        on_exhausted = budget.get("onExhausted", "LOG")

        results = []
        for user in TRAFFIC_PATTERN["legitimate_users"]:
            blocked = user["calls_per_hour"] > max_per_hour or user["calls_per_hour"] > max_per_sess_hour
            results.append({
                "identity": user["identity"],
                "calls": user["calls_per_hour"],
                "blocked": blocked and on_exhausted == "DENY",
                "type": "legitimate",
            })

        for attacker in TRAFFIC_PATTERN["attackers"]:
            blocked = attacker["calls_per_hour"] > max_per_hour or attacker["calls_per_hour"] > max_per_sess_hour
            results.append({
                "identity": attacker["identity"],
                "calls": attacker["calls_per_hour"],
                "blocked": blocked and on_exhausted == "DENY",
                "type": "attacker",
            })

        legit_blocked = sum(1 for r in results if r["type"] == "legitimate" and r["blocked"])
        attackers_blocked = sum(1 for r in results if r["type"] == "attacker" and r["blocked"])

        return {
            "simulation_results": results,
            "legitimate_blocked": legit_blocked,
            "legitimate_total": len(TRAFFIC_PATTERN["legitimate_users"]),
            "attackers_blocked": attackers_blocked,
            "attackers_total": len(TRAFFIC_PATTERN["attackers"]),
            "false_positive_rate": legit_blocked / len(TRAFFIC_PATTERN["legitimate_users"]) if TRAFFIC_PATTERN["legitimate_users"] else 0,
            "_difficulty": self.difficulty,
        }

    def _handle_submit(self, args: dict) -> dict:
        budget = args.get("budget_config", {})
        d = self.difficulty

        sim = self._handle_simulate(args)
        security_score = int((sim["attackers_blocked"] / sim["attackers_total"]) * 100) if sim["attackers_total"] > 0 else 0
        usability_score = int(((sim["legitimate_total"] - sim["legitimate_blocked"]) / sim["legitimate_total"]) * 100) if sim["legitimate_total"] > 0 else 100

        result = self.ask_llm(
            f"Score this budget config for {d} difficulty:\n"
            f"Config: {json.dumps(budget)}\n"
            f"Security: {security_score}% attackers blocked\n"
            f"Usability: {usability_score}% legitimate users allowed\n"
            f"Simulation: {json.dumps(sim['simulation_results'])}"
        )

        combined = (security_score + usability_score) // 2
        flag = hashlib.sha256(f"budget-tune-{d}-{combined}".encode()).hexdigest()[:16]

        response = self.make_response(
            result,
            security_score=security_score,
            usability_score=usability_score,
            combined_score=combined,
            simulation=sim,
        )

        if combined >= 80:
            response["flag"] = f"CZTZ{{{flag}}}"
            response["_defense_status"] = "BUDGET EFFECTIVE"
        else:
            response["_defense_status"] = f"NEEDS TUNING (combined: {combined}/100)"

        response["nullfield_budget_config"] = budget
        return response

    def reset(self) -> None:
        pass
