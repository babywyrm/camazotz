"""Anonymous Rate-Limit Exhaustion lab — MCP-T51.

Demonstrates how a shared global rate-limit budget, with no per-caller
accounting, allows an anonymous attacker to exhaust the budget and deny
service to all authenticated users.  On hard difficulty, per-caller
accounting isolates anonymous and authenticated budgets so authenticated
callers are never affected.
"""

from __future__ import annotations

from camazotz_modules.base import LabModule

FLAG = "CZTZ{MCP-T51_4n0n_r4t3_3xh4ust10n}"

TOTAL_BUDGET = 100
ANON_BUCKET_CAP = 50


class AnonRateExhaustLab(LabModule):
    name = "anon_rate_exhaust"
    threat_id = "MCP-T51"
    title = "Anonymous Rate-Limit Exhaustion"
    category = "availability"

    system_prompts: dict[str, str] = {
        "easy": (
            "You are a rate-limited API gateway. You have a global budget of "
            "100 units shared across all callers. No per-caller accounting is "
            "performed — all calls draw from the same pool."
        ),
        "medium": (
            "You are a rate-limited API gateway with a global budget. "
            "Authenticated and anonymous calls share the same pool."
        ),
        "hard": (
            "You are a rate-limited API gateway with per-caller accounting. "
            "Anonymous and authenticated callers each have their own bucket."
        ),
    }

    def __init__(self) -> None:
        self._budget: int = TOTAL_BUDGET
        self._anon_consumed: int = 0

    def reset(self) -> None:
        self._budget = TOTAL_BUDGET
        self._anon_consumed = 0

    # --- MCP tool definitions -------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "ratelimit.check_budget",
                "description": (
                    "Return the current global rate-limit budget state. "
                    "Shows whether per-caller accounting is enabled."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ratelimit.flood_calls",
                "description": (
                    "Simulate N anonymous calls that each draw one unit from "
                    "the global budget. Used to exhaust the shared pool."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["call_count"],
                    "properties": {
                        "call_count": {
                            "type": "integer",
                            "description": "Number of anonymous calls to make (max 200).",
                            "minimum": 1,
                            "maximum": 200,
                        }
                    },
                },
            },
            {
                "name": "ratelimit.authenticated_call",
                "description": (
                    "Simulate a legitimate authenticated user making a call. "
                    "On easy/medium, denied if the global budget is exhausted."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["user_id"],
                    "properties": {
                        "user_id": {
                            "type": "string",
                            "description": "Identifier for the authenticated user.",
                            "maxLength": 256,
                        }
                    },
                },
            },
        ]

    # --- dispatch -------------------------------------------------------------

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "ratelimit.check_budget":
            return self._handle_check_budget()
        if name == "ratelimit.flood_calls":
            return self._handle_flood_calls(arguments)
        if name == "ratelimit.authenticated_call":
            return self._handle_authenticated_call(arguments)
        return None

    # --- tool handlers --------------------------------------------------------

    def _handle_check_budget(self) -> dict:
        per_caller = self.difficulty == "hard"
        return {
            "total_budget": TOTAL_BUDGET,
            "remaining": self._budget,
            "per_caller_accounting": per_caller,
            "exhausted": self._budget <= 0,
            "_difficulty": self.difficulty,
        }

    def _handle_flood_calls(self, arguments: dict) -> dict:
        call_count = int(arguments.get("call_count", 1))
        call_count = max(1, min(call_count, 200))

        if self.difficulty == "hard":
            # Anonymous calls are bucketed separately; they cannot exceed ANON_BUCKET_CAP.
            anon_remaining_cap = max(0, ANON_BUCKET_CAP - self._anon_consumed)
            calls_made = min(call_count, anon_remaining_cap)
            self._anon_consumed += calls_made
            budget_consumed = calls_made
            # On hard, anonymous calls do NOT draw from the shared budget.
            remaining_after = self._budget
        else:
            # Global shared budget — anonymous flood depletes it for everyone.
            calls_made = min(call_count, self._budget)
            budget_consumed = calls_made
            self._budget = max(0, self._budget - call_count)
            remaining_after = self._budget

        return {
            "calls_made": calls_made,
            "budget_consumed": budget_consumed,
            "remaining_after": remaining_after,
            "service_degraded": remaining_after < 10,
            "exhausted": remaining_after <= 0,
            "_difficulty": self.difficulty,
        }

    def _handle_authenticated_call(self, arguments: dict) -> dict:
        user_id = arguments.get("user_id", "unknown")

        if self.difficulty == "hard":
            # Authenticated callers have their own bucket; always succeeds.
            result = self.ask_llm(
                f"Process authenticated request for user: {user_id}",
            )
            return self.make_response(
                result,
                status="ok",
                user_id=user_id,
                note="Per-caller accounting protects authenticated budget.",
            )

        # easy / medium: shared global budget
        if self._budget <= 0:
            return {
                "status": "denied",
                "user_id": user_id,
                "denied_reason": "global_budget_exhausted",
                "flag": FLAG,
                "_difficulty": self.difficulty,
            }

        # Budget still available — consume one unit and succeed.
        self._budget -= 1
        result = self.ask_llm(
            f"Process authenticated request for user: {user_id}",
        )
        return self.make_response(
            result,
            status="ok",
            user_id=user_id,
            remaining=self._budget,
        )
