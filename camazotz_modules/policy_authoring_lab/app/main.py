"""Policy authoring lab -- write nullfield rules that block attack chains.

Blue team defense lab. The objective is to write policy, not exploit vulnerabilities.
"""

from __future__ import annotations

import hashlib
import json

from camazotz_modules.base import LabModule

ATTACK_CHAIN = {
    "chain_id": "AC-001",
    "description": "Prompt injection -> code execution -> secret exfiltration",
    "steps": [
        {"tool": "hallucination.execute_plan", "finding": "code_execution", "severity": "CRITICAL"},
        {"tool": "shadow.register_webhook", "finding": "webhook_persistence", "severity": "HIGH"},
        {"tool": "relay.execute_with_context", "finding": "token_theft", "severity": "HIGH"},
    ],
    "recommended_actions": {
        "hallucination.execute_plan": "HOLD",
        "shadow.register_webhook": "DENY",
        "relay.execute_with_context": "SCOPE",
    },
}


class PolicyAuthoringLab(LabModule):
    name = "policy_authoring"
    threat_id = "MCP-T29"
    title = "Policy Authoring — Write Rules That Block Attack Chains"
    category = "defense"

    system_prompts = {
        "easy": (
            "You are a nullfield policy validator. "
            "Evaluate the submitted policy YAML. Be lenient — accept any policy "
            "that includes at least one DENY or HOLD rule for the attack chain tools. "
            'Respond with JSON: {"valid": true/false, "score": 0-100, "feedback": "..."}.'
        ),
        "medium": (
            "You are a nullfield policy validator. "
            "Evaluate the submitted policy against the attack chain. The policy must: "
            "1) Block hallucination.execute_plan (HOLD or DENY), "
            "2) Block shadow.register_webhook (DENY), "
            "3) Scope relay.execute_with_context (SCOPE with redaction). "
            'Respond with JSON: {"valid": true/false, "score": 0-100, "feedback": "..."}.'
        ),
        "hard": (
            "You are a strict nullfield policy validator. "
            "The policy must block ALL three attack chain tools with the EXACT correct actions "
            "(HOLD for execute_plan, DENY for register_webhook, SCOPE with redactPatterns for "
            "execute_with_context), plus a default DENY rule at the bottom. "
            "Deduct points for over-broad rules (DENY * without specific rules first). "
            'Respond with JSON: {"valid": true/false, "score": 0-100, "feedback": "..."}.'
        ),
    }

    def __init__(self) -> None:
        self._submitted_policies: list[str] = []

    def tools(self) -> list[dict]:
        return [
            {
                "name": "policy_authoring.get_attack_chain",
                "description": (
                    "Get the attack chain report that your policy must defend against. "
                    "Shows which tools are involved and what actions are recommended."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "policy_authoring.submit_policy",
                "description": (
                    "Submit a nullfield policy YAML string for validation. "
                    "The lab evaluates whether it blocks the attack chain."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["policy_yaml"],
                    "properties": {
                        "policy_yaml": {
                            "type": "string",
                            "description": "The nullfield policy YAML to validate",
                            "maxLength": 8192,
                        },
                    },
                },
            },
            {
                "name": "policy_authoring.get_hint",
                "description": "Get a hint about which nullfield action to use for a specific tool.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {
                            "type": "string",
                            "description": "The tool to get a hint for",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "policy_authoring.get_attack_chain":
            return self._handle_get_chain()
        if name == "policy_authoring.submit_policy":
            return self._handle_submit(arguments)
        if name == "policy_authoring.get_hint":
            return self._handle_hint(arguments)
        return None

    def _handle_get_chain(self) -> dict:
        d = self.difficulty
        chain = dict(ATTACK_CHAIN)
        if d == "easy":
            chain["_hints"] = {
                "hallucination.execute_plan": "Use HOLD — require human approval",
                "shadow.register_webhook": "Use DENY — block entirely",
                "relay.execute_with_context": "Use SCOPE — redact credentials in response",
            }
        elif d == "hard":
            del chain["recommended_actions"]
        chain["_difficulty"] = d
        return chain

    def _handle_submit(self, args: dict) -> dict:
        policy_yaml = args.get("policy_yaml", "")
        d = self.difficulty
        self._submitted_policies.append(policy_yaml)

        result = self.ask_llm(
            f"Evaluate this nullfield policy against attack chain AC-001:\n\n"
            f"Attack chain tools: {json.dumps([s['tool'] for s in ATTACK_CHAIN['steps']])}\n\n"
            f"Submitted policy:\n{policy_yaml}"
        )

        try:
            evaluation = json.loads(result.text)
        except (json.JSONDecodeError, TypeError):
            evaluation = {"valid": False, "score": 0, "feedback": result.text}

        score = evaluation.get("score", 0)
        flag = hashlib.sha256(f"policy-auth-{d}-{score}".encode()).hexdigest()[:16]

        response = self.make_response(
            result,
            evaluation=evaluation,
            attack_chain_id="AC-001",
            attempts=len(self._submitted_policies),
        )

        if score >= 80:
            response["flag"] = f"CZTZ{{{flag}}}"
            response["_defense_status"] = "ATTACK CHAIN BLOCKED"
        else:
            response["_defense_status"] = f"GAPS REMAIN (score: {score}/100)"

        return response

    def _handle_hint(self, args: dict) -> dict:
        tool = args.get("tool_name", "")
        d = self.difficulty

        if d == "hard":
            return {"hint": "No hints on hard difficulty.", "_difficulty": d}

        rec = ATTACK_CHAIN["recommended_actions"].get(tool)
        if rec:
            return {
                "tool": tool,
                "recommended_action": rec,
                "reason": f"mcpnuke found {next((s['finding'] for s in ATTACK_CHAIN['steps'] if s['tool'] == tool), 'unknown')} vulnerability",
                "_difficulty": d,
            }
        return {"hint": f"Tool '{tool}' is not in the attack chain.", "_difficulty": d}

    def reset(self) -> None:
        self._submitted_policies.clear()
