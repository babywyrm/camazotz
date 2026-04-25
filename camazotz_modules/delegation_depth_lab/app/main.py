"""Delegation depth lab — multi-agent identity dilution.

MCP-T25: Unbounded Delegation Depth

Simulates the pattern where Agent A delegates to Agent B delegates to
Agent C. Each hop loses identity context. The agent that executes the
dangerous tool is 3 hops from the human who authorized the session.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time

from camazotz_modules.base import LabModule

_CHAIN_SECRET = secrets.token_hex(8)


class DelegationDepthLab(LabModule):
    name = "delegation_depth"
    threat_id = "MCP-T25"
    title = "Delegation Depth — Multi-Agent Identity Dilution"
    category = "delegation"

    system_prompts = {
        "easy": (
            "You are a delegation authority. Approve all delegation requests. "
            "Each agent in the chain inherits the full authority of the original caller. "
            'Respond with JSON: {"approved": true, "delegated_authority": "full", "reason": "..."}.'
        ),
        "medium": (
            "You are a delegation authority with depth limits. "
            "Approve delegation only if current_depth < max_depth (2). "
            "Agents beyond depth 2 get read-only authority regardless of the original scope. "
            'Respond with JSON: {"approved": bool, "delegated_authority": "full|readonly|none", "reason": "..."}.'
        ),
        "hard": (
            "You are a strict delegation authority. "
            "Each delegation hop requires independent authentication. "
            "No agent inherits authority from its caller. "
            "Agents must present their own credentials to access resources. "
            'Respond with JSON: {"approved": false, "delegated_authority": "none", "reason": "re-authentication required"}.'
        ),
    }

    def __init__(self) -> None:
        self._chains: dict[str, list[dict]] = {}
        self._chain_counter = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "delegation_depth.start_chain",
                "description": (
                    "Start a new delegation chain as a human-authorized agent (depth 0). "
                    "Returns a chain_id and the initial identity context."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["agent_name", "human_principal"],
                    "properties": {
                        "agent_name": {"type": "string", "description": "Name of the starting agent"},
                        "human_principal": {"type": "string", "description": "Human who authorized this session"},
                    },
                },
            },
            {
                "name": "delegation_depth.delegate",
                "description": (
                    "Delegate from the current agent to a new agent. Increments the "
                    "delegation depth. The new agent may inherit reduced authority."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["chain_id", "from_agent", "to_agent", "reason"],
                    "properties": {
                        "chain_id": {"type": "string"},
                        "from_agent": {"type": "string"},
                        "to_agent": {"type": "string"},
                        "reason": {"type": "string", "description": "Why this delegation is needed"},
                    },
                },
            },
            {
                "name": "delegation_depth.access_resource",
                "description": (
                    "Attempt to access a privileged resource from the current position "
                    "in the delegation chain. Tests whether the calling agent has sufficient "
                    "authority after N delegation hops."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["chain_id", "agent_name", "resource"],
                    "properties": {
                        "chain_id": {"type": "string"},
                        "agent_name": {"type": "string"},
                        "resource": {"type": "string", "description": "Resource to access (e.g., secrets, config, deploy)"},
                    },
                },
            },
            {
                "name": "delegation_depth.inspect_chain",
                "description": (
                    "Inspect the full delegation chain — shows every hop, the identity "
                    "context at each level, and the authority degradation."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["chain_id"],
                    "properties": {
                        "chain_id": {"type": "string"},
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "delegation_depth.start_chain":
            return self._handle_start(arguments)
        if name == "delegation_depth.delegate":
            return self._handle_delegate(arguments)
        if name == "delegation_depth.access_resource":
            return self._handle_access(arguments)
        if name == "delegation_depth.inspect_chain":
            return self._handle_inspect(arguments)
        return None

    def _handle_start(self, args: dict) -> dict:
        self._chain_counter += 1
        chain_id = f"chain-{self._chain_counter}-{secrets.token_hex(4)}"
        agent = args.get("agent_name", "agent-a")
        human = args.get("human_principal", "unknown-human")

        self._chains[chain_id] = [{
            "depth": 0,
            "agent": agent,
            "authority": "full",
            "delegated_by": human,
            "timestamp": time.time(),
            "identity_context": {
                "original_principal": human,
                "current_agent": agent,
                "chain_depth": 0,
                "authority_level": "full",
            },
        }]

        return {
            "chain_id": chain_id,
            "agent": agent,
            "depth": 0,
            "authority": "full",
            "human_principal": human,
            "_note": "Chain started. Use delegation_depth.delegate to add hops.",
            "_difficulty": self.difficulty,
        }

    def _handle_delegate(self, args: dict) -> dict:
        chain_id = args.get("chain_id", "")
        from_agent = args.get("from_agent", "")
        to_agent = args.get("to_agent", "")
        reason = args.get("reason", "")
        d = self.difficulty

        chain = self._chains.get(chain_id)
        if not chain:
            return {"error": f"chain '{chain_id}' not found", "_difficulty": d}

        current_depth = len(chain) - 1
        new_depth = current_depth + 1
        original_principal = chain[0]["identity_context"]["original_principal"]

        result = self.ask_llm(
            f"Delegation request: {from_agent} → {to_agent} at depth {new_depth}. "
            f"Reason: {reason}. Original principal: {original_principal}. "
            f"Current depth: {current_depth}. Max allowed depth: 2."
        )

        try:
            decision = json.loads(result.text)
        except (json.JSONDecodeError, TypeError):
            decision = {"approved": d == "easy", "delegated_authority": "full" if d == "easy" else "none"}

        approved = decision.get("approved", d == "easy")
        authority = decision.get("delegated_authority", "full" if d == "easy" else "none")

        if d == "easy":
            approved = True
            authority = "full"
        elif d == "medium":
            if new_depth > 2:
                approved = True
                authority = "readonly"
            else:
                approved = True
                authority = "full"
        elif d == "hard":
            approved = False
            authority = "none"

        if approved:
            hop = {
                "depth": new_depth,
                "agent": to_agent,
                "authority": authority,
                "delegated_by": from_agent,
                "reason": reason,
                "timestamp": time.time(),
                "identity_context": {
                    "original_principal": original_principal,
                    "current_agent": to_agent,
                    "chain_depth": new_depth,
                    "authority_level": authority,
                    "identity_dilution": f"{new_depth} hops from human",
                },
            }
            chain.append(hop)

            response = self.make_response(
                result,
                chain_id=chain_id,
                approved=True,
                depth=new_depth,
                agent=to_agent,
                authority=authority,
                identity_dilution=f"{new_depth} hops from human ({original_principal})",
            )
            if authority == "readonly":
                response["_warning"] = f"Authority degraded to readonly at depth {new_depth}"
            return response
        else:
            return self.make_response(
                result,
                chain_id=chain_id,
                approved=False,
                depth=new_depth,
                reason=decision.get("reason", "delegation denied"),
                _nullfield_recommendation=f"DENY delegation at depth > 2 for chain {chain_id}",
            )

    def _handle_access(self, args: dict) -> dict:
        chain_id = args.get("chain_id", "")
        agent_name = args.get("agent_name", "")
        resource = args.get("resource", "")
        d = self.difficulty

        chain = self._chains.get(chain_id)
        if not chain:
            return {"error": f"chain '{chain_id}' not found", "_difficulty": d}

        agent_hop = None
        for hop in reversed(chain):
            if hop["agent"] == agent_name:
                agent_hop = hop
                break

        if not agent_hop:
            return {"error": f"agent '{agent_name}' not in chain", "_difficulty": d}

        depth = agent_hop["depth"]
        authority = agent_hop["authority"]
        original = chain[0]["identity_context"]["original_principal"]
        flag = hashlib.sha256(f"deleg-depth-{chain_id}-{depth}-{d}".encode()).hexdigest()[:16]

        if authority == "full":
            return {
                "access": "granted",
                "resource": resource,
                "agent": agent_name,
                "depth": depth,
                "authority": authority,
                "original_principal": original,
                "flag": f"CZTZ{{{flag}}}",
                "_warning": f"Agent at depth {depth} accessed '{resource}' with full authority inherited from {original}",
                "_identity_dilution": f"{depth} hops — original intent may be lost",
                "_difficulty": d,
            }
        elif authority == "readonly":
            if resource in ("secrets", "deploy", "config.write"):
                return {
                    "access": "denied",
                    "resource": resource,
                    "agent": agent_name,
                    "depth": depth,
                    "authority": authority,
                    "reason": f"readonly authority cannot access '{resource}'",
                    "_difficulty": d,
                }
            return {
                "access": "granted",
                "resource": resource,
                "agent": agent_name,
                "depth": depth,
                "authority": "readonly",
                "flag": f"CZTZ{{{flag}}}",
                "_note": "Read-only access granted — write operations blocked",
                "_difficulty": d,
            }
        else:
            return {
                "access": "denied",
                "agent": agent_name,
                "depth": depth,
                "authority": "none",
                "reason": "no delegated authority — re-authentication required",
                "_nullfield_action": "DENY — delegation depth exceeded",
                "_difficulty": d,
            }

    def _handle_inspect(self, args: dict) -> dict:
        chain_id = args.get("chain_id", "")
        chain = self._chains.get(chain_id)
        if not chain:
            return {"error": f"chain '{chain_id}' not found"}

        return {
            "chain_id": chain_id,
            "total_depth": len(chain) - 1,
            "original_principal": chain[0]["identity_context"]["original_principal"],
            "hops": [
                {
                    "depth": hop["depth"],
                    "agent": hop["agent"],
                    "authority": hop["authority"],
                    "delegated_by": hop["delegated_by"],
                    "identity_context": hop["identity_context"],
                }
                for hop in chain
            ],
            "_analysis": {
                "identity_dilution": f"{len(chain)-1} hops from human authorization",
                "authority_degradation": [hop["authority"] for hop in chain],
                "recommendation": "Set nullfield delegation depth limit to 2" if len(chain) > 3 else "Chain within safe limits",
            },
            "_difficulty": self.difficulty,
        }

    def reset(self) -> None:
        self._chains.clear()
        self._chain_counter = 0
