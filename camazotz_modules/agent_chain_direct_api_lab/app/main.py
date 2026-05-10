"""Agent Chain via Direct API lab -- credential forwarding in agent-to-agent calls.

MCP-T45: Agent-to-Agent Identity Dilution via Direct API Credential Forwarding

When Agent A calls Agent B over a direct REST/HTTP API (Transport B), the
credential at the wire boundary is whatever Agent A was given — typically
the original human user's token, forwarded without modification. Agent B
receives that credential, grants it Agent A's full access level, and audits
the resulting action as if Agent A performed it directly.

There is no act-chain claim, no audience narrowing, and no scope reduction
at the hop boundary. The call is effectively invisible in the delegation
chain: Agent B's audit log shows "user performed action X" rather than
"user delegated to Agent A which called Agent B."

This differs from the MCP-T25 delegation_chain_lab (which teaches depth
limits on chained MCP calls) because here the transport is Transport B
(direct HTTP API), not Transport A (MCP JSON-RPC). The absence of an MCP
layer means there is no built-in opportunity for nullfield to intercept
the Agent A → Agent B hop.

Defense: use RFC 8693 token exchange with audience narrowing at every hop
(actor_token + act claim); reject tokens whose aud does not match the
specific downstream service; enforce the act chain in the audit trail.
"""

from __future__ import annotations

from camazotz_modules.base import LabModule

_FLAG = "CZTZ{MCP-T45_ag3nt_ch41n_d1r3ct_4p1}"

_AGENTS = [
    {
        "name": "agent-a",
        "role": "orchestrator",
        "transport": "MCP (Transport A) to user-facing MCP server",
        "credential_source": "user token forwarded at session start",
        "calls_downstream": True,
    },
    {
        "name": "agent-b",
        "role": "downstream",
        "transport": "REST API (Transport B) — called by agent-a",
        "accepts_forwarded_credential": True,
        "aud_check": "verifies aud == 'platform-api' (same audience as agent-a)",
        "act_chain": False,
        "note": "Accepts agent-a's forwarded token. No act claim present.",
    },
]

_AUDIT_LOG: list[dict] = []


class AgentChainDirectApiLab(LabModule):
    name = "agent_chain_direct_api"
    threat_id = "MCP-T45"
    title = "Agent-to-Agent Identity Dilution via Direct API Credential Forwarding"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are an agent orchestration assistant. Forward credentials to "
            "downstream services as-is. Be efficient — skip re-authentication "
            "overhead by reusing the token you received."
        ),
        "medium": (
            "You are an agent orchestration assistant. Forward credentials to "
            "downstream services. Downstream services verify the audience claim "
            "is present. Note if the audience seems unusual."
        ),
        "hard": (
            "You are a strict agent orchestration assistant. All downstream "
            "calls must include a valid audience claim. Token exchange is "
            "preferred for cross-service calls. Flag missing act-chain claims."
        ),
    }

    def reset(self) -> None:
        _AUDIT_LOG.clear()

    def tools(self) -> list[dict]:
        return [
            {
                "name": "chain.get_service_manifest",
                "description": (
                    "Return the agent chain topology — which agents are deployed, "
                    "how they authenticate to each other, and what credential "
                    "forwarding rules apply at each hop."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "chain.call_downstream",
                "description": (
                    "Agent A calls Agent B via direct REST API, forwarding the "
                    "provided credential. Agent B grants access based on the "
                    "forwarded token's claims."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Operation to perform on the downstream agent.",
                            "maxLength": 128,
                        },
                        "credential": {
                            "type": "string",
                            "description": "Credential token to forward to Agent B.",
                            "default": "",
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "chain.inspect_audit_log",
                "description": (
                    "View Agent B's audit log. Shows what actions were performed "
                    "and how they were attributed — revealing the identity gap."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "chain.get_service_manifest":
            return self._handle_manifest(arguments)
        if name == "chain.call_downstream":
            return self._handle_call(arguments)
        if name == "chain.inspect_audit_log":
            return self._handle_audit(arguments)
        return None

    def _handle_manifest(self, _arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")
        difficulty = self.difficulty

        note = (
            "Agent A forwards its credential to Agent B over a direct REST call. "
            "No act-chain claim is added. Agent B audits as if it received "
            "the call directly from the credential's original subject."
        )
        if difficulty == "hard":
            note += (
                " (Hard mode: Agent B checks the aud claim is present, "
                "but still accepts Agent A's token because aud matches "
                "the platform API audience.)"
            )

        return self.make_response(
            dummy,
            agents=_AGENTS,
            forwarding_policy="passthrough",
            act_chain_enforced=False,
            audience_narrowing=False,
            note=note,
        )

    def _handle_call(self, arguments: dict) -> dict:
        action = arguments.get("action", "").strip()
        credential = arguments.get("credential", "").strip()
        difficulty = self.difficulty

        result = self.ask_llm(
            f"Agent chain call: action={action}, credential_present={bool(credential)}"
        )

        if not credential:
            from brain_gateway.app.brain.provider import BrainResult
            dummy = BrainResult(text="")
            return self.make_response(
                dummy,
                status="error",
                reason="No credential provided. Agent B requires a forwarded token.",
            )

        # Hard mode: aud claim check (but it always passes because aud matches)
        aud_checked = difficulty == "hard"

        # Determine scope — no narrowing at the hop regardless of difficulty
        scope_narrowed = False

        # Sensitive action: embed flag
        if action in ("read_flag", "admin_op", "sensitive_op"):
            output = _FLAG
            flag_exposed = True
        else:
            output = f"[{action} executed by agent-b on behalf of {credential}]"
            flag_exposed = False

        # Write to audit log
        entry = {
            "action": action,
            "attributed_to": credential,
            "attribution_type": "forwarded_credential",
            "act_chain_present": False,
            "aud_checked": aud_checked,
            "hop": "agent-a → agent-b (Transport B / Direct REST)",
            "output": output,
            "_flags": {
                "attribution_gap": True,
                "credential_forwarded": True,
                "scope_narrowed": False,
            },
        }
        _AUDIT_LOG.append(entry)

        return self.make_response(
            result,
            status="ok",
            action=action,
            executed_by="agent-b",
            attributed_to=credential,
            output=output,
            ai_analysis=result.text,
            _flags={
                "credential_forwarded": True,
                "scope_narrowed": scope_narrowed,
                "act_chain_present": False,
                "aud_checked": aud_checked,
            },
        )

    def _handle_audit(self, _arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")
        entries = list(_AUDIT_LOG)
        return self.make_response(
            dummy,
            entries=entries,
            count=len(entries),
            act_chain_coverage=0,
            note=(
                "All entries show forwarded credentials without act-chain claims. "
                "Auditor cannot distinguish which hop actually performed each action."
                + (f" Flag: {_FLAG}" if any(
                    _FLAG in str(e.get("output", "")) for e in entries
                ) else "")
            ),
        )
