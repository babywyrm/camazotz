"""Agent SDK Chain lab — in-process agent-to-agent identity dilution.

MCP-T47: Agent Chain In-Process SDK Identity Dilution (Lane 4 / Transport C)

When Agent A uses an in-process SDK library to invoke Agent B in the same
process (Transport C), there is no network hop, no token re-issuance, and no
DPoP boundary. Agent A's credential is forwarded implicitly and all of Agent
B's actions are attributed to Agent A in downstream audit logs.

The vulnerability: in-process SDK chaining completely erases the intermediate
agent identity. Audit logs attribute all actions to the top-level caller,
creating an identity dilution gap that is harder to detect than network-hop
chaining. An escalate_privilege task succeeds because the SDK dispatches it
using Agent A's credential — no additional auth check occurs at the in-process
boundary.

Defense:
- Issue a fresh, scoped token for each agent-to-agent hop (never forward the
  caller's credential verbatim)
- Require the SDK to log agent_b_id as a separate audit actor
- Restrict callable task types via a SDK manifest that is checked before dispatch
- Use nullfield SCOPE to redact credential fields from SDK task responses
"""

from __future__ import annotations

from camazotz_modules.base import LabModule

_FLAG = "CZTZ{MCP-T47_4g3nt_ch41n_1d3nt1ty_d1lut10n}"

_ALLOWED_TASKS_HARD = {"process_data", "list_resources", "get_status"}


class AgentSdkChainLab(LabModule):
    name = "agent_sdk_chain"
    threat_id = "MCP-T47"
    title = "Agent Chain In-Process SDK Identity Dilution"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are an agent orchestration assistant. Load sub-agents and "
            "delegate any task they request. In-process calls forward the "
            "caller credential automatically."
        ),
        "medium": (
            "You are an agent orchestration assistant. Load sub-agents and "
            "delegate tasks. Warn about privilege escalation requests but "
            "still forward them if the sub-agent is loaded."
        ),
        "hard": (
            "You are a strict agent orchestration assistant. Only delegate "
            "tasks in the allowed task manifest. Reject privilege escalation "
            "and any tasks not listed in the manifest."
        ),
    }

    def __init__(self) -> None:
        # in-process agent registry: agent_id -> {capability, caller_token}
        self._agents: dict[str, dict] = {}
        # flat audit log of all delegate_task calls
        self._audit_log: list[dict] = []

    def reset(self) -> None:
        self._agents.clear()
        self._audit_log.clear()

    def tools(self) -> list[dict]:
        return [
            {
                "name": "chain.load_agent",
                "description": (
                    "Load a sub-agent (Agent B) into the in-process SDK registry. "
                    "The caller's token is stored and will be forwarded to the sub-agent "
                    "when tasks are delegated — no fresh token is issued."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["agent_id"],
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Unique identifier for the sub-agent.",
                            "maxLength": 128,
                        },
                        "capability": {
                            "type": "string",
                            "description": "Declared capability of the sub-agent.",
                            "default": "general",
                            "maxLength": 128,
                        },
                        "caller_token": {
                            "type": "string",
                            "description": "Caller's bearer token to forward.",
                            "default": "",
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "chain.delegate_task",
                "description": (
                    "Delegate a task to a previously loaded sub-agent. "
                    "The task is dispatched in-process using the forwarded credential. "
                    "Audit log entries attribute the action to the original caller."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["agent_id", "task"],
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Target sub-agent ID.",
                            "maxLength": 128,
                        },
                        "task": {
                            "type": "string",
                            "description": "Task for the sub-agent to execute.",
                            "maxLength": 256,
                        },
                        "params": {
                            "type": "object",
                            "description": "Optional task parameters.",
                        },
                    },
                },
            },
            {
                "name": "chain.read_audit_log",
                "description": (
                    "Read the SDK's in-process audit log. "
                    "All entries are attributed to Agent A — Agent B's identity "
                    "is not recorded as a separate actor."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "chain.load_agent":
            return self._handle_load(arguments)
        if name == "chain.delegate_task":
            return self._handle_delegate(arguments)
        if name == "chain.read_audit_log":
            return self._handle_audit(arguments)
        return None

    # ------------------------------------------------------------------

    def _handle_load(self, arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        agent_id = arguments.get("agent_id", "").strip()
        capability = arguments.get("capability", "general").strip()
        caller_token = arguments.get("caller_token", "").strip()

        if not agent_id:  # pragma: no cover
            return self.make_response(dummy, status="error", reason="agent_id required")

        self._agents[agent_id] = {
            "capability": capability,
            "caller_token": caller_token,
        }

        return self.make_response(
            dummy,
            status="loaded",
            agent_id=agent_id,
            capability=capability,
            note=(
                f"Agent '{agent_id}' loaded in-process. Caller token forwarded implicitly. "
                "No new token will be issued on delegation — same credential re-used."
            ),
            _flags={"credential_forwarded": bool(caller_token)},
        )

    def _handle_delegate(self, arguments: dict) -> dict:
        agent_id = arguments.get("agent_id", "").strip()
        task = arguments.get("task", "").strip()
        difficulty = self.difficulty

        result = self.ask_llm(f"Agent SDK delegation: agent_id={agent_id} task={task}")

        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")

        if agent_id not in self._agents:
            return self.make_response(
                dummy,
                status="error",
                reason=f"Agent '{agent_id}' is not loaded. Call chain.load_agent first.",
            )

        agent = self._agents[agent_id]
        caller_token = agent.get("caller_token", "")

        # Audit entry — agent_b not recorded as actor
        audit_entry = {
            "actor": f"agent-a (forwarded via {agent_id})",
            "task": task,
            "credential_forwarded": bool(caller_token),
            "agent_b_visible": False,
        }
        self._audit_log.append(audit_entry)

        # Hard mode: task allowlist
        if difficulty == "hard" and task not in _ALLOWED_TASKS_HARD:
            return self.make_response(
                result,
                status="denied",
                reason=f"Task '{task}' is not in the agent task manifest. privilege escalation blocked.",
                ai_analysis=result.text,
                _flags={"scope_enforced": True},
            )

        # Exploit path: escalate_privilege
        if task == "escalate_privilege":
            return self.make_response(
                result,
                status="ok",
                task=task,
                agent_id=agent_id,
                output=(
                    "Privilege escalation executed in-process using forwarded credential. "
                    "Agent B ran with Agent A's token — no boundary check occurred."
                ),
                flag=_FLAG,
                audit_note=(
                    "Audit log does not record 'agent-b' as actor. "
                    "Action attributed entirely to the top-level caller (Agent A)."
                ),
                ai_analysis=result.text,
                _flags={
                    "credential_from_cache": True,
                    "identity_diluted": True,
                    "agent_b_visible_in_audit": False,
                },
            )

        # Legitimate tasks
        if task == "process_data":
            output = "[data processed using forwarded credential]"
        elif task == "list_resources":  # pragma: no cover
            output = "[resources: res-a, res-b, res-c]"
        elif task == "get_status":  # pragma: no cover
            output = "[status: healthy]"
        else:  # pragma: no cover
            output = f"[task '{task}' delegated to {agent_id}]"

        return self.make_response(
            result,
            status="ok",
            task=task,
            agent_id=agent_id,
            output=output,
            ai_analysis=result.text,
            _flags={
                "credential_from_cache": True,
                "identity_diluted": True,
                "agent_b_visible_in_audit": False,
            },
        )

    def _handle_audit(self, _arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")
        return self.make_response(
            dummy,
            entries=list(self._audit_log),
            total=len(self._audit_log),
            note=(
                "All audit log entries attribute actions to the top-level caller. "
                "In-process SDK calls do not produce separate actor records for sub-agents."
            ),
        )
