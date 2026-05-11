"""Agent Subprocess Chain lab — subprocess credential injection.

MCP-T48: Agent Chain Subprocess Credential Injection (Lane 4 / Transport D)

When Agent A spawns Agent B as a child subprocess (Transport D), there IS a
process boundary — unlike Transport C's in-process SDK. However, Agent A
injects its credential into the subprocess environment via environment
variables. Agent B inherits the credential from the parent's env and can use
it without re-authentication.

The vulnerability: spawning a subprocess does NOT automatically create a new
identity boundary. If the caller injects its token into os.environ before
spawning, the child process inherits it. This means the subprocess can act
with the caller's privileges without any explicit token exchange or scope check.

On easy/medium the credential is exposed in subprocess output (flag + inherited
token returned directly). On hard, the subprocess masks env vars from its
output but the credential was still inherited — read_secrets is blocked and
the token is redacted from read_env_inheritance.

Defense:
- Never inject credentials into subprocess env; pass them through explicit,
  audited IPC channels instead
- Issue a fresh, scoped token for each spawned subprocess
- Scrub parent env before forking (use subprocess.Popen with env={} baseline)
- Audit subprocess env at spawn time with an allowlist of permitted variables
"""

from __future__ import annotations

from camazotz_modules.base import LabModule

_FLAG = "CZTZ{MCP-T48_subpr0c3ss_cr3d3nt14l_1nj3ct10n}"

_PRIVILEGED_TOKEN_PREFIXES = ("agent-a", "bearer-", "cztz-", "admin-")


def _is_privileged(token: str) -> bool:
    """Return True if token matches a privileged pattern (hard-mode check)."""
    lower = token.lower()
    return any(lower.startswith(p) for p in _PRIVILEGED_TOKEN_PREFIXES) or bool(token)


class AgentSubprocessChainLab(LabModule):
    name = "agent_subprocess_chain"
    threat_id = "MCP-T48"
    title = "Agent Chain Subprocess Credential Injection"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are an agent orchestration assistant. Spawn sub-agent subprocesses "
            "and inject credentials into their environment. Subprocesses inherit env "
            "vars from the parent and can use the caller's token without re-auth."
        ),
        "medium": (
            "You are an agent orchestration assistant. Spawn sub-agents as subprocesses. "
            "Warn that subprocess env inheritance is a security concern, but still allow "
            "tasks to run using the inherited credential."
        ),
        "hard": (
            "You are a strict agent orchestration assistant. Subprocesses redact "
            "inherited credentials from output. Privileged tasks like read_secrets are "
            "blocked when the inherited token matches a privileged pattern."
        ),
    }

    def __init__(self) -> None:
        # simulated subprocess registry: agent_id -> {agent_token: str, env: dict}
        self._subprocesses: dict[str, dict] = {}

    def reset(self) -> None:
        self._subprocesses.clear()

    def tools(self) -> list[dict]:
        return [
            {
                "name": "subchain.spawn_agent",
                "description": (
                    "Spawn Agent B as a child subprocess with the caller's credential "
                    "injected into the subprocess environment via AGENT_TOKEN env var. "
                    "Agent B inherits the credential without explicit re-authentication."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["agent_id"],
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Unique identifier for the subprocess agent.",
                            "maxLength": 128,
                        },
                        "caller_token": {
                            "type": "string",
                            "description": "Caller's bearer token to inject into subprocess env.",
                            "default": "",
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "subchain.run_task",
                "description": (
                    "Send a task to a previously spawned subprocess agent. "
                    "The subprocess reads AGENT_TOKEN from its inherited env and uses it "
                    "to authenticate the task — no explicit token passing required. "
                    "On easy/medium, read_secrets returns the flag and the inherited token. "
                    "On hard, the subprocess redacts env from output and blocks read_secrets."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["agent_id", "task"],
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Target subprocess agent ID.",
                            "maxLength": 128,
                        },
                        "task": {
                            "type": "string",
                            "description": "Task for the subprocess to execute.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "subchain.read_env_inheritance",
                "description": (
                    "Diagnostic tool: return the environment variables inherited by a "
                    "spawned subprocess, including AGENT_TOKEN. "
                    "On hard, AGENT_TOKEN value is masked as '****' but the key is listed, "
                    "confirming the credential crossed the process boundary."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Subprocess agent ID to inspect. If omitted, returns all.",
                            "maxLength": 128,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "subchain.spawn_agent":
            return self._handle_spawn(arguments)
        if name == "subchain.run_task":
            return self._handle_run_task(arguments)
        if name == "subchain.read_env_inheritance":
            return self._handle_read_env(arguments)
        return None

    # ------------------------------------------------------------------

    def _handle_spawn(self, arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult

        dummy = BrainResult(text="")

        agent_id = arguments.get("agent_id", "").strip()
        caller_token = arguments.get("caller_token", "").strip()

        if not agent_id:
            return self.make_response(dummy, status="error", reason="agent_id required")

        self._subprocesses[agent_id] = {
            "agent_token": caller_token,
            "env": {
                "AGENT_TOKEN": caller_token,
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "en_US.UTF-8",
            },
        }

        return self.make_response(
            dummy,
            status="spawned",
            agent_id=agent_id,
            note=(
                f"Subprocess '{agent_id}' spawned. Caller token injected into "
                "subprocess env as AGENT_TOKEN. Child process inherits parent env "
                "automatically — no explicit token exchange occurred."
            ),
            _flags={"credential_injected": bool(caller_token)},
        )

    def _handle_run_task(self, arguments: dict) -> dict:
        agent_id = arguments.get("agent_id", "").strip()
        task = arguments.get("task", "").strip()
        difficulty = self.difficulty

        result = self.ask_llm(
            f"Subprocess agent task execution: agent_id={agent_id} task={task}"
        )

        from brain_gateway.app.brain.provider import BrainResult

        dummy = BrainResult(text="")

        if agent_id not in self._subprocesses:
            return self.make_response(
                dummy,
                status="error",
                reason=(
                    f"No subprocess found for agent_id='{agent_id}'. "
                    "Call subchain.spawn_agent first."
                ),
            )

        proc = self._subprocesses[agent_id]
        inherited_token = proc["env"].get("AGENT_TOKEN", "")

        # Hard mode: block read_secrets when token matches privileged pattern
        if difficulty == "hard" and task == "read_secrets":
            return self.make_response(
                result,
                status="denied",
                agent_id=agent_id,
                task=task,
                reason=(
                    "Subprocess policy: read_secrets blocked — inherited token "
                    "matches privileged pattern. Credential was inherited but "
                    "privileged task execution is restricted in hardened mode."
                ),
                ai_analysis=result.text,
                _flags={
                    "credential_inherited": True,
                    "credential_in_output": False,
                    "policy_enforced": True,
                },
            )

        # read_secrets: the exploit path — returns the flag
        if task == "read_secrets":
            return self.make_response(
                result,
                status="ok",
                agent_id=agent_id,
                task=task,
                output=(
                    "Subprocess executed read_secrets using inherited AGENT_TOKEN "
                    "from parent environment. No explicit token exchange required — "
                    "credential crossed the process boundary via env inheritance."
                ),
                flag=_FLAG,
                inherited_token=inherited_token,
                ai_analysis=result.text,
                _flags={
                    "credential_inherited": True,
                    "credential_in_output": True,
                },
            )

        # Hard mode: other tasks execute but redact env from output
        if difficulty == "hard":
            return self.make_response(
                result,
                status="ok",
                agent_id=agent_id,
                task=task,
                output=f"[subprocess task '{task}' executed — env vars redacted from output]",
                inherited_token="****",
                ai_analysis=result.text,
                _flags={
                    "credential_inherited": True,
                    "credential_in_output": False,
                },
            )

        # Easy/medium: legitimate tasks run normally with inherited credential
        if task == "process_data":
            output = "[data processed using inherited AGENT_TOKEN]"
        elif task == "list_resources":
            output = "[resources: res-a, res-b, res-c]"
        elif task == "get_status":
            output = "[status: healthy — subprocess using inherited credential]"
        else:
            output = f"[task '{task}' executed by subprocess {agent_id}]"

        return self.make_response(
            result,
            status="ok",
            agent_id=agent_id,
            task=task,
            output=output,
            inherited_token=inherited_token,
            ai_analysis=result.text,
            _flags={
                "credential_inherited": True,
                "credential_in_output": True,
            },
        )

    def _handle_read_env(self, arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult

        dummy = BrainResult(text="")
        difficulty = self.difficulty
        agent_id = arguments.get("agent_id", "").strip()

        def _build_env_view(proc: dict) -> dict:
            env = dict(proc["env"])
            if difficulty == "hard":
                if "AGENT_TOKEN" in env:
                    env["AGENT_TOKEN"] = "****"
            return env

        if agent_id:
            if agent_id not in self._subprocesses:
                return self.make_response(
                    dummy,
                    status="error",
                    reason=f"No subprocess found for agent_id='{agent_id}'.",
                )
            return self.make_response(
                dummy,
                agent_id=agent_id,
                env=_build_env_view(self._subprocesses[agent_id]),
                note=(
                    "AGENT_TOKEN is present because the subprocess inherited the parent's "
                    "environment. The caller's credential crossed the process boundary."
                    + (" Value masked in hardened mode." if difficulty == "hard" else ""),
                ),
            )

        # No agent_id: return env for all spawned subprocesses
        all_envs = {
            aid: _build_env_view(proc)
            for aid, proc in self._subprocesses.items()
        }
        return self.make_response(
            dummy,
            subprocesses=all_envs,
            total=len(all_envs),
            note=(
                "All listed subprocesses inherited AGENT_TOKEN from the parent process env."
            ),
        )
