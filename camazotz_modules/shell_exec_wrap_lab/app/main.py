"""Shell Command Wrapping Injection lab — MCP-T53.

Lane 3 (Machine Identity) / Transport D (Subprocess).

Demonstrates the danger of wrapping subprocess.run(shell=True) with
user-controlled argument interpolation.  Three difficulty tiers show
the progression from completely unsafe to properly defended.

Attack surface:
  1. Shell metacharacter injection via unsanitised args  (easy)
  2. Dangerous base command selection bypassing quote    (medium)
  3. Both neutralised by allowlist + quoting              (hard)
"""

from __future__ import annotations

import shlex
import subprocess
import threading

from camazotz_modules.base import LabModule

FLAG = "CZTZ{MCP-T53_sh3ll_wr4p_1nj3ct10n_d3f34t3d}"

_ALLOWLISTED_COMMANDS: frozenset[str] = frozenset({"echo", "date", "whoami"})

_DANGEROUS_BASE_COMMANDS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "node",
})

_INJECTION_METACHARACTERS = frozenset(";|&$`()")

_SUBPROCESS_TIMEOUT_SEC = 5


def _has_shell_metachar(s: str) -> bool:
    return any(c in s for c in _INJECTION_METACHARACTERS)


class ShellExecWrapLab(LabModule):
    name = "shell_exec_wrap"
    threat_id = "MCP-T53"
    title = "Shell Command Wrapping Injection"
    category = "injection"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._exec_count = 0

    def reset(self) -> None:
        with self._lock:
            self._exec_count = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "shellwrap.exec",
                "description": (
                    "Execute a shell command via a convenience wrapper.  Provide "
                    "a base_cmd (the program to run) and optional args.  The "
                    "wrapper constructs and executes the command via "
                    "subprocess.run(shell=True)."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["base_cmd"],
                    "properties": {
                        "base_cmd": {
                            "type": "string",
                            "description": (
                                "Base command to execute (e.g. 'echo', 'date').  "
                                "On hard difficulty, restricted to the allowlist "
                                "returned by shellwrap.list_commands."
                            ),
                            "maxLength": 64,
                        },
                        "args": {
                            "type": "string",
                            "description": (
                                "Arguments to pass to the base command.  On easy "
                                "difficulty these are interpolated raw into the "
                                "shell command string."
                            ),
                            "default": "",
                            "maxLength": 1024,
                        },
                    },
                },
            },
            {
                "name": "shellwrap.list_commands",
                "description": (
                    "Return the set of allowed base commands and the current "
                    "safety configuration for the shell wrapper."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "shellwrap.exec":
            return self._handle_exec(arguments)
        if name == "shellwrap.list_commands":
            return self._handle_list_commands()
        return None

    def _handle_list_commands(self) -> dict:
        difficulty = self.difficulty
        return {
            "allowed_commands": sorted(_ALLOWLISTED_COMMANDS),
            "allowlist_enforced": difficulty == "hard",
            "args_quoted": difficulty in ("medium", "hard"),
            "shell_mode": True,
            "_difficulty": difficulty,
        }

    def _handle_exec(self, arguments: dict) -> dict:
        base_cmd = arguments.get("base_cmd", "").strip()
        args = arguments.get("args", "")
        difficulty = self.difficulty

        with self._lock:
            self._exec_count += 1
            exec_id = self._exec_count

        if not base_cmd:
            return {
                "status": "error",
                "reason": "base_cmd is required",
                "_difficulty": difficulty,
            }

        base_word = base_cmd.split()[0] if base_cmd else ""

        if difficulty == "hard":
            if base_word not in _ALLOWLISTED_COMMANDS:
                return {
                    "status": "denied",
                    "reason": (
                        f"Command '{base_cmd}' not in allowlist "
                        f"{sorted(_ALLOWLISTED_COMMANDS)}"
                    ),
                    "base_cmd": base_cmd,
                    "_difficulty": difficulty,
                }

        if difficulty == "hard" and base_word in _DANGEROUS_BASE_COMMANDS:
            return {
                "status": "denied",
                "reason": f"Command '{base_cmd}' is blocked as dangerous",
                "base_cmd": base_cmd,
                "_difficulty": difficulty,
            }  # pragma: no cover — hard already rejects non-allowlisted

        if difficulty == "easy":
            cmd_string = f"{base_cmd} {args}"
        elif difficulty == "medium":
            if args:
                cmd_string = f"{base_cmd} {shlex.quote(args)}"
            else:
                cmd_string = base_cmd
        else:
            if args:
                cmd_string = f"{shlex.quote(base_cmd)} {shlex.quote(args)}"
            else:
                cmd_string = shlex.quote(base_cmd)

        try:
            proc = subprocess.run(
                cmd_string,
                shell=True,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SEC,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired:  # pragma: no cover
            return {
                "status": "error",
                "reason": f"Command exceeded {_SUBPROCESS_TIMEOUT_SEC}s timeout",
                "base_cmd": base_cmd,
                "_difficulty": difficulty,
            }

        stdout_lines = proc.stdout.splitlines()
        stderr_lines = proc.stderr.splitlines()

        injection_detected = False
        metachar_in_args = _has_shell_metachar(args)
        extra_output = len(stdout_lines) > 1 and metachar_in_args
        unexpected_cmd = proc.returncode == 0 and metachar_in_args and extra_output

        if difficulty == "easy" and metachar_in_args and proc.returncode == 0:
            injection_detected = True

        dangerous_base = (
            difficulty == "medium"
            and base_word in _DANGEROUS_BASE_COMMANDS
            and proc.returncode == 0
        )

        response: dict = {
            "exec_id": exec_id,
            "base_cmd": base_cmd,
            "args": args,
            "cmd_executed": cmd_string,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "_signals": {
                "injection_detected": injection_detected or dangerous_base,
                "metachar_in_args": metachar_in_args,
                "dangerous_base_used": dangerous_base,
                "args_were_quoted": difficulty in ("medium", "hard"),
                "allowlist_enforced": difficulty == "hard",
            },
            "_difficulty": difficulty,
        }

        if injection_detected or dangerous_base:
            response["flag"] = FLAG

        return response
