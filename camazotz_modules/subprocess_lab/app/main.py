"""Subprocess Credential Inheritance lab.

MCP-T34: Lane 3 (Machine Identity) / Transport D (Subprocess / native binary).

A machine-identity agent invokes a child worker process to perform a task.
The child inherits the parent's environment by default; without curating the
inherited env and validating argv, the parent's secrets and shell metacharacters
become an attack surface.

Threat surface (per ADR 0001 / Transport D):
  1. Argv injection (shell=True with user-controlled string interpolation)
  2. Environment variable leakage to child (parent secrets in os.environ)
  3. Operation drift (child invoked with unintended subcommand)

Difficulty progression:
  easy   — shell=True + raw concat + full env passthrough  (all 3 succeed)
  medium — args list + shlex split + full env passthrough  (env leak only)
  hard   — args list + arg allowlist + curated minimal env (all 3 blocked)
"""

from __future__ import annotations

import ast
import os
import shlex
import subprocess
import sys
import threading

from camazotz_modules.base import LabModule

# Mock secrets representing what a real CI runner / agent might have in its
# environment.  Injected into every subprocess call's env so the test bench
# (and the lab solver) can deterministically observe the leakage.
_MOCK_SECRETS: dict[str, str] = {
    "MOCK_AWS_SECRET_ACCESS_KEY": "AKIA-cztz-mock-aws-secret-FAKE",
    "MOCK_K8S_BEARER_TOKEN": "cztz-mock-k8s-bearer-FAKE-12345",
    "MOCK_GITHUB_TOKEN": "ghp_cztz_mock_github_token_FAKE",
    "MOCK_TELEPORT_CERT_PATH": "/tmp/cztz-mock-teleport.crt",
}

# What the child process prints — a Python literal that the lab parses with
# ast.literal_eval.  Avoiding json.dumps inside the -c snippet keeps the
# quoting tractable across shells.
_WORKER_SCRIPT = (
    "import os, sys; "
    "print({"
    "'argv': sys.argv, "
    "'env_keys': sorted(os.environ.keys()), "
    "'mock_secrets_visible': "
    "{k: os.environ[k] for k in os.environ if k.startswith('MOCK_')}"
    "})"
)

# Operations the worker formally supports.  Only these pass the hard-mode
# allowlist; on easy/medium any string is accepted and the model relies on
# the worker to figure it out (i.e. no allowlist).
_ALLOWLISTED_OPERATIONS: frozenset[str] = frozenset({"status", "list"})

# Curated environment for hard mode.  Only what the child genuinely needs.
_CURATED_ENV: dict[str, str] = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}

# Bound the subprocess execution to keep test runs fast and deny long-running
# attacker payloads.
_SUBPROCESS_TIMEOUT_SEC = 5


class SubprocessLab(LabModule):
    name = "subprocess"
    threat_id = "MCP-T34"
    title = "Subprocess Credential Inheritance"
    category = "machine-identity"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._invocation_count = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "subprocess.invoke_worker",
                "description": (
                    "Invoke a child worker process to perform an operation.  "
                    "The worker reports its argv and inherited environment in "
                    "the response — useful for observing what the parent "
                    "process leaked across the fork boundary."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["operation"],
                    "properties": {
                        "operation": {
                            "type": "string",
                            "description": (
                                "Operation name passed to the worker.  On hard "
                                "difficulty must be one of the allowlisted "
                                "operations from subprocess.list_allowlist."
                            ),
                            "maxLength": 256,
                        },
                        "extra_args": {
                            "type": "string",
                            "description": (
                                "Extra arguments appended to the worker invocation. "
                                "On easy difficulty this is concatenated into a "
                                "shell command — beware shell metacharacters."
                            ),
                            "default": "",
                            "maxLength": 1024,
                        },
                    },
                },
            },
            {
                "name": "subprocess.list_allowlist",
                "description": (
                    "Return the set of operations the worker will accept on "
                    "hard difficulty.  Useful for understanding what the "
                    "deployed defense permits."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "subprocess.invoke_worker":
            return self._invoke_worker(arguments)
        if name == "subprocess.list_allowlist":
            return self._list_allowlist()
        return None

    def reset(self) -> None:
        with self._lock:
            self._invocation_count = 0

    # -- internals ------------------------------------------------------------

    def _list_allowlist(self) -> dict:
        return {
            "allowlisted_operations": sorted(_ALLOWLISTED_OPERATIONS),
            "enforced_on_difficulty": "hard",
            "_difficulty": self.difficulty,
        }

    def _invoke_worker(self, arguments: dict) -> dict:
        operation = arguments.get("operation", "")
        extra_args = arguments.get("extra_args", "")
        difficulty = self.difficulty

        with self._lock:
            self._invocation_count += 1
            invocation_id = self._invocation_count

        # Build the env we'll hand to the child.  On easy and medium we
        # passthrough os.environ + the mock secrets (simulating a real CI
        # runner where AWS_*, GITHUB_*, KUBE_* live alongside everything else).
        # On hard we curate aggressively.
        if difficulty == "hard":
            child_env = dict(_CURATED_ENV)
        else:
            child_env = dict(os.environ)
            child_env.update(_MOCK_SECRETS)

        # Hard-mode allowlist + arg sanitization.  Returned before any exec
        # so the child never starts on rejected input.
        if difficulty == "hard":
            if operation not in _ALLOWLISTED_OPERATIONS:
                return {
                    "access": "denied",
                    "reason": (
                        f"Operation '{operation}' not in allowlist "
                        f"{sorted(_ALLOWLISTED_OPERATIONS)}"
                    ),
                    "operation": operation,
                    "_difficulty": difficulty,
                }
            if extra_args:
                return {
                    "access": "denied",
                    "reason": "extra_args not permitted in hard mode",
                    "operation": operation,
                    "_difficulty": difficulty,
                }

        # Build and run the command per difficulty.
        try:
            if difficulty == "easy":
                # UNSAFE pattern: string interpolation + shell=True.
                # extra_args lands directly in the shell after the python -c
                # invocation.  An attacker who supplies '; echo PWNED' gets
                # arbitrary command execution.
                cmd = (
                    f'{shlex.quote(sys.executable)} -c '
                    f'{shlex.quote(_WORKER_SCRIPT)} {operation} {extra_args}'
                )
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    env=child_env,
                    timeout=_SUBPROCESS_TIMEOUT_SEC,
                )
            else:
                # Medium and hard: args list, no shell.  Argv injection blocked.
                args = [sys.executable, "-c", _WORKER_SCRIPT, operation]
                if extra_args:
                    args.extend(shlex.split(extra_args))
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    env=child_env,
                    timeout=_SUBPROCESS_TIMEOUT_SEC,
                )
        except subprocess.TimeoutExpired:
            return {
                "access": "denied",
                "reason": f"worker exceeded {_SUBPROCESS_TIMEOUT_SEC}s timeout",
                "operation": operation,
                "_difficulty": difficulty,
            }

        # Try to parse the worker's structured output.  The worker prints a
        # single-line Python dict literal; we use literal_eval to keep this
        # safe (no eval) even on tampered output.
        worker_payload: dict = {}
        try:
            # The worker's stdout may have additional lines on easy mode if a
            # shell-injection appended `; echo PWNED` — take only the first
            # well-formed dict-shaped line.
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    worker_payload = ast.literal_eval(line)
                    break
        except (ValueError, SyntaxError):
            worker_payload = {"_parse_error": proc.stdout}

        # Compute summary signals the lab solver needs.
        leaked_secrets = worker_payload.get("mock_secrets_visible", {}) or {}

        # Argv injection signal: count stdout lines that are NOT the worker's
        # structured output.  Shell injection (`; echo PWNED`) adds an extra
        # line; argv passthrough (medium) keeps PWNED inside the worker dict
        # so there are no extra lines.
        extra_lines = [
            line.strip()
            for line in proc.stdout.splitlines()
            if line.strip() and not (line.strip().startswith("{") and line.strip().endswith("}"))
        ]
        injection_detected = len(extra_lines) > 0

        return {
            "operation": operation,
            "invocation_id": invocation_id,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "worker_payload": worker_payload,
            "_signals": {
                "leaked_mock_secrets": sorted(leaked_secrets.keys()),
                "leaked_count": len(leaked_secrets),
                "argv_injection_detected": injection_detected,
                "injection_extra_output": extra_lines,
                "env_curated": difficulty == "hard",
            },
            "_difficulty": difficulty,
        }
