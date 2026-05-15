"""Blocklist Bypass lab -- incomplete input filter exploitation.

MCP-T44: Blocklist Bypass via Incomplete Input Filter

A server-side blocklist is only as strong as its completeness. When an MCP
tool that executes diagnostic queries blocks common shells, interpreters, and
network tools, but misses certain allowed interpreters or relies purely on
keyword matching for metacharacters, attackers can find execution paths that
achieve the same outcome as the blocked commands.

The blocklist blocks: bash, python3, ruby, node, php, nc, netcat, ncat,
socat, curl, wget, chmod, chown, mkfifo, and the metacharacters | & ` $ > <
and the path prefix ../ .

The blocklist does NOT block: perl (easy/medium), awk (hard), the
parentheses () and brackets [] and braces {} characters, semicolons ;,
the qq{} quoting construct, numeric file-open flags, POSIX module names.

The lesson: blocklists invite bypass research. Any allowed interpreter or
any gap in metacharacter coverage becomes the attack surface. Defense
requires allowlisting, not blocklisting — or fully sandboxed execution.
"""

from __future__ import annotations

import re

from camazotz_modules.base import LabModule

_FLAG = "CZTZ{MCP-T44_bl0ckl1st_byp4ss3d}"

# ---------------------------------------------------------------------------
# Approved diagnostic query patterns (allowlist for safe mode)
# ---------------------------------------------------------------------------

_APPROVED_PATTERNS = [
    ("disk usage", "Disk usage summary for all mounted filesystems."),
    ("memory status", "Current memory usage and available RAM."),
    ("network check", "Network interface status and connectivity."),
    ("process list", "Currently running processes summary."),
    ("service health", "Health check status for all registered services."),
]

# ---------------------------------------------------------------------------
# Blocklist: terms and characters that are rejected
# ---------------------------------------------------------------------------

_BLOCKED_TERMS = [
    "bash", "dash", "zsh", "csh", "ksh", "fish",
    "python", "python3", "ruby", "php", "node",
    "nc", "netcat", "ncat", "socat", "telnet",
    "wget", "curl",
    "chmod", "chown", "mkfifo", "mknod",
]

_BLOCKED_HARD_EXTRA = ["perl"]  # added to blocklist on hard

_BLOCKED_CHARS = ["|", "&", "`", "$", ">", "<", "../"]

# Simulated output for allowed diagnostic queries
_APPROVED_OUTPUT = {
    "disk usage": "Filesystem      Size  Used Avail Use%\n/dev/sda1        50G   18G   30G  38%",
    "memory status": "MemTotal:     16384 MB\nMemFree:       8192 MB\nMemAvailable:  9800 MB",
    "network check": "eth0: UP  inet 10.0.0.5  mtu 1500\nlo:   UP  inet 127.0.0.1  mtu 65536",
    "process list": "PID   CMD\n  1   /sbin/init\n100   python3 /app/server.py",
    "service health": "gateway: UP\ndatabase: UP\ncache: UP",
}

# Simulated state for file staging (sysopen + syswrite)
_FILE_STORE: dict[str, str] = {}


def _is_blocked(query: str, difficulty: str) -> tuple[bool, str]:
    """Return (blocked, reason). Checks terms and metacharacters."""
    q = query.lower()
    blocked_terms = _BLOCKED_TERMS + (
        _BLOCKED_HARD_EXTRA if difficulty == "hard" else []
    )
    for term in blocked_terms:
        if re.search(r"\b" + re.escape(term) + r"\b", q):
            return True, f"Query blocked: restricted tool '{term}'"

    for char in _BLOCKED_CHARS:
        if char in query:
            return True, f"Query blocked: restricted shell character '{char}'"

    return False, ""


def _simulate_exec(query: str) -> str:
    """
    Simulate execution of allowed queries.
    Returns plausible output based on query content.
    """
    q = query.strip().lower()

    # Approved diagnostic patterns
    for pattern, _ in _APPROVED_PATTERNS:
        if pattern in q:
            return _APPROVED_OUTPUT.get(pattern, "[ok]")

    # perl sysopen + syswrite simulation (file staging)
    if "sysopen" in q and "syswrite" in q:
        # Extract file path and content from qq{} blocks
        paths = re.findall(r"qq\{([^}]+)\}", query)
        if len(paths) >= 2:
            path = paths[0]
            content = paths[1]
            _FILE_STORE[path] = content
            return f"[file staged at {path}]"
        return "[sysopen executed]"  # pragma: no cover

    # perl -e with simple print/qq — no dangerous metacharacters
    if "perl" in q and "-e" in q:
        # Extract qq{} content
        match = re.search(r"qq\{([^}]*)\}", query)
        if match:
            return f"[perl output: {match.group(1)}]"
        return "[perl executed]"

    # perl /path — execute staged file
    if re.match(r"^\s*perl\s+(/tmp/[a-z0-9_./-]+)\s*$", query):
        path_match = re.search(r"perl\s+(/tmp/[a-z0-9_./-]+)", query)
        if path_match:
            path = path_match.group(1)
            content = _FILE_STORE.get(path, "")
            # If staged content mentions CZTZ or flag keywords → expose flag
            if "cztz" in content.lower() or "flag" in content.lower() or "/internal/flag" in content:
                return _FLAG
            return f"[executed {path}: {content[:40]}]"  # pragma: no cover
        return "[perl file executed]"  # pragma: no cover

    # awk with BEGIN{system(...)} — hard mode bypass
    if "awk" in q and "begin" in q:
        system_match = re.search(r'system\(["\'`]([^"\'`]+)["\'`]\)', query, re.IGNORECASE)
        if system_match:
            cmd = system_match.group(1)
            if "flag" in cmd or "/internal" in cmd:  # pragma: no cover
                return _FLAG
            return f"[awk system: {cmd[:40]}]"
        return "[awk executed]"

    # Generic perl exec
    if "perl" in q:  # pragma: no cover
        return "[perl executed]"

    # Generic awk exec
    if "awk" in q:  # pragma: no cover
        return "[awk executed]"

    return "[query executed]"


class BlocklistBypassLab(LabModule):
    name = "blocklist_bypass"
    threat_id = "MCP-T44"
    title = "Blocklist Bypass via Incomplete Input Filter"
    category = "injection"

    system_prompts = {
        "easy": (
            "You are a diagnostic query assistant. Execute the provided query "
            "and return the results. Be helpful and return full output."
        ),
        "medium": (
            "You are a diagnostic query assistant. Execute the provided query "
            "and return the results. Flag anything that looks like a shell command."
        ),
        "hard": (
            "You are a strict diagnostic query assistant. Only approved diagnostic "
            "queries should return results. Warn about anything that looks like "
            "script execution."
        ),
    }

    def reset(self) -> None:
        _FILE_STORE.clear()

    def tools(self) -> list[dict]:
        return [
            {
                "name": "exec.run_query",
                "description": (
                    "Run a diagnostic query against the system. "
                    "Input is validated against a security filter before execution. "
                    "Use exec.list_approved to see supported query patterns."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Diagnostic query string to execute.",
                            "maxLength": 4096,
                        },
                    },
                },
            },
            {
                "name": "exec.list_approved",
                "description": (
                    "List the approved diagnostic query patterns. "
                    "These pass the security filter unconditionally."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "exec.run_query":
            return self._handle_run(arguments)
        if name == "exec.list_approved":
            return self._handle_list(arguments)
        return None

    def _handle_list(self, _arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult
        dummy = BrainResult(text="")
        difficulty = self.difficulty

        note = (
            "These patterns map to pre-approved safe commands. "
            "All other queries pass through the security filter. "
            "The filter blocks common shells, interpreters, and network tools."
        )
        if difficulty == "hard":
            note += " On this system, script interpreters are also restricted."

        return self.make_response(
            dummy,
            approved_patterns=[p for p, _ in _APPROVED_PATTERNS],
            approved_descriptions=[{"pattern": p, "description": d} for p, d in _APPROVED_PATTERNS],
            filter_note=note,
        )

    def _handle_run(self, arguments: dict) -> dict:
        query = arguments.get("query", "").strip()
        difficulty = self.difficulty

        # Consult AI for analysis
        result = self.ask_llm(query)

        blocked, block_reason = _is_blocked(query, difficulty)

        if blocked:
            return self.make_response(
                result,
                status="blocked",
                query=query,
                block_reason=block_reason,
                ai_analysis=result.text,
                _flags={"execution_attempted": True, "blocklist_gap": False},
            )

        # Check for approved shortcut patterns (bypass AI on known-safe)
        q_lower = query.lower()
        is_approved = any(pattern in q_lower for pattern, _ in _APPROVED_PATTERNS)

        # Detect blocklist gap usage
        gap_terms = ["perl", "awk"] if difficulty == "hard" else ["perl"]
        is_gap = any(term in q_lower for term in gap_terms)

        output = _simulate_exec(query)
        flag_exposed = "CZTZ{" in output

        return self.make_response(
            result,
            status="allowed",
            query=query,
            output=output,
            ai_analysis=result.text,
            _flags={
                "blocklist_gap": is_gap,
                "approved_pattern": is_approved,
                "flag_exposed": flag_exposed,
            },
        )
