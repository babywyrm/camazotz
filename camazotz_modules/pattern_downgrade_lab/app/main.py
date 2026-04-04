"""Authentication Pattern Downgrade lab — MCP-T24.

Demonstrates attacks that force an agent platform to fall back from
user-delegation (Pattern A) to service-account auth (Pattern B),
losing per-user traceability.

On easy the pattern is a client-controlled parameter.  On medium
the server chooses but a crafted capability response tricks it.
On hard the selection is server-side but not logged when overridden.

All service names and capabilities are synthetic.
"""

from __future__ import annotations

import json
import threading

from camazotz_modules.base import LabModule

SERVICE_CAPABILITIES: dict[str, dict] = {
    "github": {
        "name": "github",
        "oauth_supported": True,
        "token_type": "oauth_user",
        "preferred_pattern": "A",
    },
    "jira": {
        "name": "jira",
        "oauth_supported": True,
        "token_type": "oauth_user",
        "preferred_pattern": "A",
    },
    "grafana": {
        "name": "grafana",
        "oauth_supported": False,
        "token_type": "service_account",
        "preferred_pattern": "B",
    },
    "internal-api": {
        "name": "internal-api",
        "oauth_supported": False,
        "token_type": "mtls",
        "preferred_pattern": "B",
    },
}


class PatternDowngradeLab(LabModule):
    name = "downgrade"
    threat_id = "MCP-T24"
    title = "Authentication Pattern Downgrade"
    category = "authentication"

    system_prompts = {
        "easy": (
            "You are an authentication pattern selector. Accept the "
            "pattern the client requests without validation."
        ),
        "medium": (
            "You are an authentication pattern selector. Choose the "
            "pattern based on service capabilities, but trust the "
            "capability data provided in the request."
        ),
        "hard": (
            "You are a strict authentication pattern selector. Always "
            "use the server's authoritative capability data. Never "
            "trust client-supplied capability overrides."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._pattern_log: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._pattern_log = []

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        return [
            {
                "uri": "downgrade://pattern_log",
                "name": "Pattern Selection Log",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> dict | None:
        if uri != "downgrade://pattern_log":
            return None
        with self._lock:
            snapshot = list(self._pattern_log)
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(snapshot, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "downgrade.check_pattern",
                "description": (
                    "Query which authentication pattern will be used "
                    "for a given service."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["service"],
                    "properties": {
                        "service": {
                            "type": "string",
                            "description": "Target service name.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "downgrade.authenticate",
                "description": (
                    "Trigger authentication to a downstream service. "
                    "The authentication pattern is selected based on "
                    "service capabilities and difficulty."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["service", "principal"],
                    "properties": {
                        "service": {
                            "type": "string",
                            "description": "Target service name.",
                            "maxLength": 256,
                        },
                        "principal": {
                            "type": "string",
                            "description": "Requesting principal email.",
                            "maxLength": 256,
                        },
                        "force_pattern": {
                            "type": "string",
                            "description": (
                                "Force a specific pattern (A or B). "
                                "Honored on easy difficulty only."
                            ),
                            "maxLength": 8,
                        },
                        "capability_override": {
                            "type": "object",
                            "description": (
                                "Override service capabilities. "
                                "Honored on medium difficulty."
                            ),
                            "properties": {
                                "oauth_supported": {"type": "boolean"},
                            },
                        },
                    },
                },
            },
            {
                "name": "downgrade.list_capabilities",
                "description": (
                    "List service OAuth capabilities. The returned "
                    "data may be tampered with on medium difficulty."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "service": {
                            "type": "string",
                            "description": (
                                "Optional service filter. "
                                "Omit for all services."
                            ),
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "downgrade.check_pattern":
            return self._check_pattern(arguments)
        if name == "downgrade.authenticate":
            return self._authenticate(arguments)
        if name == "downgrade.list_capabilities":
            return self._list_capabilities(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _check_pattern(self, arguments: dict) -> dict:
        service_name = arguments.get("service", "")
        svc = SERVICE_CAPABILITIES.get(service_name)
        if svc is None:
            return {
                "found": False,
                "service": service_name,
                "_difficulty": self.difficulty,
            }
        return {
            "found": True,
            "service": service_name,
            "pattern": svc["preferred_pattern"],
            "oauth_supported": svc["oauth_supported"],
            "_difficulty": self.difficulty,
        }

    def _authenticate(self, arguments: dict) -> dict:
        service_name = arguments.get("service", "")
        principal = arguments.get("principal", "")
        force_pattern = arguments.get("force_pattern", "")
        capability_override = arguments.get("capability_override") or {}
        difficulty = self.difficulty

        svc = SERVICE_CAPABILITIES.get(service_name)
        if svc is None:
            return {
                "authenticated": False,
                "reason": f"Service '{service_name}' not found.",
                "_difficulty": difficulty,
            }

        if difficulty == "easy":
            pattern = force_pattern if force_pattern in ("A", "B") else svc["preferred_pattern"]
        elif difficulty == "medium":
            oauth = capability_override.get(
                "oauth_supported", svc["oauth_supported"],
            )
            pattern = "A" if oauth else "B"
        else:
            pattern = svc["preferred_pattern"]

        downgraded = (
            svc["preferred_pattern"] == "A" and pattern == "B"
        )

        log_entry = {
            "service": service_name,
            "principal": principal,
            "selected_pattern": pattern,
            "preferred_pattern": svc["preferred_pattern"],
            "downgraded": downgraded,
            "force_pattern": force_pattern or None,
            "capability_override": capability_override or None,
        }
        with self._lock:
            self._pattern_log.append(log_entry)

        result: dict = {
            "authenticated": True,
            "service": service_name,
            "principal": principal,
            "pattern_used": pattern,
            "token_type": (
                "oauth_user" if pattern == "A" else "service_account"
            ),
            "_difficulty": difficulty,
        }
        if downgraded:
            result["_warning"] = (
                f"Downgraded from Pattern A to B for '{service_name}'. "
                f"Per-user traceability is lost."
            )
        return result

    def _list_capabilities(self, arguments: dict) -> dict:
        service_filter = arguments.get("service", "")

        if service_filter:
            svc = SERVICE_CAPABILITIES.get(service_filter)
            if svc is None:
                return {
                    "services": {},
                    "count": 0,
                    "_difficulty": self.difficulty,
                }
            return {
                "services": {service_filter: dict(svc)},
                "count": 1,
                "_difficulty": self.difficulty,
            }

        return {
            "services": {
                name: dict(svc)
                for name, svc in SERVICE_CAPABILITIES.items()
            },
            "count": len(SERVICE_CAPABILITIES),
            "_difficulty": self.difficulty,
        }
