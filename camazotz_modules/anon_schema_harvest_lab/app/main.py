"""Anonymous Tool Schema Over-Disclosure lab — MCP-T50.

Simulates a server whose ``tools/list`` endpoint (which the MCP spec requires
to work without authentication) leaks sensitive architectural details in tool
descriptions and parameter schemas.  An anonymous caller can harvest internal
service hostnames, credential parameter names, bearer-token patterns, and
internal URIs without ever authenticating.

All credentials, hostnames, and paths are FAKE.
"""

from __future__ import annotations

import re

from camazotz_modules.base import LabModule

FLAG = "CZTZ{MCP-T50_4n0n_sch3m4_0v3r_d1scl0sur3}"

# Credential pattern scanner: matches cztz- prefixed tokens and CZTZ_ env vars.
CREDENTIAL_RE = re.compile(r"cztz-[a-zA-Z0-9\-]+|CZTZ_[A-Z_0-9]+")

# ---------------------------------------------------------------------------
# Simulated tool catalogs
# ---------------------------------------------------------------------------

VERBOSE_CATALOG = [
    {
        "name": "admin.reset_credentials",
        "description": (
            "Reset service credentials for the internal auth subsystem. "
            "Accepts bearer token in the format cztz-svc-bearer-abc123. "
            "Calls http://internal.corp/api/v2/secrets to rotate keys. "
            "See docs/internal/CZTZ-DEPLOY.md for usage."
        ),
    },
    {
        "name": "data.query_records",
        "description": (
            "Query internal records from the backend datastore. "
            "Requires CZTZ_SERVICE_KEY for authentication against the "
            "internal records API at http://internal.corp/api/v2/records."
        ),
    },
    {
        "name": "config.get_settings",
        "description": (
            "Retrieve service configuration from the config plane. "
            "Requires CZTZ_ADMIN_TOKEN in the Authorization header. "
            "Internal config path: /workspace/brain_gateway/app/modules/config.py"
        ),
    },
    {
        "name": "deploy.push_artifact",
        "description": (
            "Push a build artifact to the deployment pipeline. "
            "Auth header must contain cztz-deploy-key-prod-9f8e7d. "
            "Endpoint: http://internal.corp/api/v2/deploy"
        ),
    },
]

SANITIZED_CATALOG = [
    {
        "name": "service.reset",
        "description": "Reset the service to its default state.",
    },
    {
        "name": "data.query",
        "description": "Query data from the service.",
    },
    {
        "name": "config.get",
        "description": "Retrieve current configuration.",
    },
    {
        "name": "service.deploy",
        "description": "Deploy a build artifact.",
    },
]


class AnonSchemaHarvestLab(LabModule):
    name = "anon_schema_harvest"
    threat_id = "MCP-T50"
    title = "Anonymous Tool Schema Over-Disclosure"
    category = "information_disclosure"

    def tools(self) -> list[dict]:
        return [
            {
                "name": "schema.list_surface",
                "description": (
                    "Return the simulated MCP tool catalog. "
                    "No authentication required — mirrors the MCP spec requirement "
                    "that tools/list is accessible anonymously."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "schema.extract_credentials",
                "description": (
                    "Scan a tool description string for credential patterns: "
                    "bearer tokens, API keys, internal URIs, or cztz-/CZTZ_ prefixed strings."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["description"],
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Tool description text to scan for credential patterns.",
                            "maxLength": 4096,
                        }
                    },
                },
            },
            {
                "name": "schema.probe_error",
                "description": (
                    "Send a deliberately malformed argument to a named tool to "
                    "observe the error response structure."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["tool_name", "bad_arg"],
                    "properties": {
                        "tool_name": {
                            "type": "string",
                            "description": "Name of the tool to probe.",
                            "maxLength": 256,
                        },
                        "bad_arg": {
                            "type": "string",
                            "description": "Malformed argument value to send.",
                            "maxLength": 512,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "schema.list_surface":
            return self._list_surface()
        if name == "schema.extract_credentials":
            return self._extract_credentials(arguments)
        if name == "schema.probe_error":
            return self._probe_error(arguments)
        return None

    # -- tool handlers --------------------------------------------------------

    def _list_surface(self) -> dict:
        if self.difficulty in ("easy", "medium"):
            catalog = VERBOSE_CATALOG
        else:
            catalog = SANITIZED_CATALOG
        return {
            "tools": catalog,
            "_difficulty": self.difficulty,
        }

    def _extract_credentials(self, arguments: dict) -> dict:
        description = arguments.get("description", "")
        matches = CREDENTIAL_RE.findall(description)
        credential_present = bool(matches)
        result: dict = {
            "patterns_found": matches,
            "credential_present": credential_present,
            "_difficulty": self.difficulty,
        }
        if credential_present:
            result["flag"] = FLAG
        return result

    def _probe_error(self, arguments: dict) -> dict:
        if self.difficulty in ("easy", "medium"):
            return {
                "error": "invalid argument type for tool",
                "internal_path": "/workspace/brain_gateway/app/modules/",
                "config_key": "CZTZ_SECRET_SEED",
                "stack_hint": "KeyError in dispatch at line 84",
                "_difficulty": self.difficulty,
            }
        return {
            "error": "invalid argument",
            "_difficulty": self.difficulty,
        }
