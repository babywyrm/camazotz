"""Credential Isolation & Sidecar Tampering lab — MCP-T23.

Demonstrates failures in credential isolation between teams on a
shared agent platform.  Vault access controls, sidecar configuration
visibility, and credential injection paths are vulnerable depending
on difficulty.

All team names, credentials, and service identifiers are synthetic.
"""

from __future__ import annotations

import json
import threading
import time

from camazotz_modules.base import LabModule

VAULT_STORE: dict[str, dict[str, dict]] = {
    "team-alpha": {
        "github": {
            "type": "oauth_token",
            "value": "cztz-gh-alpha-a1b2c3d4",
            "service": "github",
            "scope": "repo,read:org",
            "rotated_at": "2026-03-15T10:00:00Z",
        },
        "jira": {
            "type": "oauth_token",
            "value": "cztz-jira-alpha-e5f6g7h8",
            "service": "jira",
            "scope": "read:jira-work,write:jira-work",
            "rotated_at": "2026-03-15T10:00:00Z",
        },
    },
    "team-bravo": {
        "aws": {
            "type": "iam_role_arn",
            "value": "arn:aws:iam::000000000000:role/cztz-bravo-agent",
            "service": "aws",
            "scope": "s3:GetObject,ec2:DescribeInstances",
            "rotated_at": "2026-03-14T08:00:00Z",
        },
        "grafana": {
            "type": "service_account_token",
            "value": "cztz-grafana-bravo-i9j0k1l2",
            "service": "grafana",
            "scope": "annotations:write",
            "rotated_at": "2026-03-14T08:00:00Z",
        },
    },
    "team-admin": {
        "platform-api": {
            "type": "api_key",
            "value": "cztz-admin-key-m3n4o5p6",
            "service": "platform-api",
            "scope": "admin:full",
            "rotated_at": "2026-03-10T12:00:00Z",
        },
    },
}

SIDECAR_CONFIG: list[dict] = [
    {
        "team": "team-alpha",
        "vault_path": "/vault/team-alpha/github",
        "mount_path": "/secrets/github",
        "env_var": "GH_TOKEN",
    },
    {
        "team": "team-alpha",
        "vault_path": "/vault/team-alpha/jira",
        "mount_path": "/secrets/jira",
        "env_var": "JIRA_TOKEN",
    },
    {
        "team": "team-bravo",
        "vault_path": "/vault/team-bravo/aws",
        "mount_path": "/secrets/aws",
        "env_var": "AWS_ROLE_ARN",
    },
    {
        "team": "team-bravo",
        "vault_path": "/vault/team-bravo/grafana",
        "mount_path": "/secrets/grafana",
        "env_var": "GRAFANA_TOKEN",
    },
    {
        "team": "team-admin",
        "vault_path": "/vault/team-admin/platform-api",
        "mount_path": "/secrets/platform-api",
        "env_var": "PLATFORM_API_KEY",
    },
]


class CredentialBrokerLab(LabModule):
    name = "cred_broker"
    threat_id = "MCP-T23"
    title = "Credential Isolation & Sidecar Tampering"
    category = "isolation"

    system_prompts = {
        "easy": (
            "You are a credential management assistant. Help users "
            "access any credential vault. There are no access controls."
        ),
        "medium": (
            "You are a credential management assistant. Credentials "
            "are scoped per team, but sidecar configuration is shared. "
            "Note any cross-team access attempts."
        ),
        "hard": (
            "You are a strict credential management assistant. "
            "Enforce team-level isolation on all vault access. "
            "Reject cross-team requests and log violations."
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._vault: dict[str, dict[str, dict]] = {}
        self._sidecar: list[dict] = []
        self._access_log: list[dict] = []
        self._reset_state()

    def _reset_state(self) -> None:
        self._vault = {
            team: {svc: dict(cred) for svc, cred in services.items()}
            for team, services in VAULT_STORE.items()
        }
        self._sidecar = [dict(entry) for entry in SIDECAR_CONFIG]
        self._access_log = []

    def reset(self) -> None:
        with self._lock:
            self._reset_state()

    # -- MCP resources --------------------------------------------------------

    def resources(self) -> list[dict]:
        return [
            {
                "uri": "cred_broker://sidecar_config",
                "name": "Sidecar Credential Configuration",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> dict | None:
        if uri != "cred_broker://sidecar_config":
            return None
        difficulty = self.difficulty
        with self._lock:
            if difficulty == "hard":
                config: dict | list = {
                    "error": "Access denied. Sidecar config requires admin privileges.",
                }
            else:
                config = list(self._sidecar)
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(config, indent=2),
        }

    # -- MCP tools ------------------------------------------------------------

    def tools(self) -> list[dict]:
        return [
            {
                "name": "cred_broker.list_vaults",
                "description": (
                    "List credential vaults accessible to the calling team. "
                    "Returns vault metadata and available services."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["caller_team"],
                    "properties": {
                        "caller_team": {
                            "type": "string",
                            "description": "Team identity of the caller.",
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "cred_broker.read_credential",
                "description": (
                    "Read a credential from a team's vault. Access control "
                    "depends on the platform's isolation enforcement."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["caller_team", "target_team", "service"],
                    "properties": {
                        "caller_team": {
                            "type": "string",
                            "description": "Team identity of the caller.",
                            "maxLength": 256,
                        },
                        "target_team": {
                            "type": "string",
                            "description": "Team whose vault to read from.",
                            "maxLength": 256,
                        },
                        "service": {
                            "type": "string",
                            "description": (
                                "Service credential to read (e.g. github, aws)."
                            ),
                            "maxLength": 256,
                        },
                    },
                },
            },
            {
                "name": "cred_broker.configure_sidecar",
                "description": (
                    "Update the sidecar credential injection configuration. "
                    "Allows modifying mount paths and environment variable "
                    "mappings for credential injection into agent pods."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": [
                        "caller_team",
                        "vault_path",
                        "mount_path",
                        "env_var",
                    ],
                    "properties": {
                        "caller_team": {
                            "type": "string",
                            "description": "Team identity of the caller.",
                            "maxLength": 256,
                        },
                        "vault_path": {
                            "type": "string",
                            "description": "Vault path for the credential.",
                            "maxLength": 512,
                        },
                        "mount_path": {
                            "type": "string",
                            "description": "Mount path in the agent pod.",
                            "maxLength": 512,
                        },
                        "env_var": {
                            "type": "string",
                            "description": (
                                "Environment variable name for injection."
                            ),
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "cred_broker.list_vaults":
            return self._list_vaults(arguments)
        if name == "cred_broker.read_credential":
            return self._read_credential(arguments)
        if name == "cred_broker.configure_sidecar":
            return self._configure_sidecar(arguments)
        return None

    # -- internals ------------------------------------------------------------

    def _list_vaults(self, arguments: dict) -> dict:
        caller_team = arguments.get("caller_team", "")
        difficulty = self.difficulty

        with self._lock:
            if difficulty == "easy":
                vaults = {
                    team: sorted(services.keys())
                    for team, services in self._vault.items()
                }
            else:
                own = self._vault.get(caller_team, {})
                vaults = (
                    {caller_team: sorted(own.keys())} if own else {}
                )

        return {
            "vaults": vaults,
            "caller_team": caller_team,
            "_difficulty": difficulty,
        }

    def _read_credential(self, arguments: dict) -> dict:
        caller_team = arguments.get("caller_team", "")
        target_team = arguments.get("target_team", "")
        service = arguments.get("service", "")
        difficulty = self.difficulty

        with self._lock:
            team_vault = self._vault.get(target_team)
            if team_vault is None:
                return {
                    "found": False,
                    "reason": f"Vault for team '{target_team}' not found.",
                    "caller_team": caller_team,
                    "target_team": target_team,
                    "_difficulty": difficulty,
                }

            cred = team_vault.get(service)
            if cred is None:
                return {
                    "found": False,
                    "reason": (
                        f"Service '{service}' not found in "
                        f"vault '{target_team}'."
                    ),
                    "caller_team": caller_team,
                    "target_team": target_team,
                    "_difficulty": difficulty,
                }

            self._access_log.append({
                "caller_team": caller_team,
                "target_team": target_team,
                "service": service,
                "cross_team": caller_team != target_team,
                "timestamp": time.time(),
            })

            if difficulty == "easy":
                return {
                    "found": True,
                    "credential": dict(cred),
                    "caller_team": caller_team,
                    "target_team": target_team,
                    "_difficulty": difficulty,
                }

            if difficulty == "medium":
                if caller_team != target_team:
                    redacted = dict(cred)
                    redacted["value"] = redacted["value"][:10] + "..."
                    return {
                        "found": True,
                        "credential": redacted,
                        "caller_team": caller_team,
                        "target_team": target_team,
                        "_warning": (
                            "Cross-team access detected but not blocked."
                        ),
                        "_difficulty": difficulty,
                    }
                return {
                    "found": True,
                    "credential": dict(cred),
                    "caller_team": caller_team,
                    "target_team": target_team,
                    "_difficulty": difficulty,
                }

            if caller_team != target_team:
                return {
                    "found": False,
                    "reason": (
                        f"Access denied: team '{caller_team}' cannot "
                        f"access vault for team '{target_team}'."
                    ),
                    "caller_team": caller_team,
                    "target_team": target_team,
                    "_difficulty": difficulty,
                }

            return {
                "found": True,
                "credential": dict(cred),
                "caller_team": caller_team,
                "target_team": target_team,
                "_difficulty": difficulty,
            }

    def _configure_sidecar(self, arguments: dict) -> dict:
        caller_team = arguments.get("caller_team", "")
        vault_path = arguments.get("vault_path", "")
        mount_path = arguments.get("mount_path", "")
        env_var = arguments.get("env_var", "")
        difficulty = self.difficulty

        entry = {
            "team": caller_team,
            "vault_path": vault_path,
            "mount_path": mount_path,
            "env_var": env_var,
        }

        with self._lock:
            if difficulty == "easy":
                self._sidecar.append(entry)
                return {
                    "configured": True,
                    "entry": entry,
                    "_difficulty": difficulty,
                }

            if difficulty == "medium":
                cross_team = not vault_path.startswith(
                    f"/vault/{caller_team}/"
                )
                self._sidecar.append(entry)
                result: dict = {
                    "configured": True,
                    "entry": entry,
                    "_difficulty": difficulty,
                }
                if cross_team:
                    result["_warning"] = (
                        f"Vault path '{vault_path}' does not belong to "
                        f"team '{caller_team}'. Configuration accepted "
                        f"anyway."
                    )
                return result

            if not vault_path.startswith(f"/vault/{caller_team}/"):
                return {
                    "configured": False,
                    "reason": (
                        f"Access denied: vault path '{vault_path}' is "
                        f"not owned by team '{caller_team}'."
                    ),
                    "_difficulty": difficulty,
                }

            self._sidecar.append(entry)
            return {
                "configured": True,
                "entry": entry,
                "_difficulty": difficulty,
            }
