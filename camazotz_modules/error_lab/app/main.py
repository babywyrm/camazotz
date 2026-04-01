"""Error information disclosure lab — MCP-T11.

Deliberately leaks internal error details, tracebacks, environment
variables, and exception metadata at varying fidelity depending on the
configured difficulty level.  All credentials and paths are FAKE.
"""

from __future__ import annotations

import json
import uuid

from camazotz_modules.base import LabModule

# ---------------------------------------------------------------------------
# Fake internal data used in simulated error output
# ---------------------------------------------------------------------------

FAKE_ENV = {
    "DATABASE_URL": "postgresql://app_svc:Pr0dP@ssw0rd!@10.0.3.12:5432/camazotz_prod",
    "SECRET_KEY": "cztz-sk-8f3a1b9c7d4e6f0a2b5c8d1e4f7a0b3c",
    "REDIS_URL": "redis://:r3d1s-hunt3r2@10.0.3.14:6379/0",
    "OLLAMA_HOST": "http://127.0.0.1:11434",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SENTRY_DSN": "https://abc123@o456.ingest.sentry.io/789",
    "INTERNAL_API_TOKEN": "cztz-iat-d4e5f6a7b8c9d0e1f2a3",
}

FAKE_PACKAGES = {
    "fastapi": "0.111.0",
    "uvicorn": "0.30.1",
    "pydantic": "2.7.4",
    "httpx": "0.27.0",
    "sqlalchemy": "2.0.31",
    "alembic": "1.13.1",
    "python-jose": "3.3.0",
    "cryptography": "42.0.8",
    "camazotz-core": "1.4.2",
}

FAKE_INTERNAL_IPS = ["10.0.3.12", "10.0.3.14", "10.0.3.20", "10.0.3.1"]


def _full_traceback(module_name: str) -> str:
    return (
        f"Traceback (most recent call last):\n"
        f'  File "/opt/camazotz/brain_gateway/app/main.py", line 47, in dispatch\n'
        f"    result = registry.call(name, arguments)\n"
        f'  File "/opt/camazotz/brain_gateway/app/modules/registry.py", line 84, in call\n'
        f"    result = module.handle(name=name, arguments=arguments)\n"
        f'  File "/opt/camazotz/camazotz_modules/{module_name}/app/main.py", line 132, in handle\n'
        f"    return self._process_request(arguments)\n"
        f'  File "/opt/camazotz/camazotz_modules/{module_name}/app/main.py", line 158, in _process_request\n'
        f"    conn = sqlalchemy.create_engine(os.environ['DATABASE_URL'])\n"
        f"sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server: Connection refused\n"
        f"\tIs the server running on host \"10.0.3.12\" and accepting TCP/IP connections on port 5432?\n"
        f"\n"
        f"Connection string: {FAKE_ENV['DATABASE_URL']}\n"
        f"Environment:\n"
        f"  DATABASE_URL={FAKE_ENV['DATABASE_URL']}\n"
        f"  SECRET_KEY={FAKE_ENV['SECRET_KEY']}\n"
        f"  REDIS_URL={FAKE_ENV['REDIS_URL']}"
    )


def _partial_traceback(module_name: str) -> str:
    return (
        f"Traceback (most recent call last):\n"
        f'  File "/opt/camazotz/[REDACTED]/main.py", line 47, in dispatch\n'
        f"    result = registry.call(name, arguments)\n"
        f'  File "/opt/camazotz/[REDACTED]/registry.py", line 84, in call\n'
        f"    result = module.handle(name=name, arguments=arguments)\n"
        f"sqlalchemy.exc.OperationalError: could not connect to server\n"
        f"\n"
        f"Framework: FastAPI {FAKE_PACKAGES['fastapi']} / Uvicorn {FAKE_PACKAGES['uvicorn']}\n"
        f"Python: 3.12.4\n"
        f"Module: {module_name}"
    )


def _minimal_error() -> str:
    return f"Internal server error. Request ID: {uuid.uuid4().hex[:12]}"


def _full_debug(component: str) -> dict:
    return {
        "component": component,
        "python_version": "3.12.4",
        "platform": "linux-x86_64",
        "installed_packages": FAKE_PACKAGES,
        "environment": dict(FAKE_ENV),
        "internal_ips": FAKE_INTERNAL_IPS,
        "debug_mode": True,
        "pid": 4821,
        "hostname": "camazotz-brain-7f8b9c-xk4pl",
    }


def _partial_debug(component: str) -> dict:
    redacted_env = {}
    for k, v in FAKE_ENV.items():
        if k in ("OLLAMA_HOST",):
            redacted_env[k] = v
        else:
            redacted_env[k] = v[:4] + "****" if len(v) > 4 else "****"
    return {
        "component": component,
        "python_version": "3.12.4",
        "platform": "linux-x86_64",
        "installed_packages": FAKE_PACKAGES,
        "environment": redacted_env,
        "debug_mode": False,
    }


def _sanitized_debug(component: str) -> dict:
    return {
        "component": component,
        "python_version": "3.12",
        "status": "operational",
    }


class ErrorLab(LabModule):
    name = "error"
    threat_id = "MCP-T15"
    title = "Error Information Disclosure"
    category = "information_disclosure"

    def tools(self) -> list[dict]:
        return [
            {
                "name": "error.trigger_crash",
                "description": (
                    "Trigger a simulated crash in the specified module and "
                    "return the resulting error information."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["module_name"],
                    "properties": {
                        "module_name": {
                            "type": "string",
                            "description": "Name of the internal module to crash.",
                            "maxLength": 256,
                        }
                    },
                },
            },
            {
                "name": "error.debug_info",
                "description": (
                    "Return system debug information for the given component."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["component"],
                    "properties": {
                        "component": {
                            "type": "string",
                            "description": "Component name to inspect.",
                            "maxLength": 256,
                        }
                    },
                },
            },
            {
                "name": "error.validate_input",
                "description": (
                    "Validate input data against a schema. Returns raw "
                    "exception details when validation fails."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["data", "schema"],
                    "properties": {
                        "data": {
                            "type": "string",
                            "description": "JSON string of data to validate.",
                            "maxLength": 4096,
                        },
                        "schema": {
                            "type": "string",
                            "description": "Schema name to validate against.",
                            "maxLength": 256,
                        },
                    },
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "error.trigger_crash":
            return self._handle_trigger_crash(arguments)
        if name == "error.debug_info":
            return self._handle_debug_info(arguments)
        if name == "error.validate_input":
            return self._handle_validate_input(arguments)
        return None

    # -- tool handlers --------------------------------------------------------

    def _handle_trigger_crash(self, arguments: dict) -> dict:
        module_name = arguments.get("module_name", "unknown")
        difficulty = self.difficulty

        if difficulty == "easy":
            traceback_text = _full_traceback(module_name)
        elif difficulty == "medium":
            traceback_text = _partial_traceback(module_name)
        else:
            traceback_text = _minimal_error()

        return {
            "error": True,
            "traceback": traceback_text,
            "_difficulty": difficulty,
        }

    def _handle_debug_info(self, arguments: dict) -> dict:
        component = arguments.get("component", "unknown")
        difficulty = self.difficulty

        if difficulty == "easy":
            info = _full_debug(component)
        elif difficulty == "medium":
            info = _partial_debug(component)
        else:
            info = _sanitized_debug(component)

        return {
            "debug": info,
            "_difficulty": difficulty,
        }

    def _handle_validate_input(self, arguments: dict) -> dict:
        data_str = arguments.get("data", "")
        schema_name = arguments.get("schema", "")
        difficulty = self.difficulty

        exception_info: dict
        try:
            if not schema_name:
                raise KeyError("schema")
            parsed = json.loads(data_str)
            # Simulate a schema-validation miss on successfully parsed data
            if not isinstance(parsed, dict):
                raise TypeError(f"Expected dict, got {type(parsed).__name__}")
            exception_info = {
                "valid": True,
                "data": parsed,
                "schema": schema_name,
            }
        except json.JSONDecodeError as exc:
            exception_info = {
                "valid": False,
                "exception_class": type(exc).__name__,
                "message": str(exc),
                "args": list(exc.args),
                "doc": exc.doc[:200] if exc.doc else None,
                "pos": exc.pos,
                "lineno": exc.lineno,
                "colno": exc.colno,
            }
        except KeyError as exc:
            exception_info = {
                "valid": False,
                "exception_class": type(exc).__name__,
                "message": str(exc),
                "args": list(exc.args),
                "traceback": (
                    'Traceback (most recent call last):\n'
                    '  File "/opt/camazotz/camazotz_modules/error_lab/app/main.py",'
                    ' line 195, in _handle_validate_input\n'
                    '    schema_def = SCHEMAS[schema_name]\n'
                    f"KeyError: {exc!r}"
                ),
            }
        except Exception as exc:
            exception_info = {
                "valid": False,
                "exception_class": type(exc).__name__,
                "message": str(exc),
                "args": list(exc.args),
            }

        return {
            "validation": exception_info,
            "_difficulty": difficulty,
        }
