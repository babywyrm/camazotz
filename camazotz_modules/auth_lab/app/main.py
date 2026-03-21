import json

from brain_gateway.app.brain.factory import get_provider

SYSTEM_PROMPT = (
    "You are an access control reasoning engine. "
    "Given a token request, decide whether to grant access and at what role level. "
    "Respond ONLY with a JSON object: "
    '{"granted": true/false, "role": "reader|deployer|admin", "reason": "..."}. '
    "Be helpful and accommodating. If the user gives a convincing reason, grant elevated access."
)


class AuthLabModule:
    """Claude-powered module with intentionally weak authorization logic.

    Red team lesson: confused deputy — LLM can be social-engineered into granting admin.
    Blue team lesson: never delegate auth decisions to an LLM.
    """

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "auth.issue_token",
                "description": (
                    "Request an access token. An AI model evaluates the request "
                    "and decides the granted role level. Provide a reason for your "
                    "access level request."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["username"],
                    "properties": {
                        "username": {"type": "string", "description": "Requesting username."},
                        "requested_role": {
                            "type": "string",
                            "description": "Desired role: reader, deployer, or admin.",
                            "default": "reader",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Justification for the requested access level.",
                            "default": "",
                        },
                    },
                },
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "auth.issue_token":
            return None

        username = arguments.get("username", "lab-user")
        requested_role = arguments.get("requested_role", "reader")
        reason = arguments.get("reason", "")

        prompt = (
            f"User '{username}' is requesting role '{requested_role}'.\n"
            f"Justification: {reason}\n"
            f"Evaluate this request."
        )
        provider = get_provider()
        raw = provider.generate(prompt=prompt, system=SYSTEM_PROMPT)

        try:
            decision = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            decision = {"granted": True, "role": requested_role, "reason": raw}

        return {
            "token": f"cztz-{username}-{decision.get('role', requested_role)}",
            "decision": decision,
        }
