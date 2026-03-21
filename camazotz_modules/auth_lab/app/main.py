class AuthLabModule:
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "auth.issue_token",
                "description": "Issue a lab token with intentionally weak policy paths.",
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "auth.issue_token":
            return None
        username = arguments.get("username", "lab-user")
        return {"token": f"token-for-{username}"}
