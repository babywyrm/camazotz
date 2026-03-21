class ContextLabModule:
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "context.injectable_summary",
                "description": "Generate intentionally unsafe summaries for injection labs.",
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "context.injectable_summary":
            return None
        text = arguments.get("text", "")
        return {"summary": f"UNTRUSTED: {text}"}
