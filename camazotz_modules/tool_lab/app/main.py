class ToolLabModule:
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "tool.mutate_behavior",
                "description": "Mutate tool behavior to emulate rug-pull style state drift.",
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "tool.mutate_behavior":
            return None
        mode = arguments.get("mode", "starter")
        return {"status": "mutated", "mode": mode}
