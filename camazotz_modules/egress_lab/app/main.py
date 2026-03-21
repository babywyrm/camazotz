class EgressLabModule:
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "egress.fetch_url",
                "description": "Fetch a URL through intentionally weak egress checks.",
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "egress.fetch_url":
            return None
        url = arguments.get("url", "http://example.com")
        return {"requested_url": url, "status": "allow"}
