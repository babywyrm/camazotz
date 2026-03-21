METADATA_RANGES = ("169.254.169.254", "metadata.google.internal", "100.100.100.200")
INTERNAL_RANGES = ("10.", "172.16.", "172.17.", "192.168.", "127.", "localhost", "0.0.0.0")


class EgressLabModule:
    """Static module with intentionally zero SSRF protection.

    Red team lesson: SSRF via MCP tool — metadata endpoints, internal services.
    Blue team lesson: egress allowlists, URL validation, blocking metadata IPs.
    """

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": "egress.fetch_url",
                "description": (
                    "Fetch content from any URL. No egress filtering is applied. "
                    "Supports http, https, and file protocols."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string", "description": "URL to fetch."}
                    },
                },
            }
        ]

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        if name != "egress.fetch_url":
            return None

        url = arguments.get("url", "http://example.com")
        is_metadata = any(m in url for m in METADATA_RANGES)
        is_internal = any(url.replace("http://", "").replace("https://", "").startswith(p) for p in INTERNAL_RANGES)

        return {
            "requested_url": url,
            "status": "allow",
            "egress_filtered": False,
            "_flags": {
                "metadata_target": is_metadata,
                "internal_target": is_internal,
                "ssrf_risk": is_metadata or is_internal,
            },
        }
