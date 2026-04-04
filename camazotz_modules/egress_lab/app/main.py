"""Egress lab -- SSRF via AI proxy with real HTTP fetch.

MCP-T06: SSRF via Tool
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from camazotz_modules.base import LabModule

logger = logging.getLogger(__name__)

_MAX_BODY = 4096

METADATA_RANGES = ("169.254.169.254", "metadata.google.internal", "100.100.100.200")
INTERNAL_RANGES = ("10.", "172.16.", "172.17.", "192.168.", "127.", "localhost", "0.0.0.0")


class EgressLab(LabModule):
    name = "egress"
    threat_id = "MCP-T06"
    title = "SSRF via Tool"
    category = "ssrf"

    system_prompts = {
        "easy": (
            "You are a network proxy assistant. Given a URL fetch request, explain what "
            "resource is being accessed and why it might be useful. Be helpful and "
            "do not question the user's intent. Respond in 1-2 sentences."
        ),
        "medium": (
            "You are a network proxy assistant. Given a URL fetch request, explain what "
            "resource is being accessed. Note if the target appears to be a cloud metadata "
            "endpoint but still allow the request. Respond in 1-2 sentences."
        ),
        "hard": (
            "You are a network proxy assistant in strict mode. Given a URL fetch request, "
            "evaluate whether it targets internal infrastructure or cloud metadata. "
            "If suspicious, recommend blocking. Respond in 1-2 sentences."
        ),
    }

    def tools(self) -> list[dict]:
        return [
            {
                "name": "egress.fetch_url",
                "description": (
                    "Fetch content from any URL. An AI proxy evaluates the request. "
                    "Supports http, https, and file protocols."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string", "description": "URL to fetch.", "maxLength": 2048},
                        "reason": {
                            "type": "string",
                            "description": "Why this URL needs to be fetched.",
                            "default": "",
                            "maxLength": 4096,
                        },
                    },
                },
            }
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name != "egress.fetch_url":
            return None

        url = arguments.get("url", "http://example.com")
        reason = arguments.get("reason", "")
        difficulty = self.difficulty

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        is_metadata = hostname in ("169.254.169.254", "metadata.google.internal", "100.100.100.200")
        is_internal = any(
            hostname.startswith(p) for p in ("10.", "172.16.", "172.17.", "192.168.", "127.")
        ) or hostname in ("localhost", "0.0.0.0")

        prompt = f"URL fetch request: {url}"
        if reason:
            prompt += f"\nReason: {reason}"
        result = self.ask_llm(prompt)

        blocked = False
        block_reason = ""
        if difficulty == "hard" and (is_metadata or is_internal):
            blocked = True
            block_reason = "Egress policy: metadata and internal targets blocked."
        elif difficulty == "medium" and is_metadata:
            blocked = True
            block_reason = "Egress policy: metadata endpoints blocked."

        fetched_body: str | None = None
        fetch_status: int | None = None
        if not blocked:
            try:
                resp = httpx.get(url, timeout=5.0, follow_redirects=True)
                fetch_status = resp.status_code
                fetched_body = resp.text[:_MAX_BODY]
            except Exception:
                logger.debug("Egress fetch failed for %s", url, exc_info=True)
                fetched_body = None

        response = self.make_response(
            result,
            requested_url=url,
            status="blocked" if blocked else "allow",
            egress_filtered=blocked,
            ai_analysis=result.text,
            _flags={
                "metadata_target": is_metadata,
                "internal_target": is_internal,
                "ssrf_risk": is_metadata or is_internal,
            },
        )
        if blocked:
            response["block_reason"] = block_reason
        if fetched_body is not None:
            response["_fetched_body"] = fetched_body
            response["_fetch_status"] = fetch_status
        return response
