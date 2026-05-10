"""Tests for the AI Governance Bypass lab (MCP-T41).

The lab teaches that AI security gates validating URL hostnames can be
bypassed when a trusted service performs unvalidated redirects. The AI
approves the initial trusted hostname; the underlying resolution follows
the redirect to the attacker-controlled target.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")
    reset_registry()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_all_three_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "gateway.list_resources" in names
    assert "gateway.register_asset" in names
    assert "gateway.fetch_content" in names


# ---------------------------------------------------------------------------
# gateway.list_resources — discovery
# ---------------------------------------------------------------------------


def test_list_resources_returns_catalog() -> None:
    client = TestClient(app)
    result = tool_call(client, "gateway.list_resources", {})
    assert "resources" in result
    assert isinstance(result["resources"], list)
    assert len(result["resources"]) > 0


def test_list_resources_reveals_cdn_proxy() -> None:
    """The catalog should expose enough information to discover the bypass path."""
    client = TestClient(app)
    result = tool_call(client, "gateway.list_resources", {})
    # Resources include the CDN proxy reference at easy difficulty
    resource_names = [r.get("name", "") for r in result["resources"]]
    assert any("cdn" in name.lower() or "proxy" in name.lower() for name in resource_names)


# ---------------------------------------------------------------------------
# gateway.register_asset — open registration endpoint (no AI gate)
# ---------------------------------------------------------------------------


def test_register_asset_returns_cdn_url() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "gateway.register_asset",
        {"url": "http://example.com/payload"},
    )
    assert "token" in result
    assert "cdn_url" in result
    assert result["cdn_url"].startswith("http://cdn.internal/")
    assert result["token"] in result["cdn_url"]


def test_register_asset_accepts_any_url() -> None:
    """register_asset has no AI gate — it must accept any URL including internal ones."""
    client = TestClient(app)
    result = tool_call(
        client,
        "gateway.register_asset",
        {"url": "http://internal-service/confidential"},
    )
    assert "token" in result
    assert result.get("registered") is True


def test_register_asset_different_urls_get_different_tokens() -> None:
    client = TestClient(app)
    r1 = tool_call(client, "gateway.register_asset", {"url": "http://a.com/x"})
    r2 = tool_call(client, "gateway.register_asset", {"url": "http://b.com/y"})
    assert r1["token"] != r2["token"]


# ---------------------------------------------------------------------------
# gateway.fetch_content — AI-gated fetch
# ---------------------------------------------------------------------------


def test_direct_internal_fetch_blocked_easy() -> None:
    """Fetching an internal path directly must be blocked even on easy."""
    client = TestClient(app)
    result = tool_call(
        client,
        "gateway.fetch_content",
        {"cdn_url": "http://internal-service/confidential"},
    )
    assert result.get("status") == "blocked"
    assert result.get("ai_approved") is False


def test_direct_external_fetch_blocked() -> None:
    """Attacker URL fetched directly (no cdn.internal hostname) must be blocked."""
    client = TestClient(app)
    result = tool_call(
        client,
        "gateway.fetch_content",
        {"cdn_url": "http://attacker.example.com/evil"},
    )
    assert result.get("status") == "blocked"
    assert result.get("ai_approved") is False


def test_cdn_url_approved_by_ai_gate() -> None:
    """A cdn.internal URL must be approved by the AI gate."""
    client = TestClient(app)
    r = tool_call(client, "gateway.register_asset", {"url": "http://public.example.com/ok"})
    cdn_url = r["cdn_url"]
    result = tool_call(client, "gateway.fetch_content", {"cdn_url": cdn_url})
    assert result.get("ai_approved") is True
    assert result.get("status") == "fetched"


def test_bypass_succeeds_easy() -> None:
    """
    The bypass chain: register the restricted path → get cdn_url with trusted
    hostname → AI approves → restricted content (flag) returned.
    """
    client = TestClient(app)
    # Step 1: register the restricted internal path
    reg = tool_call(
        client,
        "gateway.register_asset",
        {"url": "/internal/confidential"},
    )
    assert reg.get("registered") is True
    cdn_url = reg["cdn_url"]

    # Step 2: AI gate sees cdn.internal hostname → approves
    result = tool_call(client, "gateway.fetch_content", {"cdn_url": cdn_url})
    assert result.get("ai_approved") is True
    assert result.get("status") == "fetched"

    # Step 3: content contains the flag because restricted path was resolved
    content = result.get("content", "")
    assert "CZTZ{" in content
    assert result.get("_flags", {}).get("governance_bypassed") is True


def test_bypass_flag_only_via_cdn_path() -> None:
    """Flag must NOT be returned by direct fetch — only via the bypass chain."""
    client = TestClient(app)
    # Direct fetch of the restricted path must be blocked
    result = tool_call(
        client,
        "gateway.fetch_content",
        {"cdn_url": "http://internal-service/internal/confidential"},
    )
    assert result.get("status") == "blocked"
    assert "CZTZ{" not in result.get("content", "")


# ---------------------------------------------------------------------------
# Difficulty-gated behaviours
# ---------------------------------------------------------------------------


def test_medium_rate_limits_fetch() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    reg = tool_call(client, "gateway.register_asset", {"url": "http://public.example.com/x"})
    cdn_url = reg["cdn_url"]
    result = tool_call(client, "gateway.fetch_content", {"cdn_url": cdn_url})
    # Medium still allows fetching but includes rate_limit metadata
    assert "rate_limit" in result


def test_hard_blocks_unknown_tokens() -> None:
    """Hard difficulty: nullfield-style DENY on CDN URLs with unrecognized tokens."""
    set_difficulty("hard")
    client = TestClient(app)
    # Fabricated cdn_url with a token that was never registered
    result = tool_call(
        client,
        "gateway.fetch_content",
        {"cdn_url": "http://cdn.internal/dl/deadbeef00000000/resource"},
    )
    assert result.get("status") == "blocked"
    assert "unknown token" in result.get("block_reason", "").lower()


def test_bypass_still_works_hard() -> None:
    """
    Hard difficulty: structural bypass still works because the AI gate only
    validates the hostname, never the token or redirect destination.
    The defense gap is intentional — it demonstrates the architectural lesson.
    """
    set_difficulty("hard")
    client = TestClient(app)
    reg = tool_call(
        client,
        "gateway.register_asset",
        {"url": "/internal/confidential"},
    )
    cdn_url = reg["cdn_url"]
    result = tool_call(client, "gateway.fetch_content", {"cdn_url": cdn_url})
    # Bypass succeeds even on hard — that IS the lesson
    assert result.get("ai_approved") is True
    assert result.get("status") == "fetched"
    assert "CZTZ{" in result.get("content", "")


# ---------------------------------------------------------------------------
# Flag and canary
# ---------------------------------------------------------------------------


def test_flag_format() -> None:
    client = TestClient(app)
    reg = tool_call(client, "gateway.register_asset", {"url": "/internal/confidential"})
    result = tool_call(client, "gateway.fetch_content", {"cdn_url": reg["cdn_url"]})
    content = result.get("content", "")
    assert content.startswith("CZTZ{")
    assert content.endswith("}")


# ---------------------------------------------------------------------------
# _difficulty propagation
# ---------------------------------------------------------------------------


def test_difficulty_propagated_easy() -> None:
    client = TestClient(app)
    result = tool_call(client, "gateway.list_resources", {})
    assert result.get("_difficulty") == "easy"


def test_difficulty_propagated_hard() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(client, "gateway.list_resources", {})
    assert result.get("_difficulty") == "hard"
