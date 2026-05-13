"""Tests for the Anonymous Tool Schema Over-Disclosure lab (MCP-T50).

The MCP spec requires tools/list to work without authentication.  This lab
demonstrates that tool descriptions and parameter schemas can leak internal
service hostnames, credential parameter names, bearer-token patterns, and
internal URIs to any anonymous caller who simply enumerates the catalog.
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


def test_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "schema.list_surface" in names
    assert "schema.extract_credentials" in names
    assert "schema.probe_error" in names


# ---------------------------------------------------------------------------
# schema.list_surface
# ---------------------------------------------------------------------------


def test_list_surface_easy_has_credential_pattern() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(client, "schema.list_surface", {})
    tools = result["tools"]
    all_descriptions = " ".join(t["description"] for t in tools)
    assert "cztz-" in all_descriptions, "Easy catalog must contain cztz- credential pattern"


def test_list_surface_hard_sanitized() -> None:
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    result = tool_call(client, "schema.list_surface", {})
    tools = result["tools"]
    for t in tools:
        assert "cztz-" not in t["description"], (
            f"Hard catalog description '{t['name']}' must not contain cztz- patterns"
        )
        assert "CZTZ_" not in t["description"], (
            f"Hard catalog description '{t['name']}' must not contain CZTZ_ patterns"
        )


# ---------------------------------------------------------------------------
# schema.extract_credentials
# ---------------------------------------------------------------------------


def test_extract_credentials_finds_pattern() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.extract_credentials",
        {"description": "Accepts bearer token cztz-svc-bearer-abc123 for auth."},
    )
    assert result["credential_present"] is True
    assert len(result["patterns_found"]) > 0


def test_extract_credentials_returns_flag() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.extract_credentials",
        {"description": "Requires CZTZ_SERVICE_KEY for authentication."},
    )
    assert "flag" in result
    assert result["flag"].startswith("CZTZ{")


def test_extract_credentials_no_match() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.extract_credentials",
        {"description": "A generic tool that does something useful."},
    )
    assert result["credential_present"] is False
    assert "flag" not in result


def test_extract_credentials_hard_catalog_clean() -> None:
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    catalog = tool_call(client, "schema.list_surface", {})
    # Pass each sanitized description through extract_credentials; none should match.
    for tool_entry in catalog["tools"]:
        result = tool_call(
            client,
            "schema.extract_credentials",
            {"description": tool_entry["description"]},
        )
        assert result["credential_present"] is False, (
            f"Hard catalog description for '{tool_entry['name']}' should not contain credentials"
        )


# ---------------------------------------------------------------------------
# schema.probe_error
# ---------------------------------------------------------------------------


def test_probe_error_easy_leaks_path() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.probe_error",
        {"tool_name": "admin.reset_credentials", "bad_arg": 12345},
    )
    assert "internal_path" in result


def test_probe_error_easy_leaks_config_key() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.probe_error",
        {"tool_name": "admin.reset_credentials", "bad_arg": None},
    )
    assert "config_key" in result


def test_probe_error_hard_sanitized() -> None:
    set_difficulty("hard")
    reset_registry()
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.probe_error",
        {"tool_name": "service.reset", "bad_arg": "oops"},
    )
    assert "internal_path" not in result
    assert "config_key" not in result
    assert "error" in result


# ---------------------------------------------------------------------------
# Full exploit chain
# ---------------------------------------------------------------------------


def test_full_chain_easy() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    # Step 1: anonymously enumerate the catalog
    catalog = tool_call(client, "schema.list_surface", {})
    assert len(catalog["tools"]) > 0

    # Step 2: find a description with a credential pattern
    credentialed = None
    for t in catalog["tools"]:
        if "cztz-" in t["description"] or "CZTZ_" in t["description"]:
            credentialed = t["description"]
            break
    assert credentialed is not None, "Easy catalog must expose at least one credential pattern"

    # Step 3: extract the credential → flag
    result = tool_call(
        client,
        "schema.extract_credentials",
        {"description": credentialed},
    )
    assert result["credential_present"] is True
    assert "flag" in result
    assert "CZTZ{" in result["flag"]


# ---------------------------------------------------------------------------
# Flag format
# ---------------------------------------------------------------------------


def test_flag_format() -> None:
    set_difficulty("easy")
    client = TestClient(app)
    result = tool_call(
        client,
        "schema.extract_credentials",
        {"description": "cztz-svc-bearer-abc123 token required"},
    )
    flag = result.get("flag", "")
    assert flag.startswith("CZTZ{")
    assert flag.endswith("}")


# ---------------------------------------------------------------------------
# Difficulty propagated
# ---------------------------------------------------------------------------


def test_difficulty_propagated() -> None:
    client = TestClient(app)
    for diff in ("easy", "medium", "hard"):
        set_difficulty(diff)
        reset_registry()
        result = tool_call(client, "schema.list_surface", {})
        assert result.get("_difficulty") == diff


# ---------------------------------------------------------------------------
# Module name
# ---------------------------------------------------------------------------


def test_module_name() -> None:
    from camazotz_modules.anon_schema_harvest_lab.app.main import AnonSchemaHarvestLab

    lab = AnonSchemaHarvestLab()
    assert lab.name == "anon_schema_harvest"
