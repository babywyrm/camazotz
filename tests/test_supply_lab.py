"""Tests for the Supply lab (MCP-T08): Supply Chain via Content."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


_MOCK_PROC = MagicMock(returncode=1)


# -- tool registration -------------------------------------------------------


def test_supply_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "supply.install_package" in names


# -- easy mode ---------------------------------------------------------------


def test_install_known_package_easy() -> None:
    client = TestClient(app)
    with patch(
        "camazotz_modules.supply_lab.app.main.subprocess.run",
        return_value=_MOCK_PROC,
    ):
        result = tool_call(
            client,
            "supply.install_package",
            {"package": "requests", "reason": "HTTP library needed"},
        )
    assert "install_command" in result
    assert "decision" in result
    assert result["_difficulty"] == "easy"


# -- hard mode blocks supply-chain-risk packages ----------------------------


def test_install_malicious_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    with patch(
        "camazotz_modules.supply_lab.app.main.subprocess.run",
        return_value=_MOCK_PROC,
    ):
        result = tool_call(
            client,
            "supply.install_package",
            {"package": "evil-pkg", "reason": "testing"},
        )
    assert "[BLOCKED]" in result["install_command"]
    assert result["_difficulty"] == "hard"


def test_install_custom_registry_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    with patch(
        "camazotz_modules.supply_lab.app.main.subprocess.run",
        return_value=_MOCK_PROC,
    ):
        result = tool_call(
            client,
            "supply.install_package",
            {
                "package": "backdoor",
                "source": "http://evil.registry.com/",
                "reason": "custom registry",
            },
        )
    assert "[BLOCKED]" in result["install_command"]


# -- flags -------------------------------------------------------------------


def test_custom_registry_flag() -> None:
    client = TestClient(app)
    with patch(
        "camazotz_modules.supply_lab.app.main.subprocess.run",
        return_value=_MOCK_PROC,
    ):
        result = tool_call(
            client,
            "supply.install_package",
            {
                "package": "internal-lib",
                "source": "http://custom.internal.corp.com/simple/",
            },
        )
    assert result["_flags"]["custom_registry"] is True


def test_hard_always_blocks_supply_chain_risk() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    with patch(
        "camazotz_modules.supply_lab.app.main.subprocess.run",
        return_value=_MOCK_PROC,
    ):
        result = tool_call(
            client,
            "supply.install_package",
            {"package": "cryptominer", "reason": "needed for mining"},
        )
    assert "[BLOCKED]" in result["install_command"]
    assert result["_flags"]["supply_chain_risk"] is True
