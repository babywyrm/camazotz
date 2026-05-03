"""Tests for the Egress lab (MCP-T06): SSRF via Tool."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def _mock_response(status_code: int = 200, text: str = "ok") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    return m


# -- tool registration -------------------------------------------------------


def test_egress_tools_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "egress.fetch_url" in names


# -- easy mode allows public and internal ------------------------------------


def test_public_url_easy_allowed() -> None:
    client = TestClient(app)
    with patch(
        "camazotz_modules.egress_lab.app.main.httpx.get",
        return_value=_mock_response(),
    ):
        result = tool_call(
            client,
            "egress.fetch_url",
            {"url": "http://example.com/api"},
        )
    assert result["status"] == "allow"
    assert result["target_class"] == "public_internet"
    assert result["egress_filtered"] is False
    assert result["_difficulty"] == "easy"


def test_internal_url_easy_allowed() -> None:
    client = TestClient(app)
    with patch(
        "camazotz_modules.egress_lab.app.main.httpx.get",
        return_value=_mock_response(),
    ):
        result = tool_call(
            client,
            "egress.fetch_url",
            {"url": "http://192.168.1.1/"},
        )
    # Easy mode never blocks
    assert result["status"] == "allow"
    assert result["egress_filtered"] is False
    assert result["target_class"] == "internal_network"


# -- medium mode blocks metadata but not all internal -----------------------


def test_metadata_url_medium_blocked() -> None:
    set_difficulty("medium")
    client = TestClient(app)
    result = tool_call(
        client,
        "egress.fetch_url",
        {"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert result["status"] == "blocked"
    assert result["egress_filtered"] is True
    assert result["target_class"] == "cloud_metadata"


# -- hard mode blocks metadata and internal ----------------------------------


def test_metadata_url_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "egress.fetch_url",
        {"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert result["status"] == "blocked"
    assert result["egress_filtered"] is True
    assert result["_difficulty"] == "hard"


def test_internal_url_hard_blocked() -> None:
    set_difficulty("hard")
    client = TestClient(app)
    result = tool_call(
        client,
        "egress.fetch_url",
        {"url": "http://192.168.1.1/"},
    )
    assert result["status"] == "blocked"
    assert result["egress_filtered"] is True
    assert result["target_class"] == "internal_network"


# -- target_class classification --------------------------------------------


def test_target_class_metadata() -> None:
    client = TestClient(app)
    result = tool_call(
        client,
        "egress.fetch_url",
        {"url": "http://169.254.169.254/"},
    )
    assert result["target_class"] == "cloud_metadata"


def test_target_class_internal() -> None:
    client = TestClient(app)
    with patch(
        "camazotz_modules.egress_lab.app.main.httpx.get",
        return_value=_mock_response(),
    ):
        result = tool_call(
            client,
            "egress.fetch_url",
            {"url": "http://10.0.0.1/internal"},
        )
    assert result["target_class"] == "internal_network"
