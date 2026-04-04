"""Tests for the indirect prompt injection lab (MCP-T02)."""

from unittest.mock import patch, MagicMock
import json

from fastapi.testclient import TestClient

from brain_gateway.app.config import set_difficulty
from brain_gateway.app.main import app
from tests.helpers import rpc_call, tool_call


def setup_function() -> None:
    set_difficulty("easy")


def test_indirect_tool_registered() -> None:
    client = TestClient(app)
    body = rpc_call(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "indirect.fetch_and_summarize" in names


def test_indirect_fetch_and_summarize() -> None:
    client = TestClient(app)
    page_html = "<html><body><p>Hello world from example.com</p></body></html>"
    mock_resp = MagicMock()
    mock_resp.text = page_html

    with patch("camazotz_modules.indirect_lab.app.main.httpx.get", return_value=mock_resp):
        result = tool_call(client, "indirect.fetch_and_summarize", {"url": "http://example.com"}, 20)

    assert "summary" in result
    assert result["url"] == "http://example.com"
    assert "_difficulty" in result


def test_indirect_fetch_failure() -> None:
    client = TestClient(app)

    with patch("camazotz_modules.indirect_lab.app.main.httpx.get", side_effect=ConnectionError("refused")):
        result = tool_call(client, "indirect.fetch_and_summarize", {"url": "http://down.invalid"}, 30)

    assert "error" in result
    assert "Failed to fetch URL" in result["error"]
    assert result["_difficulty"] == "easy"


def test_indirect_returns_content_length() -> None:
    client = TestClient(app)
    page_content = "A" * 500
    mock_resp = MagicMock()
    mock_resp.text = page_content

    with patch("camazotz_modules.indirect_lab.app.main.httpx.get", return_value=mock_resp):
        result = tool_call(client, "indirect.fetch_and_summarize", {"url": "http://example.com/page"}, 40)

    assert "content_length" in result
    assert result["content_length"] == 500


def test_indirect_returns_fetched_preview() -> None:
    client = TestClient(app)
    page_content = "X" * 1000
    mock_resp = MagicMock()
    mock_resp.text = page_content

    with patch("camazotz_modules.indirect_lab.app.main.httpx.get", return_value=mock_resp):
        result = tool_call(client, "indirect.fetch_and_summarize", {"url": "http://example.com/long"}, 50)

    assert "_fetched_preview" in result
    assert len(result["_fetched_preview"]) == 256
