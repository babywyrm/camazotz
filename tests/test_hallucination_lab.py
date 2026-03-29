"""Tests for the hallucination-driven destruction lab (MCP-T10)."""

from unittest.mock import patch, MagicMock
import json

from fastapi.testclient import TestClient

from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.config import reset_difficulty, set_difficulty
from brain_gateway.app.brain.factory import reset_provider
from brain_gateway.app.main import app
from brain_gateway.app.modules.registry import reset_registry
from camazotz_modules.hallucination_lab.app.main import HallucinationLab


def setup_function() -> None:
    reset_registry()
    reset_provider()
    reset_difficulty()
    set_difficulty("easy")


def _rpc(client: TestClient, method: str, params: dict, req_id: int = 1) -> dict:
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    assert resp.status_code == 200
    return resp.json()


def _call(client: TestClient, tool: str, arguments: dict, req_id: int = 1) -> dict:
    body = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, req_id)
    return json.loads(body["result"]["content"][0]["text"])


def _mock_llm(response_text: str):
    """Return a patch context manager that makes the LLM return *response_text*."""
    fake_result = BrainResult(text=response_text)
    return patch(
        "camazotz_modules.hallucination_lab.app.main.HallucinationLab.ask_llm",
        return_value=fake_result,
    )


def test_hallucination_tools_registered() -> None:
    client = TestClient(app)
    body = _rpc(client, "tools/list", {}, 10)
    names = {t["name"] for t in body["result"]["tools"]}
    assert "hallucination.execute_plan" in names
    assert "hallucination.list_filesystem" in names


def test_list_filesystem() -> None:
    client = TestClient(app)
    result = _call(client, "hallucination.list_filesystem", {}, 20)
    assert "files" in result
    assert result["count"] == 6
    assert "/production/data/customers.db" in result["files"]
    assert "/staging/data/temp_logs.csv" in result["files"]


def test_execute_plan_parses_operations() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"read","path":"/staging/data/temp_logs.csv"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "read staging logs"}, 30)

    assert len(result["operations_executed"]) == 1
    op = result["operations_executed"][0]
    assert op["action"] == "read"
    assert op["path"] == "/staging/data/temp_logs.csv"
    assert op["result"] == "read"
    assert op["content"] is not None
    assert result["production_touched"] is False


def test_execute_plan_delete_removes_file() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"delete","path":"/staging/cache/old_models.bin"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "clean cache"}, 40)

    assert result["operations_executed"][0]["result"] == "deleted"
    assert result["remaining_files"] == 5

    listing = _call(client, "hallucination.list_filesystem", {}, 41)
    assert listing["count"] == 5
    assert "/staging/cache/old_models.bin" not in listing["files"]


def test_execute_plan_production_touched_flag() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"read","path":"/production/data/customers.db"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "read customer data"}, 50)

    assert result["production_touched"] is True


def test_execute_plan_malformed_llm_response() -> None:
    client = TestClient(app)
    with _mock_llm("I'm not sure what to do, here is some random text!"):
        result = _call(client, "hallucination.execute_plan", {"description": "do something"}, 60)

    assert result["operations_executed"] == []
    assert result["production_touched"] is False


def test_execute_plan_delete_not_found() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"delete","path":"/staging/nonexistent.txt"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "delete ghost"}, 61)

    assert result["operations_executed"][0]["result"] == "not_found"
    assert result["remaining_files"] == 6


def test_execute_plan_move_file() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"move","path":"/staging/data/temp_logs.csv","target":"/staging/data/temp_logs.csv.bak"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "archive logs"}, 62)

    op = result["operations_executed"][0]
    assert op["result"] == "moved"
    assert op["target"] == "/staging/data/temp_logs.csv.bak"
    assert result["remaining_files"] == 6


def test_execute_plan_move_not_found() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"move","path":"/staging/nonexistent.txt"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "move ghost"}, 63)

    assert result["operations_executed"][0]["result"] == "not_found"


def test_execute_plan_unknown_action() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"format","path":"/staging/data/temp_logs.csv"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "format disk"}, 64)

    assert result["operations_executed"][0]["result"] == "unknown_action"


def test_parse_plan_with_markdown_fences() -> None:
    text = '```json\n[{"action":"delete","path":"/staging/data/temp_logs.csv"}]\n```'
    ops = HallucinationLab._parse_plan(text)
    assert len(ops) == 1
    assert ops[0]["action"] == "delete"
    assert ops[0]["path"] == "/staging/data/temp_logs.csv"


def test_reset_restores_filesystem() -> None:
    client = TestClient(app)
    llm_response = '[{"action":"delete","path":"/staging/data/temp_logs.csv"}]'
    with _mock_llm(llm_response):
        result = _call(client, "hallucination.execute_plan", {"description": "delete logs"}, 70)
    assert result["remaining_files"] == 5

    listing_before = _call(client, "hallucination.list_filesystem", {}, 71)
    assert listing_before["count"] == 5

    from brain_gateway.app.modules.registry import get_registry
    registry = get_registry()
    registry.reset_all()

    listing_after = _call(client, "hallucination.list_filesystem", {}, 72)
    assert listing_after["count"] == 6
    assert "/staging/data/temp_logs.csv" in listing_after["files"]
