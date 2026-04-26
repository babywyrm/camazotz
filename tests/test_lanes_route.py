from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def flask_client(monkeypatch):
    sys.path.insert(0, "frontend")
    if "app" in sys.modules:
        importlib.reload(sys.modules["app"])
    import app as frontend_app

    monkeypatch.setattr(
        "lane_taxonomy._fetch_scenarios",
        lambda: [
            {"module_name": "auth_lab", "threat_id": "MCP-T01",
             "title": "Auth Lab", "description": "d", "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "A"}},
            {"module_name": "oauth_delegation_lab", "threat_id": "MCP-T21",
             "title": "OAuth", "description": "d", "difficulty": "easy",
             "agentic": {"primary_lane": 2, "secondary_lanes": [1], "transport": "A"}},
        ],
    )

    frontend_app.app.testing = True
    with frontend_app.app.test_client() as client:
        yield client


def test_api_lanes_returns_versioned_json(flask_client):
    resp = flask_client.get("/api/lanes")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["schema"] == "v1"
    assert "lanes" in payload
    assert "coverage" in payload


def test_api_lanes_includes_all_five_lanes(flask_client):
    resp = flask_client.get("/api/lanes")
    lanes = resp.get_json()["lanes"]
    assert [l["id"] for l in lanes] == [1, 2, 3, 4, 5]
    assert [l["slug"] for l in lanes] == [
        "human-direct", "delegated", "machine", "chain", "anonymous",
    ]


def test_api_lanes_coverage_reflects_fake_labs(flask_client):
    resp = flask_client.get("/api/lanes")
    coverage = resp.get_json()["coverage"]
    assert coverage["1"]["primary_count"] == 1
    assert coverage["1"]["secondary_count"] == 1
    assert coverage["2"]["primary_count"] == 1
