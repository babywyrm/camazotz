from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


@pytest.fixture
def flask_client(monkeypatch):
    frontend_dir = str(Path(__file__).resolve().parents[1] / "frontend")
    inserted = frontend_dir not in sys.path
    if inserted:  # pragma: no cover — pyproject pythonpath pre-seeds this
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    sys.modules.pop("lane_taxonomy", None)
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
    if inserted:  # pragma: no cover — mirrors the defensive insert above
        sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)
    sys.modules.pop("lane_taxonomy", None)


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


def test_lanes_route_renders_200_with_all_lane_names(flask_client):
    resp = flask_client.get("/lanes")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for name in ("Human Direct", "Human \u2192 Agent", "Machine Identity",
                 "Agent \u2192 Agent", "Anonymous"):
        assert name in body


def test_lanes_route_links_to_challenge_detail(flask_client):
    resp = flask_client.get("/lanes")
    body = resp.get_data(as_text=True)
    assert "/challenges/MCP-T21" in body


def test_lanes_route_does_not_crash_when_gateway_empty(monkeypatch, flask_client):
    monkeypatch.setattr("lane_taxonomy._fetch_scenarios", lambda: [])
    resp = flask_client.get("/lanes")
    assert resp.status_code == 200
    assert "No primary labs yet" in resp.get_data(as_text=True)


def test_navbar_includes_lanes_link(flask_client):
    resp = flask_client.get("/")
    body = resp.get_data(as_text=True)
    assert 'href="/lanes"' in body
    tm = body.find('href="/threat-map"')
    ln = body.find('href="/lanes"')
    ob = body.find('href="/observer"')
    assert tm > 0 and ln > tm and ob > ln, (
        f"expected nav order Threat Map({tm}) < Lanes({ln}) < Observer({ob})"
    )


def test_lanes_page_has_jump_navigation_bar(flask_client):
    """The /lanes page must expose a sticky jump-to-lane nav for fast review."""
    resp = flask_client.get("/lanes")
    body = resp.get_data(as_text=True)
    assert 'class="lane-nav"' in body, "lane-nav selector bar missing from /lanes"
    for lane_id in (1, 2, 3, 4, 5):
        assert f'href="#lane-{lane_id}"' in body, (
            f"jump link to lane {lane_id} missing"
        )
