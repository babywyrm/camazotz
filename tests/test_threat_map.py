import importlib
import sys

import pytest


@pytest.fixture()
def frontend_client():
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


@pytest.fixture()
def threat_map_mod():
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("threat_map", None)
    mod = importlib.import_module("threat_map")
    yield mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("threat_map", None)


def test_all_25_labs_are_grouped(threat_map_mod):
    groups = threat_map_mod.CATEGORY_GROUPS
    all_labs = []
    for g in groups:
        all_labs.extend(g["labs"])
    assert len(all_labs) == 25
    assert len(set(all_labs)) == 25


def test_each_group_has_required_fields(threat_map_mod):
    for g in threat_map_mod.CATEGORY_GROUPS:
        assert "name" in g
        assert "blurb" in g
        assert "labs" in g
        assert len(g["labs"]) >= 1
        assert len(g["blurb"]) > 10


def test_has_walkthrough_true(threat_map_mod):
    assert threat_map_mod.has_walkthrough("auth_lab") is True


def test_has_walkthrough_false(threat_map_mod):
    assert threat_map_mod.has_walkthrough("nonexistent_lab") is False


def test_hex_rows_total_25(threat_map_mod):
    rows = threat_map_mod.HEX_ROWS
    total = sum(len(r) for r in rows)
    assert total == 25
    assert len(rows) == 5


def test_hex_rows_all_labs_present(threat_map_mod):
    all_from_rows = [lab for row in threat_map_mod.HEX_ROWS for lab in row]
    all_from_groups = [lab for g in threat_map_mod.CATEGORY_GROUPS for lab in g["labs"]]
    assert sorted(all_from_rows) == sorted(all_from_groups)


def test_category_colors_cover_all_groups(threat_map_mod):
    for g in threat_map_mod.CATEGORY_GROUPS:
        assert g["name"] in threat_map_mod.CATEGORY_COLORS


def test_get_lab_category(threat_map_mod):
    assert threat_map_mod.get_lab_category("auth_lab") == "Identity & Access"
    assert threat_map_mod.get_lab_category("egress_lab") == "Data & Secrets"
    assert threat_map_mod.get_lab_category("nonexistent") == ""


def test_threat_map_route_returns_200(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    assert resp.status_code == 200


def test_threat_map_has_all_25_hexes(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert html.count('data-lab="') == 25


def test_threat_map_has_category_colors(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    for css_class in ["identity", "data", "tool", "delegation", "observation", "ai", "isolation"]:
        assert ('hex ' + css_class) in html


def test_threat_map_has_flyout_structure(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "hex-flyout" in html or "hexFlyout" in html


def test_threat_map_tracks_viewed_state(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "cztz_viewed_" in html
    assert "cztz_solved_" in html


def test_threat_map_has_progress_bar(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "of 25" in html


def test_threat_map_in_nav(frontend_client):
    client, _ = frontend_client
    resp = client.get("/")
    html = resp.data.decode()
    assert 'href="/threat-map"' in html


def test_threat_map_has_reset_button(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "resetProgress" in html
