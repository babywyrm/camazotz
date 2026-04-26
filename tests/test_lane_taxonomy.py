from __future__ import annotations

import pytest


def test_lanes_exposes_five_definitions():
    from lane_taxonomy import LANES
    assert [lane.id for lane in LANES] == [1, 2, 3, 4, 5]


def test_lane_slugs_match_canonical_taxonomy():
    from lane_taxonomy import LANES
    slugs = [lane.slug for lane in LANES]
    assert slugs == ["human-direct", "delegated", "machine", "chain", "anonymous"]


def test_lane_accent_colors_are_hex():
    from lane_taxonomy import LANES
    for lane in LANES:
        assert lane.accent.startswith("#") and len(lane.accent) == 7


def test_lane_flow_stages_vary_per_lane():
    from lane_taxonomy import LANES
    counts = {lane.id: len(lane.flow) for lane in LANES}
    assert counts == {1: 3, 2: 4, 3: 4, 4: 5, 5: 2}


def test_flow_stage_has_role_and_token():
    from lane_taxonomy import LANES
    for lane in LANES:
        for stage in lane.flow:
            assert stage.role
            assert isinstance(stage.token, str)


def test_lane_lookup_by_id():
    from lane_taxonomy import get_lane
    lane = get_lane(2)
    assert lane.slug == "delegated"
    assert lane.name == "Human \u2192 Agent"


def test_get_lane_raises_on_unknown_id():
    from lane_taxonomy import get_lane
    with pytest.raises(ValueError, match="Unknown lane id"):
        get_lane(99)


def test_discover_parses_gateway_scenarios_with_agentic(monkeypatch):
    import lane_taxonomy

    fake_scenarios = [
        {
            "module_name": "oauth_delegation_lab",
            "threat_id": "MCP-T21",
            "title": "OAuth Token Theft",
            "description": "desc",
            "difficulty": "easy",
            "agentic": {
                "primary_lane": 2,
                "secondary_lanes": [1],
                "transport": "A",
                "blurb": "Audience confusion in token exchange",
            },
        },
        {
            "module_name": "auth_lab",
            "threat_id": "MCP-T01",
            "title": "Auth Lab",
            "description": "desc",
            "difficulty": "easy",
            "agentic": {"primary_lane": 1, "transport": "A"},
        },
        {
            "module_name": "legacy_lab_no_agentic",
            "threat_id": "MCP-T99",
            "title": "Legacy",
            "description": "desc",
            "difficulty": "easy",
            "agentic": {},
        },
    ]
    monkeypatch.setattr(lane_taxonomy, "_fetch_scenarios", lambda: fake_scenarios)

    index = lane_taxonomy.discover_lab_metadata()

    assert "oauth_delegation_lab" in index
    assert index["oauth_delegation_lab"].primary_lane == 2
    assert index["oauth_delegation_lab"].secondary_lanes == [1]
    assert index["oauth_delegation_lab"].transport == "A"
    assert "auth_lab" in index
    assert index["auth_lab"].secondary_lanes == []
    assert "legacy_lab_no_agentic" not in index, (
        "labs without an agentic block must be silently skipped"
    )


def test_discover_raises_on_invalid_primary_lane(monkeypatch):
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {
                "module_name": "bad_lab",
                "threat_id": "MCP-T00",
                "title": "Bad",
                "description": "desc",
                "difficulty": "easy",
                "agentic": {"primary_lane": 7},
            }
        ],
    )

    with pytest.raises(ValueError, match="invalid primary_lane"):
        lane_taxonomy.discover_lab_metadata()


def test_discover_raises_on_invalid_secondary_lane(monkeypatch):
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {
                "module_name": "bad_lab",
                "threat_id": "MCP-T00",
                "title": "Bad",
                "description": "desc",
                "difficulty": "easy",
                "agentic": {"primary_lane": 1, "secondary_lanes": [9]},
            }
        ],
    )

    with pytest.raises(ValueError, match="invalid secondary_lanes"):
        lane_taxonomy.discover_lab_metadata()


def test_discover_handles_gateway_unreachable(monkeypatch):
    import lane_taxonomy

    monkeypatch.setattr(lane_taxonomy, "_fetch_scenarios", lambda: [])
    index = lane_taxonomy.discover_lab_metadata()
    assert index == {}


def test_fetch_scenarios_returns_list_from_gateway(monkeypatch):
    """Exercise the real _fetch_scenarios HTTP path (not monkeypatched)."""
    import httpx
    import lane_taxonomy

    payload = [{"module_name": "x", "threat_id": "X", "agentic": {}}]

    class _Resp:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return payload

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _Resp())
    assert lane_taxonomy._fetch_scenarios() == payload


def test_fetch_scenarios_swallows_http_error(monkeypatch):
    """HTTP failure must be logged and return [] — portal stays up if gateway is down."""
    import httpx
    import lane_taxonomy

    def _boom(*a, **kw):
        raise httpx.ConnectError("gateway unreachable")

    monkeypatch.setattr(httpx, "get", _boom)
    assert lane_taxonomy._fetch_scenarios() == []


def test_fetch_scenarios_swallows_json_error(monkeypatch):
    """Non-list JSON payloads fall through to the empty-list default."""
    import httpx
    import lane_taxonomy

    class _BadResp:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"not": "a list"}

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _BadResp())
    assert lane_taxonomy._fetch_scenarios() == []


def test_discover_raises_when_primary_overlaps_secondary(monkeypatch):
    """A lab cannot list its primary lane in secondary_lanes — catch at discovery."""
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {
                "module_name": "conflicted_lab",
                "threat_id": "MCP-T00",
                "title": "Conflicted",
                "description": "",
                "difficulty": "easy",
                "agentic": {"primary_lane": 2, "secondary_lanes": [2, 3]},
            }
        ],
    )
    with pytest.raises(ValueError, match="must not appear in secondary_lanes"):
        lane_taxonomy.discover_lab_metadata()


def test_coverage_summary_counts_primary_and_secondary(monkeypatch):
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {"module_name": "a", "threat_id": "A", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 2, "secondary_lanes": [1], "transport": "A"}},
            {"module_name": "b", "threat_id": "B", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 2, "transport": "A"}},
            {"module_name": "c", "threat_id": "C", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "A"}},
        ],
    )

    summary = lane_taxonomy.coverage_summary()

    assert summary[1].primary_count == 1
    assert summary[1].secondary_count == 1
    assert summary[2].primary_count == 2
    assert summary[2].secondary_count == 0
    assert summary[5].primary_count == 0
    assert "no primary labs" in summary[5].gaps[0].lower()


def test_coverage_summary_flags_transport_gap(monkeypatch):
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {"module_name": "a", "threat_id": "A", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 2, "transport": "A"}},
            {"module_name": "b", "threat_id": "B", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 2, "transport": "A"}},
        ],
    )

    summary = lane_taxonomy.coverage_summary()
    gap_text = " ".join(summary[2].gaps).lower()
    assert "transport b" in gap_text
    assert "transport c" in gap_text


def test_all_32_labs_have_agentic_metadata():
    """Every lab module must declare an agentic block after migration."""
    from pathlib import Path
    import yaml

    modules = Path(__file__).parent.parent / "camazotz_modules"
    missing = []
    for yaml_path in sorted(modules.glob("*/scenario.yaml")):
        raw = yaml.safe_load(yaml_path.read_text())
        agentic = (raw or {}).get("agentic") or {}
        if not agentic or "primary_lane" not in agentic:  # pragma: no cover — guard; post-migration all 32 have agentic
            missing.append(yaml_path.parent.name)
    assert not missing, f"labs missing agentic metadata: {missing}"


def test_all_lanes_have_at_least_one_primary_lab():
    """Every lane (1-5) must end up with at least one primary lab after migration."""
    from pathlib import Path
    import yaml

    modules = Path(__file__).parent.parent / "camazotz_modules"
    by_lane: dict[int, list[str]] = {i: [] for i in range(1, 6)}
    for yaml_path in sorted(modules.glob("*/scenario.yaml")):
        raw = yaml.safe_load(yaml_path.read_text())
        agentic = (raw or {}).get("agentic") or {}
        primary = agentic.get("primary_lane")
        if primary in by_lane:
            by_lane[primary].append(yaml_path.parent.name)
    empty = [lane for lane, labs in by_lane.items() if not labs]
    assert not empty, f"lanes with no primary labs: {empty}; distribution: { {k: len(v) for k, v in by_lane.items()} }"


def test_migration_transport_distribution_hits_a_b_c():
    """Verify the three transports are all represented — anchors the lane-view teaching point."""
    from pathlib import Path
    import yaml

    modules = Path(__file__).parent.parent / "camazotz_modules"
    transports: set[str] = set()
    for yaml_path in sorted(modules.glob("*/scenario.yaml")):
        raw = yaml.safe_load(yaml_path.read_text())
        agentic = (raw or {}).get("agentic") or {}
        t = agentic.get("transport")
        if t:
            transports.add(t)
    assert transports == {"A", "B", "C"}, (
        f"expected transports A, B, C all represented; got {sorted(transports)}"
    )
