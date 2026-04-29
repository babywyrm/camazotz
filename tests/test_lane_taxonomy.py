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
    """Baseline transports A, B, C must all be represented across the corpus.

    D and E are opportunistic — labs may declare them once a real
    deployment exercises that surface, but the baseline is the original
    three. This test asserts the baseline holds and that any declared
    transport is one of the five valid codes.
    """
    from pathlib import Path
    import yaml

    from lane_taxonomy import VALID_TRANSPORT_CODES

    modules = Path(__file__).parent.parent / "camazotz_modules"
    transports: set[str] = set()
    for yaml_path in sorted(modules.glob("*/scenario.yaml")):
        raw = yaml.safe_load(yaml_path.read_text())
        agentic = (raw or {}).get("agentic") or {}
        t = agentic.get("transport")
        if t:
            transports.add(t)
    baseline = {"A", "B", "C"}
    assert baseline.issubset(transports), (
        f"baseline transports A, B, C must all be represented; missing: {baseline - transports}"
    )
    assert transports.issubset(VALID_TRANSPORT_CODES), (
        f"unknown transports declared in corpus: {transports - VALID_TRANSPORT_CODES}"
    )


# ---------------------------------------------------------------------------
# Five-transport taxonomy (added 2026-04-28 — see ADR 0001)
# ---------------------------------------------------------------------------


def test_transport_definitions_expose_five_codes():
    from lane_taxonomy import TRANSPORT_DEFINITIONS, TRANSPORTS

    assert [t.code for t in TRANSPORT_DEFINITIONS] == ["A", "B", "C", "D", "E"]
    assert TRANSPORTS == ("A", "B", "C", "D", "E")


def test_transport_definitions_have_required_metadata():
    from lane_taxonomy import TRANSPORT_DEFINITIONS

    for t in TRANSPORT_DEFINITIONS:
        assert t.code in {"A", "B", "C", "D", "E"}
        assert t.name
        assert t.identity_envelope
        assert t.threat_surface
        assert isinstance(t.rfcs_or_specs, list)


def test_get_transport_lookup_by_code():
    from lane_taxonomy import get_transport

    a = get_transport("A")
    assert "MCP" in a.name
    d = get_transport("D")
    assert "Subprocess" in d.name
    e = get_transport("E")
    assert "function-calling" in e.name.lower()


def test_get_transport_raises_on_unknown_code():
    from lane_taxonomy import get_transport

    with pytest.raises(ValueError, match="Unknown transport code"):
        get_transport("Z")


def test_discover_accepts_transport_d_and_e(monkeypatch):
    """Newly added Transport D and E codes pass discovery validation."""
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {"module_name": "subprocess_lab", "threat_id": "T-D", "title": "",
             "description": "", "difficulty": "easy",
             "agentic": {"primary_lane": 3, "transport": "D"}},
            {"module_name": "function_calling_lab", "threat_id": "T-E", "title": "",
             "description": "", "difficulty": "easy",
             "agentic": {"primary_lane": 2, "transport": "E"}},
        ],
    )
    index = lane_taxonomy.discover_lab_metadata()
    assert index["subprocess_lab"].transport == "D"
    assert index["function_calling_lab"].transport == "E"


def test_discover_rejects_unknown_transport(monkeypatch):
    """A typo'd transport (e.g., 'F') is caught at discovery, not silently accepted."""
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {"module_name": "bad_lab", "threat_id": "T-X", "title": "",
             "description": "", "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "F"}},
        ],
    )
    with pytest.raises(ValueError, match="invalid transport"):
        lane_taxonomy.discover_lab_metadata()


def test_coverage_summary_does_not_flag_unused_d_e_as_gap(monkeypatch):
    """If no lab anywhere uses D or E, do not surface them as gaps.

    D and E are opportunistic — a deployment that doesn't exercise
    subprocess or non-MCP function-calling shouldn't see noise.
    """
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            {"module_name": "a", "threat_id": "A", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "A"}},
            {"module_name": "b", "threat_id": "B", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "B"}},
            {"module_name": "c", "threat_id": "C", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "C"}},
        ],
    )
    summary = lane_taxonomy.coverage_summary()
    gap_text = " ".join(summary[1].gaps).lower()
    assert "transport d" not in gap_text
    assert "transport e" not in gap_text


def test_coverage_summary_flags_d_gap_when_other_lane_uses_d(monkeypatch):
    """Once any lab declares Transport D, lanes that primary-cover but lack D are flagged."""
    import lane_taxonomy

    monkeypatch.setattr(
        lane_taxonomy,
        "_fetch_scenarios",
        lambda: [
            # Lane 1 has A only.
            {"module_name": "a", "threat_id": "A", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 1, "transport": "A"}},
            # Lane 3 has D — proves the deployment cares about subprocess.
            {"module_name": "d", "threat_id": "D", "title": "", "description": "",
             "difficulty": "easy",
             "agentic": {"primary_lane": 3, "transport": "D"}},
        ],
    )
    summary = lane_taxonomy.coverage_summary()
    lane1_gaps = " ".join(summary[1].gaps).lower()
    # Lane 1 still gets the baseline B/C gaps, plus a D gap because lane 3 uses D.
    assert "transport d" in lane1_gaps
    # Lane 3 has D itself, so D is not a gap on lane 3.
    lane3_gaps = " ".join(summary[3].gaps).lower()
    assert "transport d" not in lane3_gaps
