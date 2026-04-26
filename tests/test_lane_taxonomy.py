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
