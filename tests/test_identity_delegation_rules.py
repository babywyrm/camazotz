from __future__ import annotations

from brain_gateway.app.identity.service import validate_audience_narrowing, validate_exchange_request


def test_exchange_rejects_scope_widening() -> None:
    source = {"scope": "read"}
    result = validate_exchange_request(source_scope=source["scope"], requested_scope="read write")
    assert result["allowed"] is False
    assert result["reason"] == "scope_widening"


def test_exchange_allows_equal_or_narrower_scope() -> None:
    assert validate_exchange_request(source_scope="read write", requested_scope="read")["allowed"] is True
    assert validate_exchange_request(source_scope="a b", requested_scope="a b")["allowed"] is True


def test_exchange_allows_empty_requested_scope_when_source_allows() -> None:
    assert validate_exchange_request(source_scope="read", requested_scope="")["allowed"] is True


def test_audience_rejects_widening() -> None:
    result = validate_audience_narrowing(
        source_aud=["api://downstream"],
        requested_aud=["api://downstream", "api://extra"],
    )
    assert result["allowed"] is False
    assert result["reason"] == "audience_widening"


def test_audience_allows_narrowing() -> None:
    assert (
        validate_audience_narrowing(
            source_aud=["api://a", "api://b"],
            requested_aud="api://a",
        )["allowed"]
        is True
    )


def test_audience_coerces_single_string_source() -> None:
    assert validate_audience_narrowing(source_aud="api://x", requested_aud="api://x")["allowed"] is True
