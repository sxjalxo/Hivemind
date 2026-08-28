from datetime import datetime

import pytest

from app.seed.seeder import seed
from app.services.dashboard import _trend, build_dashboard, list_honeypots, range_to_bounds


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_range_to_bounds_supports_every_documented_window() -> None:
    for window in ("1h", "24h", "7d", "30d"):
        start, end = range_to_bounds(window)
        assert start < end


def test_range_to_bounds_windows_have_distinct_spans() -> None:
    # Each window's start must differ from the others' — otherwise every
    # "range" would silently query the same slice of time.
    starts = {window: range_to_bounds(window)[0] for window in ("1h", "24h", "7d", "30d")}
    assert len(set(starts.values())) == 4


def test_unknown_range_falls_back_to_24h() -> None:
    # range_to_bounds() calls datetime.now() independently on each
    # invocation, so two back-to-back calls are never byte-identical
    # (microsecond drift) even when they resolve to the same window.
    # Compare the actual semantic property instead: same span width,
    # and end timestamps within a second of each other (not the ~24h
    # apart a wrong fallback would produce).
    nonsense_start, nonsense_end = range_to_bounds("nonsense")
    day_start, day_end = range_to_bounds("24h")

    assert _parse(nonsense_end) - _parse(nonsense_start) == _parse(day_end) - _parse(day_start)
    assert abs((_parse(nonsense_end) - _parse(day_end)).total_seconds()) < 1


def test_trend_flat_on_zero_baseline() -> None:
    # A zero previous window must never divide-by-zero or fabricate a jump.
    assert _trend(current=10, previous=0) == (0.0, "flat")
    assert _trend(current=0, previous=0) == (0.0, "flat")


def test_trend_computes_real_percentage_change_with_nonempty_baseline() -> None:
    # This is the case a fake "always flat" implementation would fail:
    # a genuinely non-empty previous window must drive a real percentage.
    assert _trend(current=150, previous=100) == (50.0, "up")
    assert _trend(current=50, previous=100) == (-50.0, "down")
    assert _trend(current=100, previous=100) == (0.0, "flat")


@pytest.mark.asyncio
async def test_honeypots_are_derived_from_indexed_events() -> None:
    await seed(reset=True)
    honeypots = await list_honeypots()

    assert len(honeypots) >= 1
    cowrie = next(h for h in honeypots if h.id == "cowrie-01")
    assert cowrie.type == "SSH"
    assert cowrie.interaction_level == "medium"
    assert cowrie.events > 0
    assert cowrie.status in {"online", "offline", "degraded"}


@pytest.mark.asyncio
async def test_dashboard_returns_every_panel_the_ui_expects() -> None:
    await seed(reset=True)
    data = await build_dashboard("30d")

    assert {k.id for k in data.kpis} == {
        "total_events",
        "active_sessions",
        "high_risk",
        "techniques",
    }
    assert data.timeline
    assert data.risk_distribution
    assert data.top_attackers
    assert data.top_commands


@pytest.mark.asyncio
async def test_top_commands_counts_seeded_commands() -> None:
    await seed(reset=True)
    data = await build_dashboard("30d")

    commands = {c.command for c in data.top_commands}
    assert "uname -a" in commands


@pytest.mark.asyncio
async def test_top_attackers_lists_seeded_source_ips() -> None:
    await seed(reset=True)
    data = await build_dashboard("30d")

    ips = {a.ip for a in data.top_attackers}
    assert "185.220.101.44" in ips


@pytest.mark.asyncio
async def test_trend_is_flat_when_previous_window_is_empty() -> None:
    await seed(reset=True)
    data = await build_dashboard("1h")

    events_kpi = next(k for k in data.kpis if k.id == "total_events")
    if events_kpi.value == 0:
        assert events_kpi.trend_direction == "flat"
        assert events_kpi.trend_pct == 0


@pytest.mark.asyncio
async def test_30d_window_returns_at_least_as_many_events_as_1h_window() -> None:
    # The 1h window is a strict subset of the 30d window in wall-clock time,
    # so this must always hold regardless of what live traffic looks like
    # when the suite runs.
    await seed(reset=True)
    wide = await build_dashboard("30d")
    narrow = await build_dashboard("1h")

    wide_total = next(k for k in wide.kpis if k.id == "total_events").value
    narrow_total = next(k for k in narrow.kpis if k.id == "total_events").value
    assert wide_total >= narrow_total
    # The seed corpus alone (51 docs) plus any live traffic guarantees the
    # 30d window is non-trivially larger than an empty-or-near-empty 1h one.
    assert wide_total > 0


@pytest.mark.asyncio
async def test_empty_enrichment_fields_are_honestly_empty_not_fabricated() -> None:
    # No document in the index has risk.level, ai_classification, or
    # mitre.technique_id populated yet (that's Task 14's job). The
    # dashboard must reflect that honestly: zeros and empty lists, not
    # invented values.
    await seed(reset=True)
    data = await build_dashboard("30d")

    assert data.classifications == []
    assert all(bucket.value == 0 for bucket in data.risk_distribution)
    assert {bucket.level for bucket in data.risk_distribution} == {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }
    assert all(command.technique_id is None for command in data.top_commands)

    high_risk_kpi = next(k for k in data.kpis if k.id == "high_risk")
    techniques_kpi = next(k for k in data.kpis if k.id == "techniques")
    assert high_risk_kpi.value == 0
    assert techniques_kpi.value == 0
