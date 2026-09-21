import uuid
from datetime import datetime

import pytest

from app.config import get_settings
from app.es.client import get_es
from app.seed.seeder import load_corpus, seed
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
    # ip must be the real destination.ip observed on indexed events, never
    # a hardcoded loopback placeholder.
    assert cowrie.ip != "127.0.0.1"
    # risk.level is unassessed until Task 14; "informational" is this
    # codebase's convention for "not yet assessed" — never a fabricated
    # non-neutral severity like "medium".
    assert cowrie.risk == "informational"


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
async def test_top_commands_counts_seeded_commands(monkeypatch) -> None:
    """Every command on the panel must be one the corpus really recorded.

    This asserted `uname -a`, which the corpus contains exactly once. So does
    every other seeded command, and the aggregation takes the top 10 of 25 --
    ties broken by term ascending, where `uname -a` sorts last and can never
    appear. The assertion only ever passed because live honeypot traffic was
    in the same index and the evaluation agent's own probes run `uname -a`
    thousands of times. It was testing the agent, not the corpus.

    So: a command the corpus does contain and the tie-break does reach, plus
    the property that actually matters -- nothing on this panel came from
    somewhere else.

    Runs against its OWN index. Asserting exact counts over the shared index
    makes this a test of the machine's state: one real Cowrie session lands a
    `uname -a` next to the seeded one and the count becomes 2. That is not a
    dashboard defect, and a test that fails on it is measuring live traffic
    again -- the exact confusion this test was rewritten to end. The name
    matches the `honeypot-events*` template pattern so the index gets the real
    mappings; with dynamic ones `process.command_line.keyword` would not
    exist and the aggregation would return nothing.
    """
    es = get_es()
    index = f"honeypot-events-dash-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", index)
    try:
        await seed(reset=True)
        data = await build_dashboard("30d")

        seeded = {
            e["input"] for e in load_corpus() if e["eventid"] == "cowrie.command.input"
        }
        commands = {c.command for c in data.top_commands}

        assert commands, "the top-commands panel is empty"
        assert "cd /tmp" in commands
        assert commands <= seeded, f"not from the corpus: {sorted(commands - seeded)}"
        # Each seeded command appears once, so a count above one means the
        # panel is counting something the corpus did not put there.
        assert all(c.count == 1 for c in data.top_commands)
    finally:
        for name in await es.indices.get_alias(name=index):
            await es.indices.delete(index=name)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_top_attackers_lists_seeded_source_ips() -> None:
    await seed(reset=True)
    data = await build_dashboard("30d")

    ips = {a.ip for a in data.top_attackers}
    assert "185.220.101.44" in ips
    # No attacker has been assessed yet — every one must carry the
    # "not yet assessed" convention, never a fabricated severity.
    assert all(a.risk == "informational" for a in data.top_attackers)


@pytest.mark.asyncio
async def test_total_events_kpi_trend_agrees_with_the_windows_it_summarises() -> None:
    # This asserted the trend was "flat" whenever the CURRENT window held no
    # events, though its name spoke about the previous one. Those are not the
    # same thing: no events now against events an hour ago is a real decrease,
    # so the assertion started failing the moment live traffic existed -- while
    # the dashboard was right.
    #
    # _trend's zero-baseline behaviour is already covered directly by
    # test_trend_flat_on_zero_baseline. What is worth checking at this level is
    # that the dashboard hands _trend the two counts it claims to compare.
    await seed(reset=True)
    data = await build_dashboard("1h")

    start, end = range_to_bounds("1h")
    start_at, end_at = _parse(start), _parse(end)
    previous_start = start_at - (end_at - start_at)

    es = get_es()
    index = get_settings().es_index

    async def _window(begin, finish) -> int:
        return (
            await es.count(
                index=index,
                query={
                    "range": {"@timestamp": {"gte": begin.isoformat(), "lt": finish.isoformat()}}
                },
            )
        )["count"]

    # Only the PREVIOUS window is recounted here. It is entirely in the past,
    # so no ingest can change it between the dashboard's call and this one.
    # Recounting the CURRENT window would race live Cowrie traffic: the
    # dashboard fixed its bounds moments earlier, and an event arriving in
    # between would fail an equality assertion on a correct dashboard. The
    # dashboard's own reported value is used as the current count instead,
    # which still proves it fed _trend the right previous window.
    previous = await _window(previous_start, start_at)

    events_kpi = next(k for k in data.kpis if k.id == "total_events")
    expected_pct, expected_direction = _trend(events_kpi.value, previous)

    assert events_kpi.trend_direction == expected_direction
    assert events_kpi.trend_pct == expected_pct


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
async def test_timeline_spans_the_full_requested_window_not_just_observed_data() -> None:
    # extended_bounds/hard_bounds must force the date_histogram to cover
    # the entire requested range, not merely the span where documents
    # happen to exist. min_doc_count: 0 alone only fills gaps BETWEEN
    # observed documents — without explicit bounds a 30d window whose data
    # is clustered on ~8 days renders ~8 daily buckets instead of ~30, and
    # a window with zero matching documents (like a quiet 1h) renders no
    # buckets at all rather than a run of zero-valued ones.
    await seed(reset=True)
    data = await build_dashboard("30d")

    # 30 days of 1d buckets is ~30-31 buckets, never the ~8 you'd get by
    # only spanning the days that actually have data.
    assert len(data.timeline) >= 28
    # The requested window starts well before any seed/live data does, so
    # the leading buckets must exist with zero events, not be absent.
    assert data.timeline[0].events == 0

    narrow = await build_dashboard("1h")
    # 1h of 5m buckets is ~12-13 buckets, present even when the window
    # holds no events at all — an empty list would be indistinguishable
    # from a broken request on the frontend's chart.
    assert len(narrow.timeline) >= 11


@pytest.mark.asyncio
async def test_dashboard_enrichment_fields_are_never_fabricated() -> None:
    # This test used to assert these fields were *empty*, on the premise that
    # no document in the index carried risk.level, ai_classification or
    # mitre.technique_id. That premise only held while the index contained
    # nothing but unanalysed seed data. Write-back enrichment stamps those
    # fields onto real events, so the moment any live session is analysed --
    # ordinary use of the product -- the assertion failed while the dashboard
    # was behaving correctly.
    #
    # What the test is actually for is that the dashboard never reports a
    # value the index cannot back. Checking that against Elasticsearch ground
    # truth covers the empty index and the populated one, and still fails if a
    # number is invented.
    await seed(reset=True)
    data = await build_dashboard("30d")

    es = get_es()
    index = get_settings().es_index

    async def _count(query: dict) -> int:
        return (await es.count(index=index, query=query))["count"]

    # Every classification named must be one some document actually carries.
    for bucket in data.classifications:
        assert bucket.value > 0, bucket.name
        assert await _count({"term": {"ai_classification": bucket.name}}) > 0, bucket.name

    # All five levels are always present so the chart has a stable domain even
    # when nothing has been assessed, and no level may claim events that do
    # not exist.
    assert {bucket.level for bucket in data.risk_distribution} == {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }
    for bucket in data.risk_distribution:
        if bucket.value:
            backing = await _count({"term": {"risk.level": bucket.level}})
            assert backing >= bucket.value, (bucket.level, bucket.value, backing)

    # A top command may only carry a technique id its own documents carry.
    for command in data.top_commands:
        if command.technique_id is not None:
            assert (
                await _count(
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.command_line.keyword": command.command}},
                                {"term": {"mitre.technique_id": command.technique_id}},
                            ]
                        }
                    }
                )
                > 0
            ), command.command

    high_risk_kpi = next(k for k in data.kpis if k.id == "high_risk")
    techniques_kpi = next(k for k in data.kpis if k.id == "techniques")

    # The KPI must agree with the distribution it is drawn from...
    assert high_risk_kpi.value == sum(
        bucket.value for bucket in data.risk_distribution if bucket.level in {"critical", "high"}
    )
    # ...and no technique may be counted unless a document is mapped to one.
    mapped = await _count({"exists": {"field": "mitre.technique_id"}})
    if mapped == 0:
        assert techniques_kpi.value == 0
    else:
        assert 0 < techniques_kpi.value <= mapped
