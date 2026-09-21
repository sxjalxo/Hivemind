from datetime import datetime, timedelta, timezone

import pytest
from elasticsearch import NotFoundError

from app.config import get_settings
from app.es.client import get_es
from app.seed.seeder import (
    SEED_TRAILING_MARGIN,
    load_corpus,
    seed,
    seed_base_time,
    seeded_count,
)

EXPECTED_SESSIONS = {
    "seed-botnet-01",
    "seed-miner-01",
    "seed-persist-01",
    "seed-recon-01",
    "seed-brute-01",
    "seed-unmapped-01",
}


def test_corpus_covers_all_six_sessions() -> None:
    events = load_corpus()
    assert {e["session"] for e in events} == EXPECTED_SESSIONS


def test_every_corpus_event_has_a_stable_id() -> None:
    events = load_corpus()
    ids = [e["_id"] for e in events]
    assert len(ids) == len(set(ids)), "duplicate seed document ids"
    assert all(i.startswith("seed-") for i in ids)


@pytest.mark.asyncio
async def test_seeding_is_idempotent() -> None:
    first = await seed(reset=True)
    second = await seed()
    assert first == second
    assert await seeded_count() == first


@pytest.mark.asyncio
async def test_seeded_events_pass_through_the_ecs_pipeline() -> None:
    await seed(reset=True)
    result = await get_es().search(
        index=get_settings().es_index,
        query={"term": {"session.id": "seed-botnet-01"}},
        sort=[{"@timestamp": "asc"}],
        size=50,
    )
    sources = [h["_source"] for h in result["hits"]["hits"]]
    assert sources, "botnet session did not index"

    commands = [
        s["process"]["command_line"]
        for s in sources
        if s["event"]["action"] == "cowrie.command.input"
    ]
    assert "cd /tmp" in commands
    assert any(c.startswith("wget ") for c in commands)
    assert any(c.startswith("chmod ") for c in commands)
    assert all(s["labels"]["seeded"] is True for s in sources)


@pytest.mark.asyncio
async def test_seeded_scoping_ignores_stray_non_seed_prefixed_documents() -> None:
    """labels.seeded alone does not identify a corpus document -- only the
    combination of the label AND a seed- prefixed _id does. A stray document
    that sets labels.seeded: true without that id prefix (e.g. a mislabeled
    fixture from an unrelated test) must not be counted by seeded_count()
    and must survive seed(reset=True) untouched."""
    settings = get_settings()
    es = get_es()
    stray_id = "not-seed-prefixed-but-labelled-seeded"

    baseline = await seed(reset=True)

    await es.index(
        index=settings.es_index,
        id=stray_id,
        document={
            "labels": {"seeded": True},
            "honeypot": {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"},
        },
        refresh=True,
    )
    try:
        assert await seeded_count() == baseline, "stray doc must not be counted"

        second = await seed(reset=True)
        assert second == baseline, "reset must reseed exactly the real corpus"
        assert await es.exists(index=settings.es_index, id=stray_id), (
            "reset must not delete a labels.seeded doc outside the seed- id prefix"
        )
    finally:
        try:
            await es.delete(index=settings.es_index, id=stray_id)
        except NotFoundError:
            pass


def test_the_corpus_lands_inside_the_windows_the_dashboard_queries() -> None:
    """The corpus exists to fill every screen before an attacker connects.

    It was anchored to a fixed calendar date, so it aged out of the 30d
    window and every panel went blank -- with nothing logged, because an
    out-of-range document is indexed and counted exactly like any other.
    Pinning the anchor against a FIXED `now` keeps this a statement about
    the corpus rather than about the clock the suite happened to run on.
    """
    now = datetime(2027, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    stamps = [
        datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        for e in load_corpus(now=now)
    ]

    assert stamps
    # Nothing in the future: a honeypot event dated after the present moment
    # is a nonsense, and it would fall outside every window too.
    assert max(stamps) <= now
    # The newest event sits exactly the margin back, so it is in range of the
    # narrowest window the UI offers rather than merely inside 30d.
    assert now - max(stamps) == SEED_TRAILING_MARGIN
    assert now - min(stamps) < timedelta(hours=1), (
        "the corpus no longer fits the 1h dashboard window; "
        "shrink a fixture's offsets or accept a wider narrowest window"
    )


def test_the_anchor_moves_but_the_identity_of_an_event_does_not() -> None:
    """Re-anchoring must not fork the corpus into new documents.

    `seed(reset=True)` deletes by the id set `load_corpus()` reports, so an
    id derived from a timestamp would leave every previous seeding behind on
    each run instead of overwriting it.
    """
    early = load_corpus(now=datetime(2027, 3, 1, 12, 0, 0, tzinfo=timezone.utc))
    later = load_corpus(now=datetime(2027, 6, 14, 9, 30, 0, tzinfo=timezone.utc))

    assert [e["_id"] for e in early] == [e["_id"] for e in later]
    assert [e["session"] for e in early] == [e["session"] for e in later]
    # Intervals are what the timeline and session durations are built from.
    def spans(events):
        base = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        return [
            datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) - base
            for e in events
        ]

    assert spans(early) == spans(later)


def test_the_base_time_follows_a_corpus_that_grows() -> None:
    """A fixture added with a later offset must move the anchor back with it."""
    now = datetime(2027, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert seed_base_time(3030, now) > seed_base_time(9000, now)
    assert now - seed_base_time(9000, now) == SEED_TRAILING_MARGIN + timedelta(seconds=9000)
