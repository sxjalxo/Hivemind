import pytest
from elasticsearch import NotFoundError

from app.config import get_settings
from app.es.client import get_es
from app.seed.seeder import load_corpus, seed, seeded_count

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
