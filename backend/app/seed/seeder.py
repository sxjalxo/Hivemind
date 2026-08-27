import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch.helpers import async_bulk

from app.config import get_settings
from app.es.bootstrap import PIPELINE_ID, bootstrap_es
from app.es.client import get_es

SEED_BASE_TIME = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
CORPUS_DIR = Path(__file__).parent / "corpus"

HONEYPOT = {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"}


def load_corpus() -> list[dict]:
    """Expand corpus fixtures into Cowrie-format events with stable ids.

    Deterministic: the same files in produce byte-identical events out.
    """
    events: list[dict] = []
    for path in sorted(CORPUS_DIR.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        session = fixture["session"]
        for index, raw in enumerate(fixture["events"]):
            event = {k: v for k, v in raw.items() if k != "offset"}
            timestamp = SEED_BASE_TIME + timedelta(seconds=raw["offset"])
            event.update(
                {
                    "_id": f"{session}-{index:03d}",
                    "session": session,
                    "src_ip": fixture["src_ip"],
                    "src_port": fixture["src_port"],
                    "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                }
            )
            events.append(event)
    return events


def _seeded_query() -> dict:
    """Match only real corpus documents, not merely anything labelled seeded.

    Belt and braces: labels.seeded says a document claims to be seed data;
    matching against load_corpus()'s actual _id set says it is really ours.
    A document that sets labels.seeded: true without being one of our ids
    (e.g. a mislabeled fixture in an unrelated test, or future corruption)
    must not be counted, nor deleted by seed(reset=True).

    Elasticsearch's `_id` field is of type `_id`, which rejects prefix/
    wildcard queries outright ("Can only use prefix queries on keyword,
    text and wildcard fields - not on [_id]"), so a prefix check on "seed-"
    is not expressible directly. The `ids` query is the field's supported
    lookup and is exact rather than prefix-based, which is even tighter.
    """
    ids = [event["_id"] for event in load_corpus()]
    return {
        "bool": {
            "filter": [
                {"term": {"labels.seeded": True}},
                {"ids": {"values": ids}},
            ]
        }
    }


def _to_bulk_action(event: dict, index: str) -> dict:
    doc = {k: v for k, v in event.items() if k != "_id"}
    doc["honeypot"] = dict(HONEYPOT)
    doc["labels"] = {"seeded": True}
    return {
        "_op_type": "index",
        "_index": index,
        "_id": event["_id"],
        "pipeline": PIPELINE_ID,
        "_source": doc,
    }


async def seeded_count() -> int:
    settings = get_settings()
    await get_es().indices.refresh(index=settings.es_index)
    result = await get_es().count(index=settings.es_index, query=_seeded_query())
    return int(result["count"])


async def seed(reset: bool = False) -> int:
    """Index the corpus. Fixed ids make this idempotent — reruns overwrite."""
    settings = get_settings()
    await bootstrap_es()

    if reset:
        await get_es().delete_by_query(
            index=settings.es_index,
            query=_seeded_query(),
            refresh=True,
            conflicts="proceed",
        )

    events = load_corpus()
    actions = [_to_bulk_action(e, settings.es_index) for e in events]
    await async_bulk(get_es(), actions, refresh="wait_for")
    return len(actions)


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Seed the honeypot event corpus")
    parser.add_argument("--reset", action="store_true", help="delete seeded docs first")
    args = parser.parse_args()
    count = await seed(reset=args.reset)
    print(f"indexed {count} seeded events")
    await get_es().close()


if __name__ == "__main__":
    asyncio.run(_main())
