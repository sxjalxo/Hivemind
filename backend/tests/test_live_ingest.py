import pytest

from app.config import get_settings
from app.es.client import get_es


@pytest.mark.asyncio
async def test_live_cowrie_events_are_ecs_shaped() -> None:
    settings = get_settings()
    result = await get_es().search(
        index=settings.es_index,
        query={
            "bool": {
                "filter": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"term": {"labels.seeded": False}},
                    # The local Filebeat input under test. Other sensors' live
                    # events share the index (gcp-wild-01 since 2026-10-18),
                    # so an unscoped first hit could be any of them.
                    {"term": {"honeypot.id": "cowrie-01"}},
                ]
            }
        },
        size=1,
    )
    hits = result["hits"]["hits"]
    if not hits:
        pytest.skip("no live Cowrie traffic ingested yet; run the SSH step first")

    src = hits[0]["_source"]
    assert src["event"]["category"] == "process"
    assert src["process"]["command_line"]
    assert src["session"]["id"]
    assert src["honeypot"]["name"]  # stamped by that input, beside its id
