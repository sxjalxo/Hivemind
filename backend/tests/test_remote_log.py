"""app.services.evaluation.remote_log against the real index and pipeline, with
the SSH read replaced: the remote evaluation log is indexed exactly once."""

import json

import pytest
import pytest_asyncio

from app.config import EvalGate, get_settings
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es
from app.services.evaluation import remote_log

HONEYPOT = "test-remote-log"
GATE = EvalGate(host="203.0.113.5", host_key="ssh-ed25519 AAAA")


def _line(**event) -> bytes:
    base = {"session": "rl-sess", "src_ip": "203.0.113.9", "timestamp": "2026-10-18T17:00:00Z"}
    return (json.dumps({**base, **event}) + "\n").encode()


def _serve(monkeypatch, data: bytes) -> None:
    monkeypatch.setattr(remote_log.wild_pull, "read_live_log", lambda gate: (42, data))


async def _ours() -> list[dict]:
    es = get_es()
    await es.indices.refresh(index=get_settings().es_index)
    result = await es.search(
        index=get_settings().es_index, query={"term": {"honeypot.id": HONEYPOT}}, size=50
    )
    return [h["_source"] for h in result["hits"]["hits"]]


@pytest_asyncio.fixture(loop_scope="session")
async def clean():
    await bootstrap_es()
    yield
    await get_es().delete_by_query(
        index=get_settings().es_index,
        query={"term": {"honeypot.id": HONEYPOT}},
        refresh=True,
    )


@pytest.mark.asyncio
async def test_the_log_is_indexed_once_however_often_it_is_fetched(monkeypatch, clean) -> None:
    _serve(monkeypatch, _line(eventid="cowrie.session.connect"))
    assert await remote_log.ingest(GATE, HONEYPOT) == 1

    # The next fetch returns the same first line plus a new one.
    _serve(
        monkeypatch,
        _line(eventid="cowrie.session.connect")
        + _line(eventid="cowrie.command.input", input="uname -a"),
    )
    assert await remote_log.ingest(GATE, HONEYPOT) == 1
    assert await remote_log.ingest(GATE, HONEYPOT) == 0

    docs = await _ours()
    assert len(docs) == 2
    commands = [d["process"]["command_line"] for d in docs if "process" in d]
    assert commands == ["uname -a"]
    assert {d["honeypot"]["name"] for d in docs} == {GATE.name}


@pytest.mark.asyncio
async def test_an_event_the_index_refuses_is_an_error_not_a_gap(monkeypatch, clean) -> None:
    _serve(monkeypatch, _line(eventid="cowrie.session.connect", never_mapped=1))
    with pytest.raises(RuntimeError, match="refused by the index"):
        await remote_log.ingest(GATE, HONEYPOT)
