"""The HTTP honeypot (infra/webpot) and the path its events take into the app."""

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from app.config import get_settings
from app.es.bootstrap import PIPELINE_ID, bootstrap_es
from app.es.client import get_es
from app.es.queries import to_event
from app.services import session_builder

_SPEC = importlib.util.spec_from_file_location(
    "webpot", Path(__file__).resolve().parents[2] / "infra" / "webpot" / "webpot.py"
)
webpot = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(webpot)


def test_one_session_per_ip_until_the_gap_passes():
    sessions = webpot.Sessions(gap=60)
    first = sessions.id_for("203.0.113.9", 0)
    assert sessions.id_for("203.0.113.9", 59) == first  # activity keeps it alive
    assert sessions.id_for("203.0.113.9", 118) == first
    assert sessions.id_for("198.51.100.1", 118) != first  # another IP, another session
    assert sessions.id_for("203.0.113.9", 179) != first  # 61 s of silence


def test_record_splits_the_query_and_caps_what_an_attacker_controls():
    line = webpot.record(
        eventid="web.request",
        ip="203.0.113.9",
        port=40000,
        session="abc",
        method="GET",
        target="/wp-login.php?redirect_to=" + "x" * 5000,
        status=404,
        user_agent="u" * 1000,
    )
    assert line["path"] == "/wp-login.php"
    assert len(line["query"]) == webpot.MAX_FIELD
    assert len(line["user_agent"]["original"]) == 512
    assert line["network"] == {"protocol": "http"}
    assert line["timestamp"].endswith("Z")
    assert "username" not in line


@pytest.fixture
def server(tmp_path, monkeypatch):
    log = tmp_path / "webpot.json"
    monkeypatch.setattr(webpot, "LOG_PATH", str(log))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webpot.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", log
    httpd.shutdown()


def _lines(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_it_serves_and_logs_a_scan_and_a_login(server):
    base, log = server
    assert b"Staff Portal" in urllib.request.urlopen(f"{base}/").read()
    with pytest.raises(urllib.error.HTTPError) as missing:
        urllib.request.urlopen(f"{base}/.env")
    assert missing.value.code == 404
    assert missing.value.headers["Server"] == webpot.SERVER
    page = urllib.request.urlopen(f"{base}/login", data=b"username=admin&password=hunter2")
    assert b"Invalid username or password" in page.read()

    get_root, get_env, login = _lines(log)
    assert (get_root["eventid"], get_root["path"]) == ("web.request", "/")
    assert get_env["http"]["response"]["status_code"] == 404
    assert login["eventid"] == "web.login.failed"
    assert (login["username"], login["password"]) == ("admin", "hunter2")
    assert get_root["session"] == get_env["session"] == login["session"]


def test_a_malformed_content_length_is_not_a_crash(server):
    base, log = server
    request = urllib.request.Request(
        f"{base}/login", data=b"", headers={"Content-Length": "abc"}, method="POST"
    )
    assert urllib.request.urlopen(request).status == 200
    assert _lines(log)[0]["username"] == ""


@pytest.mark.asyncio
async def test_a_web_event_is_accepted_by_the_strict_index():
    """The real path: webpot line -> `cowrie` namespace (as Filebeat parses it)
    -> pipeline -> the live strict mapping. Its `path` must become `url.path`,
    never be swept into `file.url` by the Cowrie download rename."""
    await bootstrap_es()
    line = webpot.record(
        eventid="web.request",
        ip="203.0.113.9",
        port=40000,
        session="test-webpot-ingest",
        method="GET",
        target="/.env?x=1",
        status=404,
        user_agent="zgrab/0.x",
    )
    es = get_es()
    result = await es.index(
        index=get_settings().es_index,
        document={"cowrie": line, "honeypot": {"id": "web-01", "name": "Web"}},
        pipeline=PIPELINE_ID,
        refresh=True,
    )
    try:
        stored = await es.get(index=result["_index"], id=result["_id"])
        event = to_event(stored)
        assert event.url.path == "/.env" and event.url.query == "x=1"
        assert event.http.response.status_code == 404
        assert event.event.category == "web"
        assert event.network.protocol == "http"
        assert event.file is None
    finally:
        await es.delete(index=result["_index"], id=result["_id"], refresh=True)


@pytest.mark.asyncio
async def test_the_timeline_shows_the_request_line_and_status(monkeypatch):
    lines = [
        webpot.record(
            eventid="web.request",
            ip="203.0.113.9",
            port=1,
            session="s",
            method="GET",
            target="/.env",
            status=404,
            user_agent=None,
        ),
        webpot.record(
            eventid="web.login.failed",
            ip="203.0.113.9",
            port=1,
            session="s",
            method="POST",
            target="/login",
            status=200,
            user_agent=None,
            username="admin",
            password="x",
        ),
    ]
    # The pipeline's shape, built by hand: the strict-index test above holds
    # the pipeline to it.
    hits = [
        {
            "_id": f"e{i}",
            "_source": {
                "@timestamp": line["timestamp"],
                "source": {"ip": line["src_ip"]},
                "event": {"action": line["eventid"], "category": "web"},
                "network": line["network"],
                "url": {"path": line["path"]},
                "http": line["http"],
                "honeypot": {"id": "web-01", "name": "Web"},
                "session": {"id": "s"},
            },
        }
        for i, line in enumerate(lines)
    ]

    async def fake(session_id):
        return [to_event(h) for h in hits]

    monkeypatch.setattr(session_builder, "get_session_events", fake)
    request, login = await session_builder.build_timeline("s")
    assert (request.kind, request.label, request.detail) == ("request", "GET /.env", "HTTP 404")
    assert (login.kind, login.label) == ("auth", "Login failed")
