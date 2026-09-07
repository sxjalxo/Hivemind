import pytest

from app.services.evaluation.static import tcpdump


@pytest.mark.asyncio
async def test_capture_stops_even_when_the_body_raises(monkeypatch) -> None:
    stopped: list[bool] = []

    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            stopped.append(True)

        async def communicate(self):
            return (b"3 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    with pytest.raises(RuntimeError):
        async with tcpdump.capture("eth0", timeout_seconds=5):
            raise RuntimeError("agent stage blew up")

    # A leaked tcpdump process outlives the run and keeps capturing forever.
    assert stopped == [True]


@pytest.mark.asyncio
async def test_packets_seen_marks_traffic_observed(monkeypatch) -> None:
    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            pass

        async def communicate(self):
            return (b"12 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", timeout_seconds=5) as cap:
        pass
    outcome = cap.outcome

    assert outcome.module_status == "completed"
    fact = next(o for o in outcome.observations if o.establishes == "network.activity")
    assert fact.fact_status == "observed"
    assert fact.value == "12"


@pytest.mark.asyncio
async def test_zero_packets_marks_traffic_not_observed(monkeypatch) -> None:
    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            pass

        async def communicate(self):
            return (b"0 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", timeout_seconds=5) as cap:
        pass
    outcome = cap.outcome

    assert outcome.module_status == "completed"
    fact = next(o for o in outcome.observations if o.establishes == "network.activity")
    assert fact.fact_status == "not_observed"
    assert fact.value == "0"


@pytest.mark.asyncio
async def test_spawn_failure_leaves_fact_unknown_not_not_observed(monkeypatch) -> None:
    # The failure model this whole subsystem shares: a capture that could not
    # run must not be readable as "no traffic occurred". It is unknown.
    async def _boom(*args, **kwargs):
        raise OSError("tcpdump not found")

    monkeypatch.setattr(tcpdump, "_spawn", _boom)

    async with tcpdump.capture("eth0", timeout_seconds=5) as cap:
        pass
    outcome = cap.outcome

    assert outcome.module_status == "error"
    fact = next(o for o in outcome.observations if o.establishes == "network.activity")
    assert fact.fact_status == "unknown"
    assert fact.value is None
