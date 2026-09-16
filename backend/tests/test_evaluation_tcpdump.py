import asyncio

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


@pytest.mark.asyncio
async def test_body_exception_survives_stop_failure(monkeypatch) -> None:
    # If the body blows up AND stop() also raises while tearing down the
    # process, Python's exception chaining would otherwise replace the
    # propagating exception with stop()'s -- masking the real cause of the
    # run's failure. stop() must never raise; the body's exception must win.
    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            raise ProcessLookupError("no such process")

        async def communicate(self):
            return (b"3 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    with pytest.raises(RuntimeError, match="agent stage blew up"):
        async with tcpdump.capture("eth0", timeout_seconds=5):
            raise RuntimeError("agent stage blew up")


@pytest.mark.asyncio
async def test_terminate_on_already_exited_process_still_produces_outcome(
    monkeypatch,
) -> None:
    # tcpdump exiting on its own before stop() is called (interface vanished,
    # permission revoked mid-run) is a normal way for a capture to end. No
    # exception should escape, and whatever output is available should still
    # be drained and reported on.
    class _FakeProc:
        returncode = 0

        def terminate(self) -> None:
            raise ProcessLookupError("no such process")

        async def communicate(self):
            return (b"7 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", timeout_seconds=5) as cap:
        pass
    outcome = cap.outcome

    assert outcome is not None
    assert outcome.module_status == "completed"
    fact = next(o for o in outcome.observations if o.establishes == "network.activity")
    assert fact.fact_status == "observed"
    assert fact.value == "7"


@pytest.mark.asyncio
async def test_drain_timeout_marks_status_timeout_and_fact_unknown(monkeypatch) -> None:
    # timeout_seconds must be a real bound on the drain, not a stored no-op.
    # A capture whose drain never finishes must not be silently read as
    # "no traffic" -- it is unknown, and module_status records the timeout.
    killed: list[bool] = []

    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            killed.append(True)

        async def communicate(self):
            await asyncio.sleep(10)
            return (b"3 packets captured\n", b"")

    async def _fake_start(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", timeout_seconds=0.05) as cap:
        pass
    outcome = cap.outcome

    assert outcome is not None
    assert outcome.module_status == "timeout"
    fact = next(o for o in outcome.observations if o.establishes == "network.activity")
    assert fact.fact_status == "unknown"
    assert fact.value is None
    # The process must not be left running past the timeout.
    assert killed == [True]


# --- packet-count parsing -------------------------------------------------


def _proc(stdout: bytes = b"", stderr: bytes = b""):
    class _FakeProc:
        returncode = None

        def terminate(self) -> None:
            pass

        async def communicate(self):
            return (stdout, stderr)

    return _FakeProc()


@pytest.mark.asyncio
async def test_the_packet_count_comes_from_the_summary_line_on_stderr(monkeypatch) -> None:
    """tcpdump prints the summary to stderr, packets to stdout."""

    async def _fake_start(*args, **kwargs):
        return _proc(stderr=b"7 packets captured\n7 packets received by filter\n")

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", 5) as cap:
        pass

    assert cap.outcome.observations[0].value == "7"
    assert cap.outcome.observations[0].fact_status == "observed"


@pytest.mark.asyncio
async def test_a_packet_line_glued_to_the_summary_never_becomes_a_count(monkeypatch) -> None:
    """The bug this guards against produced a confident, fabricated number.

    With both streams on one pipe they interleave unsynchronised, so a partial
    packet line can abut the summary: `...tcp 470363` + `0 packets captured`
    reads as "4703630 packets captured". Observed live -- 4.7 million packets
    for a four-second SSH session, reported as an OBSERVED fact.

    Anchoring to the start of a line means the glued fragment matches nothing,
    so the module reports `unknown` -- we could not read the count -- instead of
    inventing one. Reporting that we could not read it is always preferable to
    reporting a number that is wrong.
    """

    async def _fake_start(*args, **kwargs):
        return _proc(stdout=b"18:49:37.002832 IP 10.0.0.1.22 > 10.0.0.2.5: tcp 4703630 packets captured\n")

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", 5) as cap:
        pass

    assert cap.outcome.observations[0].value != "4703630"
    assert cap.outcome.observations[0].fact_status == "unknown"
    assert cap.outcome.module_status == "error"


@pytest.mark.asyncio
async def test_a_summary_after_packet_lines_is_still_read(monkeypatch) -> None:
    """The anchor must not reject a legitimate summary that follows output."""

    async def _fake_start(*args, **kwargs):
        return _proc(
            stdout=b"18:49:37.002832 IP 10.0.0.1.22 > 10.0.0.2.5: tcp 944\n",
            stderr=b"listening on eth0\n30 packets captured\n30 packets received by filter\n",
        )

    monkeypatch.setattr(tcpdump, "_spawn", _fake_start)

    async with tcpdump.capture("eth0", 5) as cap:
        pass

    assert cap.outcome.observations[0].value == "30"
    assert cap.outcome.observations[0].fact_status == "observed"
