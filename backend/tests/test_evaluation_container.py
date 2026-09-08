"""`container.run` is the shared primitive both `reset` and `fingerprints`
depend on to look inside the honeypot.

It was previously exercised only indirectly -- `reset`'s tests monkeypatch
`reset._spawn`, which bypasses it entirely, and the fingerprint tests drive
it through `honeypot_fingerprint`. Every way this function can turn a failed
command into an empty, confident-looking result is tested here directly.

The failure shapes are not invented: `docker exec hivemind-cowrie-1
/no/such/bin` against the live container exits 127 with 141 bytes on STDOUT
and nothing on stderr.
"""

import asyncio
import shutil

import pytest

from app.services.evaluation import container


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False
        self.waited = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        self.waited = True
        return self.returncode


class _HangingProc(_FakeProc):
    def __init__(self) -> None:
        super().__init__(0)

    async def communicate(self) -> tuple[bytes, bytes]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def _spawns(monkeypatch, proc):
    async def _spawn(argv):
        return proc

    monkeypatch.setattr(container, "_spawn", _spawn)
    return proc


# ---------------------------------------------------------------------------
# The docker CLI itself
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_missing_docker_binary_raises(monkeypatch) -> None:
    async def _spawn(argv):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "inspect", "x"], timeout_seconds=5.0)
    assert "docker" in str(exc.value)


# ---------------------------------------------------------------------------
# Success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exit_zero_returns_stdout_verbatim(monkeypatch) -> None:
    _spawns(monkeypatch, _FakeProc(0, stdout=b"sha256:abc\n"))
    assert await container.run(["docker", "inspect", "x"], timeout_seconds=5.0) == b"sha256:abc\n"


@pytest.mark.asyncio
async def test_exit_zero_with_empty_stdout_returns_empty_rather_than_raising(
    monkeypatch,
) -> None:
    # `run` does NOT judge the content of a successful command: an empty
    # result can be legitimate (an empty directory listing) and only the
    # caller knows. `fingerprints` is the one that rejects a 0-length digest.
    # Encoding that policy here would make `run` unusable for anything else.
    _spawns(monkeypatch, _FakeProc(0, stdout=b""))
    assert await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0) == b""


@pytest.mark.asyncio
async def test_exit_zero_with_stderr_noise_still_succeeds(monkeypatch) -> None:
    # A warning on stderr is not a failure. Only the return code decides.
    _spawns(monkeypatch, _FakeProc(0, stdout=b"payload", stderr=b"warning: whatever\n"))
    assert await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0) == b"payload"


# ---------------------------------------------------------------------------
# Failure: the diagnostic has to survive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_nonzero_exit_with_stderr_raises_with_code_and_detail(monkeypatch) -> None:
    _spawns(
        monkeypatch,
        _FakeProc(1, stderr=b"Error response from daemon: No such container: nope\n"),
    )
    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "exec", "nope", "y"], timeout_seconds=5.0)
    message = str(exc.value)
    assert "exit code 1" in message
    assert "No such container" in message
    assert "docker exec nope" in message


@pytest.mark.asyncio
async def test_a_nonzero_exit_reported_only_on_stdout_keeps_the_message(monkeypatch) -> None:
    # The shape the live container actually produces. A stderr-only reader
    # yields "exit code 127: " -- an empty detail on precisely the failure
    # this project keeps hitting, in an image with no shell to investigate
    # with afterwards.
    observed = (
        b"OCI runtime exec failed: exec failed: unable to start container process: "
        b'exec: "/no/such/bin": stat /no/such/bin: no such file or directory\n'
    )
    _spawns(monkeypatch, _FakeProc(127, stdout=observed, stderr=b""))

    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(
            ["docker", "exec", "hivemind-cowrie-1", "/no/such/bin"], timeout_seconds=5.0
        )
    message = str(exc.value)
    assert "127" in message
    assert "no such file or directory" in message
    assert not message.rstrip().endswith("127:"), "the only diagnostic was dropped"


@pytest.mark.asyncio
async def test_stderr_wins_over_stdout_when_both_are_present(monkeypatch) -> None:
    _spawns(monkeypatch, _FakeProc(2, stdout=b"progress chatter", stderr=b"the real cause"))
    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0)
    assert "the real cause" in str(exc.value)
    assert "progress chatter" not in str(exc.value)


@pytest.mark.asyncio
async def test_a_nonzero_exit_with_no_output_at_all_still_names_the_code(monkeypatch) -> None:
    _spawns(monkeypatch, _FakeProc(3))
    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0)
    assert "exit code 3" in str(exc.value)


@pytest.mark.asyncio
async def test_a_huge_error_stream_is_truncated_head_first(monkeypatch) -> None:
    # An unbounded message becomes a multi-megabyte DB row and a log line
    # nothing renders. The head is what identifies the cause, so it is the
    # half that survives.
    noise = b"CAUSE-FIRST " + b"x" * 5_000_000
    _spawns(monkeypatch, _FakeProc(1, stderr=noise))

    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0)
    message = str(exc.value)
    assert "CAUSE-FIRST" in message
    assert len(message) < 1000
    assert "truncated" in message


def test_error_detail_leaves_short_output_untouched() -> None:
    assert container.error_detail(b"", b"boom\n") == "boom"
    assert "truncated" not in container.error_detail(b"", b"x" * container.ERROR_DETAIL_LIMIT)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_utf8_output_is_returned_as_raw_bytes(monkeypatch) -> None:
    # `run` returns bytes, so a binary or mis-encoded payload reaches the
    # caller intact instead of being lost to a decode error.
    payload = b"\xff\xfe\x00binary\x80"
    _spawns(monkeypatch, _FakeProc(0, stdout=payload))
    assert await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0) == payload


@pytest.mark.asyncio
async def test_non_utf8_error_output_does_not_crash_the_error_path(monkeypatch) -> None:
    # A UnicodeDecodeError raised while BUILDING the failure message would
    # replace a clear "exit 127" with an unrelated traceback.
    _spawns(monkeypatch, _FakeProc(127, stderr=b"bad \xff\xfe byte"))
    with pytest.raises(container.ContainerExecError) as exc:
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=5.0)
    assert "127" in str(exc.value)
    assert "bad" in str(exc.value)


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_hanging_call_times_out_and_reaps_the_process(monkeypatch) -> None:
    proc = _spawns(monkeypatch, _HangingProc())

    with pytest.raises(container.ContainerExecTimeout) as exc:
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=0.05)

    assert "timed out" in str(exc.value)
    # No stray docker client left behind: killed AND awaited, so the child
    # is reaped rather than left as a zombie.
    assert proc.killed
    assert proc.waited


@pytest.mark.asyncio
async def test_a_timeout_is_a_container_exec_error_subclass(monkeypatch) -> None:
    # Callers that only catch ContainerExecError must not miss a timeout.
    _spawns(monkeypatch, _HangingProc())
    with pytest.raises(container.ContainerExecError):
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=0.05)


@pytest.mark.asyncio
async def test_a_kill_that_fails_does_not_mask_the_timeout(monkeypatch) -> None:
    # The process may have died on its own between the deadline and the
    # kill. That must still surface as a timeout, not as a ProcessLookupError.
    class _UnkillableProc(_HangingProc):
        def kill(self) -> None:
            raise ProcessLookupError

    _spawns(monkeypatch, _UnkillableProc())
    with pytest.raises(container.ContainerExecTimeout):
        await container.run(["docker", "exec", "x", "y"], timeout_seconds=0.05)


# ---------------------------------------------------------------------------
# Container facts
# ---------------------------------------------------------------------------


def test_the_container_interpreter_is_named_by_absolute_path() -> None:
    # docker exec does not apply the image entrypoint, so a bare `python3`
    # would not resolve. The image is distroless; this is the only executable.
    assert container.CONTAINER_PYTHON.startswith("/")


@pytest.mark.parametrize("name", ["hivemind-cowrie-1", "a", "a.b_c-d"])
def test_valid_container_names_match(name) -> None:
    assert container.CONTAINER_NAME.fullmatch(name)


@pytest.mark.parametrize("name", ["", "   ", "bad name", "-leading-dash", "a/b", "a;rm -rf /"])
def test_unusable_container_names_are_rejected(name) -> None:
    assert not container.CONTAINER_NAME.fullmatch(name)


# ---------------------------------------------------------------------------
# Live: the real docker CLI. Read-only, and never against the honeypot's
# own state -- the container is only asked about a binary that is not there.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_a_missing_binary_reports_on_stdout_not_stderr() -> None:
    # Pins the premise the stdout fallback exists for. If docker ever moves
    # this message to stderr the fallback becomes dead code, and this test
    # is what would say so.
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    try:
        await container.run(
            ["docker", "exec", "hivemind-cowrie-1", "/no/such/bin"], timeout_seconds=30.0
        )
    except container.ContainerExecTimeout as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")
    except container.ContainerExecError as exc:
        message = str(exc)
        if "No such container" in message or "Cannot connect to the Docker daemon" in message:
            pytest.skip(f"cowrie container not reachable: {message}")
        assert "exit code 127" in message
        assert "no such file or directory" in message
    else:
        pytest.fail("a nonexistent binary must not succeed")
