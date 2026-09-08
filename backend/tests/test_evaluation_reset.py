import asyncio
import os
import posixpath
import shutil
import subprocess
import sys
import threading
import uuid as uuid_module
from pathlib import PurePosixPath

import pytest

from app.services.evaluation import reset

# ---------------------------------------------------------------------------
# The safety boundary: what reset must never touch.
# ---------------------------------------------------------------------------


def _covers(parent: str, child: str) -> bool:
    """True when `child` is at or beneath `parent` as a real path.

    Substring matching is not good enough here: "/cowrie/cowrie-git/etc/*"
    does not contain the substring "cowrie.cfg", yet it covers the config
    file. Every boundary assertion in this file uses path containment.
    """
    p = PurePosixPath(parent)
    c = PurePosixPath(child)
    return c == p or p in c.parents


def test_reset_never_touches_operator_authored_state() -> None:
    # Resetting cowrie.cfg or the userdb would mean every run evaluates a
    # pristine default honeypot rather than the one the developer is trying
    # to improve, which makes the whole feedback loop meaningless.
    for preserved in reset.PRESERVED_PATHS:
        for reset_path in reset.RESET_PATHS:
            assert not _covers(reset_path, preserved), (
                f"reset path {reset_path} covers preserved path {preserved}"
            )
    assert any("cowrie.cfg" in p for p in reset.PRESERVED_PATHS)


def test_reset_covers_state_an_evaluation_creates() -> None:
    # Asserted as the exact tuple, not by substring. This module's failure
    # mode is resetting *nothing* while reporting success, and a substring
    # check still passes after tty is dropped from the tuple or after a path
    # is retargeted at /tmp -- both of which are that exact failure.
    assert reset.RESET_PATHS == (
        "/cowrie/cowrie-git/var/lib/cowrie/downloads",
        "/cowrie/cowrie-git/var/lib/cowrie/tty",
    )


def test_ssh_host_keys_and_uuid_are_not_under_any_reset_path() -> None:
    # These sit in the SAME directory as the reset targets. Deleting them
    # would regenerate the honeypot's SSH fingerprint on every run -- itself
    # a realism tell -- and change what the honeypot *is* between runs, so
    # the two runs would no longer be comparable.
    identity = (
        "/cowrie/cowrie-git/var/lib/cowrie/uuid",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key.pub",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ecdsa_key",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ecdsa_key.pub",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ed25519_key",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ed25519_key.pub",
    )
    for key_path in identity:
        for reset_path in reset.RESET_PATHS:
            assert not _covers(reset_path, key_path)
        assert key_path in reset.PRESERVED_PATHS


def test_cowrie_json_is_preserved() -> None:
    # cowrie.json is the source of every session the whole system analyses.
    # It is the most tempting thing to "clean between runs" and deleting it
    # would destroy the evidence the evaluation is about to read.
    log_dir = "/cowrie/cowrie-git/var/log/cowrie"
    assert log_dir in reset.PRESERVED_PATHS
    for reset_path in reset.RESET_PATHS:
        assert not _covers(reset_path, f"{log_dir}/cowrie.json")


# ---------------------------------------------------------------------------
# The boundary is enforced in code, not just documented.
# ---------------------------------------------------------------------------


def test_boundary_guard_rejects_a_reset_path_that_is_a_preserved_path() -> None:
    with pytest.raises(reset.ResetBoundaryError):
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/etc/cowrie.cfg",),
            preserved_paths=("/cowrie/cowrie-git/etc/cowrie.cfg",),
        )


def test_boundary_guard_rejects_a_parent_directory_of_a_preserved_path() -> None:
    # The failure the plan's substring check could not catch: a glob over the
    # parent directory contains no preserved filename as a substring, yet it
    # deletes the preserved file.
    with pytest.raises(reset.ResetBoundaryError) as exc:
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/etc",),
            preserved_paths=("/cowrie/cowrie-git/etc/cowrie.cfg",),
        )
    assert "cowrie.cfg" in str(exc.value)

    # ...and the same path written as the plan wrote it, with a glob suffix.
    with pytest.raises(reset.ResetBoundaryError):
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/etc/*",),
            preserved_paths=("/cowrie/cowrie-git/etc/cowrie.cfg",),
        )


def test_boundary_guard_rejects_wiping_the_state_directory() -> None:
    # The concrete catastrophe: a glob over var/lib/cowrie destroys the SSH
    # host keys that define the honeypot's identity.
    with pytest.raises(reset.ResetBoundaryError):
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/var/lib/cowrie",),
            preserved_paths=("/cowrie/cowrie-git/var/lib/cowrie/uuid",),
        )


def test_boundary_guard_rejects_glob_suffixes_in_reset_paths() -> None:
    # `asyncio.create_subprocess_exec` runs no shell, so a `*` is passed
    # through literally and matches a file named `*`. A reset path with a
    # glob in it is always a bug, never an expansion.
    with pytest.raises(reset.ResetBoundaryError):
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/var/lib/cowrie/downloads/*",),
            preserved_paths=(),
        )


def test_boundary_guard_rejects_a_traversal_out_of_a_reset_path() -> None:
    traversal = "/cowrie/cowrie-git/var/lib/cowrie/downloads/.."

    # First, what makes this dangerous rather than merely untidy. PurePosixPath
    # keeps ".." as a literal component, so the path *compares* as something
    # below downloads -- but the kernel resolves it to the directory holding
    # the honeypot's cryptographic identity, and that is what would be listed
    # and deleted at runtime.
    assert ".." in PurePosixPath(traversal).parts
    resolved = posixpath.normpath(traversal)
    assert resolved == "/cowrie/cowrie-git/var/lib/cowrie"
    reached = [p for p in reset.PRESERVED_PATHS if _covers(resolved, p)]
    assert "/cowrie/cowrie-git/var/lib/cowrie/uuid" in reached
    assert "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key" in reached
    assert "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ed25519_key" in reached

    # So the guard must refuse it outright. Not rewrite it: a ".." in a
    # hardcoded safety constant is a mistake to fail loudly on.
    with pytest.raises(reset.ResetBoundaryError) as exc:
        reset.assert_boundary_holds(
            reset_paths=(traversal,), preserved_paths=reset.PRESERVED_PATHS
        )
    assert ".." in str(exc.value)


def test_boundary_guard_normalises_a_double_slash_root() -> None:
    # POSIX lets an implementation treat exactly two leading slashes as a
    # distinct root and pathlib does, so "//cowrie/..." compares as unrelated
    # to "/cowrie/..." while Linux resolves both to the same directory.
    assert PurePosixPath("//cowrie") != PurePosixPath("/cowrie")

    with pytest.raises(reset.ResetBoundaryError) as exc:
        reset.assert_boundary_holds(
            reset_paths=("//cowrie/cowrie-git/var/lib/cowrie",),
            preserved_paths=("/cowrie/cowrie-git/var/lib/cowrie/uuid",),
        )
    assert "uuid" in str(exc.value)

    # Normalised, not banned: the same directory spelled with two slashes is
    # still the same directory, and a safe target stays acceptable.
    reset.assert_boundary_holds(
        reset_paths=("//cowrie/cowrie-git/var/lib/cowrie/downloads",),
        preserved_paths=reset.PRESERVED_PATHS,
    )


@pytest.mark.parametrize(
    "preserved",
    [
        # A missing leading slash: the typo that reads as protection and is
        # none. Before the guard validated this side, it let a reset path
        # wipe the whole of var/lib/cowrie while reporting the boundary held.
        "var/lib/cowrie/uuid",
        "",
        "/cowrie/cowrie-git/var/lib/cowrie/downloads/../uuid",
        "/cowrie/cowrie-git/var/lib/cowrie/*",
    ],
)
def test_boundary_guard_validates_preserved_paths_too(preserved: str) -> None:
    with pytest.raises(reset.ResetBoundaryError):
        reset.assert_boundary_holds(
            reset_paths=("/cowrie/cowrie-git/var/lib/cowrie",),
            preserved_paths=(preserved,),
        )


def test_preserved_names_survive_the_transport_to_the_container() -> None:
    # They are comma-joined into one argv slot and split on "," at the far
    # end; a name carrying a comma or a slash would arrive as something that
    # matches no directory entry and protects nothing.
    for name in reset.PRESERVED_NAMES:
        assert name
        assert "," not in name
        assert "/" not in name


def test_the_real_configuration_holds() -> None:
    reset.assert_boundary_holds(
        reset_paths=reset.RESET_PATHS, preserved_paths=reset.PRESERVED_PATHS
    )


def test_no_reset_path_carries_a_glob() -> None:
    for path in reset.RESET_PATHS:
        assert "*" not in path
        assert "?" not in path


# ---------------------------------------------------------------------------
# Failure must be loud. A silent no-op reset lets run B inherit run A's
# residue while the report claims the runs are comparable.
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int, stderr: bytes = b"", *, stdout: bytes = b"") -> None:
        self.returncode = returncode
        self._stderr = stderr
        self._stdout = stdout
        self.killed = False

    async def communicate(self):
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


@pytest.mark.asyncio
async def test_nonzero_exit_raises_instead_of_returning_cleanly(monkeypatch) -> None:
    async def _fake_spawn(argv):
        return _FakeProc(1, b"PermissionError: [Errno 13] Permission denied\n")

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError):
        await reset.reset_target("hivemind-cowrie-1")


@pytest.mark.asyncio
async def test_missing_rm_regression_is_reported_with_code_and_stderr(monkeypatch) -> None:
    # The exact observed failure of the original implementation: the Cowrie
    # image is distroless, so `rm` does not exist and docker exec returns
    # 127. The original swallowed this, so reset was a permanent silent
    # no-op. Whatever the cause, the reset must now say so out loud.
    observed_stderr = (
        b'OCI runtime exec failed: exec failed: unable to start container '
        b'process: exec: "rm": executable file not found in $PATH\n'
    )

    async def _fake_spawn(argv):
        return _FakeProc(127, observed_stderr)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError) as exc:
        await reset.reset_target("hivemind-cowrie-1")

    message = str(exc.value)
    assert "127" in message
    assert "executable file not found" in message
    assert "hivemind-cowrie-1" in message
    assert reset.RESET_PATHS[0] in message


@pytest.mark.asyncio
async def test_an_exec_failure_reported_only_on_stdout_is_not_lost(monkeypatch) -> None:
    # The shape docker ACTUALLY produces for this container, verified live:
    # `docker exec hivemind-cowrie-1 /no/such/bin` exits 127 with the OCI
    # message on STDOUT and stderr EMPTY. Reading stderr alone yields
    # "exit code 127: " with nothing after it -- and the image is distroless,
    # so there is no shell to go and find out what happened afterwards. The
    # test above models the failure on stderr, which is why it never caught
    # this.
    observed_stdout = (
        b"OCI runtime exec failed: exec failed: unable to start container process: "
        b'exec: "/cowrie/cowrie-env/bin/python3": stat '
        b"/cowrie/cowrie-env/bin/python3: no such file or directory\n"
    )

    async def _fake_spawn(argv):
        return _FakeProc(127, b"", stdout=observed_stdout)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError) as exc:
        await reset.reset_target("hivemind-cowrie-1")

    message = str(exc.value)
    assert "127" in message
    assert "OCI runtime exec failed" in message
    assert not message.rstrip().endswith("127:"), "the only diagnostic was dropped"


@pytest.mark.asyncio
async def test_a_huge_failure_stream_is_truncated_but_keeps_the_cause(monkeypatch) -> None:
    # A failing reset is persisted and logged by the run orchestrator. An
    # unbounded detail turns one broken `docker exec` into a multi-megabyte
    # row; the head is kept because that is where the cause is printed.
    async def _fake_spawn(argv):
        return _FakeProc(1, b"SystemExit: reset target is not a directory\n" + b"x" * 5_000_000)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError) as exc:
        await reset.reset_target("hivemind-cowrie-1")

    message = str(exc.value)
    assert "reset target is not a directory" in message
    assert len(message) < 1000


@pytest.mark.asyncio
async def test_a_hanging_docker_exec_is_bounded_and_raises(monkeypatch) -> None:
    proc = _FakeProc(0)

    async def _never_returns():
        await asyncio.Event().wait()

    proc.communicate = _never_returns  # type: ignore[method-assign]

    async def _fake_spawn(argv):
        return proc

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError) as exc:
        await reset.reset_target("hivemind-cowrie-1", timeout_seconds=0.05)

    message = str(exc.value).lower()
    assert "timed out" in message
    # Killing the client reaps the local `docker exec`; it does not signal the
    # process inside the container, which keeps deleting. The error has to say
    # so, because a Task 14 retry would otherwise race a live rmtree.
    assert proc.killed is True
    assert "may still be running" in message


@pytest.mark.asyncio
async def test_the_in_container_script_is_given_its_own_deadline(monkeypatch) -> None:
    # Killing the client cannot stop the deletion, so the script has to be
    # able to stop itself.
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)
    await reset.reset_target("hivemind-cowrie-1", timeout_seconds=17.0)

    for argv in spawned:
        assert float(argv[-2]) == 17.0
    assert "signal.alarm" in reset._CLEAR_SCRIPT
    assert "deadline" in reset._CLEAR_SCRIPT


@pytest.mark.asyncio
async def test_docker_binary_missing_raises_rather_than_passing_silently(monkeypatch) -> None:
    async def _fake_spawn(argv):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError):
        await reset.reset_target("hivemind-cowrie-1")


@pytest.mark.asyncio
@pytest.mark.parametrize("container", ["", "   ", "bad name", "-leading-dash", "a/b"])
async def test_an_invalid_container_name_is_rejected_before_shelling_out(
    monkeypatch, container: str
) -> None:
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError):
        await reset.reset_target(container)
    assert spawned == []


# ---------------------------------------------------------------------------
# What is actually executed.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_reset_path_is_acted_on_exactly_once(monkeypatch) -> None:
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)
    await reset.reset_target("hivemind-cowrie-1")

    targeted = [argv[-1] for argv in spawned]
    assert targeted == list(reset.RESET_PATHS)
    assert len(targeted) == len(set(targeted))


@pytest.mark.asyncio
async def test_invocation_targets_the_container_python_not_a_shell_utility(
    monkeypatch,
) -> None:
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)
    await reset.reset_target("hivemind-cowrie-1")

    for argv in spawned:
        assert argv[:3] == ["docker", "exec", "hivemind-cowrie-1"]
        # The image is distroless: python3 is the only executable present,
        # and docker exec does not apply the image entrypoint, so the
        # interpreter must be named by absolute path.
        assert argv[3] == reset.CONTAINER_PYTHON
        assert argv[3].startswith("/")
        assert argv[4] == "-c"
        for utility in ("rm", "sh", "bash", "find"):
            assert utility not in argv[:4]


@pytest.mark.asyncio
async def test_paths_are_passed_as_argv_never_interpolated_into_the_script(
    monkeypatch,
) -> None:
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)
    await reset.reset_target("hivemind-cowrie-1")

    # The script source is a fixed constant. If a path ever appears inside
    # it, some caller is building Python source by concatenating a path.
    for argv in spawned:
        source = argv[5]
        assert source == reset._CLEAR_SCRIPT
        for path in reset.RESET_PATHS:
            assert path not in source
        assert "sys.argv" in source


@pytest.mark.asyncio
async def test_a_success_is_only_claimed_when_every_path_succeeded(monkeypatch) -> None:
    calls: list[list[str]] = []

    async def _fake_spawn(argv):
        calls.append(argv)
        # The second path fails; the first succeeded.
        return _FakeProc(0 if len(calls) == 1 else 1, b"boom")

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetError):
        await reset.reset_target("hivemind-cowrie-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        # The state directory itself: the SSH host keys and the uuid.
        "/cowrie/cowrie-git/var/lib/cowrie",
        # The same directory reached by traversal out of a legitimate target.
        "/cowrie/cowrie-git/var/lib/cowrie/downloads/..",
        # And by the second POSIX root.
        "//cowrie/cowrie-git/var/lib/cowrie",
        # The evidence every session is read back from.
        "/cowrie/cowrie-git/var/log/cowrie",
        "relative/path",
    ],
)
async def test_clear_one_refuses_an_out_of_boundary_path_before_spawning(
    monkeypatch, path: str
) -> None:
    # `assert_boundary_holds` runs at import against the constants only.
    # `_clear_one` is the deletion primitive and the tests below call it
    # directly, so it must check the path it is actually about to clear --
    # otherwise every route to deletion except `reset_target` is unguarded.
    spawned: list[list[str]] = []

    async def _fake_spawn(argv):
        spawned.append(argv)
        return _FakeProc(0)

    monkeypatch.setattr(reset, "_spawn", _fake_spawn)

    with pytest.raises(reset.ResetBoundaryError):
        await reset._clear_one("hivemind-cowrie-1", path, timeout_seconds=30)
    assert spawned == []


# ---------------------------------------------------------------------------
# Residue. A reset that reports success while the directory is not empty
# hands run B run A's malware and breaks the only promise this module makes.
# ---------------------------------------------------------------------------


def test_a_directory_that_gains_a_file_during_the_clear_is_not_a_success(
    tmp_path,
) -> None:
    # The real script, run by this interpreter against a scratch directory --
    # the container is not needed to prove the guarantee, and this must not be
    # skippable. Cowrie finishing a download mid-reset is the live version.
    root = tmp_path / "downloads"
    root.mkdir()
    (root / ".gitignore").write_text("*\n")
    for index in range(2000):
        (root / f"f{index:04d}").write_text("x")
    seeded = set(os.listdir(root))

    stop = threading.Event()

    def _write_once_clearing_starts() -> None:
        # The file lands after the script's os.listdir snapshot was taken, so
        # the loop never considers it.
        while not stop.wait(0.001):
            if not seeded.issubset(os.listdir(root)):
                (root / "LATE_ARRIVAL").write_text("x")
                return

    writer = threading.Thread(target=_write_once_clearing_starts)
    writer.start()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                reset._CLEAR_SCRIPT,
                ",".join(reset.PRESERVED_NAMES),
                "60",
                str(root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        stop.set()
        writer.join()

    assert "LATE_ARRIVAL" in os.listdir(root), "the writer never raced the clear"
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "LATE_ARRIVAL" in completed.stderr
    # The count the script computes is reported, not discarded.
    assert "removed 2000 entries" in completed.stderr


def test_a_clean_directory_is_a_success(tmp_path) -> None:
    # The other half: the residue check must not turn a real reset into a
    # failure. An empty directory is a legitimate success, and the placeholder
    # that keeps it in the git checkout is not residue.
    root = tmp_path / "downloads"
    root.mkdir()
    (root / ".gitignore").write_text("*\n")
    (root / "payload").write_text("x")
    (root / "sub").mkdir()
    (root / "sub" / "nested").write_text("x")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            reset._CLEAR_SCRIPT,
            ",".join(reset.PRESERVED_NAMES),
            "60",
            str(root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert sorted(os.listdir(root)) == [".gitignore"]


# ---------------------------------------------------------------------------
# The mechanism itself, exercised in the real container against a scratch
# directory. Skipped when docker or the honeypot is not available so the
# default suite stays hermetic.
# ---------------------------------------------------------------------------


async def _container_python(container: str, source: str, *args: str) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        container,
        reset.CONTAINER_PYTHON,
        "-c",
        source,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
    return process.returncode, (stdout + stderr).decode("utf-8", "replace")


_SETUP = (
    "import os, sys\n"
    "root = sys.argv[1]\n"
    "os.makedirs(os.path.join(root, 'sub', 'deeper'), exist_ok=True)\n"
    "open(os.path.join(root, 'payload'), 'w').write('x')\n"
    "open(os.path.join(root, '.gitignore'), 'w').write('*\\n')\n"
    "open(os.path.join(root, 'sub', 'deeper', 'nested'), 'w').write('x')\n"
    "outside = root + '-outside'\n"
    "os.makedirs(outside, exist_ok=True)\n"
    "open(os.path.join(outside, 'must-survive'), 'w').write('x')\n"
    "link = os.path.join(root, 'escape')\n"
    "os.path.islink(link) or os.symlink(outside, link)\n"
    "print(sorted(os.listdir(root)))\n"
)

_INSPECT = (
    "import os, sys\n"
    "root = sys.argv[1]\n"
    "print('root_exists', os.path.isdir(root))\n"
    "print('contents', sorted(os.listdir(root)) if os.path.isdir(root) else None)\n"
    "print('outside_survived', sorted(os.listdir(root + '-outside')))\n"
)

_TEARDOWN = (
    "import shutil, sys\n"
    "shutil.rmtree(sys.argv[1], ignore_errors=True)\n"
    "shutil.rmtree(sys.argv[1] + '-outside', ignore_errors=True)\n"
)

LIVE_CONTAINER = "hivemind-cowrie-1"


@pytest.mark.asyncio
async def test_live_clear_empties_a_directory_without_removing_it() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    # A scratch directory, never a real reset path -- this test must not be
    # able to damage the honeypot's captured session data.
    scratch = f"/tmp/hivemind-reset-{uuid_module.uuid4().hex}"
    assert not any(_covers(p, scratch) for p in reset.RESET_PATHS)

    try:
        code, out = await _container_python(LIVE_CONTAINER, _SETUP, scratch)
    except (OSError, TimeoutError) as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")
    if code != 0:
        pytest.skip(f"cowrie container not reachable: {out.strip()}")

    try:
        await reset._clear_one(LIVE_CONTAINER, scratch, timeout_seconds=30)

        code, out = await _container_python(LIVE_CONTAINER, _INSPECT, scratch)
        assert code == 0, out
        assert "root_exists True" in out
        # Cowrie expects downloads/ and tty/ to exist; the reset clears the
        # contents and leaves the directory in place.
        assert "contents ['.gitignore']" in out
        # A symlink out of the reset root is unlinked, never followed.
        assert "outside_survived ['must-survive']" in out
    finally:
        await _container_python(LIVE_CONTAINER, _TEARDOWN, scratch)


@pytest.mark.asyncio
async def test_live_clear_of_a_missing_directory_raises() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    scratch = f"/tmp/hivemind-reset-absent-{uuid_module.uuid4().hex}"
    # A scratch path, never a real reset path.
    assert not any(_covers(p, scratch) for p in reset.RESET_PATHS)
    try:
        code, out = await _container_python(LIVE_CONTAINER, "print('ok')")
    except (OSError, TimeoutError) as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")
    if code != 0:
        pytest.skip(f"cowrie container not reachable: {out.strip()}")

    # A reset target that is not there means the container is not the
    # honeypot we think it is. Reporting that as a successful reset would be
    # the same silent no-op the original implementation had.
    with pytest.raises(reset.ResetError):
        await reset._clear_one(LIVE_CONTAINER, scratch, timeout_seconds=30)


_SEED_MANY = (
    "import os, sys\n"
    "root = sys.argv[1]\n"
    "os.makedirs(root)\n"
    "for i in range(3000):\n"
    "    open(os.path.join(root, 'f%04d' % i), 'w').write('x')\n"
    "print(len(os.listdir(root)))\n"
)

_WRITE_LATE = (
    "import os, sys, time\n"
    "root = sys.argv[1]\n"
    "seeded = int(sys.argv[2])\n"
    "open(root + '-ready', 'w').write('x')\n"
    "deadline = time.monotonic() + 30\n"
    # Wait for the clear to be under way rather than sleeping a fixed time:
    # the file has to land after the script's snapshot, and docker exec
    # startup makes any fixed delay a coin flip.
    "while time.monotonic() < deadline and len(os.listdir(root)) >= seeded:\n"
    "    time.sleep(0.005)\n"
    "open(os.path.join(root, 'LATE_ARRIVAL'), 'w').write('x')\n"
)

_READY = (
    "import os, sys, time\n"
    "deadline = time.monotonic() + 30\n"
    "while time.monotonic() < deadline and not os.path.exists(sys.argv[1] + '-ready'):\n"
    "    time.sleep(0.02)\n"
    "print('ready', os.path.exists(sys.argv[1] + '-ready'))\n"
)


@pytest.mark.asyncio
async def test_live_clear_raises_when_the_honeypot_writes_during_the_reset() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    scratch = f"/tmp/hivemind-reset-race-{uuid_module.uuid4().hex}"
    assert not any(_covers(p, scratch) for p in reset.RESET_PATHS)

    try:
        code, out = await _container_python(LIVE_CONTAINER, _SEED_MANY, scratch)
    except (OSError, TimeoutError) as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")
    if code != 0:
        pytest.skip(f"cowrie container not reachable: {out.strip()}")

    try:
        # Cowrie finishing a download while the reset runs. The file lands
        # after the script's directory snapshot, so the clear never sees it --
        # and run B would inherit it while the report called the runs
        # comparable.
        writer = asyncio.create_task(
            _container_python(LIVE_CONTAINER, _WRITE_LATE, scratch, "3000")
        )
        # Do not start clearing until the writer is actually polling, or
        # docker exec startup decides the outcome instead of the code.
        code, out = await _container_python(LIVE_CONTAINER, _READY, scratch)
        assert "ready True" in out, out

        with pytest.raises(reset.ResetError) as exc:
            await reset._clear_one(LIVE_CONTAINER, scratch, timeout_seconds=60)
        await writer
        assert "LATE_ARRIVAL" in str(exc.value)
    finally:
        await _container_python(LIVE_CONTAINER, _TEARDOWN, scratch)
        await _container_python(
            LIVE_CONTAINER,
            "import os, sys\n"
            "try:\n"
            "    os.unlink(sys.argv[1] + '-ready')\n"
            "except OSError:\n"
            "    pass\n",
            scratch,
        )
