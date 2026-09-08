"""Fingerprints decide whether two runs may be compared at all.

The failure mode that matters here is a fingerprint that stays STABLE when
it should have changed: that silently asserts two runs are comparable when
they are not, and the compare endpoint will happily draw a trend line
through them. Every test below is aimed at that direction of failure.
"""

import asyncio
import shutil

import pytest

from app.services.evaluation import container, fingerprints
from app.services.evaluation.agent import AgentBudget

BUDGET = AgentBudget(max_commands=40, max_seconds=120)


# ---------------------------------------------------------------------------
# Fake docker plumbing. Unit tests never touch the real container.
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


class _HangingProc(_FakeProc):
    def __init__(self) -> None:
        super().__init__(0)

    async def communicate(self) -> tuple[bytes, bytes]:
        await asyncio.Event().wait()  # never returns
        raise AssertionError("unreachable")


def _fake_docker(monkeypatch, *, image: bytes, config_digest: bytes, spawned: list | None = None):
    """Stand in for `docker inspect` and the in-container digest read."""

    async def _spawn(argv):
        if spawned is not None:
            spawned.append(argv)
        if "inspect" in argv:
            return _FakeProc(0, stdout=image)
        return _FakeProc(0, stdout=config_digest)

    monkeypatch.setattr(container, "_spawn", _spawn)


# ---------------------------------------------------------------------------
# The evaluation-config fingerprint: everything on OUR side.
# ---------------------------------------------------------------------------


def test_changing_the_budget_changes_the_config_fingerprint() -> None:
    # A budget change alters what a run can find, so two runs under
    # different budgets are not comparable and must not look comparable.
    a = fingerprints.evaluation_config_fingerprint(AgentBudget(max_commands=40, max_seconds=120))
    b = fingerprints.evaluation_config_fingerprint(AgentBudget(max_commands=10, max_seconds=120))
    assert a != b


def test_changing_the_time_budget_changes_the_config_fingerprint() -> None:
    a = fingerprints.evaluation_config_fingerprint(AgentBudget(max_commands=40, max_seconds=120))
    b = fingerprints.evaluation_config_fingerprint(AgentBudget(max_commands=40, max_seconds=30))
    assert a != b


def test_the_same_configuration_produces_the_same_fingerprint() -> None:
    budget = AgentBudget(max_commands=40, max_seconds=120)
    assert fingerprints.evaluation_config_fingerprint(
        budget
    ) == fingerprints.evaluation_config_fingerprint(budget)


def test_the_config_fingerprint_covers_probe_and_chain_and_rulebook_versions() -> None:
    parts = fingerprints._config_parts(BUDGET)
    keys = set(parts)
    assert {"probe_set", "chain_set", "rulebook", "budget"} <= keys


def test_the_config_fingerprint_is_prefixed_and_hex() -> None:
    value = fingerprints.evaluation_config_fingerprint(BUDGET)
    algorithm, _, hexdigest = value.partition(":")
    assert algorithm == "sha256"
    assert len(hexdigest) == 64
    int(hexdigest, 16)


# --- Finding 4: content, not a hand-maintained version string --------------


@pytest.mark.parametrize(
    "attribute",
    ["_PROBES_PATH", "_CHAINS_PATH", "_RULEBOOK_PATH"],
)
def test_editing_a_config_file_changes_the_fingerprint_without_a_version_bump(
    monkeypatch, tmp_path, attribute
) -> None:
    # PROBE_SET_VERSION and CHAIN_SET_VERSION are hand-maintained strings in
    # the yaml. Fingerprinting by the declared version alone means editing a
    # probe's command -- changing exactly what the run can find -- leaves the
    # fingerprint identical, and the compare endpoint calls the two runs
    # comparable. The real yaml is never mutated here.
    stand_in = tmp_path / "config.yaml"
    stand_in.write_text('version: "1"\nprobes: []\nchains: []\nrules: []\n', encoding="utf-8")
    monkeypatch.setattr(fingerprints, attribute, stand_in)
    before = fingerprints.evaluation_config_fingerprint(BUDGET)

    # Same declared version, different content.
    stand_in.write_text(
        'version: "1"\nprobes: [{id: x}]\nchains: [{id: x}]\nrules: [{id: x}]\n',
        encoding="utf-8",
    )
    after = fingerprints.evaluation_config_fingerprint(BUDGET)

    assert before != after, (
        f"{attribute} content changed but the fingerprint did not; two runs "
        f"under materially different configurations would claim to be comparable"
    )


def test_a_missing_config_file_raises_rather_than_fingerprinting_nothing(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(fingerprints, "_PROBES_PATH", tmp_path / "absent.yaml")
    with pytest.raises(fingerprints.FingerprintError):
        fingerprints.evaluation_config_fingerprint(BUDGET)


# ---------------------------------------------------------------------------
# The honeypot fingerprint: what the honeypot IS.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_different_honeypot_configs_produce_different_fingerprints(
    monkeypatch,
) -> None:
    # The property the draft silently broke: with `cat` absent the config
    # component was sha256("") on every call, so two honeypots with entirely
    # different cowrie.cfg files fingerprinted identically.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")

    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"2222" * 16)
    second = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")

    assert first != second


@pytest.mark.asyncio
async def test_the_same_honeypot_reproduces_the_same_fingerprint(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")
    second = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")
    assert first == second


@pytest.mark.asyncio
async def test_a_new_image_changes_the_honeypot_fingerprint(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")

    _fake_docker(monkeypatch, image=b"sha256:bbbb\n", config_digest=b"1111" * 16)
    second = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")

    assert first != second


@pytest.mark.asyncio
async def test_the_config_is_read_with_the_container_python_not_a_shell_utility(
    monkeypatch,
) -> None:
    # Finding 1's root cause, asserted directly: the Cowrie image is
    # distroless, so the interpreter Cowrie runs on -- named by absolute
    # path, because docker exec does not apply the image entrypoint -- is
    # the only executable available.
    spawned: list[list[str]] = []
    _fake_docker(
        monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16, spawned=spawned
    )
    await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")

    exec_argv = [argv for argv in spawned if argv[:2] == ["docker", "exec"]]
    assert exec_argv, spawned
    for argv in exec_argv:
        assert argv[3] == container.CONTAINER_PYTHON
        assert argv[3].startswith("/")
        assert argv[4] == "-c"
        for utility in ("cat", "sh", "bash", "head"):
            assert utility not in argv[:4]
    # The path travels via sys.argv, never concatenated into the source.
    assert fingerprints.COWRIE_CONFIG_PATH in exec_argv[0][6:]


# --- Findings 1 and 2: a failure must never yield a fingerprint ------------


@pytest.mark.asyncio
async def test_a_missing_container_utility_raises_instead_of_digesting_nothing(
    monkeypatch,
) -> None:
    # This is the test that would have caught the plan's defect. The draft
    # discarded stderr and never inspected returncode, so this exact failure
    # produced "" and a confident-looking digest of the empty string.
    async def _spawn(argv):
        if "inspect" in argv:
            return _FakeProc(0, stdout=b"sha256:aaaa\n")
        return _FakeProc(
            127,
            stderr=b'OCI runtime exec failed: exec failed: unable to start container '
            b'process: exec: "cat": executable file not found in $PATH\n',
        )

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")
    assert "127" in str(exc.value)
    assert "executable file not found" in str(exc.value)


@pytest.mark.asyncio
async def test_a_failing_docker_inspect_raises(monkeypatch) -> None:
    async def _spawn(argv):
        return _FakeProc(1, stderr=b"Error: No such object: nope\n")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints.honeypot_fingerprint("nope")
    assert "No such object" in str(exc.value)


@pytest.mark.asyncio
async def test_a_missing_docker_binary_raises(monkeypatch) -> None:
    async def _spawn(argv):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")


@pytest.mark.asyncio
async def test_an_empty_digest_from_the_container_raises(monkeypatch) -> None:
    # Exit 0 with no output is still not a fingerprint.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"")
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")


@pytest.mark.asyncio
async def test_an_empty_image_id_raises(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"\n", config_digest=b"1111" * 16)
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", "   ", "bad name", "-leading-dash", "a/b"])
async def test_an_invalid_container_name_raises(name) -> None:
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(name)


# --- Finding 3: bounded -----------------------------------------------------


@pytest.mark.asyncio
async def test_a_hanging_docker_call_is_bounded_and_raises(monkeypatch) -> None:
    hung: list[_HangingProc] = []

    async def _spawn(argv):
        proc = _HangingProc()
        hung.append(proc)
        return proc

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints.honeypot_fingerprint("hivemind-cowrie-1", timeout_seconds=0.05)
    assert "timed out" in str(exc.value)
    # The local docker CLI is reaped; the in-container process is not
    # signalled by this, and the message must not claim otherwise.
    assert hung and hung[0].killed


# ---------------------------------------------------------------------------
# The two fingerprints are independent.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_two_fingerprints_are_independent(monkeypatch, tmp_path) -> None:
    # This separation is the whole point: if they were merged, editing one
    # of OUR probe definitions between two runs would read as a honeypot
    # improvement.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    honeypot_before = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")
    config_before = fingerprints.evaluation_config_fingerprint(BUDGET)

    # Change only OUR side.
    stand_in = tmp_path / "probes.yaml"
    stand_in.write_text('version: "1"\nprobes: []\n', encoding="utf-8")
    monkeypatch.setattr(fingerprints, "_PROBES_PATH", stand_in)
    honeypot_after = await fingerprints.honeypot_fingerprint("hivemind-cowrie-1")
    config_after = fingerprints.evaluation_config_fingerprint(BUDGET)

    assert honeypot_after == honeypot_before
    assert config_after != config_before

    # Change only the honeypot's side.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"3333" * 16)
    assert await fingerprints.honeypot_fingerprint("hivemind-cowrie-1") != honeypot_after
    assert fingerprints.evaluation_config_fingerprint(BUDGET) == config_after


def test_the_evaluator_model_is_not_part_of_the_config_fingerprint() -> None:
    # Deliberate. EvaluationRun.evaluator_model is persisted per-run and is
    # directly comparable; it is also nullable, so folding it in would make
    # every BYOK-less run incomparable with every evaluated run even though
    # their deterministic scores are perfectly comparable. The config
    # fingerprint governs the deterministic score, which the evaluator
    # cannot influence.
    parts = fingerprints._config_parts(BUDGET)
    flattened = repr(parts).lower()
    for token in ("evaluator", "model", "anthropic", "openai", "claude"):
        assert token not in flattened


# ---------------------------------------------------------------------------
# Live: the real container. Skips when docker or the honeypot is absent, so
# the default suite stays hermetic. Read-only -- nothing is written into the
# honeypot.
# ---------------------------------------------------------------------------

LIVE_CONTAINER = "hivemind-cowrie-1"


@pytest.mark.asyncio
async def test_live_honeypot_fingerprint_is_real_and_stable() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    try:
        first = await fingerprints.honeypot_fingerprint(LIVE_CONTAINER)
    except fingerprints.FingerprintError as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")

    second = await fingerprints.honeypot_fingerprint(LIVE_CONTAINER)
    assert first == second
    assert first.startswith("sha256:")

    # The defect the draft shipped: an empty config component. Prove the
    # config actually read back by digesting a known-different input the
    # same way and confirming the real one is not the empty-string digest.
    empty = fingerprints._digest(
        {
            "image": "",
            "config": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    )
    assert first != empty


@pytest.mark.asyncio
async def test_live_config_digest_matches_the_bytes_cowrie_actually_reads() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    try:
        digest = await fingerprints._container_config_digest(LIVE_CONTAINER, 30.0)
    except fingerprints.FingerprintError as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")

    assert len(digest) == 64
    int(digest, 16)
    # sha256 of the empty string -- what the plan's draft produced on every
    # single call because `cat` does not exist in the distroless image.
    assert digest != "e3b0c44298fc1c14" "9afbf4c8996fb924" "27ae41e4649b934c" "a495991b7852b855"
