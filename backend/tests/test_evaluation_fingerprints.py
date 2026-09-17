"""Fingerprints decide whether two runs may be compared at all.

The failure mode that matters here is a fingerprint that stays STABLE when
it should have changed: that silently asserts two runs are comparable when
they are not, and the compare endpoint will happily draw a trend line
through them. Every test below is aimed at that direction of failure.
"""

import asyncio
import dataclasses
import hashlib
import re
import shutil
from pathlib import Path

import pytest

from app.services.evaluation import agent, container, fingerprints, probes
from app.services.evaluation.agent import AgentBudget
from app.services.evaluation.static import chains, nmap
from app.services.mitre import rules

BUDGET = AgentBudget(max_commands=40, max_seconds=120)


def _target(**overrides) -> "fingerprints.Target":
    """The default target, with individual fields overridden per test."""
    base = {
        "container_name": "hivemind-cowrie-1",
        "host": "cowrie",
        "ssh_port": 2222,
        "ssh_username": "root",
    }
    return fingerprints.Target(**{**base, **overrides})


def _apparatus(**overrides) -> "fingerprints.Apparatus":
    """The default measurement apparatus, overridden field by field."""
    base = {
        "capture_interface": "eth0",
        "capture_image": "nicolaka/netshoot",
        "nmap_timeout_seconds": 120,
        "capture_timeout_seconds": 30,
    }
    return fingerprints.Apparatus(**{**base, **overrides})



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
# Redirecting the loaders. The config fingerprint is taken over the objects
# the `@lru_cache`d loaders SERVED, not over whatever is on disk now, so a
# test that wants a different configuration has to change what the loaders
# hold -- which is the point of Finding 1 and is exercised directly below.
# ---------------------------------------------------------------------------

_LOADERS = {
    # name -> (module, path attribute, caches to clear, extra yaml to append)
    "probes": (
        probes,
        "_PROBES_PATH",
        lambda: (probes._raw, probes.load_probes),
        '  - id: extra_probe\n    characteristic: sanity\n    command: "id"\n',
    ),
    "chains": (
        chains,
        "_CHAINS_PATH",
        lambda: (chains._raw, chains.load_chains),
        '  - id: extra_chain\n    steps: ["whoami"]\n    expected_technique_ids: ["T1033"]\n',
    ),
    "rulebook": (
        rules,
        "_RULEBOOK_PATH",
        lambda: (rules.load_rules, rules._compiled),
        '  - id: T9999\n    name: extra\n    tactic: discovery\n    pattern: "zzz"\n',
    ),
}


@pytest.fixture
def reload_loader(monkeypatch):
    """Point one loader at a file and force it to actually re-read it.

    Clearing the `@lru_cache` is what makes a swap take effect at all; the
    teardown restores the real path FIRST and then clears again, so no later
    test in the session inherits a cache warmed from a temp file.
    """
    cleared: list = []

    def swap(name: str, path: Path) -> None:
        module, path_attr, caches, _ = _LOADERS[name]
        monkeypatch.setattr(module, path_attr, path)
        for cache in caches():
            cache.cache_clear()
            cleared.append(cache)

    yield swap

    monkeypatch.undo()
    for cache in cleared:
        cache.cache_clear()


def _real_source(name: str) -> str:
    module, path_attr, _, _ = _LOADERS[name]
    return Path(getattr(module, path_attr)).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The evaluation-config fingerprint: everything on OUR side.
# ---------------------------------------------------------------------------


def test_changing_the_budget_changes_the_config_fingerprint() -> None:
    # A budget change alters what a run can find, so two runs under
    # different budgets are not comparable and must not look comparable.
    a = fingerprints.evaluation_config_fingerprint(
        AgentBudget(max_commands=40, max_seconds=120), _apparatus()
    )
    b = fingerprints.evaluation_config_fingerprint(
        AgentBudget(max_commands=10, max_seconds=120), _apparatus()
    )
    assert a != b


def test_changing_the_time_budget_changes_the_config_fingerprint() -> None:
    a = fingerprints.evaluation_config_fingerprint(
        AgentBudget(max_commands=40, max_seconds=120), _apparatus()
    )
    b = fingerprints.evaluation_config_fingerprint(
        AgentBudget(max_commands=40, max_seconds=30), _apparatus()
    )
    assert a != b


def test_the_same_configuration_produces_the_same_fingerprint() -> None:
    budget = AgentBudget(max_commands=40, max_seconds=120)
    assert fingerprints.evaluation_config_fingerprint(
        budget, _apparatus()
    ) == fingerprints.evaluation_config_fingerprint(budget, _apparatus())


def test_the_config_fingerprint_covers_probe_and_chain_and_rulebook_versions() -> None:
    parts = fingerprints._config_parts(BUDGET, _apparatus())
    keys = set(parts)
    assert {"probe_set", "chain_set", "rulebook", "budget"} <= keys


def test_the_config_fingerprint_is_prefixed_and_hex() -> None:
    value = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())
    algorithm, _, hexdigest = value.partition(":")
    assert algorithm == "sha256"
    assert len(hexdigest) == 64
    int(hexdigest, 16)


def test_the_budget_is_dumped_whole_rather_than_field_by_field() -> None:
    # Enumerating `max_commands` and `max_seconds` by hand means adding a
    # third field to AgentBudget leaves two runs under materially different
    # budgets fingerprinting byte-identically until somebody remembers to
    # edit _config_parts. The fingerprint must not depend on that memory.
    parts = fingerprints._config_parts(BUDGET, _apparatus())
    assert parts["budget"] == BUDGET.model_dump(mode="json")
    assert set(parts["budget"]) == set(AgentBudget.model_fields)


# --- Finding 4: content, not a hand-maintained version string --------------


@pytest.mark.parametrize("name", list(_LOADERS))
def test_editing_a_config_file_changes_the_fingerprint_without_a_version_bump(
    reload_loader, tmp_path, name
) -> None:
    # The declared `version` in each yaml is a hand-maintained string.
    # Fingerprinting by it alone means editing a probe's command -- changing
    # exactly what the run can find -- leaves the fingerprint identical, and
    # the compare endpoint calls the two runs comparable. The real yaml is
    # never mutated here; a copy of it is, and the loader is pointed at the
    # copy and made to re-read, which is what a restarted process does.
    stand_in = tmp_path / f"{name}.yaml"
    stand_in.write_text(_real_source(name), encoding="utf-8")
    reload_loader(name, stand_in)
    before = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    # Same declared version, different content.
    stand_in.write_text(_real_source(name) + _LOADERS[name][3], encoding="utf-8")
    reload_loader(name, stand_in)
    after = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    assert before != after, (
        f"{name} content changed but the fingerprint did not; two runs "
        f"under materially different configurations would claim to be comparable"
    )


def test_a_missing_config_file_raises_rather_than_fingerprinting_nothing(
    reload_loader, tmp_path
) -> None:
    reload_loader("probes", tmp_path / "absent.yaml")
    with pytest.raises(fingerprints.FingerprintError):
        fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())


def test_malformed_config_raises_rather_than_fingerprinting_a_default(
    reload_loader, tmp_path
) -> None:
    # A probe that will not validate is not "no probes", and must never
    # reach the fingerprint as one.
    stand_in = tmp_path / "probes.yaml"
    stand_in.write_text('version: "1"\nprobes:\n  - id: broken\n', encoding="utf-8")
    reload_loader("probes", stand_in)
    with pytest.raises(fingerprints.FingerprintError):
        fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())


# --- Finding 1: the fingerprint describes the config the RUN executes ------


def test_the_fingerprint_describes_the_loaded_config_not_a_later_disk_edit(
    reload_loader, tmp_path
) -> None:
    # The loaders are @lru_cache'd, so a long-lived API process executes the
    # yaml as it was when first read. A fingerprint that re-read the file
    # would record a configuration the run never used: edit probes.yaml under
    # a running process and run A executes v1 while recording sha256(v2);
    # restart, and run B executes v2 and records sha256(v2) too. Identical
    # fingerprints, different probe sets, one trend line drawn through both.
    stand_in = tmp_path / "probes.yaml"
    stand_in.write_text(_real_source("probes"), encoding="utf-8")
    reload_loader("probes", stand_in)

    executing = probes.load_probes()
    before = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    # Someone edits the file. The running process is unaffected...
    stand_in.write_text(_real_source("probes") + _LOADERS["probes"][3], encoding="utf-8")
    assert probes.load_probes() == executing, "the loader is supposed to be cached"

    # ...and so is the fingerprint, because it describes the same run.
    assert fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus()) == before

    # The recorded digest is the digest of what the run would execute.
    parts = fingerprints._config_parts(BUDGET, _apparatus())
    expected = fingerprints._content_digest(
        {
            "version": str(probes._raw()["version"]),
            "probes": [probe.model_dump(mode="json") for probe in probes.load_probes()],
        }
    )
    assert parts["probe_set_sha256"] == expected

    # Only a restart -- the loader actually re-reading -- moves it.
    reload_loader("probes", stand_in)
    assert fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus()) != before


@pytest.mark.parametrize(
    ("name", "version_key", "digest_key"),
    [("probes", "probe_set", "probe_set_sha256"), ("chains", "chain_set", "chain_set_sha256")],
)
def test_the_declared_version_and_its_hash_describe_the_same_file(
    reload_loader, tmp_path, name, version_key, digest_key
) -> None:
    # The original defect in miniature: `probe_set` came from a module
    # constant fixed at import while `probe_set_sha256` was read fresh from
    # disk, so one stored fingerprint could name version 1 and hash version
    # 2. Both must come from the loader's single cached read.
    source = _real_source(name)
    stand_in = tmp_path / f"{name}.yaml"
    stand_in.write_text(source.replace('version: "1"', 'version: "97"', 1), encoding="utf-8")
    reload_loader(name, stand_in)
    first = fingerprints._config_parts(BUDGET, _apparatus())
    assert first[version_key] == "97"

    stand_in.write_text(source.replace('version: "1"', 'version: "98"', 1), encoding="utf-8")
    reload_loader(name, stand_in)
    second = fingerprints._config_parts(BUDGET, _apparatus())

    # Same content, different declared version: both halves moved together.
    assert second[version_key] == "98"
    assert second[digest_key] != first[digest_key], (
        f"{version_key} changed but {digest_key} did not -- the two halves of "
        f"one stored fingerprint would describe different file versions"
    )


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
    first = await fingerprints.honeypot_fingerprint(_target())

    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"2222" * 16)
    second = await fingerprints.honeypot_fingerprint(_target())

    assert first != second


@pytest.mark.asyncio
async def test_the_same_honeypot_reproduces_the_same_fingerprint(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint(_target())
    second = await fingerprints.honeypot_fingerprint(_target())
    assert first == second


@pytest.mark.asyncio
async def test_a_new_image_changes_the_honeypot_fingerprint(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint(_target())

    _fake_docker(monkeypatch, image=b"sha256:bbbb\n", config_digest=b"1111" * 16)
    second = await fingerprints.honeypot_fingerprint(_target())

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
    await fingerprints.honeypot_fingerprint(_target())

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
        await fingerprints.honeypot_fingerprint(_target())
    assert "127" in str(exc.value)
    assert "executable file not found" in str(exc.value)


@pytest.mark.asyncio
async def test_a_127_reported_only_on_stdout_still_reaches_the_caller(monkeypatch) -> None:
    # The shape docker actually produces, verified against the live
    # container: `docker exec hivemind-cowrie-1 /no/such/bin` exits 127 with
    # the OCI message on STDOUT and stderr EMPTY. A stderr-only reader
    # reports "exit code 127: " and the operator loses the only diagnostic
    # there is -- the image is distroless, so there is no shell to look with.
    async def _spawn(argv):
        if "inspect" in argv:
            return _FakeProc(0, stdout=b"sha256:aaaa\n")
        return _FakeProc(
            127,
            stdout=b"OCI runtime exec failed: exec failed: unable to start container "
            b'process: exec: "/cowrie/cowrie-env/bin/python3": stat '
            b"/cowrie/cowrie-env/bin/python3: no such file or directory\n",
            stderr=b"",
        )

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints.honeypot_fingerprint(_target())
    assert "OCI runtime exec failed" in str(exc.value)


@pytest.mark.asyncio
async def test_a_failing_docker_inspect_raises(monkeypatch) -> None:
    async def _spawn(argv):
        return _FakeProc(1, stderr=b"Error: No such object: nope\n")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints.honeypot_fingerprint(_target(container_name="nope"))
    assert "No such object" in str(exc.value)


@pytest.mark.asyncio
async def test_a_missing_container_is_a_fingerprint_error_not_a_docker_error(
    monkeypatch,
) -> None:
    # `_container_config_digest` is called directly by the live tests, which
    # guard on FingerprintError. A bare ContainerExecError escaping it turns
    # an intended skip into a hard failure on any machine that has docker
    # but has not run `docker compose up` -- CI, a fresh clone.
    async def _spawn(argv):
        return _FakeProc(1, stderr=b"Error response from daemon: No such container: nope\n")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError) as exc:
        await fingerprints._container_config_digest("nope", 5.0)
    assert not isinstance(exc.value, container.ContainerExecError)
    assert "No such container" in str(exc.value)


@pytest.mark.asyncio
async def test_a_missing_docker_binary_raises(monkeypatch) -> None:
    async def _spawn(argv):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(container, "_spawn", _spawn)

    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(_target())


@pytest.mark.asyncio
async def test_an_empty_digest_from_the_container_raises(monkeypatch) -> None:
    # Exit 0 with no output is still not a fingerprint.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"")
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(_target())


@pytest.mark.asyncio
async def test_an_empty_image_id_raises(monkeypatch) -> None:
    _fake_docker(monkeypatch, image=b"\n", config_digest=b"1111" * 16)
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(_target())


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", "   ", "bad name", "-leading-dash", "a/b"])
async def test_an_invalid_container_name_raises(name) -> None:
    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(_target(container_name=name))


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
        await fingerprints.honeypot_fingerprint(_target(), timeout_seconds=0.05)
    assert "timed out" in str(exc.value)
    # The local docker CLI is reaped; the in-container process is not
    # signalled by this, and the message must not claim otherwise.
    assert hung and hung[0].killed


# ---------------------------------------------------------------------------
# The two fingerprints are independent.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_two_fingerprints_are_independent(monkeypatch, reload_loader, tmp_path) -> None:
    # This separation is the whole point: if they were merged, editing one
    # of OUR probe definitions between two runs would read as a honeypot
    # improvement.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    honeypot_before = await fingerprints.honeypot_fingerprint(_target())
    config_before = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    # Change only OUR side.
    stand_in = tmp_path / "probes.yaml"
    stand_in.write_text('version: "1"\nprobes: []\n', encoding="utf-8")
    reload_loader("probes", stand_in)
    honeypot_after = await fingerprints.honeypot_fingerprint(_target())
    config_after = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    assert honeypot_after == honeypot_before
    assert config_after != config_before

    # Change only the honeypot's side.
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"3333" * 16)
    assert await fingerprints.honeypot_fingerprint(_target()) != honeypot_after
    assert fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus()) == config_after


def test_the_evaluator_model_is_not_part_of_the_config_fingerprint() -> None:
    # Deliberate. EvaluationRun.evaluator_model is persisted per-run and is
    # directly comparable; it is also nullable, so folding it in would make
    # every BYOK-less run incomparable with every evaluated run even though
    # their deterministic scores are perfectly comparable. The config
    # fingerprint governs the deterministic score, which the evaluator
    # cannot influence.
    parts = fingerprints._config_parts(BUDGET, _apparatus())
    flattened = repr(parts).lower()
    for token in ("evaluator", "model", "anthropic", "openai", "claude"):
        assert token not in flattened


# ---------------------------------------------------------------------------
# Live: the real container. Skips when docker or the honeypot is absent, so
# the default suite stays hermetic. Read-only -- nothing is written into the
# honeypot.
#
# Every call that touches docker sits inside the guarded block. A container
# that goes away between two calls must skip, not fail, and the guard has to
# name every exception those calls can raise -- `_container_config_digest`
# used to leak `container.ContainerExecError`, which is not a
# `FingerprintError`, so this file hard-failed on any machine with docker
# installed but the stack not up.
# ---------------------------------------------------------------------------

LIVE_CONTAINER = "hivemind-cowrie-1"
LIVE_TARGET = _target(container_name=LIVE_CONTAINER)
LIVE_UNREACHABLE = (fingerprints.FingerprintError, container.ContainerExecError, OSError)

# cowrie.cfg is bind-mounted read-only from the host into the container
# (`./infra/cowrie/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro`), so the
# bytes Cowrie reads are byte-for-byte this file. That makes the host copy an
# INDEPENDENT expected value for the config component -- the only way to
# check that component is real rather than a constant.
HOST_COWRIE_CFG = Path(__file__).resolve().parents[2] / "infra" / "cowrie" / "cowrie.cfg"


def _host_config_sha256() -> str:
    return hashlib.sha256(HOST_COWRIE_CFG.read_bytes()).hexdigest()


@pytest.mark.asyncio
async def test_live_honeypot_fingerprint_is_real_and_stable() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if not HOST_COWRIE_CFG.is_file():
        pytest.skip(f"{HOST_COWRIE_CFG} not present")

    try:
        first = await fingerprints.honeypot_fingerprint(LIVE_TARGET)
        second = await fingerprints.honeypot_fingerprint(LIVE_TARGET)
        image = (
            await container.run(
                ["docker", "inspect", "--format", "{{.Image}}", LIVE_CONTAINER],
                timeout_seconds=30.0,
            )
        ).decode("utf-8", "replace").strip()
    except LIVE_UNREACHABLE as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")

    assert first == second
    assert first.startswith("sha256:")

    # Both components are checked against independently-known values, so
    # this cannot pass on a fingerprint that has gone constant. Asserting
    # only `first != _digest({"image": "", "config": sha256("")})` does not:
    # the image halves already differ, so it holds no matter what the config
    # component is -- including the empty-string digest the draft produced.
    assert image and image != ""
    assert first == fingerprints._digest(
        {
            "image": image,
            "config": _host_config_sha256(),
            "target": dataclasses.asdict(LIVE_TARGET),
        }
    )


@pytest.mark.asyncio
async def test_live_config_digest_matches_the_bytes_cowrie_actually_reads() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if not HOST_COWRIE_CFG.is_file():
        pytest.skip(f"{HOST_COWRIE_CFG} not present")

    try:
        digest = await fingerprints._container_config_digest(LIVE_CONTAINER, 30.0)
    except LIVE_UNREACHABLE as exc:
        pytest.skip(f"cowrie container not reachable: {exc}")

    assert len(digest) == 64
    int(digest, 16)
    # The real check, not "is not the empty digest": the file is bind-mounted
    # read-only, so the in-container digest must equal the host file's.
    assert digest == _host_config_sha256(), (
        f"the honeypot is reading a different cowrie.cfg than {HOST_COWRIE_CFG}"
    )


@pytest.mark.asyncio
async def test_live_an_absent_container_skips_rather_than_erroring() -> None:
    # Docker present, container absent -- CI and a fresh clone. Every guarded
    # live call above must raise something `LIVE_UNREACHABLE` catches, or the
    # skip is not a skip.
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    absent = "hivemind-cowrie-absent-for-tests"
    with pytest.raises(LIVE_UNREACHABLE):
        await fingerprints.honeypot_fingerprint(_target(container_name=absent))
    with pytest.raises(LIVE_UNREACHABLE):
        await fingerprints._container_config_digest(absent, 30.0)


# ---------------------------------------------------------------------------
# Target identity. Two honeypots that hash identically are still two
# honeypots, and a comparison that cannot tell them apart asserts a
# comparability nobody checked.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("container_name", "hivemind-cowrie-2"),
        ("host", "127.0.0.1"),
        ("ssh_port", 2322),
        ("ssh_username", "admin"),
    ],
)
async def test_changing_the_target_changes_the_honeypot_fingerprint(
    monkeypatch, field, value
) -> None:
    """Identical image, identical cowrie.cfg, different target.

    This is the case the image+config pair cannot see. The docstring on
    `honeypot_fingerprint` already concedes that the container's writable
    layer is uncovered -- a `docker cp`'d binary or a hand-edited fs.pickle
    changes the honeypot with no fingerprint movement. Two such containers
    are byte-identical to this function. Carrying the target means the
    stored fingerprints at least disagree, so the compare endpoint reports a
    change instead of drawing a trend line through two different hosts.
    """
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint(_target())
    second = await fingerprints.honeypot_fingerprint(_target(**{field: value}))

    assert first != second, f"{field} moved but the fingerprint did not"


@pytest.mark.asyncio
async def test_the_same_target_still_reproduces_the_same_fingerprint(monkeypatch) -> None:
    """Carrying the target must not make the fingerprint unstable."""
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)
    first = await fingerprints.honeypot_fingerprint(_target())
    second = await fingerprints.honeypot_fingerprint(_target())

    assert first == second


def test_the_target_carries_no_credential() -> None:
    """The password is not part of what the honeypot IS.

    It does not change the decoy's behaviour, and fingerprints are stored in
    Postgres and rendered in the comparison view. A field added here would
    put a credential in both. Cowrie's password is not much of a secret --
    the whole point of the target is that anyone can log in -- but the rule
    that fingerprints never carry credentials should not have its first
    exception be an accident.
    """
    names = {field.name for field in dataclasses.fields(fingerprints.Target)}

    assert names == {"container_name", "host", "ssh_port", "ssh_username"}


def test_the_target_is_frozen() -> None:
    """A fingerprint computed from a value that can be mutated afterwards is
    not reproducible. Freezing is what makes the recorded digest mean the
    target the run actually used."""
    target = _target()

    with pytest.raises(dataclasses.FrozenInstanceError):
        target.host = "elsewhere"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_an_invalid_container_name_still_raises_through_the_target(
    monkeypatch,
) -> None:
    """Validation lives in the fingerprint function, not in `Target`.

    `Target` is a plain frozen dataclass on purpose: it is also the value a
    caller assembles from settings, and a constructor that raised would turn
    a misconfigured container name into an import-time or request-time crash
    somewhere far from the fingerprint. The check stays where the error type
    is meaningful.
    """
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)

    with pytest.raises(fingerprints.FingerprintError):
        await fingerprints.honeypot_fingerprint(_target(container_name="../etc"))


# ---------------------------------------------------------------------------
# Measurement apparatus and the constants that live in code rather than yaml.
#
# These change what a run can FIND without changing the honeypot, so they
# belong on our side of the comparison. Before this they were in neither
# fingerprint: halve the nmap timeout and every service reads `unknown`, with
# both runs still claiming to be comparable.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_interface", "eth1"),
        ("capture_image", ""),
        ("nmap_timeout_seconds", 5),
        ("capture_timeout_seconds", 1),
    ],
)
def test_changing_the_apparatus_changes_the_config_fingerprint(field, value) -> None:
    first = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())
    second = fingerprints.evaluation_config_fingerprint(
        BUDGET, _apparatus(**{field: value})
    )

    assert first != second, f"{field} moved but the fingerprint did not"


def test_the_apparatus_is_frozen_and_whole() -> None:
    """Frozen for reproducibility; `asdict` so a new field cannot be forgotten."""
    apparatus = _apparatus()

    with pytest.raises(dataclasses.FrozenInstanceError):
        apparatus.capture_interface = "eth9"  # type: ignore[misc]

    assert dataclasses.asdict(apparatus) == fingerprints._config_parts(
        BUDGET, apparatus
    )["apparatus"]


@pytest.mark.parametrize(
    "module_name,attr,value",
    [
        ("agent", "PER_COMMAND_TIMEOUT_SECONDS", 21),
        ("agent", "_PROMPT_PREFIX", re.compile(r"^zzz")),
        ("agent", "_ANSI_SEQUENCE", re.compile(r"^zzz")),
        ("nmap", "_EXPECTED_SERVICES", {"service.ssh": 2222}),
        ("nmap", "_OPEN_LINE", re.compile(r"^zzz")),
        ("rules", "_DATA_PRODUCING_HEAD", re.compile(r"^zzz")),
        ("rules", "_RAW_TEXT_RULE_IDS", frozenset({"T1105"})),
    ],
)
def test_a_result_deciding_constant_moves_the_config_fingerprint(
    monkeypatch, module_name, attr, value
) -> None:
    """Every one of these decides what a run can find.

    `PER_COMMAND_TIMEOUT_SECONDS` decides when a probe counts as failed.
    `_PROMPT_PREFIX` and `_ANSI_SEQUENCE` decide what the agent's output is
    cleaned down to, and a cleaning bug is what once turned a genuine absence
    into a false `observed`. `_EXPECTED_SERVICES` decides which ports a scan
    even asks about. `_DATA_PRODUCING_HEAD` and `_RAW_TEXT_RULE_IDS` decide
    which command text the rulebook is allowed to see.

    Hashing their VALUES rather than the .py files is deliberate: the module
    docstring rejects file hashing because a comment or a refactor would
    invalidate every stored fingerprint and train people to ignore it. A
    constant's value moves only when the behaviour does.
    """
    module = {"agent": agent, "nmap": nmap, "rules": rules}[module_name]

    first = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())
    monkeypatch.setattr(module, attr, value)
    second = fingerprints.evaluation_config_fingerprint(BUDGET, _apparatus())

    assert first != second, f"{module_name}.{attr} moved but the fingerprint did not"


@pytest.mark.asyncio
async def test_the_apparatus_does_not_touch_the_honeypot_fingerprint(monkeypatch) -> None:
    """The two fingerprints stay independent.

    Apparatus is our side. If it leaked into the honeypot fingerprint,
    shortening a timeout would read as the honeypot having changed -- the
    exact confusion the two-fingerprint split exists to prevent.
    """
    _fake_docker(monkeypatch, image=b"sha256:aaaa\n", config_digest=b"1111" * 16)

    first = await fingerprints.honeypot_fingerprint(_target())
    monkeypatch.setattr(agent, "PER_COMMAND_TIMEOUT_SECONDS", 99)
    second = await fingerprints.honeypot_fingerprint(_target())

    assert first == second
