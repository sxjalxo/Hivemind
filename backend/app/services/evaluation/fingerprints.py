"""Two fingerprints, kept deliberately apart.

Hivemind lets a developer compare evaluation runs over time to see whether
their changes made the honeypot more realistic. Two independent things can
move between runs:

  * the honeypot -- the thing being improved (its image, its config)
  * the evaluation configuration -- OUR probes, chains, rulebook, budget

They are fingerprinted separately on purpose. Merged into one value,
editing one of our own probe definitions between two runs would show up as
a honeypot change; and a honeypot rebuild would look like we had changed
the evaluation. The compare endpoint refuses to draw a trend through runs
whose fingerprints differ, so each value has to mean exactly one thing.

Failure model. These functions raise; they never return a fingerprint they
could not compute. This is the same ruling `reset.py` records: modules that
produce *evidence* (nmap, tcpdump) degrade a failure into an `unknown`
fact, because our inability to look is not evidence. A fingerprint produces
no evidence -- it establishes the precondition under which comparing two
runs means anything. A fingerprint that is silently wrong is worse than no
fingerprint at all, because it asserts comparability that was never
checked.

Which direction of error matters. A fingerprint that changes when it did
not need to costs a developer one lost comparison. A fingerprint that stays
STABLE when it should have changed silently merges two incomparable runs
into a trend line. Every judgement here leans toward the first.
"""

import hashlib
import json
from pathlib import Path

from app.services.evaluation import container
from app.services.evaluation.agent import AgentBudget
from app.services.evaluation.probes import PROBE_SET_VERSION
from app.services.evaluation.static.chains import CHAIN_SET_VERSION

# Read fresh on every call, never cached and never resolved at import: a
# fingerprint that reports the configuration as it was when the process
# started is exactly the stale-but-confident value this module exists to
# avoid. Held as module attributes so tests can point them at a temp file
# instead of mutating the real yaml.
_PROBES_PATH = Path(__file__).resolve().parent / "probes.yaml"
_CHAINS_PATH = Path(__file__).resolve().parent / "static" / "chains.yaml"
_RULEBOOK_PATH = Path(__file__).resolve().parents[1] / "mitre" / "rulebook.yaml"

# The one file in the honeypot that is not part of its image: bind-mounted
# read-only from ./infra/cowrie/cowrie.cfg, so it changes what the honeypot
# IS without changing the image id.
COWRIE_CONFIG_PATH = "/cowrie/cowrie-git/etc/cowrie.cfg"

_DEFAULT_TIMEOUT_SECONDS = 30.0

# Fixed source run by the container's own interpreter. The path arrives via
# `sys.argv` and is never concatenated into this text. Hashing inside the
# container rather than shipping the bytes out means no encoding or newline
# translation can sit between the file and its digest, and a missing or
# unreadable file raises there and surfaces here as a non-zero exit rather
# than as an empty read.
_DIGEST_SCRIPT = """
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for block in iter(lambda: handle.read(65536), b""):
        digest.update(block)
sys.stdout.write(digest.hexdigest())
"""


class FingerprintError(RuntimeError):
    """A fingerprint that could not be computed. The run is not comparable."""


def _digest(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise FingerprintError(f"could not read {path}: {exc}") from exc


def _config_parts(budget: AgentBudget) -> dict:
    """Everything on OUR side that changes what a run can find.

    Content hashes, not declared versions. `PROBE_SET_VERSION` and
    `CHAIN_SET_VERSION` are `str(_raw()["version"])` -- hand-maintained
    strings in the yaml. Fingerprinting by those alone means editing a
    probe's command, which changes precisely what the run can find, leaves
    the fingerprint identical and the two runs claiming to be comparable.
    Correctness must not depend on anyone remembering to bump a string.

    The declared versions are kept alongside the hashes because they are the
    half a human can read off a stored fingerprint; they are not what makes
    it correct.

    The evaluator's model and provider are deliberately NOT here. Three
    reasons: `EvaluationRun.evaluator_model` is already persisted per-run
    and can be compared directly, so this would add nothing; this
    fingerprint governs the deterministic score, which is computed from
    probe/chain facts the evaluator cannot influence (`scoring.py` never
    combines the two quantities); and the column is nullable, so folding it
    in would make every run without a BYOK evaluator incomparable with
    every evaluated run even though their deterministic scores are
    perfectly comparable. Comparing `evaluator_rating` across two different
    evaluator models is a caller-side check against that column.
    """
    return {
        "probe_set": PROBE_SET_VERSION,
        "probe_set_sha256": _file_digest(_PROBES_PATH),
        "chain_set": CHAIN_SET_VERSION,
        "chain_set_sha256": _file_digest(_CHAINS_PATH),
        "rulebook": _file_digest(_RULEBOOK_PATH),
        "budget": {
            "max_commands": budget.max_commands,
            "max_seconds": budget.max_seconds,
        },
    }


def evaluation_config_fingerprint(budget: AgentBudget) -> str:
    """Fingerprint OUR side of the run. Raises if any input is unreadable."""
    return _digest(_config_parts(budget))


async def _container_config_digest(name: str, timeout_seconds: float) -> str:
    """SHA-256 of the cowrie.cfg the running honeypot actually reads."""
    stdout = await container.run(
        [
            "docker",
            "exec",
            name,
            container.CONTAINER_PYTHON,
            "-c",
            _DIGEST_SCRIPT,
            COWRIE_CONFIG_PATH,
        ],
        timeout_seconds=timeout_seconds,
    )
    digest = stdout.decode("utf-8", "replace").strip()
    if len(digest) != 64:
        # Exit 0 with nothing useful on stdout is not a fingerprint. Without
        # this the empty string would hash cleanly and read as a valid,
        # reproducible config -- the same silent lie as swallowing the error.
        raise FingerprintError(
            f"reading {COWRIE_CONFIG_PATH} in {name!r} produced no usable digest: "
            f"{digest!r}"
        )
    return digest


async def honeypot_fingerprint(
    name: str, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
) -> str:
    """Fingerprint what the honeypot IS: its image plus its running config.

    Two components, because either one alone is incomplete. The image id
    misses `cowrie.cfg`, which is bind-mounted read-only from the host and
    so changes the honeypot without changing the image. The config alone
    misses a rebuilt or re-pulled image, which changes the fake filesystem,
    the shipped userdb and Cowrie's own version.

    Note what `docker exec` cannot do here: `cat /cowrie/.../cowrie.cfg`
    fails with exit 127 because the image is distroless, and an
    implementation that discards that failure digests the empty string on
    every call -- so two honeypots with entirely different configs
    fingerprint identically. The config is therefore hashed by the
    container's own interpreter; see `container.CONTAINER_PYTHON`.
    """
    if not container.CONTAINER_NAME.fullmatch(name):
        raise FingerprintError(f"invalid container name: {name!r}")

    try:
        # Runs on the HOST, so it needs no in-container executable. This is
        # the resolved image id of the running container, not the tag it was
        # started from, so it moves when the image is rebuilt or re-pulled.
        image = (
            await container.run(
                ["docker", "inspect", "--format", "{{.Image}}", name],
                timeout_seconds=timeout_seconds,
            )
        ).decode("utf-8", "replace").strip()

        if not image:
            raise FingerprintError(
                f"docker inspect returned no image id for {name!r}"
            )

        config = await _container_config_digest(name, timeout_seconds)
    except container.ContainerExecTimeout as exc:
        raise FingerprintError(
            f"fingerprinting {name!r} timed out after {timeout_seconds}s: {exc}"
        ) from exc
    except container.ContainerExecError as exc:
        raise FingerprintError(f"could not fingerprint {name!r}: {exc}") from exc

    return _digest({"image": image, "config": config})
