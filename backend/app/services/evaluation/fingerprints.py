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
from dataclasses import asdict, dataclass

from app.services.evaluation import agent, container, probes
from app.services.evaluation.agent import AgentBudget
from app.services.evaluation.static import chains, nmap
from app.services.mitre import rules


@dataclass(frozen=True)
class Target:
    """What the run connected to.

    Frozen because a fingerprint taken over a value that can be mutated
    afterwards is not reproducible: the stored digest has to mean the target
    the run actually used.

    No credential. The password does not change what the honeypot IS, and
    these values are hashed into a digest that is stored in Postgres and
    rendered in the comparison view. Cowrie's password is barely a secret --
    the target exists to be logged into -- but the rule that a fingerprint
    never carries one should not acquire its first exception by accident.

    A plain dataclass rather than a validated model on purpose. The
    container-name check lives in `honeypot_fingerprint`, where the failure
    is a `FingerprintError` and means "this run is not comparable". Raising
    in the constructor instead would turn a misconfigured name into a crash
    at whatever unrelated point the settings were first read.
    """

    kind: str
    container_name: str | None
    host: str
    ssh_port: int
    ssh_username: str


@dataclass(frozen=True)
class Apparatus:
    """How the run measured, as opposed to what it asked or what it tested.

    A third category, and the reason it needed naming: these settings change
    what a run can FIND without changing either the honeypot or the probe
    set. Halve `nmap_timeout_seconds` and every service comes back `unknown`;
    point `capture_interface` at the wrong device and the packet count is
    `unknown` too. Before this they were in neither fingerprint, so two runs
    measured through different apparatus compared as though they had asked
    the same question of the same honeypot.

    They belong in the evaluation-config fingerprint rather than the honeypot
    one: they are our instrument, not the thing under test.
    """

    capture_interface: str
    # The capture sidecar, replacing the old `capture_image`. The backend no
    # longer chooses an image -- compose declares the container and the
    # backend execs into it -- so fingerprinting an image setting would claim
    # to describe something this side does not control. What IS covered is
    # which sidecar was used; the image behind it is the operator's, the same
    # accepted gap as the honeypot container's writable layer.
    #
    # Renaming the field moves every stored evaluation-config fingerprint
    # once. That is this module's preferred direction of error: one lost
    # comparison, rather than two runs measured through different apparatus
    # comparing as though they were the same.
    capture_container: str | None
    nmap_timeout_seconds: int
    capture_timeout_seconds: int

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


def _content_digest(payload: object) -> str:
    """Bare hex digest of one config component, canonically serialised."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _code_constants() -> dict:
    """Result-deciding values that live in .py files rather than in yaml.

    Hashing the VALUES, not the files. The module docstring's rejection of
    file hashing stands -- a comment or a refactor would invalidate every
    stored fingerprint and train people to ignore it -- but that argument was
    doing double duty as an excuse to cover none of this. A constant's value
    moves only when the behaviour moves, which is exactly the property a
    fingerprint wants.

    Each of these decides what a run can find:

      * `PER_COMMAND_TIMEOUT_SECONDS` -- when a probe counts as failed.
      * `_PROMPT_PREFIX`, `_ANSI_SEQUENCE` -- what the agent's raw output is
        cleaned down to before anything reads it. A cleaning bug here is what
        once let a prompt echo turn a genuine absence into a false `observed`.
      * `_EXPECTED_SERVICES`, `_OPEN_LINE` -- which ports a scan asks about
        and what counts as an answer.
      * `_DATA_PRODUCING_HEAD`, `_RAW_TEXT_RULE_IDS` -- which command text the
        rulebook is allowed to see at all.

    Regexes are hashed by `.pattern`: the compiled object is not
    serialisable, and the pattern is what carries the meaning. Note that
    compile-time flags are NOT covered, so swapping `re.IGNORECASE` on or off
    without touching the pattern text moves no fingerprint.

    Still uncovered, and honestly: the scoring and compaction ALGORITHMS.
    `scoring.py` holds no constants to hash -- it is pure functions -- so a
    change to how a fraction is computed moves nothing here. Two runs across
    that kind of edit are still compared by git revision.
    """
    return {
        "agent_per_command_timeout_seconds": agent.PER_COMMAND_TIMEOUT_SECONDS,
        "agent_prompt_prefix": agent._PROMPT_PREFIX.pattern,
        "agent_ansi_sequence": agent._ANSI_SEQUENCE.pattern,
        "nmap_expected_services": nmap._EXPECTED_SERVICES,
        "nmap_open_line": nmap._OPEN_LINE.pattern,
        "rules_data_producing_head": rules._DATA_PRODUCING_HEAD.pattern,
        # A frozenset has no stable serialisation order; sort it so the digest
        # is reproducible across processes.
        "rules_raw_text_rule_ids": sorted(rules._RAW_TEXT_RULE_IDS),
    }


def _config_parts(budget: AgentBudget, apparatus: Apparatus) -> dict:
    """Everything on OUR side that changes what a run can find.

    Fingerprints the configuration the run ACTUALLY EXECUTES, not the
    configuration currently on disk. That distinction is the whole point of
    this function and it is easy to get backwards.

    `probes.load_probes`, `chains.load_chains` and `rules.load_rules` are
    all `@lru_cache`d, so a long-lived API process runs whatever those files
    said when it first read them. Re-reading the yaml here would fingerprint
    a *different* configuration than the one being executed: edit
    probes.yaml under a running process and run A executes v1 while
    recording sha256(v2); restart, and run B executes v2 and records
    sha256(v2) as well. The two runs then carry identical config
    fingerprints and the compare endpoint draws a trend through runs that
    used different probe sets. Stale-but-confident is exactly what this
    module exists to avoid, and the stale thing is the RUN -- so the
    fingerprint has to describe that.

    The digest is therefore taken over the loaded objects themselves, which
    are the cached product of the loaders' own single read. There is no
    second read to disagree with the first. The human-readable declared
    version is pulled from the same cached call that produced the objects
    (`probes._raw()` is what `load_probes()` is built on), so `probe_set`
    and `probe_set_sha256` can never describe two different file versions.

    Content hashes, not declared versions. `version` in the yaml is a
    hand-maintained string; fingerprinting by it alone means editing a
    probe's command -- which changes precisely what the run can find --
    leaves the fingerprint identical and the two runs claiming to be
    comparable. Correctness must not depend on anyone remembering to bump a
    string. The declared version is kept alongside the hash because it is
    the half a human can read off a stored fingerprint; it is not what makes
    it correct.

    The budget is dumped whole rather than enumerated field by field. Naming
    `max_commands` and `max_seconds` by hand is the same defect in miniature:
    add a third field to `AgentBudget` and two runs under materially
    different budgets fingerprint byte-identically until somebody remembers
    to edit this dict.

    What is still NOT covered: the deterministic scoring *code*. Only its
    data files are. `apply_rules` is `rules.py` as much as it is
    rulebook.yaml -- `_split_command_segments`, `_filtered_command_text`,
    `_DATA_PRODUCING_HEAD` and `_RAW_TEXT_RULE_IDS` all decide what counts
    as a technique hit; `app/services/compaction.py` decides what text those
    rules ever see; `static/nmap.py`'s `_EXPECTED_SERVICES` and `_OPEN_LINE`
    decide what a port scan establishes; `agent.PER_COMMAND_TIMEOUT_SECONDS`
    decides how long a probe gets before it counts as failed. Editing any of
    them changes a run's results with no fingerprint movement. (One narrow
    exception falls out of hashing loaded objects: `rules._CMD_START` is
    substituted into every anchored pattern by `load_rules`, so the patterns
    as loaded -- and hence that constant, as it stood at load time -- are
    covered.) Hashing the .py files themselves was rejected: it would
    invalidate every stored fingerprint on a comment or a refactor, which
    trains developers to ignore the value. Two runs across a code change to
    the scoring pipeline are compared by git revision, not by this.

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
    try:
        # `_raw()` and `load_probes()` share one `@lru_cache` entry --
        # `load_probes` is built on `_raw` -- so the declared version and
        # the hashed objects come from a single read of a single file. The
        # module-level `PROBE_SET_VERSION` is a snapshot of that same call
        # and is deliberately not used here, so nothing depends on when it
        # happened to be taken.
        probe_set = str(probes._raw()["version"])
        probe_payload = {
            "version": probe_set,
            "probes": [probe.model_dump(mode="json") for probe in probes.load_probes()],
        }
        chain_set = str(chains._raw()["version"])
        chain_payload = {
            "version": chain_set,
            "chains": [chain.model_dump(mode="json") for chain in chains.load_chains()],
        }
        rule_payload = {
            "rules": [rule.model_dump(mode="json") for rule in rules.load_rules()]
        }
    except Exception as exc:
        # Any failure to produce the configuration -- an unreadable file,
        # malformed yaml, a model that will not validate -- is a run that
        # cannot be compared. Never a partial or default fingerprint.
        raise FingerprintError(f"could not load the evaluation config: {exc}") from exc

    return {
        "probe_set": probe_set,
        "probe_set_sha256": _content_digest(probe_payload),
        "chain_set": chain_set,
        "chain_set_sha256": _content_digest(chain_payload),
        "rulebook": _content_digest(rule_payload),
        "budget": budget.model_dump(mode="json"),
        # `asdict` for the same reason the budget is dumped whole: add a
        # field and it enters the digest without anyone remembering to.
        "apparatus": asdict(apparatus),
        "code_constants": _code_constants(),
    }


def evaluation_config_fingerprint(budget: AgentBudget, apparatus: Apparatus) -> str:
    """Fingerprint OUR side of the run. Raises if any input is unloadable."""
    return _digest(_config_parts(budget, apparatus))


async def _container_config_digest(name: str, timeout_seconds: float) -> str:
    """SHA-256 of the cowrie.cfg the running honeypot actually reads.

    Raises `FingerprintError` for every failure, including the underlying
    `container.ContainerExecError`. Callers -- and the live tests -- get one
    exception type to guard on; a docker failure leaking out unwrapped is
    how a test that meant to skip turns into a hard error on any machine
    that has docker but has not run `docker compose up`.
    """
    try:
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
    except container.ContainerExecTimeout as exc:
        raise FingerprintError(
            f"reading {COWRIE_CONFIG_PATH} in {name!r} timed out after "
            f"{timeout_seconds}s: {exc}"
        ) from exc
    except container.ContainerExecError as exc:
        raise FingerprintError(f"could not fingerprint {name!r}: {exc}") from exc

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


def _uninspectable_fingerprint(target: Target) -> str:
    """The fingerprint of a target we cannot look inside.

    A `generic` target -- a real VM, a bare host, another team's decoy -- has
    no image id to read and no `cowrie.cfg` to digest. This covers WHERE it
    is and what kind of thing it is, and nothing about what it CONTAINS.

    That limit is stated rather than hidden, because it is the dangerous
    direction this module's own preamble names: a fingerprint that stays
    stable when it should have moved merges two different honeypots into one
    trend line silently. Reinstall a generic target between two runs,
    reconfigure its services, patch its kernel -- the fingerprint does not
    move, and the comparison view will call the delta attributable. It is
    not. **Two runs against a generic target are comparable only insofar as
    the operator did not change it, and nothing here can check that.**

    `image` and `config` are carried as explicit nulls rather than omitted or
    empty-stringed. Omitting them would make this digest collide with a
    hypothetical future payload shape; an empty string is precisely the
    silent lie `_container_config_digest` refuses to tell. A null says "there
    was nothing to read", which is what happened.

    It cannot raise. There is no subprocess, nothing to time out, nothing to
    swallow -- so unlike the Cowrie path there is no failure to convert into
    a `FingerprintError`.
    """
    return _digest({"image": None, "config": None, "target": asdict(target)})


async def honeypot_fingerprint(
    target: Target, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
) -> str:
    """Fingerprint what the honeypot IS: its target, image and running config.

    Three components, because no two of them are enough. The image id
    misses `cowrie.cfg`, which is bind-mounted read-only from the host and
    so changes the honeypot without changing the image. The config alone
    misses a rebuilt or re-pulled image, which changes the fake filesystem,
    the shipped userdb and Cowrie's own version. And image-plus-config
    misses the target entirely: two containers from the same image with the
    same config are byte-identical here, so runs against different hosts,
    ports or containers fingerprinted the same and the compare endpoint drew
    a trend line straight through them. That was harmless only while there
    was exactly one target to point at; it stops being harmless the moment a
    second honeypot exists to compare against.

    The target belongs in THIS fingerprint and not the evaluation-config
    one. The config fingerprint means "our probes, chains, rulebook and
    budget" -- the question we asked. Putting the target there would make
    pointing at a second honeypot read as "we changed the question, so the
    delta is not attributable", which is backwards: the target names the
    thing under test, so it belongs with the thing under test.

    Note the direction of error this accepts. Moving an unchanged honeypot
    to a different port now reads as a honeypot change and costs one lost
    comparison. That is this module's stated preference, and the trade is
    not symmetric: the other direction merges two different honeypots into
    one trend line and says nothing.

    What the image id does NOT cover is the running container's writable
    layer: anything changed inside the container after it started -- a
    `docker cp`'d binary, a hand-edited `fs.pickle`, a package installed
    into it -- changes the honeypot with no fingerprint movement at all.
    That is the stable-when-it-should-have-changed direction, and it is
    accepted only because the alternative (hashing a live container
    filesystem that Cowrie is actively writing session logs into) cannot be
    made reproducible. Recreate the container rather than patching it in
    place if two runs are meant to be comparable.

    Note what `docker exec` cannot do here: `cat /cowrie/.../cowrie.cfg`
    fails with exit 127 because the image is distroless, and an
    implementation that discards that failure digests the empty string on
    every call -- so two honeypots with entirely different configs
    fingerprint identically. The config is therefore hashed by the
    container's own interpreter; see `container.CONTAINER_PYTHON`.
    """
    if target.kind != "cowrie":
        return _uninspectable_fingerprint(target)

    name = target.container_name
    if not name or not container.CONTAINER_NAME.fullmatch(name):
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
    except container.ContainerExecTimeout as exc:
        raise FingerprintError(
            f"fingerprinting {name!r} timed out after {timeout_seconds}s: {exc}"
        ) from exc
    except container.ContainerExecError as exc:
        raise FingerprintError(f"could not fingerprint {name!r}: {exc}") from exc

    if not image:
        raise FingerprintError(f"docker inspect returned no image id for {name!r}")

    config = await _container_config_digest(name, timeout_seconds)

    # `asdict` rather than a hand-written dict: add a field to `Target` and
    # it enters the digest automatically. Enumerating the fields here is the
    # same defect the budget comment describes -- two runs against
    # materially different targets hashing identically until somebody
    # remembers to edit this line.
    return _digest({"image": image, "config": config, "target": asdict(target)})
