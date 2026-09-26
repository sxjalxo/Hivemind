"""Evaluate every arm of the degradation matrix and print the comparison.

WHAT THIS IS FOR

The realism evaluation's central claim is that it discriminates: that a
better honeypot scores better and a worse one scores worse, and that the
separation is visible per characteristic rather than only in aggregate.
Demonstrating that needs honeypots of known, differing quality.

The obvious way to get them -- two machines, a VPS, a lab -- costs money and
wall-clock time, and produces a WORSE experiment: two dissimilar hosts differ
in dozens of uncontrolled ways, so a score delta between them is not
attributable to any one of them. The `matrix` compose profile instead runs
several containers from one pinned image, each differing from the stock decoy
in exactly one declared respect. Every arm is the same Cowrie, on the same
host, through the same apparatus, so a delta has exactly one candidate cause.

WHAT IT MEASURES

Two axes, deliberately separated, because the arms are built to move them
independently:

  * the per-characteristic deterministic score -- "did the decoy answer?"
    The degraded-fs arm empties /etc/passwd and /proc/cpuinfo, so file_system
    falls from 3/3 to 1/3 while nothing else moves.
  * the contradiction findings -- "do its answers agree?" The degraded-sanity
    arm answers EVERYTHING, so its sanity score is a perfect 3/3, and it
    contradicts itself twice. A run that reported only scores would call it
    indistinguishable from the hardened arm.

That second row is the point. Score and self-consistency are different
questions, and an evaluation that collapsed them would rank a fluent liar
above a decoy that simply admits it has no /etc/os-release.

USAGE

    docker compose --profile matrix up -d
    # EVALUATION_TARGETS must map every arm -- see backend/.env.example
    python scripts/run_degradation_matrix.py
    python scripts/run_degradation_matrix.py --arm matrix-hardened --arm cowrie-01

If an arm reports `context` as unestablished while its neighbours score it,
its capture sidecar is almost certainly orphaned: restarting an arm destroys
the network namespace its sidecar joined, and the sidecar keeps running
attached to nothing. Restart the sidecar too. docker-compose.yml has the
full note beside the matrix services.

Each arm runs a full evaluation: a container reset, an nmap scan, the agent's
command budget, the attack chains and their read-back, plus one evaluator call
per characteristic if a BYOK key is configured. Budget a few minutes per arm.

The runs are ordinary evaluation runs and are stored as such, so every number
printed here is also in the UI, and any two arms can be opened side by side in
the comparison view afterwards.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.auth import Actor
from app.config import get_settings
from app.db import locks
from app.es.client import get_es
from app.models.evaluation import EvaluationRunOut
from app.services.evaluation import read, runs

# The same namespace `POST /api/evaluations` locks under. This script is a
# second direct caller of `start_run`, and "one run at a time per honeypot"
# is enforced by the ROUTER rather than by `start_run` itself -- so calling
# it from here without taking the lock would reintroduce precisely the
# overlap the lock exists to prevent: two runs resetting one container
# underneath each other and reading each other's commands back out of the
# same window. Matching the namespace is what makes the script and the API
# mutually exclusive rather than merely each internally consistent.
_LOCK_NAMESPACE = b"hivemind.evaluation.run:"

# The stock decoy. Printed first and used as the baseline every other arm's
# delta is measured against, because it is the honeypot the project actually
# ships -- the interesting question is what moves relative to what you have,
# not relative to the best arm.
BASELINE = "cowrie-01"

# Declared here rather than discovered from the target map, so that running
# the matrix against a half-configured deployment fails by NAMING the arm it
# cannot find instead of quietly measuring fewer arms than the experiment
# claims. The order is the intended ladder: best first.
ARMS: tuple[str, ...] = (
    "matrix-hardened",
    BASELINE,
    "matrix-degraded-sanity",
    "matrix-degraded-fs",
)

CHARACTERISTICS = (
    "basic_commands",
    "file_system",
    "services",
    "attack_possibilities",
    "sanity",
    "context",
)


def _fmt(value: float | None) -> str:
    """A score, or a dash for one that was never established.

    Never 0.0 for an unestablished score. `None` means the run could not
    determine the characteristic at all, and printing it as zero would turn
    our own failure to look into a verdict against the honeypot -- the exact
    substitution the whole evaluation is built to refuse.
    """
    return "  -  " if value is None else f"{value:>5.3f}"


def _contradictions(run: EvaluationRunOut) -> list[str]:
    """Finding keys for self-contradictions, which start `sanity:`."""
    return sorted(f.finding_key for f in run.findings if f.finding_key.startswith("sanity:"))


async def _evaluate(arm: str) -> EvaluationRunOut:
    connection = await locks.acquire(_LOCK_NAMESPACE, arm)
    if connection is None:
        raise SystemExit(
            f"{arm} already has an evaluation running -- started from the UI, the "
            f"API, or another copy of this script. Refusing rather than running a "
            f"second one: two runs reset the same container underneath each other "
            f"and read each other's commands back out of one window, so both "
            f"results would be wrong and neither would look it."
        )
    try:
        # `unauthenticated` is the honest actor for a local script: no identity
        # existed to record, which is a different claim from `unrecorded` (the
        # run predates the audit trail) and must not be collapsed into it.
        run_id = await runs.start_run(arm, actor=Actor.unauthenticated())
        loaded = await read.load_run(run_id)
        if loaded is None:
            raise RuntimeError(f"run {run_id} for {arm} vanished between start and read")
        return loaded
    finally:
        await locks.release(connection, _LOCK_NAMESPACE, arm)


def _check_targets(arms: tuple[str, ...]) -> None:
    configured = get_settings().evaluation_targets
    if not configured:
        raise SystemExit(
            "EVALUATION_TARGETS is empty, so every arm would resolve to the single "
            "default target and all of them would evaluate the SAME honeypot -- "
            "four identical rows presented as an experiment. Configure the map "
            "first; backend/.env.example has the matrix entries ready to paste."
        )
    missing = [arm for arm in arms if arm not in configured]
    if missing:
        raise SystemExit(
            f"EVALUATION_TARGETS has no entry for {missing}. Add them, or pass "
            f"--arm explicitly to run only the arms you have configured. "
            f"Configured: {sorted(configured)}"
        )


def _print_report(results: dict[str, EvaluationRunOut]) -> None:
    width = max(len(a) for a in results) + 2

    print()
    print("Deterministic score per characteristic")
    print("-" * (width + 8 * len(CHARACTERISTICS)))
    header = "arm".ljust(width) + "".join(c[:7].rjust(8) for c in CHARACTERISTICS)
    print(header)
    for arm, run in results.items():
        scores = {c.characteristic: c.deterministic_score for c in run.category_scores}
        row = arm.ljust(width) + "".join(_fmt(scores.get(c)).rjust(8) for c in CHARACTERISTICS)
        print(row)

    print()
    print("Self-consistency (contradiction findings)")
    print("-" * (width + 40))
    for arm, run in results.items():
        keys = _contradictions(run)
        detail = ", ".join(k.removeprefix("sanity:") for k in keys) if keys else "none"
        print(f"{arm.ljust(width)}{len(keys):>3}  {detail}")

    print()
    print("Findings and fingerprints")
    print("-" * (width + 40))
    for arm, run in results.items():
        print(
            f"{arm.ljust(width)}{len(run.findings):>3} findings   "
            f"honeypot={run.honeypot_fingerprint[7:19]}  "
            f"evaluator={run.evaluator_status}"
        )

    fingerprints = {r.evaluation_config_fingerprint for r in results.values()}
    print()
    if len(fingerprints) == 1:
        # The precondition for the whole comparison. Every arm must have been
        # asked the SAME question, or the deltas describe our own apparatus
        # moving rather than the honeypots differing.
        print(f"All arms share one evaluation config fingerprint: {fingerprints.pop()}")
    else:
        print(
            "WARNING: the arms do NOT share an evaluation config fingerprint, so "
            "these runs are not comparable. Something about the probe set, chains, "
            "rulebook, budget or apparatus changed while the matrix was running.\n"
            f"  {sorted(fingerprints)}"
        )


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--arm",
        action="append",
        dest="arms",
        help="Evaluate only this honeypot id. Repeatable. Defaults to every arm.",
    )
    args = parser.parse_args()
    arms = tuple(args.arms) if args.arms else ARMS

    _check_targets(arms)

    results: dict[str, EvaluationRunOut] = {}
    for arm in arms:
        print(f"evaluating {arm} ...", flush=True)
        run = await _evaluate(arm)
        results[arm] = run
        print(f"  {arm}: {run.status}, run {run.id}", flush=True)

    _print_report(results)
    # The same close `app.main`'s shutdown does. Without it the cached
    # AsyncElasticsearch leaks its aiohttp session and the script's last words
    # are a connector warning, which reads like a failure at the exact moment
    # the operator is trying to read a result table.
    await get_es().close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
