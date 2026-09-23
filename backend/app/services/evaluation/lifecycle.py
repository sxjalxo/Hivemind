"""What happened to a defect between two runs.

`compare_runs` answers "the score moved, and here is whether that is
attributable". This answers the question a developer actually asks: the
missing /etc/os-release you reported last week -- is it fixed?

Resolution is a PURE function over already-loaded runs. The database work of
assembling a `RunFacts` lives in `runs.py`; everything here is decidable from
those values alone, which is what makes the state table testable without a
honeypot, an evaluator or a database.

The rule the whole module rests on: absence of a finding is not evidence the
defect is gone. A key is absent from a run for two unrelated reasons -- the
fact came back `observed`, or the fact was never established -- and treating
the second as `fixed` manufactures good news out of an infrastructure
failure. That is the same error the tri-state fact model exists to prevent,
so `state()` keeps all three apart and `undetermined` is a reportable outcome
rather than a gap.
"""

from dataclasses import dataclass, field
from typing import Literal

from app.db.models import FactStatus, RunStatus

State = Literal["present", "absent", "undetermined"]
Status = Literal["new", "persisting", "fixed", "regressed", "undetermined"]

# Worst news first. A developer scanning this list should meet a defect that
# came BACK before one that is merely still there, and should not have to
# scroll past a column of good news to find either.
_ORDER: dict[str, int] = {
    "regressed": 0,
    "new": 1,
    "persisting": 2,
    "undetermined": 3,
    "fixed": 4,
}

_EVALUATOR_PREFIX = "evaluator:"

# Statuses that mean the evaluator did not produce verdicts this run. Every
# evaluator key is `undetermined` under these, never `fixed`.
_EVALUATOR_SILENT = frozenset({"unavailable", "evaluator_failed"})


@dataclass(frozen=True)
class RunFacts:
    """One run, reduced to what lifecycle resolution needs.

    `fact_status_by_key` is the underlying fact per key -- the join that keeps
    `absent` and `undetermined` apart. A key missing from it entirely means
    the run never attempted that check.
    """

    run_id: str
    status: str
    evaluator_status: str
    finding_keys: frozenset[str] = field(default_factory=frozenset)
    fact_status_by_key: dict[str, str] = field(default_factory=dict)
    # characteristic -> that characteristic's own evaluator status.
    #
    # `evaluator_status` above is the run's aggregate and is lossy in the
    # dangerous direction: a COMPLETED run may contain a characteristic the
    # evaluator never assessed. Empty, or a value of "unrecorded", means the
    # run predates the per-characteristic column and `state()` falls back.
    evaluator_status_by_characteristic: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LifecycleEntry:
    key: str
    status: Status
    # Which run the renderable row comes from. For `fixed` there is no row in
    # head at all, so the caller has to read base to show text and evidence.
    from_run: str
    is_slot: bool


def is_evaluator_key(key: str) -> bool:
    """An evaluator key is a SLOT, not a flaw.

    One verdict per characteristic per run means the key always matches
    itself, so "still present" means only that the evaluator had something to
    say about that characteristic -- its critique may describe an entirely
    different problem. Callers must label it rather than claim the flaw
    persists.
    """
    return key.startswith(_EVALUATOR_PREFIX) and len(key) > len(_EVALUATOR_PREFIX)


def state(facts: RunFacts, key: str) -> State:
    """Whether the run says the defect is there, gone, or unestablished."""
    if key in facts.finding_keys:
        return "present"

    if is_evaluator_key(key):
        # No probe or chain row exists to join, so an evaluator status is the
        # only thing that can distinguish "it had nothing to say" from "it
        # never ran".
        #
        # Prefer THIS characteristic's status. The run-level column is an
        # aggregate (`any FAILED -> FAILED; else any COMPLETED -> COMPLETED`),
        # so a mixed run reports COMPLETED while containing a characteristic
        # the evaluator never assessed -- and resolving that one against the
        # aggregate returns `absent`, which turns into `fixed`. That is the
        # "absence is not evidence of absence" rule breaking on our own data.
        characteristic = key[len(_EVALUATOR_PREFIX) :]
        own = facts.evaluator_status_by_characteristic.get(characteristic)
        if own is not None and own != "unrecorded":
            return "undetermined" if own in _EVALUATOR_SILENT else "absent"
        if own is None and facts.evaluator_status_by_characteristic:
            # A NO ROW AT ALL, in a run that produced per-characteristic rows
            # for other characteristics. The map is built from
            # `category_scores`, and a row is written only for a
            # characteristic that was scored or rated -- `scoring` omits
            # `attack_possibilities` outright when no chain ran, so a run
            # whose target refuses every destructive chain has no row for it.
            #
            # Never scored and never rated is never ESTABLISHED, which is the
            # same "we did not look" the tri-state fact model keeps apart from
            # "we looked and found nothing". Falling through to the aggregate
            # here would resolve it `absent` and manufacture a `fixed` -- the
            # bug above in a narrower shape.
            return "undetermined"
        # Unrecorded, or a run predating the column entirely (an empty map).
        # Fall back to the old rule: no worse than before, and the
        # information to do better was never written.
        return "undetermined" if facts.evaluator_status in _EVALUATOR_SILENT else "absent"

    fact = facts.fact_status_by_key.get(key)
    if fact == FactStatus.OBSERVED:
        return "absent"
    # `unknown`, or a key this run never attempted. Either way the run is
    # silent about the defect, and silence is not absence.
    return "undetermined"


def _was_present_earlier(history: list[RunFacts], key: str) -> bool:
    """Did any usable earlier run actually report this defect?

    Two filters, both load bearing. A run that did not complete describes a
    partial execution, and a run that could not establish the fact neither
    confirms nor denies -- letting either vote turns a first-time defect into
    a phantom regression.
    """
    return any(
        run.status == RunStatus.COMPLETED and state(run, key) == "present"
        for run in history
    )


def resolve(
    base: RunFacts, head: RunFacts, history: list[RunFacts]
) -> list[LifecycleEntry]:
    """Every key either run has an opinion about, with what happened to it."""
    keys = (
        set(base.finding_keys)
        | set(head.finding_keys)
        | set(base.fact_status_by_key)
        | set(head.fact_status_by_key)
    )

    entries: list[LifecycleEntry] = []
    for key in sorted(keys):
        before, after = state(base, key), state(head, key)

        if after == "present":
            if before == "present":
                status: Status = "persisting"
            else:
                status = "regressed" if _was_present_earlier(history, key) else "new"
            from_run = head.run_id
        elif before == "present":
            # The only place `fixed` can be reached, and only from `absent`.
            status = "fixed" if after == "absent" else "undetermined"
            from_run = base.run_id
        else:
            # Neither run reports it. Nothing to say, and saying nothing is
            # the honest output -- an `undetermined`/`undetermined` pair is
            # not news, it is two runs that both failed to look.
            continue

        entries.append(
            LifecycleEntry(
                key=key,
                status=status,
                from_run=from_run,
                is_slot=is_evaluator_key(key),
            )
        )

    entries.sort(key=lambda entry: (_ORDER[entry.status], entry.key))
    return entries
