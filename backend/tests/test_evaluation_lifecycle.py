"""Lifecycle resolution: is this the same defect, and what happened to it.

The failure that matters most is reporting `fixed` when nothing was fixed.
A finding is absent from a run for two unrelated reasons -- the fact came
back `observed`, or the fact was never established at all -- and conflating
them turns an infrastructure failure into good news. Most of these tests aim
at that one boundary.

Resolution is a pure function over already-loaded runs, so none of this
touches the database.
"""

import pytest

from app.services.evaluation import lifecycle

OBSERVED = "observed"
NOT_OBSERVED = "not_observed"
UNKNOWN = "unknown"

KEY = "probe:os_release:os.identity"


def _facts(
    *,
    run_id="r",
    status="completed",
    evaluator_status="unavailable",
    findings=(),
    facts=None,
    evaluator_by_characteristic=None,
):
    return lifecycle.RunFacts(
        run_id=run_id,
        status=status,
        evaluator_status=evaluator_status,
        finding_keys=frozenset(findings),
        fact_status_by_key=dict(facts or {}),
        evaluator_status_by_characteristic=dict(evaluator_by_characteristic or {}),
    )


# --- state(), the three-way distinction everything else rests on -----------


def test_a_finding_present_in_the_run_is_present() -> None:
    facts = _facts(findings=[KEY], facts={KEY: NOT_OBSERVED})
    assert lifecycle.state(facts, KEY) == "present"


def test_no_finding_and_an_observed_fact_is_absent() -> None:
    assert lifecycle.state(_facts(facts={KEY: OBSERVED}), KEY) == "absent"


def test_no_finding_and_an_unknown_fact_is_undetermined() -> None:
    """The distinction the whole feature depends on.

    `unknown` means the probe failed on our side. Calling that `absent` would
    make the next comparison report the defect as fixed.
    """
    assert lifecycle.state(_facts(facts={KEY: UNKNOWN}), KEY) == "undetermined"


def test_a_key_the_run_never_attempted_is_undetermined() -> None:
    """A probe removed from probes.yaml, or a module that never ran.

    Silence about a key is not a statement that the defect is gone.
    """
    assert lifecycle.state(_facts(), KEY) == "undetermined"


# --- the state table -------------------------------------------------------


def test_present_in_both_is_persisting() -> None:
    base = _facts(run_id="b", findings=[KEY], facts={KEY: NOT_OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    entry = lifecycle.resolve(base, head, history=[])[0]

    assert entry.key == KEY
    assert entry.status == "persisting"


def test_absent_then_present_is_new() -> None:
    base = _facts(run_id="b", facts={KEY: OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    assert lifecycle.resolve(base, head, history=[])[0].status == "new"


def test_present_then_absent_is_fixed() -> None:
    base = _facts(run_id="b", findings=[KEY], facts={KEY: NOT_OBSERVED})
    head = _facts(run_id="h", facts={KEY: OBSERVED})

    entry = lifecycle.resolve(base, head, history=[])[0]

    assert entry.status == "fixed"
    # A fixed finding has no row in head by definition, so the caller needs
    # base's row to render anything auditable at all.
    assert entry.from_run == "b"


def test_present_then_unknown_is_undetermined_never_fixed() -> None:
    """The single worst wrong answer this feature could give.

    The honeypot may well still be broken; this run simply could not look.
    """
    base = _facts(run_id="b", findings=[KEY], facts={KEY: NOT_OBSERVED})
    head = _facts(run_id="h", facts={KEY: UNKNOWN})

    assert lifecycle.resolve(base, head, history=[])[0].status == "undetermined"


def test_absent_in_both_is_not_reported() -> None:
    base = _facts(run_id="b", facts={KEY: OBSERVED})
    head = _facts(run_id="h", facts={KEY: OBSERVED})

    assert lifecycle.resolve(base, head, history=[]) == []


# --- regressed -------------------------------------------------------------


def test_present_earlier_absent_in_base_present_again_is_regressed() -> None:
    older = _facts(run_id="o", findings=[KEY], facts={KEY: NOT_OBSERVED})
    base = _facts(run_id="b", facts={KEY: OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    assert lifecycle.resolve(base, head, history=[older])[0].status == "regressed"


def test_a_failed_historical_run_does_not_make_a_defect_regressed() -> None:
    """History is read only from runs that completed.

    A failed run's findings describe a partial execution, and letting them
    vote turns a first-time defect into a phantom regression.
    """
    older = _facts(
        run_id="o", status="failed", findings=[KEY], facts={KEY: NOT_OBSERVED}
    )
    base = _facts(run_id="b", facts={KEY: OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    assert lifecycle.resolve(base, head, history=[older])[0].status == "new"


def test_an_undetermined_historical_run_does_not_make_a_defect_regressed() -> None:
    """A run that could not establish the fact neither confirms nor denies."""
    older = _facts(run_id="o", facts={KEY: UNKNOWN})
    base = _facts(run_id="b", facts={KEY: OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    assert lifecycle.resolve(base, head, history=[older])[0].status == "new"


# --- the evaluator slot ----------------------------------------------------

EVAL_KEY = "evaluator:file_system"


def test_an_evaluator_finding_vanishing_with_no_key_is_undetermined() -> None:
    """The case that would otherwise fabricate six fixes at once.

    Running one evaluation with a BYOK key and the next without is routine --
    the key is optional. Without this rule every evaluator finding from the
    first run reports as fixed, produced by nothing but an absent API key.
    """
    base = _facts(run_id="b", evaluator_status="completed", findings=[EVAL_KEY])
    head = _facts(run_id="h", evaluator_status="unavailable")

    assert lifecycle.resolve(base, head, history=[])[0].status == "undetermined"


def test_an_evaluator_finding_gone_while_the_evaluator_ran_is_fixed() -> None:
    base = _facts(run_id="b", evaluator_status="completed", findings=[EVAL_KEY])
    head = _facts(run_id="h", evaluator_status="completed")

    assert lifecycle.resolve(base, head, history=[])[0].status == "fixed"


def test_an_evaluator_entry_is_flagged_as_a_slot() -> None:
    """One verdict per characteristic per run means the key always matches
    itself. "Still present" says the evaluator had something to say, not that
    the same flaw persists -- the prose may describe a different problem
    entirely, and the UI must not claim otherwise."""
    base = _facts(run_id="b", evaluator_status="completed", findings=[EVAL_KEY])
    head = _facts(run_id="h", evaluator_status="completed", findings=[EVAL_KEY])

    entry = lifecycle.resolve(base, head, history=[])[0]

    assert entry.status == "persisting"
    assert entry.is_slot is True


def test_a_deterministic_entry_is_not_a_slot() -> None:
    base = _facts(run_id="b", findings=[KEY], facts={KEY: NOT_OBSERVED})
    head = _facts(run_id="h", findings=[KEY], facts={KEY: NOT_OBSERVED})

    assert lifecycle.resolve(base, head, history=[])[0].is_slot is False


# --- ordering --------------------------------------------------------------


def test_entries_come_back_worst_news_first() -> None:
    keys = {
        "regressed": "probe:a:f",
        "new": "probe:b:f",
        "persisting": "probe:c:f",
        "fixed": "probe:d:f",
        "undetermined": "probe:e:f",
    }
    older = _facts(run_id="o", findings=[keys["regressed"]], facts={keys["regressed"]: NOT_OBSERVED})
    base = _facts(
        run_id="b",
        findings=[keys["persisting"], keys["fixed"], keys["undetermined"]],
        facts={
            keys["regressed"]: OBSERVED,
            keys["new"]: OBSERVED,
            keys["persisting"]: NOT_OBSERVED,
            keys["fixed"]: NOT_OBSERVED,
            keys["undetermined"]: NOT_OBSERVED,
        },
    )
    head = _facts(
        run_id="h",
        findings=[keys["regressed"], keys["new"], keys["persisting"]],
        facts={
            keys["regressed"]: NOT_OBSERVED,
            keys["new"]: NOT_OBSERVED,
            keys["persisting"]: NOT_OBSERVED,
            keys["fixed"]: OBSERVED,
            keys["undetermined"]: UNKNOWN,
        },
    )

    statuses = [e.status for e in lifecycle.resolve(base, head, history=[older])]

    assert statuses == [
        "regressed",
        "new",
        "persisting",
        "undetermined",
        "fixed",
    ]


@pytest.mark.parametrize("bad", ["", "nocolon", ":leading"])
def test_a_malformed_key_is_not_treated_as_an_evaluator_slot(bad) -> None:
    base = _facts(run_id="b", findings=[bad])
    head = _facts(run_id="h", findings=[bad])

    entry = lifecycle.resolve(base, head, history=[])[0]

    assert entry.is_slot is False


# --- the per-characteristic evaluator status, and the hole it closes -------

MIXED_KEY = "evaluator:attack_possibilities"


def test_a_mixed_run_does_not_report_an_unassessed_characteristic_as_fixed() -> None:
    """The hole this column was added to close.

    `_aggregate_evaluator_status` is `any FAILED -> FAILED; else any
    COMPLETED -> COMPLETED`. So a run where one characteristic got a verdict
    and another gathered no evidence aggregates to COMPLETED. Resolving the
    unassessed one against that aggregate says `absent` -- "the evaluator had
    nothing to say" -- and base=present + head=absent resolves to `fixed`.

    Nothing was fixed. The characteristic was never looked at.
    """
    head = _facts(
        run_id="head",
        evaluator_status="completed",  # the lossy aggregate
        evaluator_by_characteristic={
            "os_identity": "completed",
            "attack_possibilities": "unavailable",  # the truth for this one
        },
    )
    assert lifecycle.state(head, MIXED_KEY) == "undetermined"


def test_a_mixed_run_still_reports_an_assessed_characteristic_as_absent() -> None:
    """The precision must cut both ways, or it is just a blanket refusal."""
    head = _facts(
        run_id="head",
        evaluator_status="completed",
        evaluator_by_characteristic={
            "os_identity": "completed",
            "attack_possibilities": "completed",
        },
    )
    assert lifecycle.state(head, MIXED_KEY) == "absent"


def test_an_unrecorded_characteristic_falls_back_to_the_run_level_rule() -> None:
    """Rows predating the column keep today's behaviour, no worse and no better."""
    head = _facts(
        run_id="head",
        evaluator_status="completed",
        evaluator_by_characteristic={"attack_possibilities": "unrecorded"},
    )
    assert lifecycle.state(head, MIXED_KEY) == "absent"

    silent = _facts(
        run_id="head",
        evaluator_status="evaluator_failed",
        evaluator_by_characteristic={"attack_possibilities": "unrecorded"},
    )
    assert lifecycle.state(silent, MIXED_KEY) == "undetermined"


def test_a_characteristic_with_no_row_at_all_is_undetermined() -> None:
    """Never scored and never rated is never established.

    `scoring` omits `attack_possibilities` entirely when no chain ran, so a
    run against a target that refuses every destructive chain writes NO
    category row for it -- not a row saying `unavailable`, no row. Falling
    through to the aggregate resolves that `absent`, and `absent` is the one
    value that becomes `fixed`. Same bug, narrower shape.
    """
    head = _facts(
        run_id="head",
        evaluator_status="completed",
        evaluator_by_characteristic={"os_identity": "completed"},
    )
    assert lifecycle.state(head, MIXED_KEY) == "undetermined"


def test_an_empty_map_still_falls_back_to_the_run_level_rule() -> None:
    """No per-characteristic data at all is a different claim from a gap.

    An empty map means the run has no category rows, or predates the column.
    That is exactly the case the fallback exists for -- treating it as "never
    established" would turn every historic `fixed` into `undetermined`.
    """
    head = _facts(run_id="head", evaluator_status="completed")
    assert lifecycle.state(head, MIXED_KEY) == "absent"

    silent = _facts(run_id="head", evaluator_status="unavailable")
    assert lifecycle.state(silent, MIXED_KEY) == "undetermined"
