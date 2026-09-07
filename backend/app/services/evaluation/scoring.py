from app.db.models import Characteristic, FactStatus
from app.services.evaluation.sanity import Observation
from app.services.evaluation.static.chains import ChainStepResult


def _fraction_observed(statuses: list[str]) -> float | None:
    """Observed over everything we actually established.

    `unknown` is excluded from BOTH numerator and denominator: a fact we
    could not determine is not evidence against the honeypot. When nothing
    was established the answer is None -- "not established" -- never 0.0,
    which would read as a verdict.
    """
    established = [s for s in statuses if s != FactStatus.UNKNOWN]
    if not established:
        return None
    observed = sum(1 for s in established if s == FactStatus.OBSERVED)
    return round(observed / len(established), 3)


def score_characteristics(
    observations_by_characteristic: dict[str, list[Observation]],
    chain_results: list[ChainStepResult],
) -> dict[str, float | None]:
    """Deterministic per-characteristic scores.

    This answers "did the honeypot do the checkable things?" only. The
    evaluator's realism judgement is a separate quantity and is never
    combined with these numbers. There is deliberately no composite or
    overall score here -- callers must not average these values together.

    Keys of the returned dict are always plain `str`, matching the caller-
    supplied keys of `observations_by_characteristic`. `attack_possibilities`
    is derived internally from `chain_results` rather than supplied by the
    caller, so it is added using `Characteristic.ATTACK_POSSIBILITIES.value`
    (a plain str) rather than the enum member itself, to keep every key in
    the returned dict the same type.
    """
    scores: dict[str, float | None] = {}

    for characteristic, observations in observations_by_characteristic.items():
        scores[characteristic] = _fraction_observed([o.fact_status for o in observations])

    if chain_results:
        scores[Characteristic.ATTACK_POSSIBILITIES.value] = _fraction_observed(
            [r.fact_status for r in chain_results]
        )

    return scores
