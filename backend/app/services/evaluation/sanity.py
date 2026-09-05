from itertools import combinations

from pydantic import BaseModel

from app.db.models import FactStatus


class Observation(BaseModel):
    probe_id: str
    establishes: str | None
    value: str | None
    fact_status: str


class Contradiction(BaseModel):
    fact: str
    probe_ids: tuple[str, str]
    values: tuple[str, str]


def find_contradictions(observations: list[Observation]) -> list[Contradiction]:
    """Two COMPLETED probes establishing the same canonical fact, disagreeing.

    Deliberately narrow. Inferring conflict from raw output would flag every
    pair of unrelated facts; requiring a declared `establishes` keeps the
    detector to claims the probe set actually makes. An `unknown` probe is
    excluded entirely -- not determining a fact is not disagreeing about it.
    """
    usable = [
        o
        for o in observations
        if o.establishes and o.value is not None and o.fact_status == FactStatus.OBSERVED
    ]

    contradictions: list[Contradiction] = []
    for left, right in combinations(usable, 2):
        if left.establishes != right.establishes:
            continue
        if left.value == right.value:
            continue
        contradictions.append(
            Contradiction(
                fact=left.establishes,
                probe_ids=(left.probe_id, right.probe_id),
                values=(left.value, right.value),
            )
        )
    return contradictions
