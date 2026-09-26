import re
from collections.abc import Mapping
from functools import lru_cache
from itertools import combinations

from pydantic import BaseModel

from app.db.models import FactStatus
from app.services.evaluation.probes import load_probes

_WHITESPACE = re.compile(r"\s+")


@lru_cache
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def probe_extracts() -> dict[str, str]:
    """probe id -> its declared extract pattern, for probes that declare one."""
    return {p.id: p.extract for p in load_probes() if p.extract}


def comparable_value(
    observation: "Observation", extracts: Mapping[str, str]
) -> str | None:
    """What this observation actually CLAIMS about its fact, or None.

    A probe with no declared extract claims its raw output, which is the
    right answer when every probe for the fact prints the same form -- both
    hostname probes print a bare hostname and nothing else.

    A probe WITH an extract claims only the captured group, normalised. When
    the pattern does not match, this returns None and the caller drops the
    observation: we could not read the claim, which is not the same as the
    claim agreeing with its partner.
    """
    if observation.value is None:
        return None
    pattern = extracts.get(observation.probe_id)
    if pattern is None:
        return observation.value
    match = _compiled(pattern).search(observation.value)
    if match is None:
        return None
    return _WHITESPACE.sub(" ", match.group(1)).strip().lower()


class Observation(BaseModel):
    probe_id: str
    establishes: str | None
    value: str | None
    fact_status: str


class Contradiction(BaseModel):
    fact: str
    probe_ids: tuple[str, str]
    values: tuple[str, str]


def find_contradictions(
    observations: list[Observation], extracts: Mapping[str, str] | None = None
) -> list[Contradiction]:
    """Two COMPLETED probes establishing the same canonical fact, disagreeing.

    Deliberately narrow. Inferring conflict from raw output would flag every
    pair of unrelated facts; requiring a declared `establishes` keeps the
    detector to claims the probe set actually makes. An `unknown` probe is
    excluded entirely -- not determining a fact is not disagreeing about it.

    Probes are compared on what they CLAIM, not on what they printed. Two
    probes may establish one fact in two different forms -- `uname -a` and
    `cat /etc/os-release` both name the distribution, and their raw outputs
    can never be equal even when both are correct -- so each observation is
    reduced through its probe's declared `extract` first. Raw output remains
    the comparison wherever no extract is declared, which is every fact whose
    probes already print the same form.

    An observation whose declared extract does not match is dropped rather
    than compared, so a claim we could not read never reads as agreement.

    `extracts` defaults to the loaded probe set, which is the same cached
    read `run_probes` executed, so the patterns applied here are the ones the
    run actually used. It is a parameter so a caller can compare a set of
    observations against an explicit form map.
    """
    if extracts is None:
        extracts = probe_extracts()

    usable = [
        (o, comparable_value(o, extracts))
        for o in observations
        if o.establishes and o.value is not None and o.fact_status == FactStatus.OBSERVED
    ]
    usable = [(o, claim) for o, claim in usable if claim is not None]

    contradictions: list[Contradiction] = []
    for (left, left_claim), (right, right_claim) in combinations(usable, 2):
        if left.establishes != right.establishes:
            continue
        if left_claim == right_claim:
            continue
        contradictions.append(
            Contradiction(
                fact=left.establishes,
                probe_ids=(left.probe_id, right.probe_id),
                # The RAW values, deliberately. The comparison ran on the
                # extracted claims, but a developer reading the finding needs
                # to see what the honeypot actually printed to go and fix it.
                values=(left.value, right.value),
            )
        )
    return contradictions
