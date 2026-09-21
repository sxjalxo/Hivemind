from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from app.db.models import FactStatus
from app.services.compaction import CompactedCommand
from app.services.mitre.rules import RuleHit, apply_rules

_CHAINS_PATH = Path(__file__).resolve().parent / "chains.yaml"


class Chain(BaseModel):
    id: str
    # No default, deliberately. A new chain must state whether its steps have
    # real side effects; defaulting to False would let one be added that
    # quietly executes against a real host, and defaulting to True would let
    # one be added that is needlessly refused. Neither is a decision this
    # file should make on an author's behalf -- see chains.yaml.
    destructive: bool
    steps: list[str]
    expected_technique_ids: list[str]


class ChainStepResult(BaseModel):
    chain_id: str
    step_index: int
    command: str
    cowrie_event_id: str | None
    matched_rule_id: str | None
    expected_technique_id: str
    fact_status: str


@lru_cache
def _raw() -> dict:
    return yaml.safe_load(_CHAINS_PATH.read_text(encoding="utf-8"))


@lru_cache
def load_chains() -> tuple[Chain, ...]:
    return tuple(Chain(**entry) for entry in _raw()["chains"])


CHAIN_SET_VERSION: str = str(_raw()["version"])


def verify_chain(chain: Chain, executed: list[CompactedCommand]) -> list[ChainStepResult]:
    """Check the honeypot actually produced the chain's expected techniques.

    The same deterministic classifier that interprets real attacker activity
    is used here, so a chain result is never a bare "T1105 = pass": each
    expected technique keeps the command, the Cowrie event id and the rule
    that matched, and the event id resolves through GET /api/events/{id}.

    A single technique can be hit by several executed commands (e.g. the
    miner chain's T1496 pattern has no {CMD_START} anchor, so "xmrig"
    matches the wget, the chmod and the exec alike). Exactly one hit is
    cited as evidence -- never more, since the deterministic score is
    observed-over-expected across `ChainStepResult` rows and duplicating
    rows would inflate it. The hit chosen is the one whose command appears
    LATEST in the chain's own declared `steps` list: the most advanced step
    exhibiting a technique is the one that best justifies it (for the miner
    chain, `./xmrig` rather than the `wget` that only downloaded it). This
    ranks by position in `chain.steps`, not by the order commands happen to
    arrive in `executed`, so the choice is stable under reordering, retries
    or duplicated events. A hit whose command does not appear in
    `chain.steps` at all ranks below every hit that does, and among such
    unmatched hits the first one encountered wins.
    """
    hits, _ = apply_rules(executed)

    def step_rank(hit: RuleHit) -> int:
        try:
            return chain.steps.index(hit.command)
        except ValueError:
            return -1

    by_technique: dict[str, RuleHit] = {}
    for hit in hits:
        current = by_technique.get(hit.rule.id)
        if current is None or step_rank(hit) > step_rank(current):
            by_technique[hit.rule.id] = hit

    results: list[ChainStepResult] = []
    for index, technique_id in enumerate(chain.expected_technique_ids):
        hit = by_technique.get(technique_id)
        results.append(
            ChainStepResult(
                chain_id=chain.id,
                step_index=index,
                command=hit.command if hit else "",
                cowrie_event_id=hit.event_id if hit else None,
                matched_rule_id=hit.rule.id if hit else None,
                expected_technique_id=technique_id,
                # not_observed, never unknown: the commands WERE executed and
                # the rules WERE applied, so the absence is a real finding.
                fact_status=FactStatus.OBSERVED if hit else FactStatus.NOT_OBSERVED,
            )
        )
    return results
