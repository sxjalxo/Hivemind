from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from app.db.models import FactStatus
from app.services.compaction import CompactedCommand
from app.services.mitre.rules import apply_rules

_CHAINS_PATH = Path(__file__).resolve().parent / "chains.yaml"


class Chain(BaseModel):
    id: str
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
    """
    hits, _ = apply_rules(executed)
    by_technique = {hit.rule.id: hit for hit in hits}

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
