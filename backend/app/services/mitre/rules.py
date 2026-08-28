import re
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from app.services.compaction import CompactedCommand

_RULEBOOK_PATH = Path(__file__).parent / "rulebook.yaml"


class Rule(BaseModel):
    id: str
    name: str
    tactic: str
    pattern: str


class RuleHit(BaseModel):
    rule: Rule
    command: str
    event_id: str
    timestamp: str


@lru_cache
def load_rules() -> list[Rule]:
    raw = yaml.safe_load(_RULEBOOK_PATH.read_text(encoding="utf-8"))
    return [Rule.model_validate(r) for r in raw["rules"]]


@lru_cache
def _compiled() -> list[tuple[Rule, re.Pattern[str]]]:
    return [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in load_rules()]


def apply_rules(
    commands: list[CompactedCommand],
) -> tuple[list[RuleHit], list[CompactedCommand]]:
    """Match commands against the rulebook.

    Returns (hits, unmatched). A command may hit several rules — an attacker
    chaining `cd /tmp && wget ...` legitimately exhibits more than one
    technique. Unmatched commands go to the LLM in Task 12.
    """
    hits: list[RuleHit] = []
    unmatched: list[CompactedCommand] = []

    for command in commands:
        matched = False
        for rule, pattern in _compiled():
            if pattern.search(command.command):
                hits.append(
                    RuleHit(
                        rule=rule,
                        command=command.command,
                        event_id=command.event_id,
                        timestamp=command.timestamp,
                    )
                )
                matched = True
        if not matched:
            unmatched.append(command)

    return hits, unmatched
