import re
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from app.services.compaction import CompactedCommand

_RULEBOOK_PATH = Path(__file__).parent / "rulebook.yaml"

# Shared "command position" fragment substituted into every rulebook pattern
# that contains the literal placeholder "{CMD_START}". Defining it once here
# (rather than hand-copying it into each pattern in rulebook.yaml) means the
# ten anchored rules cannot drift apart from each other.
#
# Matches: start of the command line, or immediately after a chain/pipe
# operator (;, &, &&, |, ||) or a command-substitution opener ($( or a
# backtick) -- optionally followed by zero or more wrapper binaries that
# EXECUTE their argument rather than merely printing or searching it:
# sudo, nohup, env FOO=1, timeout N, command, exec, stdbuf, setsid, and
# bash -c "..." / sh -c "...". A trigger word after one of these wrappers is
# still a real invocation ("sudo wget ..." really does transfer a tool);
# a trigger word after echo/grep is not (see _filter_data_segments below).
_CMD_START = (
    r"(?:^\s*|[;&|]+\s*|\$\(\s*|`\s*)"
    r"(?:"
    r"(?:sudo|command|exec|stdbuf|setsid|nohup)\b(?:\s+-\S+)*\s+"
    r"|env\b(?:\s+\w+=\S+)*\s+"
    r"|timeout\b\s+\S+\s+"
    r"|(?:bash|sh)\s+-c\s+['\"]?"
    r")*"
)

# Command heads whose argument is DATA -- text emitted or searched for --
# never a resource being acted on or a tool being invoked. A trigger token
# appearing only inside one of these commands' arguments must not earn any
# rule a hit, including the permissive path/identifier rules (T1003.008,
# T1082's path alternatives, T1496) that have no verb to command-position
# anchor. echo/printf only print; grep/egrep/fgrep only search -- neither
# executes, writes, or transfers anything.
_DATA_PRODUCING_HEAD = re.compile(r"^\s*(?:echo|printf|grep|egrep|fgrep)\b", re.IGNORECASE)

# Split on chain/pipe operators and newlines, keeping the delimiter so each
# segment's neighbours can be told apart. A run of one or more of ; & | is
# one delimiter (so && / || split as a single unit); a literal newline is
# normalized to the same footing as a semicolon.
_CHAIN_SPLIT = re.compile(r"([;&|]+|\n)")

# T1098.004 is matched against the *raw*, unfiltered command text rather
# than the data-segment-filtered text every other rule uses. Its own
# pattern already requires literal write syntax (a redirect or `tee`) that
# an echoed reference alone can never satisfy, and filtering out an echo
# segment would destroy the redirect target that IS the evidence for
# `echo "..." >> .ssh/authorized_keys` -- the seed corpus's own real
# example of this technique.
_RAW_TEXT_RULE_IDS = frozenset({"T1098.004"})


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
    rules = []
    for entry in raw["rules"]:
        pattern = entry["pattern"].replace("{CMD_START}", _CMD_START)
        rules.append(
            Rule(id=entry["id"], name=entry["name"], tactic=entry["tactic"], pattern=pattern)
        )
    return rules


@lru_cache
def _compiled() -> list[tuple[Rule, re.Pattern[str]]]:
    return [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in load_rules()]


def _filtered_command_text(command_text: str) -> str:
    """Reduce a command line to only the segments that could plausibly
    execute or act on something, normalizing newlines to ';' along the way.

    Splits on chain/pipe operators and newlines, then drops any segment
    whose head verb only emits (echo/printf) or searches (grep family)
    text. This stops a trigger token that is merely quoted, echoed, or
    grepped for from being mistaken for the token being actually invoked
    or referenced as a real target -- the same reference-vs-execution
    distinction command-position anchoring enforces for verb rules,
    extended here to the permissive path/identifier rules that have no
    verb to anchor.

    Newlines are normalized to ';' rather than handled with re.MULTILINE
    so that a multi-line compacted command (e.g. "id\\nwget http://x")
    still lets a real command on a later line be found in command
    position by the ordinary chain-operator anchor, without needing every
    pattern to special-case line boundaries.
    """
    parts = _CHAIN_SPLIT.split(command_text)
    kept: list[str] = []
    for index, part in enumerate(parts):
        if index % 2 == 1:
            # A delimiter: ; & | (in any combination) or a newline. All are
            # normalized to ';', which every anchored pattern already
            # recognizes as a chain operator.
            kept.append(";")
            continue
        if part.strip() and _DATA_PRODUCING_HEAD.match(part):
            continue
        kept.append(part)
    return "".join(kept)


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
        filtered_text = _filtered_command_text(command.command)
        matched = False
        for rule, pattern in _compiled():
            text = command.command if rule.id in _RAW_TEXT_RULE_IDS else filtered_text
            if pattern.search(text):
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
