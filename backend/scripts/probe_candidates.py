"""Which commands real attackers run that no evaluator probe covers yet.

Attackers decide whether a box is a honeypot by running commands against it --
`uname -a`, `cat /proc/cpuinfo`, `free -m`, `nproc`. The probe set should ask
what they ask. This ranks the commands seen in captured sessions and marks
each one covered by an existing probe or not, so the analysis half can feed
the evaluation half.

It REPORTS candidates; it never edits `probes.yaml`. The probe set is part of
`evaluation_config_fingerprint`, so adding a probe makes every later run
incomparable with every earlier one. That has to be a decision someone makes
on purpose, with this table in front of them -- not a side effect.

    python -m scripts.probe_candidates                  # real attackers only
    python -m scripts.probe_candidates --include-seeded --include-private

Counted by default: public source addresses, not the seed corpus, not the
evaluation agent. Each exclusion exists because without it the report would
measure ourselves: the agent's sessions run exactly the probe commands, the
seed corpus is hand-written, and local test traffic comes from private
addresses (the Docker gateway).
"""

import argparse
import asyncio
import ipaddress
from collections import defaultdict
from dataclasses import dataclass

from app.config import get_settings
from app.es.client import get_es
from app.services.evaluation.probes import Probe, load_probes
from app.services.mitre.rules import _split_command_segments
from app.services.profiles import normalize_command

_COMMAND_ACTION = "cowrie.command.input"


@dataclass(frozen=True)
class Candidate:
    command: str  # normalised segment: the grouping key
    example: str  # one segment as an attacker typed it. Normalising lowercases,
    # and `chmod -R` is not `chmod -r`, so the key is never what gets displayed.
    sessions: int
    source_ips: int
    covered_by: str | None  # probe id, or None when no probe asks this


def segments(command: str) -> list[tuple[str, str]]:
    """(normalised, as typed) for each command in one line: `a; b | c` is three."""
    return [(n, s.strip()) for s in _split_command_segments(command) if (n := normalize_command(s))]


def rank(rows: list[tuple[str, str, str]], probes: tuple[Probe, ...]) -> list[Candidate]:
    """Rank normalised command segments by how many sessions ran them. Pure.

    `rows` are (session_id, source_ip, command_line). Counted per DISTINCT
    session, so one bot looping a command a hundred times counts once.
    """
    by_probe = {normalize_command(p.command): p.id for p in probes}
    sessions: dict[str, set[str]] = defaultdict(set)
    ips: dict[str, set[str]] = defaultdict(set)
    examples: dict[str, str] = {}
    for session_id, ip, command in rows:
        for segment, typed in segments(command):
            sessions[segment].add(session_id)
            ips[segment].add(ip)
            examples.setdefault(segment, typed)
    ranked = [
        Candidate(
            segment,
            examples[segment],
            len(sessions[segment]),
            len(ips[segment]),
            by_probe.get(segment),
        )
        for segment in sessions
    ]
    ranked.sort(key=lambda c: (-c.sessions, -c.source_ips, c.command))
    return ranked


def _counts(ip: str, include_private: bool) -> bool:
    if include_private:
        return True
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def _agent_sessions(index: str) -> list[str]:
    """Sessions the evaluation agent opened, identified by the password it uses."""
    settings = get_settings()
    passwords = {settings.evaluation_ssh_password} | {
        t.ssh_password for t in settings.evaluation_targets.values()
    }
    found: list[str] = []
    after = None
    while True:
        composite: dict = {"size": 1000, "sources": [{"s": {"terms": {"field": "session.id"}}}]}
        if after:
            composite["after"] = after
        result = await get_es().search(
            index=index,
            size=0,
            query={"terms": {"credential.password": sorted(passwords)}},
            aggs={"sessions": {"composite": composite}},
        )
        agg = result["aggregations"]["sessions"]
        found += [b["key"]["s"] for b in agg["buckets"]]
        after = agg.get("after_key")
        if not after:
            return found


async def collect(include_seeded: bool) -> tuple[list[tuple[str, str, str]], int, int]:
    """(rows, agent sessions excluded, command events too long to examine)."""
    index = get_settings().es_index
    agent = await _agent_sessions(index)
    must_not: list[dict] = []
    if agent:
        must_not.append({"terms": {"session.id": agent}})
    if not include_seeded:
        must_not.append({"term": {"labels.seeded": True}})
    query = {
        "bool": {"filter": [{"term": {"event.action": _COMMAND_ACTION}}], "must_not": must_not}
    }

    rows: list[tuple[str, str, str]] = []
    examined = 0
    after = None
    while True:
        composite: dict = {
            "size": 1000,
            "sources": [
                {"s": {"terms": {"field": "session.id"}}},
                {"ip": {"terms": {"field": "source.ip"}}},
                {"c": {"terms": {"field": "process.command_line.keyword"}}},
            ],
        }
        if after:
            composite["after"] = after
        result = await get_es().search(
            index=index, size=0, query=query, aggs={"rows": {"composite": composite}}
        )
        agg = result["aggregations"]["rows"]
        for bucket in agg["buckets"]:
            rows.append((bucket["key"]["s"], bucket["key"]["ip"], bucket["key"]["c"]))
            examined += bucket["doc_count"]
        after = agg.get("after_key")
        if not after:
            break

    # The keyword sub-field has `ignore_above: 1024`, so a longer command line
    # has no keyword and never reaches a composite bucket. Counted, not hidden.
    total = (await get_es().count(index=index, query=query))["count"]
    return rows, len(agent), total - examined


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--include-seeded", action="store_true", help="count the seed corpus")
    parser.add_argument(
        "--include-private", action="store_true", help="count private/loopback sources"
    )
    parser.add_argument("--top", type=int, default=30)
    args = parser.parse_args()

    rows, agent_excluded, too_long = await collect(args.include_seeded)
    rows = [r for r in rows if _counts(r[1], args.include_private)]
    ranked = rank(rows, load_probes())
    await get_es().close()

    print(
        f"{len({r[0] for r in rows})} sessions counted; excluded: {agent_excluded} evaluation-agent "
        f"sessions{'' if args.include_seeded else ', the seed corpus'}"
        f"{'' if args.include_private else ', private/loopback sources'}"
    )
    if too_long:
        print(f"{too_long} command events longer than 1024 chars were not examined")
    if not ranked:
        print(
            "\nNo commands to rank. On a stack without real attacker traffic that is the honest answer."
        )
        return
    print(f"\n{'sessions':>8} {'IPs':>5}  {'covered by':<14} command")
    for c in ranked[: args.top]:
        print(
            f"{c.sessions:>8} {c.source_ips:>5}  {c.covered_by or '-- candidate':<14} {c.example}"
        )


if __name__ == "__main__":
    asyncio.run(_main())
