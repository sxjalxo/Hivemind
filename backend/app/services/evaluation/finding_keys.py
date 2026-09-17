"""Stable identity for a finding, across runs.

A finding row answers "what is wrong". Its key answers "is this the SAME
thing that was wrong last time" -- and without that second answer the
evaluation is stateless, which is the limitation the source paper records
about its own work.

Why not hash the finding text. The evaluator writes prose, and prose varies
run to run while describing an unchanged flaw. A text hash would therefore
report every evaluator finding as new, every time, and the lifecycle would be
noise. Keys are structured instead, derived from what the finding is ABOUT:

    probe:{probe_id}:{establishes}        a probe fact that was not observed
    chain:{chain_id}:{technique_id}       a chain step whose technique was absent
    service:{fact}                        an expected service the scan did not find
    sanity:{fact}:{probe_a}+{probe_b}     two probes contradicting each other
    evaluator:{characteristic}            the evaluator's critique of one characteristic
    legacy:{row id}                       written before keys existed; never matched

Every component comes from `probes.yaml`, `chains.yaml`, nmap's expected
service list or the `Characteristic` enum. None of it is attacker-controlled
and none of it is free text, so keys need no escaping and cannot grow
unbounded -- which is deliberate. A key built from honeypot output would be
attacker-influenced identity, and an attacker able to choose whether this
run's finding matches last run's could hide a regression.

`evaluator:` is a SLOT, not a flaw. There is exactly one evaluator verdict per
characteristic per run, so the key always matches itself. "Still present"
means the evaluator still had something to say about the file system -- the
critique may describe a completely different problem. Callers must present it
that way; see the lifecycle design note.
"""


def probe_key(probe_id: str, establishes: str) -> str:
    """Identity of one probe failing to establish one fact.

    BOTH halves are in the key, and neither is redundant. `uname` and
    `os_release` both establish `os.identity`, so keying on the fact alone
    would merge two different defects and fixing one would report the other
    fixed. Keying on the probe alone would merge a probe that establishes two
    facts.
    """
    return f"probe:{probe_id}:{establishes}"


def chain_key(chain_id: str, technique_id: str) -> str:
    """Identity of one expected technique missing from one chain.

    Scoped to the chain, not global to the technique: `dropper` and `miner`
    both expect T1105, and the downloader failing inside one is not the same
    fact as it failing inside the other. A shared key would let a fix in one
    chain mask a live defect in the other.
    """
    return f"chain:{chain_id}:{technique_id}"


def service_key(fact: str) -> str:
    """Identity of an expected service the scan did not find."""
    return f"service:{fact}"


def sanity_key(fact: str, probe_ids: tuple[str, ...] | list[str]) -> str:
    """Identity of a contradiction between two probes about one fact.

    The probe ids are SORTED. `find_contradictions` reports a pair, and
    nothing guarantees it reports them in the same order twice -- it depends
    on observation order, which depends on which probe finished first. An
    unsorted key would fork one defect into two identities that alternate run
    to run, reporting a permanent contradiction as endlessly fixed and new.
    """
    return f"sanity:{fact}:{'+'.join(sorted(probe_ids))}"


def evaluator_key(characteristic: str) -> str:
    """Identity of the evaluator's slot for one characteristic.

    A slot, not a flaw -- see the module docstring.
    """
    return f"evaluator:{characteristic}"
