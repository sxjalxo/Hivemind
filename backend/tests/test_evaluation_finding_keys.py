"""Finding keys are the identity a lifecycle is built on.

Two failure directions, both bad and both silent:

  * a key that MOVES when the defect has not -- every run reports the same
    flaw as new, and "fixed" never happens
  * a key that COLLIDES across different defects -- two unrelated problems
    merge into one history, and fixing one reports the other fixed too

Every test below aims at one of those.
"""

from app.services.evaluation import finding_keys


def test_a_probe_key_is_stable_and_names_both_halves() -> None:
    key = finding_keys.probe_key("os_release", "os.identity")

    assert key == "probe:os_release:os.identity"
    assert key == finding_keys.probe_key("os_release", "os.identity")


def test_two_probes_establishing_one_fact_keep_separate_keys() -> None:
    """`uname` and `os_release` both establish `os.identity`.

    Keying on the fact alone would merge them, so fixing one would report the
    other fixed as well. The probe id is what keeps them apart.
    """
    assert finding_keys.probe_key("uname", "os.identity") != finding_keys.probe_key(
        "os_release", "os.identity"
    )


def test_one_probe_establishing_two_facts_keeps_separate_keys() -> None:
    assert finding_keys.probe_key("uname", "os.identity") != finding_keys.probe_key(
        "uname", "host.name"
    )


def test_a_chain_key_is_stable_and_names_both_halves() -> None:
    assert finding_keys.chain_key("dropper", "T1105") == "chain:dropper:T1105"


def test_the_same_technique_in_two_chains_keeps_separate_keys() -> None:
    """`dropper` and `miner` both expect T1105 and T1222.002.

    They are different defects: the downloader failing inside the miner chain
    is not the same fact as it failing inside the dropper chain, and a shared
    key would let one mask the other.
    """
    assert finding_keys.chain_key("dropper", "T1105") != finding_keys.chain_key(
        "miner", "T1105"
    )


def test_a_service_key_names_the_fact() -> None:
    assert finding_keys.service_key("service.http") == "service:service.http"


def test_a_contradiction_key_does_not_depend_on_probe_order() -> None:
    """The reason the ids are sorted.

    `find_contradictions` reports a pair in whatever order the observations
    arrived, which depends on which probe finished first. An unsorted key
    would fork one permanent contradiction into two identities that alternate
    run to run -- reported as endlessly fixed and new.
    """
    forward = finding_keys.sanity_key("host.name", ["hostname_cmd", "hostname_file"])
    reversed_ = finding_keys.sanity_key("host.name", ["hostname_file", "hostname_cmd"])

    assert forward == reversed_ == "sanity:host.name:hostname_cmd+hostname_file"


def test_an_evaluator_key_is_the_characteristic() -> None:
    assert finding_keys.evaluator_key("file_system") == "evaluator:file_system"


def test_every_kind_of_key_lives_in_its_own_namespace() -> None:
    """Prefixes are what stop one kind of defect being mistaken for another.

    Without them a probe named `file_system` and the evaluator's slot for the
    `file_system` characteristic would share a key, and the lifecycle would
    treat a fixed probe as a fixed critique.
    """
    keys = [
        finding_keys.probe_key("file_system", "fs.etc_passwd"),
        finding_keys.chain_key("file_system", "T1105"),
        finding_keys.service_key("file_system"),
        finding_keys.sanity_key("file_system", ["a", "b"]),
        finding_keys.evaluator_key("file_system"),
    ]

    assert len(set(keys)) == len(keys)
    assert {key.split(":", 1)[0] for key in keys} == {
        "probe",
        "chain",
        "service",
        "sanity",
        "evaluator",
    }
