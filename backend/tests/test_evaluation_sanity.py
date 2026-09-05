from app.services.evaluation.sanity import Observation, find_contradictions


def _obs(probe_id: str, fact: str | None, value: str | None, status: str = "observed"):
    return Observation(probe_id=probe_id, establishes=fact, value=value, fact_status=status)


def test_two_probes_disagreeing_on_one_fact_is_a_contradiction() -> None:
    found = find_contradictions(
        [
            _obs("os_release", "os.identity", "Ubuntu"),
            _obs("uname", "os.identity", "Debian"),
        ]
    )
    assert len(found) == 1
    assert found[0].fact == "os.identity"
    # Both sides are cited: a contradiction finding must point at both.
    assert set(found[0].probe_ids) == {"os_release", "uname"}


def test_probes_establishing_different_facts_never_contradict() -> None:
    # /etc/passwd existing and /etc/shadow existing are independent facts.
    # Without this the detector degenerates into flagging everything.
    assert (
        find_contradictions(
            [
                _obs("passwd_present", "fs.etc_passwd", "present"),
                _obs("shadow_present", "fs.etc_shadow", "present"),
            ]
        )
        == []
    )


def test_agreeing_probes_are_not_a_contradiction() -> None:
    assert (
        find_contradictions(
            [
                _obs("hostname_cmd", "host.name", "med-ws-04"),
                _obs("hostname_file", "host.name", "med-ws-04"),
            ]
        )
        == []
    )


def test_an_unknown_probe_is_not_a_contradiction() -> None:
    # A timed-out probe means "we could not determine", never "it disagrees".
    assert (
        find_contradictions(
            [
                _obs("os_release", "os.identity", "Ubuntu"),
                _obs("uname", "os.identity", None, status="unknown"),
            ]
        )
        == []
    )
