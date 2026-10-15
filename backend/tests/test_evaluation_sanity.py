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


# ---------------------------------------------------------------------------
# Comparing CLAIMS rather than raw output.
#
# `uname -a` prints a kernel string and `cat /etc/os-release` prints key=value
# lines. Compared raw they can never be equal, so a honeypot where both
# correctly describe the same Debian was reported as contradicting itself --
# and an operator who populated an empty /etc/os-release was handed a new
# defect for fixing a real one. These pin the fix in both directions.

UNAME_DEBIAN = "Linux med-ws-04 6.1.0-21-amd64 #1 SMP Debian 6.1.90-1 x86_64 GNU/Linux"
OS_RELEASE_DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian'
OS_RELEASE_UBUNTU = 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nID=ubuntu'


def test_two_correct_probes_in_different_formats_do_not_contradict() -> None:
    # The regression. Both describe Debian; the raw strings share almost
    # nothing. If this fails, improving a honeypot lowers its report.
    assert (
        find_contradictions(
            [
                _obs("uname", "os.identity", UNAME_DEBIAN),
                _obs("os_release", "os.identity", OS_RELEASE_DEBIAN),
            ]
        )
        == []
    )


def test_a_genuine_os_disagreement_is_still_caught() -> None:
    # The other half: the fix must not buy its silence by comparing nothing.
    found = find_contradictions(
        [
            _obs("uname", "os.identity", UNAME_DEBIAN),
            _obs("os_release", "os.identity", OS_RELEASE_UBUNTU),
        ]
    )
    assert len(found) == 1
    assert set(found[0].probe_ids) == {"uname", "os_release"}
    # The finding still quotes what the honeypot actually printed, not the
    # extracted tokens -- that is what a developer needs in order to fix it.
    assert found[0].values[0] == UNAME_DEBIAN


def test_an_unreadable_claim_is_dropped_rather_than_compared() -> None:
    # A kernel string naming no distribution: the extract does not match, so
    # the claim could not be read. That is not evidence the two agree, and it
    # is not evidence they disagree either.
    assert (
        find_contradictions(
            [
                _obs("uname", "os.identity", "Linux svr04 5.15.0-91-generic x86_64"),
                _obs("os_release", "os.identity", OS_RELEASE_DEBIAN),
            ]
        )
        == []
    )


def test_a_fact_whose_probes_declare_no_extract_still_compares_raw() -> None:
    # Without extracts, two probes are compared on their raw output. (Since
    # probe set v3 host.name's probes DO declare one, to read /etc/hosts too;
    # see the hosts_file tests below.)
    assert len(find_contradictions(_hostnames("med-ws-04", "svr04"))) == 1
    assert find_contradictions(_hostnames("med-ws-04", "med-ws-04")) == []


def _hostnames(from_cmd: str, from_file: str) -> list[Observation]:
    return [
        _obs("hostname_cmd", "host.name", from_cmd),
        _obs("hostname_file", "host.name", from_file),
    ]


def test_the_shipped_probe_set_agrees_on_every_fact_it_establishes() -> None:
    # The load-time guard, run against the real probes.yaml. A pair that
    # half-declares an extract compares an extracted token against a raw
    # dump, which reports a contradiction on every run and blames the
    # honeypot for our own inconsistency.
    from app.services.evaluation.probes import load_probes

    forms: dict[str, set[bool]] = {}
    for probe in load_probes():
        if probe.establishes:
            forms.setdefault(probe.establishes, set()).add(probe.extract is not None)
    assert all(len(declared) == 1 for declared in forms.values()), forms


def _stock_hostnames(hosts_file: str) -> list[Observation]:
    return [
        _obs("hostname_cmd", "host.name", "med-ws-04"),
        _obs("hostname_file", "host.name", "med-ws-04"),
        _obs("hosts_file", "host.name", hosts_file),
    ]


STOCK_HOSTS = (
    "127.0.0.1\tlocalhost\n127.0.1.1\tnas3\n\n"
    "# The following lines are desirable for IPv6 capable hosts\n"
    "::1     localhost ip6-localhost ip6-loopback\n"
)


def test_a_hosts_file_naming_another_machine_is_a_contradiction() -> None:
    """Stock Cowrie's /etc/hosts says `nas3` whatever the decoy is called --
    seen in a terminal replay on 2026-10-14, invisible to probe set v2."""
    from app.services.evaluation.sanity import probe_extracts

    found = find_contradictions(_stock_hostnames(STOCK_HOSTS), probe_extracts())
    assert {c.probe_ids for c in found} == {
        ("hostname_cmd", "hosts_file"),
        ("hostname_file", "hosts_file"),
    }
    assert all(any("nas3" in value for value in c.values) for c in found)


def test_a_consistent_hosts_file_or_one_without_a_127_0_1_1_line_is_not() -> None:
    from app.services.evaluation.sanity import probe_extracts

    agreeing = STOCK_HOSTS.replace("nas3", "med-ws-04")
    assert find_contradictions(_stock_hostnames(agreeing), probe_extracts()) == []
    # No 127.0.1.1 line: the file makes no claim about the name, and an
    # unreadable claim is never counted as agreement OR disagreement.
    nameless = "127.0.0.1 localhost\n::1 localhost\n"
    assert find_contradictions(_stock_hostnames(nameless), probe_extracts()) == []
