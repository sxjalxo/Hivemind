import pytest

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


_ARCH_PATTERN = r"\b(x86_64|aarch64|genuineintel)\b"
_ARCH_EXTRACTS = {"m": _ARCH_PATTERN, "cpu": _ARCH_PATTERN}
_ARCH_ALIASES = {"m": {"genuineintel": "x86_64"}, "cpu": {"genuineintel": "x86_64"}}


def test_aliases_reduce_two_different_words_to_one_claim() -> None:
    from app.services.evaluation.sanity import comparable_value

    cpu = _obs("cpu", "host.arch", "vendor_id\t: GenuineIntel")
    assert comparable_value(cpu, _ARCH_EXTRACTS, _ARCH_ALIASES) == "x86_64"
    agreeing = [_obs("m", "host.arch", "x86_64"), cpu]
    assert find_contradictions(agreeing, _ARCH_EXTRACTS, _ARCH_ALIASES) == []


def test_a_token_with_no_alias_compares_as_itself() -> None:
    from app.services.evaluation.sanity import comparable_value

    arm = _obs("m", "host.arch", "aarch64")
    assert comparable_value(arm, _ARCH_EXTRACTS, _ARCH_ALIASES) == "aarch64"
    disagreeing = [arm, _obs("cpu", "host.arch", "vendor_id\t: GenuineIntel")]
    assert len(find_contradictions(disagreeing, _ARCH_EXTRACTS, _ARCH_ALIASES)) == 1


X86_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\nflags\t\t: fpu vme de pse lm\n"
)
AMD_CPUINFO = (
    "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7502P 32-Core Processor\n"
)
ARM_CPUINFO = (
    "processor\t: 0\nBogoMIPS\t: 108.00\nFeatures\t: fp asimd evtstrm crc32 cpuid\n"
    "CPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xd08\n"
)
X86_LIB = (
    "apt              binfmt.d         dpkg             init\n"
    "os-release       python3          python3.11       x86_64-linux-gnu\n"
)
ARM_LIB = "apt              dpkg             aarch64-linux-gnu  os-release\n"


def _arch(machine: str, cpuinfo: str, lib: str) -> list[Observation]:
    return [
        _obs("uname_m", "host.arch", machine),
        _obs("cpu_arch", "host.arch", cpuinfo),
        _obs("lib_arch", "host.arch", lib),
    ]


@pytest.mark.parametrize(
    ("machine", "cpuinfo", "lib"),
    [
        ("x86_64", X86_CPUINFO, X86_LIB),
        ("x86_64", AMD_CPUINFO, X86_LIB),
        ("aarch64", ARM_CPUINFO, ARM_LIB),
    ],
)
def test_a_consistent_machine_agrees_on_its_architecture(machine, cpuinfo, lib) -> None:
    assert find_contradictions(_arch(machine, cpuinfo, lib)) == []


def test_an_arm_disguise_over_an_x86_file_tree_is_caught() -> None:
    # The rpi persona's expected result: uname and cpuinfo say ARM (the persona
    # wrote both), Cowrie's own file tree still says x86.
    found = find_contradictions(_arch("aarch64", ARM_CPUINFO, X86_LIB))
    assert {c.probe_ids for c in found} == {("uname_m", "lib_arch"), ("cpu_arch", "lib_arch")}
