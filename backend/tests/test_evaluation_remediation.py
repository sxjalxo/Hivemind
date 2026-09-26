"""Remediation turns a finding into something applicable, or says it cannot.

The failure this guards is a patch that LOOKS right and does nothing, or one
generated for a finding nobody can mechanically fix. Both are worse than no
patch: an operator who applies them believes the defect is addressed. So the
tests below check two things in equal measure -- that a real fix is produced
and is correct in its details, and that a refusal stays a refusal.
"""

import pytest

from app.models.evaluation import EvaluationRunOut, FindingOut, ProbeResultOut
from app.services.evaluation import remediation

UNAME_DEBIAN = "Linux med-ws-04 6.1.0-21-amd64 #1 SMP Debian 6.1.90-1 x86_64 GNU/Linux"
UNAME_UBUNTU = "Linux web-07 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"


def _probe(probe_id: str, establishes: str, value: str | None, status: str = "observed"):
    return ProbeResultOut(
        id=probe_id,
        module="agent",
        probe_id=probe_id,
        target="honeypot",
        establishes=establishes,
        value=value,
        fact_status=status,
    )


def _finding(key: str) -> FindingOut:
    return FindingOut(
        id=key,
        characteristic="sanity",
        severity="medium",
        finding=key,
        source="deterministic",
        finding_key=key,
        evidence=[],
    )


def _run(finding_keys: list[str], probes: list[ProbeResultOut]) -> EvaluationRunOut:
    return EvaluationRunOut(
        id="run",
        honeypot_id="cowrie-01",
        status="completed",
        started_at="2026-09-26T00:00:00Z",
        agent_model="probes",
        evaluator_status="unavailable",
        honeypot_fingerprint="sha256:aa",
        evaluation_config_fingerprint="sha256:bb",
        category_scores=[],
        modules=[],
        findings=[_finding(k) for k in finding_keys],
        chain_steps=[],
        probe_results=probes,
    )


def _only(run: EvaluationRunOut) -> remediation.Remediation:
    items = remediation.remediate(run)
    assert len(items) == 1
    return items[0]


# ---------------------------------------------------------------------------
# Fixes derived from the run's own evidence.


def test_the_hostname_fix_uses_the_value_the_honeypot_itself_reported() -> None:
    # Derived, not templated: the name written into /etc/hostname is the one
    # `hostname` printed, which is what cowrie.cfg configures. Writing any
    # other value would make the two agree on a name nobody chose.
    item = _only(
        _run(
            ["sanity:host.name:hostname_cmd+hostname_file"],
            [
                _probe("hostname_cmd", "host.name", "med-ws-04"),
                _probe("hostname_file", "host.name", "svr04"),
            ],
        )
    )

    assert item.is_actionable
    assert not item.from_template
    assert len(item.honeyfs_files) == 1
    assert item.honeyfs_files[0].path == "etc/hostname"
    assert item.honeyfs_files[0].content == "med-ws-04\n"


def test_the_os_release_fix_matches_the_distribution_uname_reports() -> None:
    # The fix must AGREE with the kernel string. Writing a Debian os-release
    # onto a honeypot whose uname says Ubuntu would close the missing-file
    # finding and open a contradiction finding -- moving a defect, not
    # removing one.
    debian = _only(
        _run(["probe:os_release:os.identity"], [_probe("uname", "os.identity", UNAME_DEBIAN)])
    )
    ubuntu = _only(
        _run(["probe:os_release:os.identity"], [_probe("uname", "os.identity", UNAME_UBUNTU)])
    )

    assert "ID=debian" in debian.honeyfs_files[0].content
    assert "ID=ubuntu" in ubuntu.honeyfs_files[0].content


def test_the_os_release_fix_targets_the_symlink_target_not_the_link() -> None:
    # The whole point, and invisible from the outside. /etc/os-release is a
    # symlink in the image and Cowrie attaches honeyfs content only to real
    # files, skipping links in silence. A patch written to etc/os-release
    # applies cleanly and changes nothing.
    item = _only(
        _run(["probe:os_release:os.identity"], [_probe("uname", "os.identity", UNAME_DEBIAN)])
    )

    assert item.honeyfs_files[0].path == "usr/lib/os-release"


def test_a_contradiction_about_the_os_is_fixed_the_same_way() -> None:
    # Two different finding keys, one underlying defect: the file disagrees
    # with the kernel either by being empty or by naming something else.
    item = _only(
        _run(
            ["sanity:os.identity:os_release+uname"],
            [
                _probe("uname", "os.identity", UNAME_DEBIAN),
                _probe("os_release", "os.identity", 'ID=ubuntu\nNAME="Ubuntu"'),
            ],
        )
    )

    assert item.is_actionable
    assert item.honeyfs_files[0].path == "usr/lib/os-release"
    assert "ID=debian" in item.honeyfs_files[0].content


def test_a_templated_fix_says_it_is_templated() -> None:
    # Nobody can derive the accounts an emptied /etc/passwd is meant to hold
    # from the fact that it is empty. The body is a starting point and the
    # flag is what tells an operator to read it before applying it.
    item = _only(_run(["probe:passwd_present:fs.etc_passwd"], []))

    assert item.is_actionable
    assert item.from_template
    assert item.honeyfs_files[0].path == "etc/passwd"
    assert "root:x:0:0:" in item.honeyfs_files[0].content


# ---------------------------------------------------------------------------
# Refusals. Each of these is a finding a patch generator would be tempted to
# guess at.


@pytest.mark.parametrize(
    "key",
    [
        # Cowrie has no HTTP listener, so no cowrie.cfg edit produces one.
        # Reported by every arm of the matrix including the best one.
        "service:service.http",
        # A technique missing from a chain has several possible causes that
        # need different fixes.
        "chain:dropper:T1105",
        # The evaluator writes prose judgement, deliberately not reduced to a
        # mechanical change.
        "evaluator:file_system",
        # Rows written before structured keys existed.
        "legacy:2b1c",
    ],
)
def test_a_finding_with_no_mechanical_fix_is_refused_with_a_reason(key: str) -> None:
    item = _only(_run([key], []))

    assert not item.is_actionable
    assert item.unsupported_reason


def test_a_refusal_never_also_ships_a_patch() -> None:
    # The invariant behind every refusal above. A remediation that explained
    # why it could not help AND carried files would tell an operator two
    # different things, and the one they act on is the files.
    keys = [
        "service:service.http",
        "chain:dropper:T1105",
        "evaluator:file_system",
        "legacy:2b1c",
        "probe:tmp_writable:fs.tmp_writable",
        "sanity:kernel.version:a+b",
    ]
    for item in remediation.remediate(_run(keys, [])):
        if not item.is_actionable:
            assert not item.honeyfs_files, item.finding_key
            assert not item.config_settings, item.finding_key


def test_an_os_release_fix_is_refused_when_the_kernel_names_no_distribution() -> None:
    # Guessing here would replace a missing-file finding with a contradiction
    # finding. A fix we cannot verify agrees is not offered at all.
    item = _only(
        _run(
            ["probe:os_release:os.identity"],
            [_probe("uname", "os.identity", "Linux box 5.15.0-91-generic x86_64")],
        )
    )

    assert not item.is_actionable
    assert not item.honeyfs_files
    assert "recognisable" in item.unsupported_reason


def test_the_hostname_fix_is_refused_when_the_command_was_not_observed() -> None:
    # An unobserved fact is not an authoritative value to copy. Same rule as
    # `unknown` in scoring, one layer out.
    item = _only(
        _run(
            ["sanity:host.name:hostname_cmd+hostname_file"],
            [_probe("hostname_cmd", "host.name", None, status="unknown")],
        )
    )

    assert not item.is_actionable
    assert not item.honeyfs_files


# ---------------------------------------------------------------------------


def test_every_finding_gets_an_entry_including_the_unfixable_ones() -> None:
    # A caller who applied the whole response must not be able to believe
    # they addressed the whole run when part of it had no fix.
    keys = [
        "probe:os_release:os.identity",
        "sanity:host.name:hostname_cmd+hostname_file",
        "service:service.http",
    ]
    items = remediation.remediate(
        _run(
            keys,
            [
                _probe("uname", "os.identity", UNAME_DEBIAN),
                _probe("hostname_cmd", "host.name", "med-ws-04"),
            ],
        )
    )

    assert [i.finding_key for i in items] == keys
    assert sum(i.is_actionable for i in items) == 2


def test_a_clean_run_produces_nothing() -> None:
    assert remediation.remediate(_run([], [])) == []


def test_generated_paths_are_relative_and_stay_inside_the_honeyfs_root() -> None:
    # These paths are joined onto a directory an operator names. An absolute
    # path or a parent traversal would write outside it.
    keys = [
        "probe:os_release:os.identity",
        "probe:passwd_present:fs.etc_passwd",
        "probe:proc_cpuinfo:fs.proc_cpuinfo",
        "sanity:host.name:hostname_cmd+hostname_file",
    ]
    items = remediation.remediate(
        _run(
            keys,
            [
                _probe("uname", "os.identity", UNAME_DEBIAN),
                _probe("hostname_cmd", "host.name", "med-ws-04"),
            ],
        )
    )

    paths = [f.path for item in items for f in item.honeyfs_files]
    assert paths
    for path in paths:
        assert not path.startswith("/")
        assert ".." not in path.split("/")
