"""Turning a finding into something a developer can apply.

A finding says what is wrong. Until now nothing said what to do about it: the
`recommendation` column exists and every deterministic finding wrote `None`
into it, so the loop the project draws -- capture, analyse, evaluate, IMPROVE
-- had no last arrow. Closing it is what this module does.

WHY THIS IS A TABLE AND NOT A MODEL CALL

The finding key already encodes what a finding is ABOUT (`probe:os_release:
os.identity`, `sanity:host.name:hostname_cmd+hostname_file`), and the set of
things a Cowrie honeypot can be wrong about in a way a probe detects is
small and enumerable. A lookup is therefore exact where a model would be
plausible, and "plausible" is the failure mode this whole subsystem exists to
refuse. Nothing here generates prose.

DERIVED BEATS TEMPLATED, AND BOTH ARE LABELLED

Where the run's own evidence determines the fix, the fix is computed from it:
the hostname to write into `/etc/hostname` is the hostname the honeypot's own
`hostname` command printed, read out of this run's probe rows. Where it does
not -- nobody can derive the contents of an emptied `/etc/passwd` from the
fact that it is empty -- the fix is a template, and `from_template` says so,
because a template is a starting point an operator must review and a derived
value is not.

WHAT IT REFUSES TO DO

A finding with no mechanical fix gets `unsupported_reason` and NOTHING else.
No half-fix, no cowrie.cfg stanza that looks like it would help, no prose
suggestion dressed as a patch. `service.http` is the standing example: every
arm of the degradation matrix reports it, including the best one, because
nmap expects an HTTP service and Cowrie has no HTTP listener to enable. The
honest answer is that this is not fixable by editing this honeypot's
configuration, and saying so is worth more than a plausible-looking diff that
changes nothing.

That is the same rule as `unknown` in scoring and `undetermined` in the
lifecycle, applied one layer further out: not being able to answer is
reported as not being able to answer.

HOW A FIX IS APPLIED

`honeyfs_files` are paths relative to a honeyfs root that cowrie.cfg points
at with `contents_path`. `infra/cowrie/matrix/*/` are exactly this shape, so
the output of this module drops straight into an arm directory. Two Cowrie
constraints are baked into the paths here and neither is guessable:

  * `/etc/os-release` is a SYMLINK to `usr/lib/os-release` in the image, and
    Cowrie's `init_honeyfs` attaches content only to real files -- a symlink
    is skipped in silence. So the fix writes `usr/lib/os-release`. Writing
    `etc/os-release` would produce a patch that applies cleanly and does
    nothing, which is worse than no patch.
  * An overlay can replace content but cannot remove a node, so there is no
    such thing as a generated fix that deletes a file.
"""

from dataclasses import dataclass, field

from app.db.models import FactStatus
from app.models.evaluation import EvaluationRunOut, FindingOut, ProbeResultOut
from app.services.evaluation.sanity import Observation, comparable_value, probe_extracts


@dataclass(frozen=True)
class HoneyfsFile:
    """One file to place in the honeypot's honeyfs overlay.

    `path` is relative to the honeyfs root and never absolute: it is joined
    onto a directory the operator chooses, and an absolute path would escape
    it.
    """

    path: str
    content: str


@dataclass(frozen=True)
class ConfigSetting:
    """One cowrie.cfg option to set."""

    section: str
    option: str
    value: str


@dataclass(frozen=True)
class Remediation:
    """What to do about one finding, or why nothing can be done about it."""

    finding_key: str
    summary: str
    honeyfs_files: tuple[HoneyfsFile, ...] = ()
    config_settings: tuple[ConfigSetting, ...] = ()
    # Set when there is no mechanical fix. When this is set the two collections
    # above are empty, and that invariant is asserted by the tests: a
    # remediation that both explains why it cannot help AND ships a patch is
    # telling an operator two different things.
    unsupported_reason: str | None = None
    # True when the content is a reviewed starting point rather than a value
    # derived from this run's own evidence. An operator applying a template is
    # making a claim about their honeypot; one applying a derived value is not.
    from_template: bool = False

    @property
    def is_actionable(self) -> bool:
        return self.unsupported_reason is None


# A minimal, coherent Debian bookworm passwd. A template: the run cannot tell
# us what accounts the decoy is supposed to have, only that it currently
# claims none. Kept consistent with the image's own kernel string so applying
# it does not create a fresh contradiction somewhere else.
_PASSWD_TEMPLATE = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
"""

_CPUINFO_TEMPLATE = """\
processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 79
model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
stepping\t: 1
microcode\t: 0xb000040
cpu MHz\t\t: 2399.998
cache size\t: 35840 KB
siblings\t: 1
core id\t\t: 0
cpu cores\t: 1
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat
bogomips\t: 4799.99
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 46 bits physical, 48 bits virtual
"""

# os-release bodies keyed by the distribution token `probes.yaml` extracts, so
# a generated os-release always AGREES with the kernel string the honeypot
# already reports. Generating a Debian os-release for a honeypot whose uname
# says Ubuntu would fix the missing-file finding and create a contradiction
# finding in its place -- a fix that moves a defect rather than removing one.
_OS_RELEASE_BY_DISTRO = {
    "debian": """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
""",
    "ubuntu": """\
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
""",
}

# `/etc/os-release` is a symlink to this in the image; see the module
# docstring for why writing the link path instead produces a no-op patch.
_OS_RELEASE_PATH = "usr/lib/os-release"

# Probes whose fact is a file whose contents the run cannot derive.
_FILE_TEMPLATES = {
    "passwd_present": ("etc/passwd", _PASSWD_TEMPLATE),
    "proc_cpuinfo": ("proc/cpuinfo", _CPUINFO_TEMPLATE),
}


@dataclass
class _RunFacts:
    """The run's own evidence, indexed for the fixes that derive from it."""

    values: dict[str, str] = field(default_factory=dict)

    @classmethod
    def of(cls, probe_results: list[ProbeResultOut]) -> "_RunFacts":
        return cls(
            values={
                row.probe_id: row.value
                for row in probe_results
                if row.value and row.fact_status == FactStatus.OBSERVED
            }
        )

    def distro(self) -> str | None:
        """The distribution the honeypot's own kernel string names, or None.

        Read through the SAME extract `probes.yaml` declares and
        contradiction detection uses, so a generated os-release is checked
        for agreement by exactly the rule that would later flag it. Rolling a
        second parser here would let the two drift and start disagreeing
        about what the honeypot claims.
        """
        raw = self.values.get("uname")
        if raw is None:
            return None
        claim = comparable_value(
            Observation(
                probe_id="uname",
                establishes="os.identity",
                value=raw,
                fact_status=FactStatus.OBSERVED,
            ),
            probe_extracts(),
        )
        return claim


def _os_release_fix(facts: _RunFacts, key: str, why: str) -> Remediation:
    distro = facts.distro()
    if distro is None or distro not in _OS_RELEASE_BY_DISTRO:
        named = distro or "nothing recognisable"
        return Remediation(
            finding_key=key,
            summary="Cannot generate an /etc/os-release that agrees with this honeypot.",
            unsupported_reason=(
                f"the kernel string names {named}, so there is no body to write that is "
                f"certain to agree with it. Writing one anyway would replace a missing-file "
                f"finding with a contradiction finding. Add an entry for that distribution, "
                f"or write the file by hand."
            ),
        )
    return Remediation(
        finding_key=key,
        summary=(
            f"{why} Write an os-release describing {distro}, matching the distribution "
            f"this honeypot's own `uname -a` already reports."
        ),
        honeyfs_files=(
            HoneyfsFile(_OS_RELEASE_PATH, _OS_RELEASE_BY_DISTRO[distro]),
        ),
        # The distro is derived from the run; the body for it is a template.
        from_template=True,
    )


def _hostname_fix(facts: _RunFacts, key: str) -> Remediation:
    """Make /etc/hostname agree with what `hostname` prints.

    The command is treated as authoritative and the file is changed to match,
    never the other way round. `hostname` returns the value from cowrie.cfg,
    which is what the operator deliberately configured this decoy to be
    called; `/etc/hostname` holding something else is the image's default
    showing through. Changing the cfg to match the stale file would make the
    two agree on a name nobody chose.
    """
    configured = facts.values.get("hostname_cmd")
    if not configured:
        return Remediation(
            finding_key=key,
            summary="Cannot reconcile the hostname.",
            unsupported_reason=(
                "this run did not observe what `hostname` prints, so there is no "
                "authoritative value to copy into /etc/hostname."
            ),
        )
    return Remediation(
        finding_key=key,
        summary=(
            f"Write {configured!r} into /etc/hostname so the file agrees with the "
            f"`hostname` command, which reports the name cowrie.cfg configures."
        ),
        honeyfs_files=(HoneyfsFile("etc/hostname", f"{configured}\n"),),
    )


def _unsupported(key: str, summary: str, reason: str) -> Remediation:
    return Remediation(finding_key=key, summary=summary, unsupported_reason=reason)


def _for_finding(finding: FindingOut, facts: _RunFacts) -> Remediation:
    key = finding.finding_key
    kind, _, rest = key.partition(":")

    if kind == "probe":
        probe_id, _, _fact = rest.partition(":")
        if probe_id == "os_release":
            return _os_release_fix(
                facts, key, "The honeypot returns an empty /etc/os-release."
            )
        if probe_id in _FILE_TEMPLATES:
            path, content = _FILE_TEMPLATES[probe_id]
            return Remediation(
                finding_key=key,
                summary=(
                    f"Populate /{path}, which the honeypot currently returns empty. "
                    f"The body below is a starting point to review, not a measured value."
                ),
                honeyfs_files=(HoneyfsFile(path, content),),
                from_template=True,
            )
        return _unsupported(
            key,
            f"No generated fix for probe {probe_id!r}.",
            "this probe's fact has no known honeyfs or cowrie.cfg lever in this image. "
            "Fixing it means changing what the honeypot emulates, not what it serves.",
        )

    if kind == "sanity":
        fact, _, _pair = rest.partition(":")
        if fact == "host.name":
            return _hostname_fix(facts, key)
        if fact == "os.identity":
            return _os_release_fix(
                facts,
                key,
                "The honeypot's /etc/os-release contradicts its own kernel string.",
            )
        return _unsupported(
            key,
            f"No generated fix for a contradiction about {fact!r}.",
            "no lever is known for reconciling these two sources in this image.",
        )

    if kind == "service":
        return _unsupported(
            key,
            f"No generated fix for the missing {rest}.",
            "the expected-service list is part of the evaluation's own configuration, and "
            "Cowrie serves only SSH and Telnet -- there is no HTTP listener to enable in "
            "cowrie.cfg. Either run a decoy that serves it, or reconsider whether the scan "
            "should expect it here. This one is reported by every honeypot in the "
            "degradation matrix, including the best arm, which is the tell that it "
            "describes the question rather than the answer.",
        )

    if kind == "chain":
        chain_id, _, technique = rest.partition(":")
        return _unsupported(
            key,
            f"No generated fix for {technique} missing from the {chain_id} chain.",
            "a technique failing to appear has many possible causes -- an unimplemented "
            "command, a step that errored, ingest lag -- and they need different fixes. "
            "Read the chain step's own evidence.",
        )

    if kind == "evaluator":
        return _unsupported(
            key,
            "The evaluator's critique is prose, not a patch.",
            "this is a model's judgement about one characteristic, deliberately not "
            "reduced to a mechanical change. Read it and decide.",
        )

    return _unsupported(
        key,
        "Unrecognised finding key.",
        f"no remediation rule handles a {kind!r} key. Legacy rows carry a `legacy:` "
        f"prefix and never had structured identity to act on.",
    )


def remediate(run: EvaluationRunOut) -> list[Remediation]:
    """A remediation for every finding in the run, actionable or not.

    Every finding gets an entry, including the ones nothing can be done
    about. Returning only the fixable ones would let an operator who applied
    everything believe they had addressed the whole run.
    """
    facts = _RunFacts.of(run.probe_results)
    return [_for_finding(finding, facts) for finding in run.findings]
