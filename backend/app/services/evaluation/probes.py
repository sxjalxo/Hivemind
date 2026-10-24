from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

_PROBES_PATH = Path(__file__).resolve().parent / "probes.yaml"


class Probe(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    characteristic: str
    command: str
    # The canonical fact this probe establishes. Contradiction detection
    # compares two completed probes that name the SAME fact; probes naming
    # different facts are independent and can never contradict each other.
    establishes: str | None = None
    expect_absent: bool = False
    # How to read this probe's own claim about `establishes` out of its raw
    # output: a regex with exactly one capture group, matched case-insensitively.
    #
    # Why a fact needs one at all. Two probes can establish the same fact in
    # two different FORMS. `hostname` and `cat /etc/hostname` both print a bare
    # hostname, so their raw outputs are directly comparable and neither
    # declares an extract. `uname -a` and `cat /etc/os-release` both claim
    # `os.identity`, and their raw outputs can never be equal even when both
    # correctly describe the same Debian -- so comparing them raw reported a
    # CORRECT honeypot as contradicting itself, and an operator who fixed
    # their empty `/etc/os-release` was handed a new defect for their trouble.
    #
    # A declared extract that does not match leaves the fact with no
    # comparable form, and the probe is dropped from contradiction detection
    # rather than compared some other way. Not being able to read a claim is
    # not evidence that two claims agree -- the same rule `unknown` follows in
    # scoring. (A kernel string naming no distribution at all is the ordinary
    # way this happens; the pair is then simply not cross-checked.)
    extract: str | None = None
    # Optional: what a captured token MEANS, when one fact is printed as
    # different words by different sources. `/proc/cpuinfo` names a vendor
    # (`GenuineIntel`) where `uname -m` names an architecture (`x86_64`); the
    # alias maps the normalised token to the word it implies. A token with no
    # entry compares as itself. Applied after `extract`, so it only ever sees
    # a claim we could read.
    aliases: dict[str, str] | None = None


@lru_cache
def _raw() -> dict:
    return yaml.safe_load(_PROBES_PATH.read_text(encoding="utf-8"))


class ProbeSetError(ValueError):
    """The probe set is internally inconsistent and must not be loaded."""


@lru_cache
def load_probes() -> tuple[Probe, ...]:
    probes = tuple(Probe(**entry) for entry in _raw()["probes"])
    _check_comparable_forms(probes)
    return probes


def _check_comparable_forms(probes: tuple[Probe, ...]) -> None:
    """Every probe establishing one fact must agree on how to read it.

    Loud at load time because the failure is otherwise silent and looks like
    a honeypot defect. Let one probe for `os.identity` declare an extract
    while its partner does not, and the comparison runs an extracted token
    against a raw command dump: they differ, every run reports a
    contradiction, and the honeypot gets blamed for our own mismatched
    declaration. That is the exact bug this field was added to remove, so it
    must not be reachable by editing half of a pair.

    The rule covers the pattern and the alias table too, not just whether an
    extract is declared: two probes reading one fact through different
    patterns or alias tables reduce the same machine to different words, and
    disagree in the same silent way.
    """
    forms: dict[str, set[tuple[str | None, tuple[tuple[str, str], ...]]]] = {}
    for probe in probes:
        if probe.establishes:
            reading = (probe.extract, tuple(sorted((probe.aliases or {}).items())))
            forms.setdefault(probe.establishes, set()).add(reading)

    split = sorted(fact for fact, readings in forms.items() if len(readings) > 1)
    if split:
        raise ProbeSetError(
            f"probes establishing {split} do not read their fact the same way. Every "
            f"probe naming one fact must declare the same `extract` and the same "
            f"`aliases` (or none of either), or their values are not comparable and "
            f"every run reports a false contradiction."
        )


PROBE_SET_VERSION: str = str(_raw()["version"])
