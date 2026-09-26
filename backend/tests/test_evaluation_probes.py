from app.services.evaluation.probes import PROBE_SET_VERSION, load_probes


def test_every_probe_has_a_characteristic_and_a_unique_id() -> None:
    probes = load_probes()
    assert probes, "the probe set must not be empty"
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids)), "probe ids must be unique"
    valid = {
        "basic_commands",
        "file_system",
        "services",
        "attack_possibilities",
        "sanity",
        "context",
    }
    assert {p.characteristic for p in probes} <= valid


def test_sanity_probes_declare_the_fact_they_establish() -> None:
    # Contradiction detection compares canonical facts, so a sanity probe
    # that establishes nothing can never participate and is a definition bug.
    sanity = [p for p in load_probes() if p.characteristic == "sanity"]
    assert sanity, "there must be sanity probes"
    assert all(p.establishes for p in sanity)


def test_at_least_two_sanity_probes_share_one_fact() -> None:
    # A contradiction needs two independent probes establishing the same
    # fact. With one probe per fact the detector can never fire.
    sanity = [p for p in load_probes() if p.characteristic == "sanity"]
    facts = [p.establishes for p in sanity if p.establishes]
    assert any(facts.count(f) >= 2 for f in facts)


def test_probe_set_version_is_pinned() -> None:
    assert PROBE_SET_VERSION


def test_a_half_declared_extract_is_refused_at_load() -> None:
    # The silent failure this guard exists for: one probe of a pair reads its
    # fact through an extract and the other does not, so an extracted token is
    # compared against a raw command dump. They differ on every run, every run
    # reports a contradiction, and the honeypot is blamed for our own
    # inconsistent declaration. Refused loudly instead.
    import pytest

    from app.services.evaluation.probes import Probe, ProbeSetError, _check_comparable_forms

    mixed = (
        Probe(id="a", characteristic="sanity", command="x", establishes="os.identity",
              extract=r"\b(debian)\b"),
        Probe(id="b", characteristic="sanity", command="y", establishes="os.identity"),
    )
    with pytest.raises(ProbeSetError, match="os.identity"):
        _check_comparable_forms(mixed)


def test_a_consistently_declared_pair_loads() -> None:
    from app.services.evaluation.probes import Probe, _check_comparable_forms

    pattern = r"\b(debian)\b"
    both = (
        Probe(id="a", characteristic="sanity", command="x", establishes="os.identity",
              extract=pattern),
        Probe(id="b", characteristic="sanity", command="y", establishes="os.identity",
              extract=pattern),
    )
    _check_comparable_forms(both)  # must not raise

    neither = (
        Probe(id="c", characteristic="sanity", command="x", establishes="host.name"),
        Probe(id="d", characteristic="sanity", command="y", establishes="host.name"),
    )
    _check_comparable_forms(neither)  # must not raise
