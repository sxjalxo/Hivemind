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
