from sqlalchemy import select

from app.db.models import Analysis, EvidenceRef, ParentType, TechniqueMapping
from app.db.session import get_session_factory
from app.models.analysis import EvidenceRefOut
from app.models.mitre import MitreCoverage, MitreTechniqueOut
from app.services.mitre.catalog import load_catalog


async def build_coverage(session_id: str | None = None) -> MitreCoverage:
    """Project stored mappings onto the full ATT&CK catalog.

    `observed` is true only when a deterministic rule produced the mapping.
    An LLM-inferred technique appears in the matrix but is not marked observed.
    """
    catalog = load_catalog()

    async with get_session_factory()() as db:
        statement = select(TechniqueMapping, Analysis).join(
            Analysis, TechniqueMapping.analysis_id == Analysis.id
        )
        if session_id:
            statement = statement.where(Analysis.session_id == session_id)
        rows = (await db.execute(statement)).all()

        by_technique: dict[str, list] = {}
        for mapping, analysis in rows:
            by_technique.setdefault(mapping.technique_id, []).append((mapping, analysis))

        techniques: list[MitreTechniqueOut] = []
        observed_count = 0

        for entry in catalog.values():
            matches = by_technique.get(entry.id, [])
            if not matches:
                techniques.append(
                    MitreTechniqueOut(
                        id=entry.id,
                        name=entry.name,
                        tactic=entry.tactic,
                        observed=False,
                        session_count=0,
                        evidence=[],
                        related_commands=[],
                    )
                )
                continue

            evidence: list[EvidenceRefOut] = []
            for mapping, _ in matches:
                refs = (
                    (
                        await db.execute(
                            select(EvidenceRef).where(
                                EvidenceRef.parent_type == ParentType.TECHNIQUE_MAPPING,
                                EvidenceRef.parent_id == mapping.id,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                evidence.extend(
                    EvidenceRefOut(
                        artifact=r.artifact,
                        session_id=r.session_id,
                        timestamp=r.timestamp.isoformat().replace("+00:00", "Z"),
                        event_id=r.es_event_id,
                    )
                    for r in refs
                )

            rule_backed = any(m.source == "rule" for m, _ in matches)
            if rule_backed:
                observed_count += 1

            explanation = next((m.ai_explanation for m, _ in matches if m.ai_explanation), None)
            techniques.append(
                MitreTechniqueOut(
                    id=entry.id,
                    name=entry.name,
                    tactic=entry.tactic,
                    observed=rule_backed,
                    session_count=len({a.session_id for _, a in matches}),
                    confidence=max(m.confidence for m, _ in matches),
                    evidence=evidence,
                    related_commands=[e.artifact for e in evidence],
                    ai_explanation=explanation,
                    last_seen=max(m.timestamp for m, _ in matches)
                    .isoformat()
                    .replace("+00:00", "Z"),
                )
            )

    return MitreCoverage(
        techniques=techniques,
        observed_count=observed_count,
        total_count=len(catalog),
    )
