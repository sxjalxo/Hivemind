"""Elasticsearch enrichment write-back.

Per the spec, `risk.*`, `mitre.*`, and `ai_classification` are enrichment
fields written only after analysis -- their presence is what distinguishes
an analyzed event from an unanalyzed one (see `to_event`'s "informational
until assessed" fallback in `app.es.queries`, and the identical convention
in `app.services.dashboard.list_honeypots`/`build_dashboard`). Nothing in
the original seven-stage pipeline plan ever wrote them, which left
`/api/dashboard`'s `classifications` panel and `riskDistribution` always
empty/zero, `topCommands[].techniqueId` always null, and the `risk` /
`techniqueId` filters on `/api/logs` permanently unmatchable.

Postgres remains the system of record -- `app.services.persistence.
persist_analysis` is still the only place a claim is grounded and
written. This module runs strictly AFTER that write succeeds, and does
nothing but project a read-only copy of already-persisted facts onto the
session's Elasticsearch documents, for search and aggregation.
"""

import logging

from app.config import get_settings
from app.es.client import get_es
from app.services.mitre.mapper import MappedTechnique

logger = logging.getLogger(__name__)


async def write_back_enrichment(
    session_id: str,
    risk_score: int,
    risk: str,
    classification: str,
    techniques: list[MappedTechnique],
) -> None:
    """Stamp analysis results onto the session's indexed events.

    `risk.score` / `risk.level` (from the analysis) and `ai_classification`
    (from the classification stage) are written onto every event in the
    session -- the analysis is a verdict about the session as a whole.

    `mitre.technique_id` / `mitre.tactic` are written per-event, and ONLY
    for events cited by a RULE-BACKED mapping (`technique.source ==
    "rule"`). An LLM-inferred mapping (`source == "llm"`) is never stamped
    onto an event: that field is the one place the rest of this system
    (dashboard aggregations, the `techniqueId` log filter) treats as
    observed telemetry, and stamping an inference there would make a
    guess indistinguishable from something the honeypot actually recorded
    happening -- exactly the line this system exists to hold.

    The `mitre` sub-document has room for exactly one technique per event
    (see `infra/elasticsearch/index-template.json`); when a single command
    matches more than one rule, the first rule-backed technique to cite
    that event id (in `techniques` order, which is deterministic) wins.
    """
    settings = get_settings()
    es = get_es()

    await es.update_by_query(
        index=settings.es_index,
        query={"term": {"session.id": session_id}},
        script={
            "source": (
                "ctx._source.risk = ['score': params.score, 'level': params.level]; "
                "ctx._source.ai_classification = params.classification;"
            ),
            "lang": "painless",
            "params": {
                "score": risk_score,
                "level": risk,
                "classification": classification,
            },
        },
        conflicts="proceed",
        refresh=True,
    )

    event_to_technique: dict[str, tuple[str, str]] = {}
    for technique in techniques:
        if technique.source != "rule":
            continue
        for citation in technique.evidence:
            event_to_technique.setdefault(
                citation.event_id, (technique.technique_id, technique.tactic)
            )

    for event_id, (technique_id, tactic) in event_to_technique.items():
        try:
            await es.update(
                index=settings.es_index,
                id=event_id,
                doc={"mitre": {"technique_id": technique_id, "tactic": tactic}},
            )
        except Exception as exc:  # noqa: BLE001 -- one bad event id must not
            # abort the rest of the write-back; Postgres already holds the
            # authoritative record regardless of whether this projection
            # fully lands.
            logger.warning("failed to stamp mitre.* on event %s: %s", event_id, exc)

    if event_to_technique:
        await es.indices.refresh(index=settings.es_index)
