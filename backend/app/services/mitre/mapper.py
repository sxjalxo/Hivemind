import logging
from pathlib import Path

from pydantic import BaseModel

from app.services.compaction import CompactedCommand
from app.services.llm.base import LLMClient, LLMValidationError
from app.services.llm.schemas import EvidenceCitation, TechniqueProposals
from app.services.mitre.catalog import load_catalog
from app.services.mitre.rules import apply_rules

logger = logging.getLogger(__name__)

_PROMPT_PATH = (
    Path(__file__).resolve().parents[1] / "llm" / "prompts" / "mitre_gapfill.md"
)


class MappedTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    ai_explanation: str | None
    source: str
    rule_id: str | None
    observed: bool
    evidence: list[EvidenceCitation]


class MappingResult(BaseModel):
    techniques: list[MappedTechnique]
    rejected: int


def _render_prompt(commands: list[CompactedCommand]) -> str:
    catalog = load_catalog()
    rendered = "\n".join(
        f"- event_id: {c.event_id}\n  command: {c.command}" for c in commands
    )
    allowed = "\n".join(f"- {e.id} ({e.name}) — {e.tactic}" for e in catalog.values())
    template = _PROMPT_PATH.read_text(encoding="utf-8")
    return template.replace("{commands}", rendered).replace(
        "{allowed_techniques}", allowed
    )


def _from_rules(commands: list[CompactedCommand]) -> tuple[list[MappedTechnique], list[CompactedCommand]]:
    hits, unmatched = apply_rules(commands)

    by_technique: dict[str, MappedTechnique] = {}
    for hit in hits:
        citation = EvidenceCitation(event_id=hit.event_id, artifact=hit.command)
        existing = by_technique.get(hit.rule.id)
        if existing:
            existing.evidence.append(citation)
            continue
        by_technique[hit.rule.id] = MappedTechnique(
            technique_id=hit.rule.id,
            technique_name=hit.rule.name,
            tactic=hit.rule.tactic,
            confidence=1.0,
            ai_explanation=None,
            source="rule",
            rule_id=hit.rule.id,
            observed=True,
            evidence=[citation],
        )
    return list(by_technique.values()), unmatched


async def map_techniques(
    commands: list[CompactedCommand], client: LLMClient
) -> MappingResult:
    """Map commands to ATT&CK: deterministic rules first, LLM for the rest.

    Rule hits are OBSERVED with confidence 1.0. LLM proposals are AI INFERENCE
    and must survive catalog validation and evidence validation to be kept.
    """
    mapped, unmatched = _from_rules(commands)
    if not unmatched:
        return MappingResult(techniques=mapped, rejected=0)

    try:
        proposals = await client.complete_json(
            _render_prompt(unmatched), TechniqueProposals
        )
    except LLMValidationError as exc:
        logger.warning("MITRE gap-fill failed, keeping rule mappings only: %s", exc)
        return MappingResult(techniques=mapped, rejected=0)

    catalog = load_catalog()
    offered_ids = {c.event_id for c in unmatched}
    rejected = 0

    for proposal in proposals.techniques:
        entry = catalog.get(proposal.technique_id)
        if entry is None:
            logger.warning("rejected hallucinated technique %s", proposal.technique_id)
            rejected += 1
            continue

        grounded = [c for c in proposal.evidence if c.event_id in offered_ids]
        if not grounded:
            logger.warning(
                "rejected %s: cited event ids were never offered", proposal.technique_id
            )
            rejected += 1
            continue

        mapped.append(
            MappedTechnique(
                technique_id=entry.id,
                technique_name=entry.name,
                tactic=entry.tactic,
                confidence=proposal.confidence,
                ai_explanation=proposal.ai_explanation,
                source="llm",
                rule_id=None,
                observed=False,
                evidence=grounded,
            )
        )

    return MappingResult(techniques=mapped, rejected=rejected)
