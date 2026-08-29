import logging
from pathlib import Path

from pydantic import BaseModel

from app.services.chunking import (
    MAX_ITEM_CHARS,
    SESSION_TOKEN_BUDGET,
    chunk_items,
    estimate_tokens,
    truncate_text,
)
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


def _render_prompt(commands: list[CompactedCommand], ruled_ids: set[str]) -> str:
    """Render the gap-fill prompt.

    The allowed-technique list excludes ids a rule already produced, so the
    model isn't invited to re-propose something we already know
    deterministically. If that would empty the list (rules covered the whole
    catalog — unlikely with 21 entries, but not impossible in principle), fall
    back to the full catalog rather than send an empty, incoherent prompt.
    """
    catalog = load_catalog()
    rendered = "\n".join(
        f"- event_id: {c.event_id}\n  command: {c.command}" for c in commands
    )
    remaining = [e for e in catalog.values() if e.id not in ruled_ids]
    if not remaining:
        remaining = list(catalog.values())
    allowed = "\n".join(f"- {e.id} ({e.name}) — {e.tactic}" for e in remaining)
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


def _bound_unmatched(unmatched: list[CompactedCommand], ruled_ids: set[str]) -> list[CompactedCommand]:
    """Explicitly truncate any single unmatched command whose own gap-fill
    rendering alone would exceed the session token budget.

    Mirrors `app.services.compaction.chunk_session`'s per-item bound: an
    atomic command cannot be split further, so an oversized one must be
    visibly truncated rather than silently overflowing the model's context.
    """
    bounded: list[CompactedCommand] = []
    for command in unmatched:
        if estimate_tokens(_render_prompt([command], ruled_ids)) > SESSION_TOKEN_BUDGET:
            bounded.append(
                command.model_copy(
                    update={"command": truncate_text(command.command, MAX_ITEM_CHARS)}
                )
            )
        else:
            bounded.append(command)
    return bounded


async def map_techniques(
    commands: list[CompactedCommand], client: LLMClient
) -> MappingResult:
    """Map commands to ATT&CK: deterministic rules first, LLM for the rest.

    Rule hits are OBSERVED with confidence 1.0. LLM proposals are AI INFERENCE
    and must survive catalog validation and evidence validation to be kept.

    The gap-fill prompt lists every unmatched command; on a large session
    that alone can exceed the model's context window. When it would, the
    unmatched commands are chunked (see `app.services.chunking`) and each
    chunk gets its own gap-fill call -- still one context per call, never a
    prompt silently truncated by the model itself.
    """
    mapped, unmatched = _from_rules(commands)
    ruled_ids = {m.technique_id for m in mapped}
    if not unmatched:
        return MappingResult(techniques=mapped, rejected=0)

    bounded = _bound_unmatched(unmatched, ruled_ids)
    groups = chunk_items(
        bounded, lambda group: _render_prompt(group, ruled_ids), SESSION_TOKEN_BUDGET
    )

    catalog = load_catalog()
    rejected = 0

    for group in groups:
        try:
            proposals = await client.complete_json(
                _render_prompt(group, ruled_ids), TechniqueProposals
            )
        except LLMValidationError as exc:
            logger.warning("MITRE gap-fill failed for one chunk, skipping it: %s", exc)
            continue

        offered_ids = {c.event_id for c in group}

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

            if entry.id in ruled_ids:
                # A rule already produced this technique, from other evidence
                # in the same session, with observed=True at confidence 1.0.
                # That is strictly stronger than a model inference and
                # already correct -- the LLM entry would add no information,
                # only a second, contradictory-looking record for the same
                # id. Drop it, but this is not a hallucination or a
                # fabrication: the model named something real and grounded,
                # it's just redundant. Do not count it in `rejected`, which
                # is a model-quality signal reserved for actual
                # hallucinations/fabrications.
                logger.info(
                    "dropped duplicate LLM proposal for %s: already produced by a rule",
                    entry.id,
                )
                continue

            # A technique already produced by an *earlier chunk's* LLM call
            # in this same run is chunking-as-implementation-detail, not a
            # second, independent finding -- but unlike the rule-duplicate
            # case above, the earlier chunk's citations are NOT stronger
            # evidence than this chunk's: both are equally-provenanced model
            # inference, just grounded in different (chunk-local) commands.
            # Dropping this proposal outright would silently lose real,
            # grounded evidence the barrier is supposed to preserve. Merge
            # the new grounded citations into the existing LLM entry instead,
            # deduplicated by event_id so an event already cited from a
            # previous chunk is never cited twice.
            existing_llm = next(
                (m for m in mapped if m.technique_id == entry.id and m.source == "llm"),
                None,
            )
            if existing_llm is not None:
                seen_ids = {c.event_id for c in existing_llm.evidence}
                new_citations = [c for c in grounded if c.event_id not in seen_ids]
                if new_citations:
                    existing_llm.evidence.extend(new_citations)
                    logger.info(
                        "merged %d citation(s) into %s from a later chunk's LLM proposal",
                        len(new_citations),
                        entry.id,
                    )
                else:
                    logger.info(
                        "dropped duplicate LLM proposal for %s: citations already "
                        "present from an earlier chunk",
                        entry.id,
                    )
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
