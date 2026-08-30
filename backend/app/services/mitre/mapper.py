import logging
from dataclasses import dataclass
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
from app.services.mitre.catalog import CatalogEntry, load_catalog
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


@dataclass
class _LlmProposal:
    """One chunk's proposal for one technique, its citations already deduped."""

    confidence: float
    ai_explanation: str | None
    citations: list[EvidenceCitation]


def _merge_llm_proposals(
    entry: CatalogEntry, proposals: list[_LlmProposal]
) -> MappedTechnique | None:
    """Combine every chunk's proposal for one technique into a single entry.

    Chunking exists only because the context window is finite, so it must not
    be visible in the result: analysing a session as one chunk or as five has
    to yield the same confidence and the same explanation. This previously
    kept whichever chunk was processed FIRST and threw the rest away, which
    made the output a function of chunk ordering.

    Confidence is the evidence-weighted mean,
    `sum(confidence_i * weight_i) / sum(weight_i)`, where the weight is the
    number of distinct events the proposal grounded. Three chunks reporting
    0.55, 0.60 and 0.65 should not silently become 0.65 (`max` ignores two of
    them), and a proposal resting on one command should not count as heavily
    as one resting on six (a plain mean ignores that). Both the sum and the
    union below are commutative, so the result does not depend on order.

    Citations are deduped within a proposal before it gets here, so a model
    repeating the same event id cannot inflate that proposal's weight.
    """
    # A proposal with no citations has nothing to weight and nothing to sort
    # by; `min()` over an empty sequence would raise. The caller already drops
    # ungrounded proposals, but keeping the invariant local means a second
    # caller cannot turn it into a mid-analysis crash. An entry with no
    # evidence at all is not a claim this system may store, so None means
    # "nothing to record".
    proposals = [p for p in proposals if p.citations]
    if not proposals:
        return None

    # Ordered by earliest cited event so the explanation reads in session
    # order, and so the ordering itself is a property of the evidence rather
    # than of the order chunks happened to be processed in.
    ordered = sorted(proposals, key=lambda p: min(c.event_id for c in p.citations))

    evidence: dict[str, EvidenceCitation] = {}
    for proposal in ordered:
        for citation in proposal.citations:
            evidence.setdefault(citation.event_id, citation)

    weight_total = sum(len(p.citations) for p in proposals)
    weighted = sum(p.confidence * len(p.citations) for p in proposals)
    confidence = round(weighted / weight_total, 3) if weight_total else 0.0

    explanations: list[str] = []
    for proposal in ordered:
        explanation = (proposal.ai_explanation or "").strip()
        if explanation and explanation not in explanations:
            explanations.append(explanation)

    return MappedTechnique(
        technique_id=entry.id,
        technique_name=entry.name,
        tactic=entry.tactic,
        confidence=confidence,
        ai_explanation=" ".join(explanations) or None,
        source="llm",
        rule_id=None,
        observed=False,
        evidence=list(evidence.values()),
    )


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
    # Every chunk's proposals are collected first and merged once at the end.
    # Merging incrementally is what made the result order-dependent.
    llm_proposals: dict[str, list[_LlmProposal]] = {}
    llm_entries: dict[str, CatalogEntry] = {}

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

            # A technique proposed by more than one chunk is
            # chunking-as-implementation-detail, not several independent
            # findings -- but unlike the rule-duplicate case above, no chunk's
            # citations are stronger evidence than another's: all are
            # equally-provenanced model inference, grounded in different
            # (chunk-local) commands. Collect them all and reconcile once,
            # below, so no chunk's assessment is discarded for arriving late.
            #
            # Deduplicate within this proposal first: a model that cites the
            # same event twice has offered one piece of evidence, and must not
            # earn double weight for it.
            seen_ids: set[str] = set()
            citations: list[EvidenceCitation] = []
            for citation in grounded:
                if citation.event_id not in seen_ids:
                    seen_ids.add(citation.event_id)
                    citations.append(citation)

            llm_entries[entry.id] = entry
            llm_proposals.setdefault(entry.id, []).append(
                _LlmProposal(
                    confidence=proposal.confidence,
                    ai_explanation=proposal.ai_explanation,
                    citations=citations,
                )
            )

    # Sorted so the technique order in the result is stable too, not an
    # artefact of which chunk mentioned what first.
    for technique_id in sorted(llm_proposals):
        proposals_for_technique = llm_proposals[technique_id]
        if len(proposals_for_technique) > 1:
            logger.info(
                "merged %d chunk proposals for %s into one evidence-weighted entry",
                len(proposals_for_technique),
                technique_id,
            )
        merged = _merge_llm_proposals(llm_entries[technique_id], proposals_for_technique)
        if merged is not None:
            mapped.append(merged)

    return MappingResult(techniques=mapped, rejected=rejected)
