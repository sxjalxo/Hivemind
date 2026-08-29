import pytest

from app.services.compaction import CompactedCommand
from app.services.llm.base import LLMValidationError
from app.services.llm.schemas import (
    EvidenceCitation,
    TechniqueProposal,
    TechniqueProposals,
)
from app.services.mitre.mapper import map_techniques

RULED = CompactedCommand(
    event_id="e-wget", timestamp="2026-08-20T10:00:20Z", command="wget http://x/y.sh"
)
UNRULED = CompactedCommand(
    event_id="e-dmi",
    timestamp="2026-08-20T10:00:30Z",
    command="dmidecode -s system-manufacturer",
)


class StubClient:
    def __init__(self, response: TechniqueProposals | Exception) -> None:
        self._response = response
        self.prompts: list[str] = []

    @property
    def model_name(self) -> str:
        return "stub"

    async def complete_json(self, prompt: str, schema):  # noqa: ANN001
        self.prompts.append(prompt)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _proposals(technique_id: str, event_id: str) -> TechniqueProposals:
    return TechniqueProposals(
        techniques=[
            TechniqueProposal(
                technique_id=technique_id,
                tactic="Discovery",
                confidence=0.7,
                ai_explanation="Reads hardware identity.",
                evidence=[EvidenceCitation(event_id=event_id, artifact="dmidecode")],
            )
        ]
    )


def _multi_proposals(items: list[tuple[str, str]]) -> TechniqueProposals:
    return TechniqueProposals(
        techniques=[
            TechniqueProposal(
                technique_id=technique_id,
                tactic="Discovery",
                confidence=0.7,
                ai_explanation="Reads hardware identity.",
                evidence=[EvidenceCitation(event_id=event_id, artifact="dmidecode")],
            )
            for technique_id, event_id in items
        ]
    )


@pytest.mark.asyncio
async def test_rule_hits_are_observed_with_full_confidence() -> None:
    client = StubClient(TechniqueProposals(techniques=[]))
    result = await map_techniques([RULED], client)

    wget = next(t for t in result.techniques if t.technique_id == "T1105")
    assert wget.source == "rule"
    assert wget.observed is True
    assert wget.confidence == 1.0
    assert wget.ai_explanation is None
    assert wget.evidence[0].event_id == "e-wget"


@pytest.mark.asyncio
async def test_llm_fills_gaps_and_is_marked_inference() -> None:
    client = StubClient(_proposals("T1082", "e-dmi"))
    result = await map_techniques([RULED, UNRULED], client)

    inferred = next(t for t in result.techniques if t.source == "llm")
    assert inferred.technique_id == "T1082"
    assert inferred.observed is False
    assert inferred.ai_explanation
    assert result.rejected == 0


@pytest.mark.asyncio
async def test_hallucinated_technique_id_is_rejected() -> None:
    client = StubClient(_proposals("T9999", "e-dmi"))
    result = await map_techniques([UNRULED], client)

    assert all(t.technique_id != "T9999" for t in result.techniques)
    assert result.rejected == 1


@pytest.mark.asyncio
async def test_citation_of_an_unoffered_event_is_rejected() -> None:
    client = StubClient(_proposals("T1082", "e-never-shown"))
    result = await map_techniques([UNRULED], client)

    assert all(t.source != "llm" for t in result.techniques)
    assert result.rejected == 1


@pytest.mark.asyncio
async def test_llm_failure_degrades_to_rules_only() -> None:
    client = StubClient(LLMValidationError("model returned garbage"))
    result = await map_techniques([RULED, UNRULED], client)

    assert [t.technique_id for t in result.techniques] == ["T1105"]
    assert result.rejected == 0


@pytest.mark.asyncio
async def test_llm_is_not_called_when_rules_explain_everything() -> None:
    client = StubClient(TechniqueProposals(techniques=[]))
    await map_techniques([RULED], client)

    assert client.prompts == []


@pytest.mark.asyncio
async def test_prompt_lists_only_the_unmatched_commands() -> None:
    client = StubClient(TechniqueProposals(techniques=[]))
    await map_techniques([RULED, UNRULED], client)

    prompt = client.prompts[0]
    assert "dmidecode" in prompt
    assert "e-dmi" in prompt
    assert "wget http://x/y.sh" not in prompt


@pytest.mark.asyncio
async def test_llm_duplicate_of_a_rule_hit_is_dropped_not_appended() -> None:
    # T1105 was already produced by the rule that matched RULED ("wget ...").
    # The LLM proposing T1105 again -- from the unrelated UNRULED command --
    # must not create a second, contradictory-provenance entry for the same
    # technique id.
    client = StubClient(_proposals("T1105", "e-dmi"))
    result = await map_techniques([RULED, UNRULED], client)

    wget_entries = [t for t in result.techniques if t.technique_id == "T1105"]
    assert len(wget_entries) == 1

    entry = wget_entries[0]
    assert entry.source == "rule"
    assert entry.observed is True
    assert entry.confidence == 1.0
    # The rule's own evidence (the wget command) survives untouched; the
    # LLM's citation (e-dmi) must NOT be merged into an OBSERVED record.
    assert [c.event_id for c in entry.evidence] == ["e-wget"]


@pytest.mark.asyncio
async def test_dropped_duplicate_does_not_increment_rejected() -> None:
    # Dropping a redundant-but-truthful duplicate is not a hallucination and
    # must not corrupt the `rejected` model-quality signal.
    client = StubClient(_proposals("T1105", "e-dmi"))
    result = await map_techniques([RULED, UNRULED], client)

    assert result.rejected == 0


CHUNK_A = CompactedCommand(
    event_id="e-chunk-a", timestamp="2026-08-20T10:00:40Z", command="ip route show default"
)
CHUNK_B = CompactedCommand(
    event_id="e-chunk-b",
    timestamp="2026-08-20T10:00:41Z",
    command="systemctl list-units --type=service",
)


class SequencedClient:
    """A stub whose response depends on call order, one per (forced) chunk."""

    def __init__(self, responses: list[TechniqueProposals]) -> None:
        self._responses = responses
        self._calls = 0
        self.prompts: list[str] = []

    @property
    def model_name(self) -> str:
        return "stub"

    async def complete_json(self, prompt: str, schema):  # noqa: ANN001
        self.prompts.append(prompt)
        response = self._responses[self._calls]
        self._calls += 1
        return response


@pytest.mark.asyncio
async def test_llm_proposals_for_the_same_technique_across_chunks_are_merged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force exactly two chunks, one command each, regardless of the real
    # token-budget math -- isolates the merge behaviour from chunk sizing.
    monkeypatch.setattr(
        "app.services.mitre.mapper.chunk_items",
        lambda items, render, budget_tokens: [[CHUNK_A], [CHUNK_B]],
    )
    client = SequencedClient(
        [_proposals("T1082", "e-chunk-a"), _proposals("T1082", "e-chunk-b")]
    )

    result = await map_techniques([CHUNK_A, CHUNK_B], client)

    entries = [t for t in result.techniques if t.technique_id == "T1082"]
    assert len(entries) == 1, "the two chunks' proposals must merge into ONE entry, not two"
    entry = entries[0]
    assert entry.source == "llm"
    assert {c.event_id for c in entry.evidence} == {"e-chunk-a", "e-chunk-b"}
    assert result.rejected == 0


@pytest.mark.asyncio
async def test_cross_chunk_llm_merge_deduplicates_by_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A defensive case: the second (forced) chunk re-proposes a citation for
    # an event id the first chunk's proposal already grounded. The merge
    # must not double it up in the final evidence list.
    monkeypatch.setattr(
        "app.services.mitre.mapper.chunk_items",
        lambda items, render, budget_tokens: [[CHUNK_A, CHUNK_B], [CHUNK_B]],
    )
    first_call = TechniqueProposals(
        techniques=[
            TechniqueProposal(
                technique_id="T1082",
                tactic="Discovery",
                confidence=0.7,
                ai_explanation="Reads hardware identity.",
                evidence=[
                    EvidenceCitation(event_id="e-chunk-a", artifact="ip route"),
                    EvidenceCitation(event_id="e-chunk-b", artifact="systemctl"),
                ],
            )
        ]
    )
    second_call = _proposals("T1082", "e-chunk-b")  # re-cites e-chunk-b
    client = SequencedClient([first_call, second_call])

    result = await map_techniques([CHUNK_A, CHUNK_B], client)

    entries = [t for t in result.techniques if t.technique_id == "T1082"]
    assert len(entries) == 1
    ids = [c.event_id for c in entries[0].evidence]
    assert sorted(ids) == ["e-chunk-a", "e-chunk-b"]
    assert len(ids) == len(set(ids)), "e-chunk-b must not be cited twice"


@pytest.mark.asyncio
async def test_non_duplicate_llm_proposal_still_accepted_alongside_a_dropped_duplicate() -> None:
    # Guard against over-dropping: a technique no rule produced (T1082) must
    # still be accepted normally even in the same response that also
    # contains a duplicate (T1105) that gets dropped.
    client = StubClient(_multi_proposals([("T1105", "e-dmi"), ("T1082", "e-dmi")]))
    result = await map_techniques([RULED, UNRULED], client)

    assert [t.technique_id for t in result.techniques if t.technique_id == "T1105"] == ["T1105"]
    llm_entries = [t for t in result.techniques if t.source == "llm"]
    assert [t.technique_id for t in llm_entries] == ["T1082"]
    assert result.rejected == 0
