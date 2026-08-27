import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Column, DateTime, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.types import String
from sqlmodel import Field, SQLModel

# All datetimes in this schema are stored as tz-aware TIMESTAMPTZ. asyncpg
# rejects tz-aware Python datetimes on a "timestamp without time zone"
# column, and every timestamp this system produces or consumes (ECS
# `@timestamp`, analysis `created_at`, evidence `timestamp`) is UTC-aware,
# so every datetime column below is explicit about timezone=True.
_TZDateTime = DateTime(timezone=True)


class ParentType(StrEnum):
    TECHNIQUE_MAPPING = "technique_mapping"
    OBSERVED_BEHAVIOR = "observed_behavior"
    SUSPICIOUS_INDICATOR = "suspicious_indicator"
    INDICATOR = "indicator"


class Analysis(SQLModel, table=True):
    __tablename__ = "analyses"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    session_id: str = Field(index=True)
    model: str
    analysis_type: str
    status: str
    created_at: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    duration_seconds: int
    classification: str
    confidence: float
    risk_score: int
    risk: str
    behavior_summary: str
    model_tier: str
    evaluator_model: str | None = None
    prompt_version: str
    rejected_claims: int = 0


class TechniqueMapping(SQLModel, table=True):
    __tablename__ = "technique_mappings"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    analysis_id: uuid.UUID = Field(foreign_key="analyses.id", index=True)
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    ai_explanation: str | None = None
    source: str
    rule_id: str | None = None
    timestamp: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))


class ObservedBehavior(SQLModel, table=True):
    __tablename__ = "observed_behaviors"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    analysis_id: uuid.UUID = Field(foreign_key="analyses.id", index=True)
    label: str


class SuspiciousIndicator(SQLModel, table=True):
    __tablename__ = "suspicious_indicators"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    analysis_id: uuid.UUID = Field(foreign_key="analyses.id", index=True)
    label: str
    severity: str


class RecommendedAction(SQLModel, table=True):
    __tablename__ = "recommended_actions"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    analysis_id: uuid.UUID = Field(foreign_key="analyses.id", index=True)
    priority: str
    action: str
    rationale: str


class Indicator(SQLModel, table=True):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_indicator_type_value"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    type: str
    value: str
    confidence: float
    first_seen: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    last_seen: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    source: str
    tags: list[str] = Field(default_factory=list, sa_column=Column(ARRAY(String)))


class IndicatorSession(SQLModel, table=True):
    __tablename__ = "indicator_sessions"

    indicator_id: uuid.UUID = Field(foreign_key="indicators.id", primary_key=True)
    session_id: str = Field(primary_key=True)


class EvidenceRef(SQLModel, table=True):
    __tablename__ = "evidence_refs"
    __table_args__ = (
        Index("ix_evidence_parent", "parent_type", "parent_id"),
        Index("ix_evidence_es_event", "es_event_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    es_event_id: str
    session_id: str
    timestamp: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    artifact: str
    parent_type: ParentType
    parent_id: uuid.UUID


class Report(SQLModel, table=True):
    __tablename__ = "reports"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    session_id: str = Field(index=True)
    analysis_id: uuid.UUID = Field(foreign_key="analyses.id")
    title: str
    created_at: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    generated_by: str
    body: dict = Field(default_factory=dict, sa_column=Column(JSONB))


class AttackerProfile(SQLModel, table=True):
    __tablename__ = "attacker_profiles"

    ip: str = Field(primary_key=True)
    risk: str
    risk_score: int
    behavior_label: str
    first_seen: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    last_seen: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
    geo: dict | None = Field(default=None, sa_column=Column(JSONB))
    updated_at: datetime = Field(sa_column=Column(_TZDateTime, nullable=False))
