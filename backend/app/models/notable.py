from typing import Literal

from app.serialization import CamelModel


class Notable(CamelModel):
    """One item in the notables feed. See `app.services.notables`."""

    # Stable across requests, so a client can tell an item it has seen from a new one.
    id: str
    kind: Literal["high_risk_session", "technique_first_seen", "campaign"]
    provenance: Literal["OBSERVED", "AI INFERENCE", "CORRELATED"]
    title: str
    detail: str
    timestamp: str
    session_id: str | None = None
    technique_id: str | None = None
