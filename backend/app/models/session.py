from app.serialization import CamelModel


class AttackSession(CamelModel):
    id: str
    attacker_ip: str
    # Omitted, never 0, when the source never recorded a port: "not
    # recorded" and "recorded as zero" are different claims. Same precedent as
    # DownloadedFile.size and destination.ip.
    source_port: int | None = None
    destination_port: int | None = None
    honeypot_id: str
    honeypot_name: str
    protocol: str
    started_at: str
    ended_at: str | None = None
    duration_seconds: int
    command_count: int
    risk_score: int
    risk: str
    classification_chain: list[str] = []
    mitre_technique_ids: list[str] = []
    analysis_state: str
    country: str | None = None
    username: str | None = None


class SessionTimelineEvent(CamelModel):
    id: str
    timestamp: str
    kind: str
    label: str
    detail: str | None = None
    severity: str
    technique_id: str | None = None
