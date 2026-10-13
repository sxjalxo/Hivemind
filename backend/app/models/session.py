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


class Campaign(CamelModel):
    """Sessions whose ordered, normalised command sequences are identical.

    Lists are capped for the response; every `*_count` is exact.
    """

    fingerprint: str
    # Normalised (IP literals and digests masked), from the newest session.
    commands: list[str]
    command_count: int
    session_count: int
    session_ids: list[str]
    attacker_ips: list[str]
    attacker_ip_count: int
    honeypot_ids: list[str]
    first_seen: str
    last_seen: str


class CampaignList(CamelModel):
    campaigns: list[Campaign]
    sessions_considered: int
    # False when a cap left sessions unexamined. The campaigns returned are
    # still exact for the sessions that were examined; what is missing is
    # sessions, never part of one.
    complete: bool
    incomplete_reason: str | None = None



class TwinAnalysis(CamelModel):
    session_id: str
    analysis_id: str
    classification: str
    # The model's rating, as on every other surface: an inference.
    risk: str
    created_at: str


class SessionTwins(CamelModel):
    """Sessions with the same command sequence as one session.

    `analysed` points at THEIR analyses; nothing is copied onto this session.
    """

    fingerprint: str | None
    twin_count: int
    analysed: list[TwinAnalysis]
    complete: bool
    incomplete_reason: str | None = None


class AnnotationIn(CamelModel):
    kind: str  # "tag" | "note"
    body: str


class Annotation(CamelModel):
    """An analyst's statement about a session -- neither telemetry nor model output."""

    id: str
    session_id: str
    kind: str
    body: str
    author: str
    author_label: str | None = None
    created_at: str
