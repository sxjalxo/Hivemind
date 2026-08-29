from app.serialization import CamelModel


class Indicator(CamelModel):
    id: str
    type: str
    value: str
    confidence: float
    first_seen: str
    last_seen: str
    session_ids: list[str]
    source: str
    tags: list[str]


class DownloadedFile(CamelModel):
    name: str
    sha256: str
    size: int


class SimilarAttacker(CamelModel):
    ip: str
    score: float


class AttackerProfileOut(CamelModel):
    ip: str
    risk: str
    risk_score: int
    behavior_label: str
    sessions: int
    first_seen: str
    last_seen: str
    targeted_honeypots: list[str]
    commands: list[str]
    technique_ids: list[str]
    downloaded_files: list[DownloadedFile]
    indicator_ids: list[str]
    geo: dict | None
    similarity: list[SimilarAttacker]
    attack_pattern: list[str]
