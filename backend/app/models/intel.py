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
    # Cowrie's raw `size` is stripped as known-noise by the ingest pipeline, so
    # it is omitted (not 0) whenever the source never recorded it.
    size: int | None = None


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
    # How many neighbours scored above zero in total. `similarity` itself is
    # cut to the top few for display, so without this a consumer cannot tell a
    # complete list of 5 from the first 5 of 30.
    similarity_total: int = 0
    # False when the command sets behind `similarity` were truncated by an
    # aggregation cap. `similarity` is then empty: a score computed from a
    # subset of an attacker's commands is wrong, and presenting it as exact is
    # the failure mode this project exists to avoid.
    similarity_complete: bool = True
    similarity_incomplete_reason: str | None = None
    attack_pattern: list[str]
