from typing import Generic, TypeVar

from pydantic import Field

from app.serialization import CamelModel

T = TypeVar("T")


class SourceInfo(CamelModel):
    ip: str
    port: int | None = None
    country: str | None = None


class DestinationInfo(CamelModel):
    ip: str | None = None
    port: int | None = None


class EventInfo(CamelModel):
    action: str
    category: str
    outcome: str | None = None


class NetworkInfo(CamelModel):
    protocol: str


class UserInfo(CamelModel):
    name: str | None = None


class ProcessInfo(CamelModel):
    command_line: str | None = None
    output: str | None = None


class HoneypotInfo(CamelModel):
    id: str
    name: str


class SessionInfo(CamelModel):
    id: str


class RiskInfo(CamelModel):
    score: int
    level: str


class MitreInfo(CamelModel):
    technique_id: str | None = None
    tactic: str | None = None


class HoneypotEvent(CamelModel):
    id: str
    timestamp: str
    source: SourceInfo
    destination: DestinationInfo
    event: EventInfo
    network: NetworkInfo
    user: UserInfo | None = None
    process: ProcessInfo | None = None
    honeypot: HoneypotInfo
    session: SessionInfo
    risk: RiskInfo
    mitre: MitreInfo | None = None
    ai_classification: str | None = None
    raw: dict | None = None


class LogQuery(CamelModel):
    q: str | None = None
    honeypot_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    event_category: str | None = None
    risk: str | None = None
    technique_id: str | None = None
    session_id: str | None = None
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    page: int = 1
    page_size: int = 50


class Paginated(CamelModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
