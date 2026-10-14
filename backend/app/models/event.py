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


class FileHashInfo(CamelModel):
    sha256: str | None = None


class FileInfo(CamelModel):
    """A `cowrie.session.file_download`'s payload, ECS-shaped.

    The ingest pipeline (`infra/elasticsearch/pipelines/cowrie-ecs.json`)
    renames Cowrie's raw `shasum`/`url`/`outfile` fields to
    `file.hash.sha256`/`file.url`/`file.name` on ingest; this mirrors that
    shape exactly rather than re-flattening it. Cowrie's raw `size` field is
    deliberately stripped as known-noise by the same pipeline (see its
    comment), so there is no `file.size` to model here -- a downstream
    consumer must not assume a real size is ever available.
    """

    name: str | None = None
    url: str | None = None
    hash: FileHashInfo | None = None


class UrlInfo(CamelModel):
    """The requested URL of an HTTP honeypot event (infra/webpot)."""

    path: str | None = None
    query: str | None = None


class HttpRequestInfo(CamelModel):
    method: str | None = None


class HttpResponseInfo(CamelModel):
    status_code: int | None = None


class HttpInfo(CamelModel):
    request: HttpRequestInfo | None = None
    response: HttpResponseInfo | None = None


class UserAgentInfo(CamelModel):
    original: str | None = None


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
    file: FileInfo | None = None
    url: UrlInfo | None = None
    http: HttpInfo | None = None
    user_agent: UserAgentInfo | None = None
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


class FacetValue(CamelModel):
    value: str
    count: int


class LogFacets(CamelModel):
    """The values each Log Explorer filter can actually match, with counts.

    The filter dropdowns used to be hardcoded: `SSH` where the index stores
    `ssh`, `T1222` where it stores `T1222.002`, two event categories the
    pipeline never emits. Every one of those returned zero events and looked
    like an empty honeypot. Offering only indexed values makes that impossible.
    """

    protocols: list[FacetValue]
    categories: list[FacetValue]
    techniques: list[FacetValue]
    risks: list[FacetValue]
