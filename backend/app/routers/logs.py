from typing import Annotated

from fastapi import APIRouter, Query

from app.es.queries import search_logs
from app.models.event import HoneypotEvent, LogQuery, Paginated

router = APIRouter()


@router.get("/logs", response_model=Paginated[HoneypotEvent])
async def get_logs(
    q: Annotated[str | None, Query()] = None,
    honeypot_id: Annotated[str | None, Query(alias="honeypotId")] = None,
    source_ip: Annotated[str | None, Query(alias="sourceIp")] = None,
    destination_ip: Annotated[str | None, Query(alias="destinationIp")] = None,
    protocol: Annotated[str | None, Query()] = None,
    event_category: Annotated[str | None, Query(alias="eventCategory")] = None,
    risk: Annotated[str | None, Query()] = None,
    technique_id: Annotated[str | None, Query(alias="techniqueId")] = None,
    session_id: Annotated[str | None, Query(alias="sessionId")] = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query()] = 1,
    page_size: Annotated[int, Query(alias="pageSize")] = 50,
) -> Paginated[HoneypotEvent]:
    """Bind every documented LogQuery param explicitly.

    FastAPI's Depends() on a plain Pydantic model does not reliably honor a
    field's alias when deriving the HTTP query parameter name (observed:
    every other aliased field bound correctly, but `from_` bound as the
    literal Python attribute name `from_` instead of its alias `from`, even
    though `LogQuery.model_fields["from_"].alias == "from"`). Declaring each
    parameter here with an explicit `Query(alias=...)` sidesteps that
    unreliable introspection entirely, so every parameter name that appears
    in `/openapi.json` matches what the frontend actually sends.
    """
    query = LogQuery(
        q=q,
        honeypot_id=honeypot_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        event_category=event_category,
        risk=risk,
        technique_id=technique_id,
        session_id=session_id,
        from_=from_,
        to=to,
        page=page,
        page_size=page_size,
    )
    return await search_logs(query)
