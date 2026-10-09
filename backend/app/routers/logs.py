from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.auth import denied_honeypots, denies_everything, require_user
from app.es.queries import search_logs
from app.models.event import HoneypotEvent, LogQuery, Paginated
from app.routers.limits import MAX_PAGE_LIMIT

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
    page: Annotated[int, Query(ge=1)] = 1,
    # The only list parameter a caller already controlled, and the only one
    # with no ceiling: `pageSize=1000000` was a valid request for a million
    # events in one response. Bounded here rather than clamped, so an
    # over-large ask is a 422 naming the limit instead of a short page that
    # looks like the whole answer.
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=MAX_PAGE_LIMIT)] = 50,
    claims: dict | None = Depends(require_user),
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
    if denies_everything(claims):
        # An empty page rather than a 403: the raw log surface is a search,
        # and a caller denied every sensor has nothing to search, not an
        # error to report.
        return Paginated(items=[], total=0, page=page, page_size=page_size)
    return await search_logs(query, denied_honeypots(claims))
