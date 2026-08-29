from fastapi import APIRouter, HTTPException

from app.es.queries import get_event_by_id
from app.models.event import HoneypotEvent

router = APIRouter()


@router.get("/events/{event_id}", response_model=HoneypotEvent)
async def get_event(event_id: str) -> HoneypotEvent:
    """Resolve an EvidenceRef to its source event.

    This is what makes evidence a pointer rather than a copied string.
    """
    event = await get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"unknown event {event_id}")
    return event
