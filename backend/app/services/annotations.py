"""Analyst tags and notes on sessions. See `app.db.models.SessionAnnotation`."""

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth import Actor
from app.db.models import SessionAnnotation
from app.db.session import get_session_factory
from app.models.session import Annotation

# Tags are for grouping and filtering, so they are normalised: lowercase, no
# spaces, a short safe alphabet. `Botnet`, `botnet ` and `BOTNET` are one tag.
_TAG = re.compile(r"[a-z0-9][a-z0-9._:-]{0,39}")
_NOTE_MAX = 2000


class AnnotationError(ValueError):
    """The annotation is malformed; the message says how."""


def normalise(kind: str, body: str) -> str:
    """The stored form of an annotation body, or AnnotationError. Pure."""
    if "\x00" in body:
        # Postgres cannot store it; refused here rather than failing in asyncpg as a 500.
        raise AnnotationError("an annotation cannot contain a NUL character")
    text = body.strip()
    if kind == "tag":
        tag = text.lower()
        if not _TAG.fullmatch(tag):
            raise AnnotationError(
                "a tag is 1-40 characters of a-z, 0-9, '.', '_', ':' or '-', "
                "starting with a letter or digit"
            )
        return tag
    if kind == "note":
        if not text:
            raise AnnotationError("a note cannot be empty")
        if len(text) > _NOTE_MAX:
            raise AnnotationError(f"a note is at most {_NOTE_MAX} characters")
        return text
    raise AnnotationError("kind must be 'tag' or 'note'")


def _out(row: SessionAnnotation) -> Annotation:
    return Annotation(
        id=str(row.id),
        session_id=row.session_id,
        kind=row.kind,
        body=row.body,
        author=row.author,
        author_label=row.author_label,
        created_at=row.created_at.isoformat(),
    )


async def list_annotations(session_id: str) -> list[Annotation]:
    async with get_session_factory()() as db:
        rows = (
            (
                await db.execute(
                    select(SessionAnnotation)
                    .where(SessionAnnotation.session_id == session_id)
                    .order_by(SessionAnnotation.created_at, SessionAnnotation.id)
                )
            )
            .scalars()
            .all()
        )
    return [_out(r) for r in rows]


async def add_annotation(session_id: str, kind: str, body: str, actor: Actor) -> Annotation:
    """Store one annotation. Adding a tag the session already has returns that tag."""
    stored = normalise(kind, body)
    row = SessionAnnotation(
        session_id=session_id,
        kind=kind,
        body=stored,
        author=actor.key,
        author_label=actor.label,
        created_at=datetime.now(UTC),
    )
    async with get_session_factory()() as db:
        db.add(row)
        try:
            await db.commit()
        except IntegrityError:
            # The partial unique index: this tag is already on the session.
            await db.rollback()
            existing = (
                await db.execute(
                    select(SessionAnnotation).where(
                        SessionAnnotation.session_id == session_id,
                        SessionAnnotation.kind == "tag",
                        SessionAnnotation.body == stored,
                    )
                )
            ).scalar_one()
            return _out(existing)
        await db.refresh(row)
    return _out(row)


async def delete_annotation(session_id: str, annotation_id: str) -> bool:
    """True if it existed ON THIS SESSION; an id from another session is not found."""
    try:
        parsed = uuid.UUID(annotation_id)
    except ValueError:
        return False
    async with get_session_factory()() as db:
        row = await db.get(SessionAnnotation, parsed)
        if row is None or row.session_id != session_id:
            return False
        await db.delete(row)
        await db.commit()
    return True
