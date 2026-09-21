"""Postgres advisory locks, for guarding work that must not run twice at once.

Extracted from `app.routers.evaluation`, which worked this protocol out and
documented why each part of it is the way it is. It is subtle enough that a
second caller copying it would eventually copy it slightly wrong -- the
release in particular, where the obvious implementation leaks the lock onto
an unrelated later request.

Why an advisory lock rather than a status column plus a SELECT: that check is
a TOCTOU with nothing behind it. Two concurrent requests both read "not
running" and both proceed. A partial unique index would close it for rows
that exist, but not for the window before the row is inserted -- and for
session analysis there is no status column to read in the first place.
"""

import hashlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.db.session import get_engine

logger = logging.getLogger(__name__)


def lock_key(namespace: bytes, name: str) -> int:
    """A stable signed 64-bit advisory-lock key for one named thing.

    `pg_try_advisory_lock` takes a bigint and the names here are strings, so
    the name is hashed rather than mapped through a table. `namespace` keeps
    one caller's key space disjoint from every other caller's: two subsystems
    locking on the same id -- an analysis of session "s-1" and anything else
    named "s-1" -- must not block each other.
    """
    digest = hashlib.sha256(namespace + name.encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def acquire(namespace: bytes, name: str) -> AsyncConnection | None:
    """Take the lock, or return None if someone already holds it.

    Session-scoped, not `pg_advisory_xact_lock`: a caller may need to hold
    this across many pooled sessions and minutes of work, so it is pinned to
    one connection that the caller holds for the duration and hands back to
    `release`. Postgres drops a session lock when its connection dies, so a
    killed process cannot leave a name locked out forever -- unlike a status
    column, which needs a reconciliation sweep to clear.

    `commit()` after acquiring so the connection sits idle rather than idle
    in transaction for the whole job; a session-level advisory lock is not
    released by a commit.
    """
    connection = await get_engine().connect()
    try:
        held = (
            await connection.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": lock_key(namespace, name)}
            )
        ).scalar()
        await connection.commit()
    except BaseException:
        await connection.close()
        raise
    if not held:
        await connection.close()
        return None
    return connection


async def release(connection: AsyncConnection, namespace: bytes, name: str) -> None:
    """Release explicitly, then return the connection to the pool.

    Closing alone is NOT enough: the pool hands the same DBAPI connection out
    again after a rollback, and a rollback does not release a session-level
    advisory lock. Skipping the unlock leaks it onto an unrelated later
    caller, which is then refused until the process restarts.

    Never raises. It runs when the work is already over, and an error here
    must not replace or mask that work's own outcome.
    """
    try:
        await connection.execute(
            text("SELECT pg_advisory_unlock(:key)"), {"key": lock_key(namespace, name)}
        )
        await connection.commit()
    except Exception:  # noqa: BLE001 - the job is over; never mask its outcome
        logger.exception("could not release the advisory lock for %s", name)
    finally:
        await connection.close()


@asynccontextmanager
async def held(namespace: bytes, name: str) -> AsyncIterator[bool]:
    """Hold the lock for the duration of a block, for a caller that finishes
    inside one request.

    Yields False when the lock was already held, so the caller decides what
    that means -- refusing, waiting, or carrying on are all reasonable and
    none of them belong here.

    A caller whose work outlives the request cannot use this (the evaluation
    run acquires in the handler and releases in a background task); it uses
    `acquire`/`release` directly.
    """
    connection = await acquire(namespace, name)
    if connection is None:
        yield False
        return
    try:
        yield True
    finally:
        await release(connection, namespace, name)
