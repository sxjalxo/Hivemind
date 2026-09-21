"""Who started an evaluation run.

A run resets a honeypot's container and executes attack chains against it, so
the record has to be able to answer "who did this". The property under test is
not that an id is stored -- it is that the three situations which would all
otherwise be a null stay three distinguishable values.
"""

import uuid

import pytest

from tests.conftest import null_capture
from sqlalchemy import select

from app.auth import Actor
from app.db.models import EvaluationRun
from app.db.session import get_session_factory


def test_an_authenticated_actor_is_prefixed_and_keeps_its_email() -> None:
    actor = Actor.from_claims({"sub": "user_abc123", "email": "sujal@example.com"})

    assert actor.key == "user:user_abc123"
    assert actor.label == "sujal@example.com"


def test_no_authentication_is_not_the_same_value_as_no_record() -> None:
    """The distinction the whole design exists for.

    "Nobody was authenticated, because authentication was off" and "this run
    predates the audit trail" are different claims. One says an action had no
    actor; the other says we never asked. An audit trail that answers the
    same way for both lets a gap read as an anonymous action -- the same
    collapse `undetermined` prevents for findings.
    """
    unauthenticated = Actor.from_claims(None)
    unrecorded = Actor.unrecorded()

    assert unauthenticated.key == "unauthenticated"
    assert unrecorded.key == "unrecorded"
    assert unauthenticated.key != unrecorded.key
    assert unauthenticated.label is None
    assert unrecorded.label is None


def test_a_token_without_an_email_still_yields_an_identity() -> None:
    """The label is optional; the identity is not."""
    actor = Actor.from_claims({"sub": "user_abc123"})

    assert actor.key == "user:user_abc123"
    assert actor.label is None


def test_a_verified_token_with_no_subject_is_not_credited_to_anyone() -> None:
    """`verify_token` requires `sub`, so this is unreachable through the real
    path -- handled rather than asserted because the alternative is a 500 on
    an audit field, and crediting a run to `user:None` would be worse."""
    for claims in ({}, {"sub": ""}, {"sub": 123}):
        assert Actor.from_claims(claims).key == "unauthenticated"


@pytest.mark.asyncio
async def test_a_run_records_the_actor_that_started_it(monkeypatch) -> None:
    """End to end through `start_run`, not just the dataclass."""
    from app.services.evaluation import runs

    honeypot_id = "cowrie-01"
    run_id = uuid.uuid4()
    actor = Actor(key="user:user_test123", label="tester@example.com")

    async def _noop(*args, **kwargs):
        return None

    async def _fixed(*args, **kwargs):
        return "sha256:FIXED"

    monkeypatch.setattr(runs, "_reset_target", _noop)
    monkeypatch.setattr(runs, "_assert_target_reachable", _noop)
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed)
    monkeypatch.setattr(runs, "_evaluation_config_fingerprint", lambda *a, **k: "sha256:CFG")
    monkeypatch.setattr(runs, "_capture", null_capture)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_run_nmap", _noop)
    monkeypatch.setattr(runs, "_run_agent", _noop)
    monkeypatch.setattr(runs, "_run_chains", _noop)
    monkeypatch.setattr(runs, "_execute_run", _noop)

    try:
        await runs.start_run(honeypot_id, run_id=run_id, actor=actor)

        async with get_session_factory()() as db:
            row = (
                await db.execute(select(EvaluationRun).where(EvaluationRun.id == run_id))
            ).scalar_one()
            assert row.started_by == "user:user_test123"
            assert row.started_by_label == "tester@example.com"
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_a_run_started_with_no_actor_is_marked_unrecorded(monkeypatch) -> None:
    """`unrecorded` is reserved for callers that predate the audit trail.

    It is the default only so that the column can be NOT NULL; every real
    caller passes an actor, and the unauthenticated case has its own value
    rather than sharing this one.
    """
    from app.services.evaluation import runs

    run_id = uuid.uuid4()

    async def _noop(*args, **kwargs):
        return None

    async def _fixed(*args, **kwargs):
        return "sha256:FIXED"

    monkeypatch.setattr(runs, "_reset_target", _noop)
    monkeypatch.setattr(runs, "_assert_target_reachable", _noop)
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed)
    monkeypatch.setattr(runs, "_evaluation_config_fingerprint", lambda *a, **k: "sha256:CFG")
    monkeypatch.setattr(runs, "_capture", null_capture)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_execute_run", _noop)

    try:
        await runs.start_run("cowrie-01", run_id=run_id)

        async with get_session_factory()() as db:
            row = (
                await db.execute(select(EvaluationRun).where(EvaluationRun.id == run_id))
            ).scalar_one()
            assert row.started_by == "unrecorded"
            assert row.started_by_label is None
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_every_stored_run_has_an_actor() -> None:
    """NOT NULL in the schema; asserted here against the real table so a row
    written by any path -- including the backfilled ones -- carries one."""
    async with get_session_factory()() as db:
        rows = (await db.execute(select(EvaluationRun.started_by))).scalars().all()

    assert all(value for value in rows), "a run exists with no recorded actor"
    for value in rows:
        assert value.startswith("user:") or value in {"unauthenticated", "unrecorded"}, value


# --- per-honeypot roles ---------------------------------------------------


def test_an_explicit_per_honeypot_role_beats_the_global_one() -> None:
    """Including when it is LOWER.

    Naming a honeypot `viewer` while holding a global `admin` has to mean
    something, or the map is decoration. A resolution order that only ever
    widens access is not an access-control list.
    """
    from app.auth import role_for

    claims = {"role": "admin", "roles": {"cowrie-01": "viewer"}}

    assert role_for(claims, "cowrie-01") == "viewer"
    assert role_for(claims, "anything-else") == "admin"


def test_an_unlisted_honeypot_falls_back_to_the_global_role() -> None:
    """What keeps a single-role account working everywhere it used to."""
    from app.auth import role_for

    assert role_for({"role": "admin"}, "cowrie-01") == "admin"
    assert role_for({"role": "viewer"}, "cowrie-01") == "viewer"
    assert role_for({}, "cowrie-01") == "viewer"
    assert role_for(None, "cowrie-01") == "viewer"


def test_a_malformed_entry_is_dropped_rather_than_honoured() -> None:
    """The map is written by hand through the Clerk API.

    `{"cowrie-01": "Admin"}` is a live possibility, and a value nobody
    defined has no correct interpretation. Dropping it falls through to the
    global role -- an unreadable grant is not a grant.
    """
    from app.auth import role_for, roles_map

    claims = {
        "role": "viewer",
        "roles": {"a": "Admin", "b": "root", "c": 1, 4: "admin", "ok": "admin"},
    }

    assert roles_map(claims) == {"ok": "admin"}
    assert role_for(claims, "a") == "viewer"
    assert role_for(claims, "ok") == "admin"


def test_a_roles_claim_that_is_not_a_map_is_ignored() -> None:
    from app.auth import roles_map

    for bad in ("admin", ["admin"], 7, None):
        assert roles_map({"roles": bad}) == {}


def test_admin_anywhere_is_what_the_coarse_gate_asks() -> None:
    """It runs before a route knows which honeypot it is acting on."""
    from app.auth import is_admin_anywhere

    assert is_admin_anywhere({"role": "admin"}) is True
    assert is_admin_anywhere({"role": "viewer", "roles": {"x": "admin"}}) is True
    assert is_admin_anywhere({"role": "viewer", "roles": {"x": "viewer"}}) is False
    assert is_admin_anywhere({}) is False
    assert is_admin_anywhere(None) is False
