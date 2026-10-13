"""Analyst tags and notes on sessions."""

import httpx
import pytest
from sqlalchemy import delete

from app.db.models import SessionAnnotation
from app.db.session import get_session_factory
from app.main import app
from app.seed.seeder import seed
from app.services.annotations import AnnotationError, normalise
from tests.test_auth import _token, auth_on  # noqa: F401 - auth_on is a fixture

SEEDED = "seed-recon-01"
SEEDED_HONEYPOT = "cowrie-01"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _auth(pem: str, **overrides) -> dict[str, str]:
    return {"Authorization": "Bearer " + _token(pem, **overrides)}


async def _clear(session_id: str) -> None:
    async with get_session_factory()() as db:
        await db.execute(
            delete(SessionAnnotation).where(SessionAnnotation.session_id == session_id)
        )
        await db.commit()


def test_tags_are_normalised_and_constrained():
    assert normalise("tag", "  Botnet ") == "botnet"
    assert normalise("tag", "mirai:variant-2") == "mirai:variant-2"
    for bad in ("", "two words", "-leading", "x" * 41, "<script>"):
        with pytest.raises(AnnotationError):
            normalise("tag", bad)


def test_notes_keep_their_text_but_not_their_padding():
    assert normalise("note", "  Same dropper as last week.\n") == "Same dropper as last week."
    with pytest.raises(AnnotationError):
        normalise("note", "   ")
    with pytest.raises(AnnotationError):
        normalise("note", "x" * 2001)
    with pytest.raises(AnnotationError):
        normalise("verdict", "x")


@pytest.mark.asyncio
async def test_tag_note_list_and_delete_round_trip() -> None:
    await seed(reset=True)
    await _clear(SEEDED)
    try:
        async with _client() as client:
            url = f"/api/sessions/{SEEDED}/annotations"
            first = await client.post(url, json={"kind": "tag", "body": "Botnet"})
            again = await client.post(url, json={"kind": "tag", "body": " botnet "})
            note = await client.post(url, json={"kind": "note", "body": "Same script as Monday."})
            bad = await client.post(url, json={"kind": "tag", "body": "two words"})
            listed = (await client.get(url)).json()

            # An id from this session, deleted under a DIFFERENT session's URL, is not found.
            wrong_session = await client.delete(
                f"/api/sessions/seed-botnet-01/annotations/{note.json()['id']}"
            )
            removed = await client.delete(f"{url}/{note.json()['id']}")
            after = (await client.get(url)).json()

        assert first.status_code == 201 and first.json()["body"] == "botnet"
        assert again.json()["id"] == first.json()["id"], "a tag attached twice is one tag"
        assert bad.status_code == 422
        assert [(a["kind"], a["body"]) for a in listed] == [
            ("tag", "botnet"),
            ("note", "Same script as Monday."),
        ]
        assert listed[0]["author"] == "unauthenticated"  # auth is off in this test
        assert wrong_session.status_code == 404
        assert removed.status_code == 204
        assert [a["kind"] for a in after] == ["tag"]
    finally:
        await _clear(SEEDED)


@pytest.mark.asyncio
async def test_an_unknown_session_cannot_be_annotated() -> None:
    async with _client() as client:
        response = await client.post(
            "/api/sessions/no-such-session/annotations", json={"kind": "tag", "body": "x"}
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_a_viewer_cannot_annotate(auth_on) -> None:  # noqa: F811
    """Pointed at a session that does not exist, so even a broken gate writes nothing."""
    async with _client() as client:
        response = await client.post(
            "/api/sessions/no-such-session/annotations",
            json={"kind": "tag", "body": "x"},
            headers=_auth(auth_on, role="viewer"),
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_elsewhere_is_not_admin_on_this_sensor(auth_on) -> None:  # noqa: F811
    await seed(reset=True)
    try:
        async with _client() as client:
            response = await client.post(
                f"/api/sessions/{SEEDED}/annotations",
                json={"kind": "tag", "body": "x"},
                headers=_auth(auth_on, role="admin", roles={SEEDED_HONEYPOT: "viewer"}),
            )
        assert response.status_code == 403
    finally:
        await _clear(SEEDED)


@pytest.mark.asyncio
async def test_a_denied_sensors_annotations_are_404_not_403(auth_on) -> None:  # noqa: F811
    await seed(reset=True)
    async with _client() as client:
        response = await client.get(
            f"/api/sessions/{SEEDED}/annotations",
            headers=_auth(auth_on, role="admin", roles={SEEDED_HONEYPOT: "none"}),
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_nul_bytes_are_a_clean_refusal_never_a_server_error() -> None:
    """Found by stress-testing: Postgres cannot store NUL, so it used to reach asyncpg as a 500."""
    async with _client() as client:
        path = await client.get("/api/sessions/%00/annotations")
        query = await client.get("/api/threat-intelligence", params={"q": "\x00"})
        body = await client.post(
            f"/api/sessions/{SEEDED}/annotations", json={"kind": "note", "body": "a\x00b"}
        )
    assert path.status_code == 400 and query.status_code == 400
    assert body.status_code == 422
