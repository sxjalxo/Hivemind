"""Clerk session-token verification.

The property under test is not "a good token works" -- it is that a BAD one
does not, and that every route is covered rather than the handful somebody
remembered. An API that authenticates most of itself is not authenticated.

Tokens here are signed with a throwaway RSA key and served through a stubbed
JWKS, so nothing contacts Clerk and no real credential appears in the suite.
"""

import asyncio
import base64
import time
import uuid
from typing import ClassVar

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import auth
from app.config import get_settings
from app.main import app

ISSUER = "https://test-instance.clerk.accounts.dev"
PARTY = "http://localhost:8080"


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def auth_on(monkeypatch):
    """Turn auth on and serve a throwaway JWKS instead of Clerk's."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n),
                "e": _b64(numbers.e),
            }
        ]
    }

    class _FakeJwkClient:
        def __init__(self, url, **kwargs):
            self._keys = jwks["keys"]

        def get_signing_key_from_jwt(self, token):
            header = jwt.get_unverified_header(token)
            for entry in self._keys:
                if entry["kid"] == header.get("kid"):
                    return jwt.PyJWK(entry)
            raise jwt.PyJWTError("no key for that kid")

    monkeypatch.setattr(auth, "PyJWKClient", _FakeJwkClient)
    auth.reset_jwks_cache()
    get_settings.cache_clear()
    monkeypatch.setenv("CLERK_ISSUER", ISSUER)
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", '["' + PARTY + '"]')
    yield _pem(key)
    get_settings.cache_clear()
    auth.reset_jwks_cache()


def _token(pem: str, **overrides) -> str:
    claims = {
        "sub": "user_test",
        "iss": ISSUER,
        "azp": PARTY,
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-key"})


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


# --- with auth configured -------------------------------------------------


@pytest.mark.asyncio
async def test_a_request_with_no_token_is_refused(auth_on) -> None:
    async with _client() as client:
        response = await client.get("/api/status")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_a_valid_token_is_accepted(auth_on) -> None:
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + _token(auth_on)}
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_an_expired_token_is_refused(auth_on) -> None:
    stale = _token(auth_on, exp=int(time.time()) - 600, iat=int(time.time()) - 700)
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + stale}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_token_from_another_clerk_instance_is_refused(auth_on) -> None:
    """A perfectly valid token signed for somebody else's instance."""
    foreign = _token(auth_on, iss="https://someone-else.clerk.accounts.dev")
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + foreign}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_token_for_another_application_is_refused(auth_on) -> None:
    """Clerk mints tokens per application on one instance.

    Without the `azp` check a token from a sibling app on the same instance
    verifies against the same JWKS and would be accepted here.
    """
    other_app = _token(auth_on, azp="https://some-other-app.example")
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + other_app}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_token_signed_with_the_wrong_key_is_refused(auth_on) -> None:
    """The signature is the point; everything else is a claim check."""
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _token(_pem(attacker))
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + forged}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_an_unsigned_token_is_refused(auth_on) -> None:
    """`alg: none` is the oldest JWT attack there is."""
    unsigned = jwt.encode(
        {"sub": "user_test", "iss": ISSUER, "exp": int(time.time()) + 60},
        key="",
        algorithm="none",
        headers={"kid": "test-key"},
    )
    async with _client() as client:
        response = await client.get(
            "/api/status", headers={"Authorization": "Bearer " + unsigned}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_malformed_authorization_header_is_refused(auth_on) -> None:
    for header in ("", "Bearer", "Bearer ", "Basic abc", _token(auth_on)):
        async with _client() as client:
            response = await client.get("/api/status", headers={"Authorization": header})
        assert response.status_code == 401, "accepted " + repr(header)


@pytest.mark.asyncio
async def test_every_api_route_is_covered_not_just_the_ones_we_remembered(auth_on) -> None:
    """The dependency sits on the router, so this holds for routes added later.

    Enumerated from the app's own routing table rather than a hand-written
    list, which is what makes it a statement about the API instead of about
    whoever wrote the test.
    """
    # Read from the OpenAPI schema rather than `app.routes`: that is the
    # surface actually served, it already carries the /api prefix, and it does
    # not depend on how this FastAPI version happens to nest included routers.
    schema = app.openapi()["paths"]
    operations = [
        (method.upper(), path)
        for path, methods in schema.items()
        if path.startswith("/api")
        for method in methods
        if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    ]
    assert len(operations) >= 15, "expected the full API surface, saw " + str(
        len(operations)
    )

    async with _client() as client:
        for method, path in operations:
            # A path param's value is irrelevant: authentication is refused
            # before the handler ever runs, so any placeholder works.
            concrete = path
            for name in ("run_id", "analysis_id"):
                concrete = concrete.replace("{" + name + "}", str(uuid.uuid4()))
            for name in ("session_id", "id", "event_id", "honeypot_id"):
                concrete = concrete.replace("{" + name + "}", "x")
            concrete = concrete.replace("{ip}", "1.2.3.4")

            response = await client.request(method, concrete)
            assert response.status_code == 401, (
                method + " " + concrete + " returned " + str(response.status_code)
                + " without a token"
            )


# --- with auth unconfigured (the default) ---------------------------------


@pytest.mark.asyncio
async def test_an_unconfigured_deployment_stays_open() -> None:
    """The documented fail-open default, pinned so it cannot change silently."""
    assert get_settings().auth_enabled is False

    async with _client() as client:
        response = await client.get("/api/status")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_status_reports_authentication_as_disabled() -> None:
    """Fail-open has to be VISIBLE, not merely documented."""
    async with _client() as client:
        response = await client.get("/api/status")

    row = next(r for r in response.json() if r["id"] == "authentication")
    assert row["state"] == "disconnected"
    assert "OPEN" in row["detail"]


# --- the websocket channels ----------------------------------------------


def test_the_token_is_read_from_the_subprotocol_not_the_query_string() -> None:
    """A browser cannot set an Authorization header on a handshake.

    The token must not travel in the URL either: query strings reach access
    logs, proxy logs and browser history, and a session token is a bearer
    credential.
    """

    class _FakeWs:
        headers: ClassVar[dict] = {"sec-websocket-protocol": "clerk, clerk-token.abc.def.ghi"}

    token, echo = auth.websocket_token(_FakeWs())
    assert token == "abc.def.ghi"
    assert echo == "clerk"


def test_no_offered_protocol_yields_no_token_and_nothing_to_echo() -> None:
    class _FakeWs:
        headers: ClassVar[dict] = {}

    assert auth.websocket_token(_FakeWs()) == (None, None)


@pytest.mark.asyncio
async def test_a_websocket_without_a_token_is_closed_before_accept(auth_on) -> None:
    """Every progress channel is keyed by an id the POST just handed out.

    Unauthenticated, anyone who learns a run id can read that run's stages.
    """
    closed: list[int] = []

    class _FakeWs:
        headers: ClassVar[dict] = {}

        async def close(self, code: int = 1000) -> None:
            closed.append(code)

        async def accept(self, **kwargs):  # pragma: no cover - asserts absence
            raise AssertionError("accepted a handshake that carried no token")

    ok, echo = await auth.authenticate_websocket(_FakeWs())

    assert ok is False
    assert echo is None
    assert closed == [1008]


@pytest.mark.asyncio
async def test_a_websocket_with_a_valid_token_is_allowed(auth_on) -> None:
    class _FakeWs:
        headers: ClassVar[dict] = {"sec-websocket-protocol": "clerk, clerk-token." + _token(auth_on)}

        async def close(self, code: int = 1000) -> None:  # pragma: no cover
            raise AssertionError("closed a valid handshake")

    ok, echo = await auth.authenticate_websocket(_FakeWs())

    assert ok is True
    assert echo == "clerk"


@pytest.mark.asyncio
async def test_a_websocket_with_a_forged_token_is_closed(auth_on) -> None:
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    closed: list[int] = []

    class _FakeWs:
        headers: ClassVar[dict] = {"sec-websocket-protocol": "clerk, clerk-token." + _token(_pem(attacker))}

        async def close(self, code: int = 1000) -> None:
            closed.append(code)

    ok, _echo = await auth.authenticate_websocket(_FakeWs())

    assert ok is False
    assert closed == [1008]


def test_a_rejection_never_echoes_the_token(auth_on) -> None:
    """Error text is logged and returned; it must name the check, not the
    credential."""
    token = _token(auth_on, iss="https://someone-else.clerk.accounts.dev")
    try:
        auth.verify_token(token)
    except auth.AuthError as exc:
        message = str(exc)
    else:  # pragma: no cover
        raise AssertionError("a foreign issuer was accepted")

    assert token not in message
    assert token.split(".")[1] not in message


@pytest.mark.asyncio
async def test_stream_progress_itself_refuses_an_unauthenticated_handshake(
    auth_on,
) -> None:
    """Drives the real handler, not `authenticate_websocket` directly.

    The tests above verify the checker. This verifies the CALLER actually
    consults it -- the gap that let a mutation removing the call from
    `stream_progress` pass every one of them.
    """
    from app.workers.queue import stream_progress

    events: list[str] = []

    class _FakeWs:
        headers: ClassVar[dict] = {}

        async def accept(self, **kwargs):
            events.append("accepted")

        async def close(self, code: int = 1000) -> None:
            events.append("closed:" + str(code))

        async def receive(self):  # pragma: no cover - must never be reached
            raise AssertionError("read from an unauthenticated socket")

        async def send_json(self, payload):  # pragma: no cover
            raise AssertionError("sent to an unauthenticated socket")

    await stream_progress(_FakeWs(), "analysis:whatever")

    assert events == ["closed:1008"], events
    assert "accepted" not in events


@pytest.mark.asyncio
async def test_a_websocket_route_still_works_with_auth_on(auth_on) -> None:
    """Through the real ASGI stack, which is what caught the bug this pins.

    The `/api` router carries both HTTP and WebSocket routes and its
    dependency runs on all of them. `require_user` originally declared
    `Request`, which FastAPI cannot satisfy on a WebSocket scope -- so it
    called the dependency with no arguments and the handshake died with a
    TypeError, with auth ON or OFF. Both progress channels were broken and it
    surfaced as a socket that hung, not as a dependency error.

    Every direct unit test of the checker passed throughout. Only driving the
    route showed it.
    """
    from tests.conftest import asgi_websocket

    token = _token(auth_on)
    async with asgi_websocket(
        app,
        "/api/evaluations/" + str(uuid.uuid4()) + "/progress",
        protocols=["clerk", "clerk-token." + token],
    ) as session:
        assert session.opening["type"] == "websocket.accept", session.opening
        assert session.opening.get("subprotocol") == "clerk"


@pytest.mark.asyncio
async def test_a_websocket_route_refuses_a_handshake_with_no_token(auth_on) -> None:
    """The same route, same stack, without a credential."""
    from tests.conftest import asgi_websocket

    async with asgi_websocket(
        app, "/api/evaluations/" + str(uuid.uuid4()) + "/progress"
    ) as session:
        assert session.opening["type"] == "websocket.close", session.opening


# --- roles ----------------------------------------------------------------


def test_a_missing_or_unknown_role_reads_as_viewer_not_as_a_rejection() -> None:
    """Deliberate, and the reasoning is in `auth.ROLE_VIEWER`.

    The role arrives as a Clerk session claim, so anything that stops the
    claim propagating -- config reverted, user invited but unassigned --
    would otherwise lock every account out at once, operator included, with
    the recovery being to turn authentication off. Degrading to read-only
    cannot GRANT anything: every admin route demands the role explicitly.
    """
    assert auth.role_of({"role": "admin"}) == auth.ROLE_ADMIN
    assert auth.role_of({"role": "viewer"}) == auth.ROLE_VIEWER
    assert auth.role_of({}) == auth.ROLE_VIEWER
    assert auth.role_of(None) == auth.ROLE_VIEWER
    assert auth.role_of({"role": "superuser"}) == auth.ROLE_VIEWER
    assert auth.role_of({"role": ["admin"]}) == auth.ROLE_VIEWER
    assert auth.role_of({"role": True}) == auth.ROLE_VIEWER


@pytest.mark.asyncio
async def test_a_viewer_may_read(auth_on) -> None:
    async with _client() as client:
        response = await client.get(
            "/api/status",
            headers={"Authorization": "Bearer " + _token(auth_on, role="viewer")},
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_a_viewer_may_not_start_an_evaluation(auth_on) -> None:
    """The route that resets a honeypot's container and runs attack chains."""
    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={"honeypotId": "cowrie-01"},
            headers={"Authorization": "Bearer " + _token(auth_on, role="viewer")},
        )
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


@pytest.mark.asyncio
async def test_a_token_with_no_role_may_not_write(auth_on) -> None:
    """Read-only is the floor, not a bypass.

    The session id is deliberately one that does not exist. A negative
    authorisation test must not be CAPABLE of the side effect it guards
    against: pointed at a real seeded session, this ran a full analysis and
    wrote a report the moment a mutation check weakened `role_of` -- residue
    that then failed two unrelated tests in a later run, which is exactly the
    order-dependence this suite is supposed to be free of. With an unknown
    id, a broken gate yields 404 and leaves nothing behind.
    """
    async with _client() as client:
        response = await client.post(
            "/api/reports",
            json={"sessionId": "no-such-session-" + uuid.uuid4().hex[:8]},
            headers={"Authorization": "Bearer " + _token(auth_on)},
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_every_mutating_route_requires_admin(auth_on) -> None:
    """Enumerated from the routing table, so a POST added later is covered.

    A hand-written list of admin routes is a list of the ones somebody
    remembered. This asks the app which operations mutate and demands that
    each one refuses a viewer -- so a new write endpoint that forgets the
    dependency fails here rather than shipping open to every account.
    """
    schema = app.openapi()["paths"]
    mutating = [
        (method.upper(), path)
        for path, methods in schema.items()
        if path.startswith("/api")
        for method in methods
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
    ]
    assert mutating, "no mutating operations found -- the enumeration is broken"

    viewer = "Bearer " + _token(auth_on, role="viewer")
    async with _client() as client:
        for method, path in mutating:
            concrete = path
            for name in ("run_id", "analysis_id"):
                concrete = concrete.replace("{" + name + "}", str(uuid.uuid4()))
            for name in ("session_id", "id", "event_id", "honeypot_id"):
                concrete = concrete.replace("{" + name + "}", "x")

            response = await client.request(
                method, concrete, headers={"Authorization": viewer}, json={}
            )
            assert response.status_code == 403, (
                method + " " + concrete + " let a viewer through with "
                + str(response.status_code)
            )


@pytest.mark.asyncio
async def test_an_admin_is_not_stopped_by_the_role_check(auth_on) -> None:
    """The gate must let the operator through, or it is just an outage.

    422 is the expected answer here: the body is deliberately empty, so the
    request fails VALIDATION -- which only happens after authorisation
    passed. 403 would mean admin was refused.
    """
    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={},
            headers={"Authorization": "Bearer " + _token(auth_on, role="admin")},
        )
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_roles_are_not_enforced_when_authentication_is_off() -> None:
    """An open deployment has no identities, so it has no roles either.

    Same fail-open default `require_user` documents. Gating the buttons of a
    localhost tool that anyone can already curl would be theatre.
    """
    async with _client() as client:
        response = await client.post("/api/reports", json={})
    assert response.status_code != 403


@pytest.mark.asyncio
async def test_a_run_is_credited_to_the_verified_token_not_the_request(auth_on) -> None:
    """The actor comes from the token the gate already verified.

    A request body cannot name who it is: `StartEvaluationRequest` forbids
    extra fields, and the actor is derived from the claims the dependency
    produced. This posts a body that TRIES to claim a different identity and
    asserts the attempt is rejected outright rather than quietly ignored --
    an audit trail a caller can write to is not an audit trail.
    """
    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={
                "honeypotId": "cowrie-01",
                "startedBy": "user:somebody_else",
                "startedByLabel": "not-me@example.com",
            },
            headers={"Authorization": "Bearer " + _token(auth_on, role="admin")},
        )

    # 422 from `extra="forbid"`, not a 202 with the caller's values stored.
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_the_actor_recorded_is_the_token_subject(auth_on) -> None:
    """`Actor.from_claims` is fed the verified claims, so the id is the one
    the signature proved -- not one the caller chose."""
    claims = auth.verify_token(_token(auth_on, sub="user_specific", email="who@example.com"))
    actor = auth.Actor.from_claims(claims)

    assert actor.key == "user:user_specific"
    assert actor.label == "who@example.com"


@pytest.mark.asyncio
async def test_the_stored_actor_comes_from_the_route_not_just_the_helper(
    auth_on, monkeypatch
) -> None:
    """Drives POST /api/evaluations and reads back what was persisted.

    The unit tests cover `Actor.from_claims`; this covers the wiring. A
    mutation that made the router pass `Actor.unrecorded()` instead of the
    verified claims passed every one of them -- the audit trail would have
    recorded nothing while looking entirely correct.
    """
    from sqlalchemy import select

    from app.db.models import EvaluationRun
    from app.db.session import get_session_factory
    from app.services.evaluation import runs

    seen: dict = {}

    async def _capture_actor(honeypot_id, run_id=None, actor=None):
        seen["actor"] = actor
        return run_id

    monkeypatch.setattr(runs, "start_run", _capture_actor)

    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={"honeypotId": "cowrie-01"},
            headers={
                "Authorization": "Bearer "
                + _token(auth_on, role="admin", sub="user_auditme", email="audit@example.com")
            },
        )

    assert response.status_code == 202, response.text
    # Give the dispatched task a turn to run.
    for _ in range(50):
        if "actor" in seen:
            break
        await asyncio.sleep(0.02)

    assert seen.get("actor") is not None, "the route dispatched without an actor"
    assert seen["actor"].key == "user:user_auditme"
    assert seen["actor"].label == "audit@example.com"

    # And nothing the caller sent could have influenced it.
    async with get_session_factory()() as db:
        stored = (
            await db.execute(
                select(EvaluationRun.started_by).where(EvaluationRun.started_by == "user:somebody_else")
            )
        ).scalars().all()
    assert stored == []


@pytest.mark.asyncio
async def test_admin_on_one_honeypot_may_not_act_on_another(auth_on) -> None:
    """The point of per-honeypot roles, through the route.

    Admin on `vm-baseline`, viewer everywhere else. The coarse gate lets this
    caller past -- they are admin somewhere -- and the specific check refuses
    the honeypot they actually named.
    """
    token = _token(
        auth_on,
        role="viewer",
        roles={"vm-baseline": "admin"},
    )
    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={"honeypotId": "cowrie-01"},
            headers={"Authorization": "Bearer " + token},
        )

    assert response.status_code == 403, response.text
    assert "cowrie-01" in response.json()["detail"]


@pytest.mark.asyncio
async def test_admin_on_a_honeypot_may_act_on_that_one(auth_on) -> None:
    """422 means authorisation passed and the body was then validated.

    `cowrie-01` is not in EVALUATION_TARGETS here, so a 404 would also mean
    the gate let it through -- but 422 on a deliberately malformed body is
    the earliest unambiguous proof, since it comes from the same request
    solving that would have raised 403 first.
    """
    token = _token(auth_on, role="viewer", roles={"cowrie-01": "admin"})
    async with _client() as client:
        response = await client.post(
            "/api/evaluations",
            json={},
            headers={"Authorization": "Bearer " + token},
        )

    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_a_caller_who_is_admin_nowhere_is_refused_before_any_lookup(
    auth_on, monkeypatch
) -> None:
    """The coarse gate exists so a pure viewer cannot probe session ids.

    `/api/analyze/{id}` has to resolve the session to learn its honeypot. If
    the only check ran after that, a viewer would get 404 for a session that
    does not exist and 403 for one that does -- which is an existence oracle.
    """
    from app.routers import analyze as analyze_router

    async def _must_not_run(*args, **kwargs):  # pragma: no cover - asserts absence
        raise AssertionError("a session was resolved for a caller who is admin nowhere")

    monkeypatch.setattr(analyze_router, "get_session", _must_not_run)

    async with _client() as client:
        response = await client.post(
            "/api/analyze/some-session",
            headers={"Authorization": "Bearer " + _token(auth_on, role="viewer")},
        )

    assert response.status_code == 403
