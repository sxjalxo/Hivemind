"""Read scoping: who may SEE one honeypot's operational record.

The semantics under test, stated once here because the rest of the file is
the proof of them:

  * Roles form a ladder -- `none` < `viewer` < `admin`.
  * The GLOBAL role (`role`) is the default on every honeypot, including ones
    the per-honeypot map never mentions. **This fallback is the thing most
    at risk from a scoping change**, so it is asserted directly: an account
    holding only a global role must keep reading every sensor, and must not
    lose one the moment some unrelated entry appears in its map.
  * The per-honeypot map (`roles`) OVERRIDES that default, up or down.
    `{"cowrie-01": "none"}` hides exactly that sensor.
  * Reads require anything above `none`. Writes still require exactly
    `admin`, unchanged.
  * Threat intelligence is NOT scoped, deliberately -- it correlates
    indicators across honeypots, so filtering it by sensor removes the
    feature rather than securing it.

Access is therefore expressed as explicit DENIAL, never as "the honeypots
named in your map". The alternative reads access off the map's keys, which
would silently strip every sensor from a global-role account the first time
anyone added a single entry to it.
"""

import httpx
import pytest

from app import auth
from app.main import app
from tests.test_auth import _token, auth_on  # noqa: F401 - auth_on is a fixture

SEEDED = "seed-botnet-01"
SEEDED_HONEYPOT = "cowrie-01"
OTHER_HONEYPOT = "matrix-hardened"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _auth(pem: str, **overrides) -> dict[str, str]:
    return {"Authorization": "Bearer " + _token(pem, **overrides)}


# --- semantics, independent of any route ----------------------------------


def test_the_ladder_has_a_rung_below_viewer() -> None:
    """Without `none` there is no value that denies, so nothing can be scoped."""
    assert auth.role_of({"role": "none"}) == auth.ROLE_NONE
    assert auth.role_of({"role": "viewer"}) == auth.ROLE_VIEWER
    assert auth.role_of({"role": "admin"}) == auth.ROLE_ADMIN


def test_an_unknown_role_is_still_viewer_not_denied() -> None:
    """Unchanged, and load-bearing.

    A claim that failed to propagate must cost write access, never read
    access -- degrading to `none` would lock an operator out of their own
    console on a Clerk misconfiguration, which is exactly the failure
    `role_of` was written to avoid.
    """
    assert auth.role_of({}) == auth.ROLE_VIEWER
    assert auth.role_of(None) == auth.ROLE_VIEWER
    assert auth.role_of({"role": "superuser"}) == auth.ROLE_VIEWER
    assert auth.role_of({"role": "None"}) == auth.ROLE_VIEWER


def test_the_global_role_still_answers_for_an_unmapped_honeypot() -> None:
    """The fallback a scoping change could most easily have destroyed."""
    claims = {"role": "admin", "roles": {OTHER_HONEYPOT: "none"}}
    assert auth.role_for(claims, SEEDED_HONEYPOT) == auth.ROLE_ADMIN
    assert auth.role_for(claims, "a-honeypot-nobody-named") == auth.ROLE_ADMIN
    assert auth.role_for(claims, OTHER_HONEYPOT) == auth.ROLE_NONE


def test_an_explicit_denial_outranks_a_global_admin() -> None:
    claims = {"role": "admin", "roles": {SEEDED_HONEYPOT: "none"}}
    assert auth.role_for(claims, SEEDED_HONEYPOT) == auth.ROLE_NONE


def test_a_malformed_entry_is_dropped_and_said_out_loud(caplog) -> None:
    """The asymmetry this change introduced, pinned so it stays visible.

    Before `none`, every map entry was a grant and dropping an unreadable one
    could only cost access. A denial is the opposite: `"None"` is dropped,
    falls through to the global role, and the sensor stays readable. The
    conservative-for-grants rule is kept, so the log line is the only thing
    standing between a typo and a denial that silently did not take.
    """
    import logging

    with caplog.at_level(logging.WARNING):
        kept = auth.roles_map({"roles": {SEEDED_HONEYPOT: "None", OTHER_HONEYPOT: "none"}})

    assert kept == {OTHER_HONEYPOT: auth.ROLE_NONE}
    assert SEEDED_HONEYPOT in caplog.text


# --- the read gate --------------------------------------------------------


def test_reads_are_open_when_authentication_is_off() -> None:
    """An open deployment has no identities, so it has no denials."""
    assert get_auth_disabled_can_read() is True


def get_auth_disabled_can_read() -> bool:
    # Settings default to auth off in the suite; a denial in the claims must
    # not matter when there is nobody to deny.
    return auth.can_read({"roles": {SEEDED_HONEYPOT: "none"}}, SEEDED_HONEYPOT)


@pytest.mark.asyncio
async def test_a_global_role_alone_reads_every_sensor(auth_on) -> None:  # noqa: F811
    """The non-regression: no map, nothing hidden."""
    async with _client() as client:
        response = await client.get(
            "/api/sessions", params={"limit": 200}, headers=_auth(auth_on, role="viewer")
        )
    assert response.status_code == 200
    assert any(s["honeypotId"] == SEEDED_HONEYPOT for s in response.json())


@pytest.mark.asyncio
async def test_denying_one_sensor_leaves_the_others_readable(auth_on) -> None:  # noqa: F811
    """Scoping must subtract one sensor, not collapse to an allow-list."""
    async with _client() as client:
        response = await client.get(
            "/api/sessions",
            params={"limit": 200},
            headers=_auth(auth_on, role="viewer", roles={OTHER_HONEYPOT: "none"}),
        )
    assert response.status_code == 200
    rows = response.json()
    assert all(s["honeypotId"] != OTHER_HONEYPOT for s in rows)
    assert any(s["honeypotId"] == SEEDED_HONEYPOT for s in rows)


@pytest.mark.asyncio
async def test_a_denied_sensors_sessions_are_absent_from_the_list(auth_on) -> None:  # noqa: F811
    async with _client() as client:
        response = await client.get(
            "/api/sessions",
            params={"limit": 200},
            headers=_auth(auth_on, role="admin", roles={SEEDED_HONEYPOT: "none"}),
        )
    assert response.status_code == 200
    rows = response.json()
    assert all(s["honeypotId"] != SEEDED_HONEYPOT for s in rows)
    assert SEEDED not in {s["id"] for s in rows}


@pytest.mark.asyncio
async def test_a_denied_session_is_404_not_403(auth_on) -> None:  # noqa: F811
    """403 would confirm the session exists, which is the thing being hidden."""
    async with _client() as client:
        headers = _auth(auth_on, role="admin", roles={SEEDED_HONEYPOT: "none"})
        detail = await client.get(f"/api/sessions/{SEEDED}", headers=headers)
        events = await client.get(f"/api/sessions/{SEEDED}/events", headers=headers)
        timeline = await client.get(f"/api/sessions/{SEEDED}/timeline", headers=headers)

    assert detail.status_code == 404
    assert events.status_code == 404
    assert timeline.status_code == 404


@pytest.mark.asyncio
async def test_the_same_session_is_readable_without_the_denial(auth_on) -> None:  # noqa: F811
    """The 404 above has to come from the scope, not from a missing session."""
    async with _client() as client:
        response = await client.get(
            f"/api/sessions/{SEEDED}", headers=_auth(auth_on, role="viewer")
        )
    assert response.status_code == 200
    assert response.json()["id"] == SEEDED


@pytest.mark.asyncio
async def test_logs_are_scoped(auth_on) -> None:  # noqa: F811
    async with _client() as client:
        response = await client.get(
            "/api/logs",
            params={"honeypotId": SEEDED_HONEYPOT, "pageSize": 50},
            headers=_auth(auth_on, role="viewer", roles={SEEDED_HONEYPOT: "none"}),
        )
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    # The total has to drop too: a filter applied after the query would leave
    # a count that still described the hidden sensor.
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_analyses_of_a_denied_sensor_are_absent(auth_on) -> None:  # noqa: F811
    async with _client() as client:
        headers = _auth(auth_on, role="admin", roles={SEEDED_HONEYPOT: "none"})
        response = await client.get("/api/analysis", params={"limit": 200}, headers=headers)
    assert response.status_code == 200
    assert all(a["sessionId"] != SEEDED for a in response.json())


# --- what stays global ----------------------------------------------------


@pytest.mark.asyncio
async def test_threat_intelligence_is_not_scoped(auth_on) -> None:  # noqa: F811
    """Deliberate, and the reason read scoping stopped where it did.

    Indicators are correlated ACROSS honeypots -- an IOC seen on two sensors
    is a different and stronger claim than one seen on either. Filtering this
    surface by sensor does not secure the feature, it deletes it. If this
    test ever fails because somebody scoped it, that is a product decision
    and `OVERVIEW.md` has to change with it.
    """
    async with _client() as client:
        open_view = await client.get(
            "/api/threat-intelligence", params={"limit": 200}, headers=_auth(auth_on, role="viewer")
        )
        scoped_view = await client.get(
            "/api/threat-intelligence",
            params={"limit": 200},
            headers=_auth(auth_on, role="viewer", roles={SEEDED_HONEYPOT: "none"}),
        )

    assert open_view.status_code == scoped_view.status_code == 200
    assert open_view.json() == scoped_view.json()
    assert open_view.json(), "the seed corpus should yield indicators to compare"


@pytest.mark.asyncio
async def test_a_denial_does_not_grant_a_write(auth_on) -> None:  # noqa: F811
    """Writes still require `admin` explicitly; `none` cannot be mistaken for it."""
    async with _client() as client:
        response = await client.post(
            f"/api/analyze/{SEEDED}",
            headers=_auth(auth_on, role="viewer", roles={SEEDED_HONEYPOT: "none"}),
        )
    assert response.status_code == 403
