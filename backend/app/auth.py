"""Clerk session-token verification for the HTTP API and both WebSockets.

The frontend holds a Clerk session; this module is what makes that mean
something on the server. Without it the React app can require a login while
`curl http://localhost:8000/api/sessions` still answers anyone -- auth-shaped
rather than authenticated, which is worse than none because it looks solved.

Tokens are verified locally against Clerk's published JWKS. No call to Clerk
is made per request: the signing keys are fetched once and cached, so a
verification costs a signature check and nothing on the network. That matters
here because one analysis can issue dozens of requests, and because an API
that cannot reach Clerk should keep serving the operator it already
authenticated rather than fail closed on a network blip.

What is checked, and why each one:

  * **Signature** against the instance's JWKS (RS256). The core of it.
  * **`iss`** must equal the configured issuer. A valid token from somebody
    else's Clerk instance is still a valid token.
  * **`azp`** against `clerk_authorized_parties`, when configured. Clerk mints
    tokens per application on an instance; without this, a token from another
    app on the same instance is accepted here.
  * **`exp` / `nbf`** with a small leeway, because Clerk session tokens live
    ~60 seconds and a host clock a few seconds fast otherwise rejects every
    one of them with an error that reads like a broken integration.

Deliberately NOT checked: `aud`. Clerk does not set it on session tokens by
default, and `jwt.decode` with `audience=None` does not verify it -- stating
that here so nobody later reads its absence as an oversight and "fixes" it
into rejecting every real token.
"""

import logging
import time
from dataclasses import dataclass

import httpx
import jwt
from fastapi import Depends, HTTPException, WebSocket, status
from jwt import PyJWKClient
from starlette.requests import HTTPConnection

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# How long a fetched JWKS is trusted before refetching. Clerk rotates signing
# keys rarely and unannounced; `PyJWKClient` also refetches on an unknown
# `kid`, so rotation is handled promptly regardless of this interval. This
# only bounds how long a REVOKED key stays usable.
_JWKS_TTL_SECONDS = 3600

# The WebSocket subprotocol carrying the token. A browser cannot set an
# `Authorization` header on a WebSocket, and the token must not go in the
# query string -- URLs land in access logs, proxy logs and browser history,
# and a Clerk session token is a bearer credential. The subprotocol header is
# the one channel a browser will send on the handshake.
WS_TOKEN_PROTOCOL_PREFIX = "clerk-token."
WS_PROTOCOL = "clerk"


# The two roles, and what a token that names neither gets.
#
# `viewer` may read everything and change nothing. `admin` may also run the
# operations that cost something or touch a honeypot: session analysis (one
# GPU pipeline per call), report creation (which can trigger one), and
# evaluation runs, which reset a honeypot's container and execute attack
# chains against it. That last one is why this is not merely about tidiness.
#
# **A token with no role, or an unrecognised one, is a VIEWER -- not a
# rejection.** Failing closed entirely is the reflex, and it is wrong here in
# a specific way: the role arrives as a Clerk session claim
# (`session.claims.role` -> `user.public_metadata.role`), so anything that
# stops that claim propagating -- an instance config reverted, a user invited
# but not yet assigned -- would lock every account out of the application at
# once, including the operator's, with the recovery being to turn
# authentication off. Degrading to read-only instead cannot grant anything:
# every destructive and expensive route requires `admin` EXPLICITLY, so a
# missing claim loses access, never gains it. The failure is visible (the UI
# shows a viewer) and recoverable without disabling auth.
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"

# The floor, and the only way to say "not this one".
#
# Added when read paths were scoped. The problem it solves: `role_for` falls
# back to the GLOBAL role for any honeypot the map does not mention, so with
# only `admin`/`viewer` every authenticated caller is at least a viewer
# everywhere and there is no value that denies anything. Scoping reads by
# "which honeypots appear in the map" would have been the other way to get
# there, and it is the wrong way -- an account holding only a global role
# names no honeypots, so the day anyone added one entry it would silently
# lose access to every other sensor. The fallback has to survive; what was
# missing was a role BELOW viewer.
#
# So the three form a ladder -- `none` < `viewer` < `admin` -- and scoping is
# expressed as explicit denial rather than an allow-list. `{"cowrie-01":
# "none"}` means exactly that one honeypot is hidden from this account;
# everything else still resolves through the global role as before.
ROLE_NONE = "none"

_KNOWN_ROLES = frozenset({ROLE_ADMIN, ROLE_VIEWER, ROLE_NONE})


def role_of(claims: dict | None) -> str:
    """The caller's GLOBAL role -- the default where no honeypot is named.

    Prefer `role_for` wherever a honeypot is in scope. This remains the answer
    for anything not attached to one, and the fallback `role_for` uses.
    """
    if not claims:
        return ROLE_VIEWER
    role = claims.get("role")
    if isinstance(role, str) and role in _KNOWN_ROLES:
        return role
    return ROLE_VIEWER


def roles_map(claims: dict | None) -> dict[str, str]:
    """Per-honeypot roles from the token, ignoring anything malformed.

    Comes from `public_metadata.roles` on the Clerk user, surfaced as a
    `roles` claim. Shaped `{"cowrie-01": "admin", "vm-baseline": "viewer"}`.

    Entries that are not a known role are DROPPED rather than tolerated: the
    map is written by hand through the Clerk API, so `{"cowrie-01": "Admin"}`
    or a typo is a live possibility, and a value nobody defined has no correct
    interpretation. Dropping it falls through to the global role, which is the
    conservative direction -- an unreadable grant is not a grant.
    """
    raw = (claims or {}).get("roles")
    if not isinstance(raw, dict):
        return {}
    kept = {
        key: value
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, str) and value in _KNOWN_ROLES
    }
    # Dropping is still the behaviour, but it is no longer symmetric and that
    # has to be visible. Before `none` existed every entry was a GRANT, so an
    # unreadable one falling through to the global role could only ever cost
    # access. A denial is the opposite: `{"cowrie-01": "None"}` is dropped,
    # falls through to the global role, and the honeypot the operator meant
    # to hide stays readable. Nothing here can tell a typo from a value a
    # future version will understand, so the conservative-for-grants rule is
    # kept and the event is logged instead -- a denial that did not take is
    # recoverable if someone can see it happen, and silent if not.
    if len(kept) != len(raw):
        # `repr` before sorting, not after: a key does not have to be a string
        # (`{4: "admin"}` is a live possibility through the Clerk API, and
        # `test_a_malformed_entry_is_dropped_rather_than_honoured` has one),
        # and sorting str against int raises -- which would turn a log line
        # about a bad grant into a 500 on every request carrying one.
        dropped = sorted(repr(key) for key in set(raw) - set(kept))
        logger.warning(
            "ignored %d unreadable per-honeypot role entries (%s): each falls back "
            "to the global role, so an intended DENIAL among them did not take",
            len(dropped),
            ", ".join(dropped[:5]),
        )
    return kept


def role_for(claims: dict | None, honeypot_id: str) -> str:
    """The caller's role ON ONE HONEYPOT.

    Resolution order, most specific first:

      1. An explicit entry in the per-honeypot map. This wins even when it is
         LOWER than the global role -- naming a honeypot `viewer` while being
         a global admin has to mean something, or the map is decoration.
      2. The global `role` claim, for any honeypot the map does not mention.
         That is what keeps an existing single-role account working
         everywhere, and makes the map an override rather than a replacement.
      3. `viewer`, the floor.

    Two questions are answered from this one value, and they are not the same
    question:

      * **Write** -- `assert_admin_for` requires exactly `admin`.
      * **Read** -- `can_read` requires anything above `none`.

    Reads were unscoped until `ROLE_NONE` existed, because every authenticated
    caller resolved to at least `viewer` everywhere and nothing could say
    otherwise. They are scoped now for sessions, logs and analyses.

    Threat intelligence is deliberately NOT scoped and must stay that way:
    it correlates indicators ACROSS honeypots, so filtering it by sensor does
    not secure the feature, it removes it. See `OVERVIEW.md`.
    """
    explicit = roles_map(claims).get(honeypot_id)
    if explicit is not None:
        return explicit
    return role_of(claims)


def can_read(claims: dict | None, honeypot_id: str) -> bool:
    """Whether the caller may see one honeypot's operational data.

    True for every honeypot unless the roles map explicitly says `none`, which
    is what keeps an account holding only a global role working exactly as it
    did. Always True when authentication is not configured: an open deployment
    has no identities, so it has no denials either.
    """
    if not get_settings().auth_enabled:
        return True
    return role_for(claims, honeypot_id) != ROLE_NONE


def denied_honeypots(claims: dict | None) -> set[str]:
    """The honeypot ids this caller may not read, for filtering a list.

    The deny set rather than the allow set, because the allow set is "every
    honeypot that exists" minus these -- it cannot be enumerated from the
    token, and asking the registry for it would make every list route depend
    on the registry being reachable.

    Empty when authentication is off, so an open deployment filters nothing.
    """
    if not get_settings().auth_enabled:
        return set()
    denied = {
        honeypot_id
        for honeypot_id, role in roles_map(claims).items()
        if role == ROLE_NONE
    }
    # A global `none` would deny everything, which no list filter can express
    # as a set of ids. Routes call `can_read` per honeypot as well, so this is
    # only about the list path: it is refused outright there instead.
    return denied


def denies_everything(claims: dict | None) -> bool:
    """Whether the caller's GLOBAL role denies, so no list can be served.

    Separate from `denied_honeypots` because "deny these three" and "deny
    everything except where told otherwise" are different shapes, and a set of
    ids cannot carry the second.
    """
    if not get_settings().auth_enabled:
        return False
    return role_of(claims) == ROLE_NONE


def assert_can_read(claims: dict | None, honeypot_id: str) -> None:
    """404 unless the caller may read this honeypot.

    404 and not 403, which is the opposite of `assert_admin_for`, and the
    difference is deliberate. A write refusal can be a 403 because the caller
    can already SEE the thing they may not change -- the status code leaks
    nothing they did not have. A read refusal cannot: answering 403 for a
    session that exists and 404 for one that does not turns this route into an
    oracle for which sessions a hidden honeypot has, which is the thing being
    denied. `require_admin` already refuses admin-nowhere callers early for
    the same reason.
    """
    if can_read(claims, honeypot_id):
        return
    logger.warning("refused a read of honeypot %s: role is %r", honeypot_id, ROLE_NONE)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")


def is_admin_anywhere(claims: dict | None) -> bool:
    """Whether the caller is admin on anything at all.

    Backs the coarse gate that runs BEFORE a route resolves which honeypot it
    is acting on. Some routes only learn that by looking up a session, and a
    caller who is admin nowhere should be refused without that lookup
    happening at all -- otherwise a pure viewer probing session ids gets 404s
    and 403s that differ by whether the session exists.
    """
    if role_of(claims) == ROLE_ADMIN:
        return True
    return any(role == ROLE_ADMIN for role in roles_map(claims).values())


class AuthError(Exception):
    """A token that could not be verified. Never carries the token itself."""


class _JwksCache:
    """One `PyJWKClient` per JWKS URL, rebuilt when it goes stale.

    `PyJWKClient` does its own per-key caching and refetches when it is handed
    a `kid` it has not seen, which is what makes key rotation work without a
    restart. The TTL here exists for the opposite case: a key Clerk has
    REVOKED stays in a long-lived client's cache until something discards it.
    """

    def __init__(self) -> None:
        self._client: PyJWKClient | None = None
        self._url: str | None = None
        self._fetched_at: float = 0.0

    def get(self, url: str) -> PyJWKClient:
        stale = time.monotonic() - self._fetched_at > _JWKS_TTL_SECONDS
        if self._client is None or self._url != url or stale:
            # `lifespan` is not involved: building this is cheap and lazy, and
            # doing it here means a misconfigured issuer surfaces on the first
            # request that needs it rather than preventing the process from
            # starting at all.
            self._client = PyJWKClient(url, cache_keys=True)
            self._url = url
            self._fetched_at = time.monotonic()
        return self._client

    def clear(self) -> None:
        self._client = None
        self._url = None
        self._fetched_at = 0.0


_jwks = _JwksCache()


def reset_jwks_cache() -> None:
    """Drop the cached signing keys. For tests and for key revocation."""
    _jwks.clear()


def verify_token(token: str, settings: Settings | None = None) -> dict:
    """Return the token's claims, or raise `AuthError`.

    Every failure leaves by `AuthError` with a short reason. The reason is
    safe to log and safe to return: it names the CHECK that failed, never the
    token, and never a fragment of it.
    """
    settings = settings or get_settings()
    if not settings.clerk_issuer:
        raise AuthError("authentication is not configured")

    try:
        signing_key = _jwks.get(settings.jwks_url).get_signing_key_from_jwt(token)
    except httpx.HTTPError as exc:  # pragma: no cover - network dependent
        raise AuthError(f"could not reach the signing keys: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise AuthError(f"no usable signing key for this token: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - PyJWKClient raises urllib errors too
        raise AuthError(f"could not load the signing keys: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=settings.clerk_issuer.rstrip("/"),
            leeway=settings.clerk_leeway_seconds,
            # See the module docstring: Clerk session tokens carry no `aud`,
            # so verifying it would reject every real token.
            options={"verify_aud": False, "require": ["exp", "iss", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"token rejected: {exc}") from exc

    parties = settings.clerk_authorized_parties
    if parties:
        azp = claims.get("azp")
        if azp not in parties:
            # Not a formatting quibble: Clerk issues tokens per application on
            # an instance, so without this a token minted for a different app
            # verifies perfectly and is accepted here.
            raise AuthError("token was not issued for this application")

    return claims


def _bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def require_user(connection: HTTPConnection) -> dict | None:
    """FastAPI dependency: the verified claims, or 401.

    Takes `HTTPConnection`, the common base of `Request` and `WebSocket`, and
    NOT `Request`. This dependency is attached to the whole `/api` router,
    which carries two WebSocket routes as well as the HTTP ones; declaring
    `Request` made FastAPI unable to satisfy the parameter on a WebSocket
    scope, so it called this with no arguments and the handshake died with a
    TypeError -- with auth on OR off. Both progress channels were broken and
    the failure looked like a hung socket, not a dependency error.

    WebSocket scopes are then skipped deliberately rather than checked here.
    A browser cannot put a token in a handshake header, so it arrives as a
    subprotocol that this function has no way to act on: rejecting needs a
    close frame and accepting needs the protocol echoed back, both of which
    belong to the handler. `stream_progress` does the real check, and
    `test_stream_progress_itself_refuses_an_unauthenticated_handshake` is
    what stops that from quietly becoming a no-op.

    Returns None when authentication is not configured, so an unconfigured
    deployment behaves exactly as it did before this module existed. See
    `Settings.clerk_issuer` for why that default is what it is and how it is
    kept visible.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return None
    if connection.scope.get("type") == "websocket":
        return None

    token = _bearer_token(connection.headers.get("authorization"))
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a Clerk session token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_token(token, settings)
    except AuthError as exc:
        logger.warning("rejected a request: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def websocket_token(websocket: WebSocket) -> tuple[str | None, str | None]:
    """The token a browser offered on the handshake, and the protocol to echo.

    A browser sends `new WebSocket(url, [protocols])` as
    `Sec-WebSocket-Protocol`, and the server MUST echo exactly one offered
    value back or the browser fails the connection. So the client offers two:
    a marker (`clerk`) and `clerk-token.<jwt>`; we read the token from the
    second and echo the first.

    Returns `(token, protocol_to_echo)`, either of which may be None when the
    client offered nothing -- which is the ordinary case for a client that
    predates auth, and is rejected by the caller when auth is on.
    """
    offered = [
        value.strip()
        for value in (websocket.headers.get("sec-websocket-protocol") or "").split(",")
        if value.strip()
    ]
    token = None
    for value in offered:
        if value.startswith(WS_TOKEN_PROTOCOL_PREFIX):
            token = value[len(WS_TOKEN_PROTOCOL_PREFIX) :] or None
            break
    echo = WS_PROTOCOL if WS_PROTOCOL in offered else None
    return token, echo


async def authenticate_websocket(websocket: WebSocket) -> tuple[bool, str | None]:
    """Verify a WebSocket handshake, closing it if the token is bad.

    Returns `(ok, subprotocol_to_echo)`. Two values rather than one because
    the subprotocol alone cannot carry the answer: None is the correct echo
    for an authenticated client that offered no protocol AND the only thing
    to return on rejection, so a single return value makes "allowed" and
    "refused" indistinguishable at the call site. That is precisely the kind
    of collapse this codebase keeps finding, so it does not get to happen in
    the function that decides whether a stranger may read a run's progress.

    On failure the socket is closed here and `ok` is False; the caller must
    return without sending anything.

    Closed WITHOUT accepting first, which makes Starlette reject the handshake
    outright rather than opening a socket and immediately closing it. A
    browser then surfaces a connection failure instead of a socket that opened
    and went quiet -- the same distinction `stream_progress` already cares
    about between a dead channel and an idle one.
    """
    settings = get_settings()
    token, echo = websocket_token(websocket)

    if not settings.auth_enabled:
        return True, echo

    if token is None:
        logger.warning("websocket handshake carried no token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False, None
    try:
        verify_token(token, settings)
    except AuthError as exc:
        logger.warning("rejected a websocket handshake: %s", exc)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False, None
    return True, echo


async def require_admin(claims: dict | None = Depends(require_user)) -> dict | None:
    """FastAPI dependency: 403 unless the caller is an admin.

    Stacked on top of `require_user` rather than repeating its work, so a
    route carrying this gets authentication AND authorisation, in that order,
    and an unauthenticated caller still sees 401 rather than 403.

    Returns without checking when authentication is not configured -- an open
    deployment has no identities to have roles. That is the same fail-open
    default `require_user` documents, and the same reasoning: `CLERK_ISSUER`
    unset means this is a localhost tool, and locking its own operator out of
    the buttons would be theatre rather than security.

    403, not 404: the caller is authenticated and the route exists. Hiding
    that would be pretending a viewer cannot see what they are not allowed to
    do, which the UI already shows them anyway.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return claims

    if not is_admin_anywhere(claims):
        logger.warning("refused an admin-only route: caller is admin nowhere")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "this action requires the admin role on the honeypot it "
                "targets, and your account has it on none. Roles come from "
                "`public_metadata.role` and `public_metadata.roles` on the "
                "Clerk user."
            ),
        )
    return claims


def assert_admin_for(claims: dict | None, honeypot_id: str) -> None:
    """403 unless the caller is admin ON THIS HONEYPOT.

    The second half of the gate. `require_admin` runs as a dependency and can
    only ask "admin anywhere", because the honeypot a route acts on is often
    not known until the body is parsed or a session is resolved. This is the
    check that actually decides, and every mutating route calls it once it
    knows what it is about to touch.

    Both halves are kept. The coarse one refuses a caller who is admin
    nowhere before any lookup happens, so probing session ids cannot tell a
    viewer which sessions exist; this one refuses the specific action. Either
    alone would leave a hole -- the first is not specific enough, the second
    runs too late to keep a lookup from happening.

    Does nothing when authentication is not configured: an open deployment
    has no identities, so it has no roles either.
    """
    if not get_settings().auth_enabled:
        return

    role = role_for(claims, honeypot_id)
    if role != ROLE_ADMIN:
        logger.warning(
            "refused an admin action on honeypot %s to role %r", honeypot_id, role
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"this action requires the admin role on honeypot "
                f"{honeypot_id!r}; your role there is {role!r}."
            ),
        )


@dataclass(frozen=True)
class Actor:
    """Who did something, in a form a record can store without lying.

    `key` is what lands in `evaluation_runs.started_by`, and it is prefixed
    rather than a bare id so that three genuinely different situations stay
    three different values instead of collapsing into one null:

        user:<clerk_id>   an authenticated caller
        unauthenticated   no identity existed -- CLERK_ISSUER was unset, so
                          nobody was asked and nobody could have answered
        unrecorded        the run predates the audit trail entirely

    "Nobody was authenticated" and "we never asked" are not the same claim,
    and an audit trail that says the same thing for both is one that lets a
    gap read as an anonymous action. Same reasoning as `undetermined` for
    findings, and the same `legacy:`-style prefix convention `finding_key`
    uses for rows written before their question existed.

    `label` is the email the token asserted AT THE TIME, for a human reading
    the history. It is never the identity: an email can be changed or handed
    to somebody else, a Clerk user id cannot.
    """

    key: str
    label: str | None = None

    @classmethod
    def from_claims(cls, claims: dict | None) -> "Actor":
        """The actor a verified token describes.

        `claims is None` means authentication is not configured -- see
        `require_user`, which returns None in exactly that case. It does NOT
        mean an anonymous caller slipped past a configured gate; that cannot
        happen, because `require_user` raises 401 instead.
        """
        if claims is None:
            return cls.unauthenticated()
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            # A token that verified but carries no subject. `verify_token`
            # requires `sub`, so this is unreachable through the real path;
            # it is handled rather than asserted because the alternative is
            # a 500 on an audit field.
            return cls.unauthenticated()
        email = claims.get("email")
        return cls(
            key=f"user:{subject}",
            label=email if isinstance(email, str) and email else None,
        )

    @classmethod
    def unauthenticated(cls) -> "Actor":
        return cls(key="unauthenticated")

    @classmethod
    def unrecorded(cls) -> "Actor":
        return cls(key="unrecorded")
