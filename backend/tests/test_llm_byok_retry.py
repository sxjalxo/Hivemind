"""The BYOK retry ladder.

The evaluator spends one paid call per characteristic and cannot defer one,
so a single 429 used to end that characteristic permanently and file the
result as `evaluator_failed` -- a gap in the record produced by a provider
hiccup rather than by anything the honeypot did.

Both directions are load-bearing and both are pinned here. Retrying too
little fabricates that gap. Retrying too much spends real money on a key
that was never going to work, and delays the honest failure the operator
needs to see.
"""

import httpx
import pytest
from pydantic import BaseModel

from app.services.llm import byok
from app.services.llm.base import LLMValidationError
from app.services.llm.byok import ByokClient


class _Verdict(BaseModel):
    ok: bool


def _client() -> ByokClient:
    return ByokClient(provider="anthropic", api_key="sk-test", model="claude-test")


def _ok_body() -> dict:
    return {"content": [{"text": '{"ok": true}'}]}


class _Posts:
    """Queued responses, one per attempt, counting the calls actually made.

    The count is the assertion that matters: a test that only checked the
    final outcome would pass just as happily if the client had made thirty
    paid calls to get there.
    """

    def __init__(self, *responses) -> None:
        self._responses = list(responses)
        self.calls = 0

    # No `self` for the client: an instance is not a descriptor, so patching
    # it onto the class hands it the call arguments directly rather than
    # binding it as a method.
    async def __call__(self, url, **kwargs) -> httpx.Response:
        self.calls += 1
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _response(status: int, *, body: dict | None = None, headers: dict | None = None):
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return httpx.Response(
        status, request=request, json=body or _ok_body(), headers=headers or {}
    )


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch):
    """Assert on the delays instead of waiting them out.

    Without this the 429 tests below would spend five real seconds each. The
    slept values are recorded so the backoff schedule itself stays checkable.
    """
    slept: list[float] = []

    async def _sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(byok.asyncio, "sleep", _sleep)
    return slept


async def test_a_rate_limit_is_retried_and_can_succeed(monkeypatch, _no_real_sleeping):
    # The case the whole ladder exists for: the provider says "not now", and
    # a moment later answers normally. Before this, that characteristic was
    # reported as an evaluator failure.
    posts = _Posts(_response(429), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    result = await _client().complete_json("prompt", _Verdict)

    assert result.ok is True
    assert posts.calls == 2
    assert _no_real_sleeping == [1.0]


async def test_a_server_error_is_retried(monkeypatch):
    posts = _Posts(_response(503), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    assert (await _client().complete_json("prompt", _Verdict)).ok is True
    assert posts.calls == 2


async def test_a_transport_failure_is_retried(monkeypatch):
    # Never reached the provider at all, so nothing was spent and nothing
    # was settled.
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    posts = _Posts(httpx.ConnectError("refused", request=request), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    assert (await _client().complete_json("prompt", _Verdict)).ok is True
    assert posts.calls == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_a_settled_client_error_is_not_retried(monkeypatch, status):
    # The failure that actually happens in the field is a wrong or expired
    # key. Retrying it spends the same call to receive the same answer and
    # delays the `evaluator_failed` the operator needs. If this ever starts
    # failing, a bad key costs three calls instead of one.
    posts = _Posts(_response(status), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    with pytest.raises(httpx.HTTPStatusError):
        await _client().complete_json("prompt", _Verdict)

    assert posts.calls == 1


async def test_retries_are_bounded(monkeypatch, _no_real_sleeping):
    # A persistent outage must not become open-ended spend.
    posts = _Posts(_response(429), _response(429), _response(429), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    with pytest.raises(httpx.HTTPStatusError):
        await _client().complete_json("prompt", _Verdict)

    assert posts.calls == 3
    assert _no_real_sleeping == [1.0, 4.0]


async def test_the_final_error_reaches_the_caller_unchanged(monkeypatch):
    # `evaluate_characteristic` reports `type(exc).__name__: {exc}` as the
    # stored detail, so wrapping the exhausted error in something of our own
    # would replace the provider's own words with ours in the audit trail.
    posts = _Posts(_response(429), _response(429), _response(503))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    with pytest.raises(httpx.HTTPStatusError) as caught:
        await _client().complete_json("prompt", _Verdict)

    assert caught.value.response.status_code == 503


async def test_a_retry_after_header_is_honoured(monkeypatch, _no_real_sleeping):
    posts = _Posts(_response(429, headers={"retry-after": "7"}), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    await _client().complete_json("prompt", _Verdict)

    assert _no_real_sleeping == [7.0]


async def test_an_absurd_retry_after_is_capped(monkeypatch, _no_real_sleeping):
    # A provider asking for an hour has ended the run either way; blocking
    # the evaluation to discover that helps nobody.
    posts = _Posts(_response(429, headers={"retry-after": "3600"}), _response(200))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    await _client().complete_json("prompt", _Verdict)

    assert _no_real_sleeping == [byok._MAX_RETRY_AFTER_SECONDS]


async def test_an_unparseable_retry_after_falls_back_to_the_backoff(
    monkeypatch, _no_real_sleeping
):
    # The HTTP-date form is legal and is not read; guessing at it would be
    # worse than using our own schedule.
    posts = _Posts(
        _response(429, headers={"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        _response(200),
    )
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    await _client().complete_json("prompt", _Verdict)

    assert _no_real_sleeping == [1.0]


async def test_a_schema_rejection_is_not_retried(monkeypatch):
    # The model answered; it answered wrongly. That is a product decision
    # about paid calls, not a transport failure, and re-asking it here would
    # quietly double the cost of every malformed response.
    posts = _Posts(_response(200, body={"content": [{"text": "not json"}]}))
    monkeypatch.setattr(httpx.AsyncClient, "post", posts)

    with pytest.raises(LLMValidationError):
        await _client().complete_json("prompt", _Verdict)

    assert posts.calls == 1
