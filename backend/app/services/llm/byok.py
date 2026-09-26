import asyncio
import json
import logging

import httpx
from pydantic import BaseModel, ValidationError

from app.services.llm.base import LLMValidationError

logger = logging.getLogger(__name__)

_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/chat/completions",
}

# Three attempts, so two retries, and the waits between them.
#
# Why this exists at all: the evaluator spends one paid call per
# characteristic and has no way to defer one. Without a retry a single 429 --
# the most ordinary failure a cloud key has -- ends that characteristic's
# evaluation permanently, and the run reports `evaluator_failed` for
# something that would have succeeded a second later. That is a fabricated
# gap in the record, which this system treats as worse than a slow answer.
#
# Why it stays this small: a retry is a second paid call. Bounded at two, it
# cannot turn a persistent outage into an open-ended spend, and the whole
# ladder costs at most five seconds on top of a failure that was going to
# happen anyway.
_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (1.0, 4.0)

# A provider may answer 429 with `Retry-After`. Honour it, but never for
# longer than this: a provider that asks for an hour has effectively ended
# the run, and blocking the evaluation to find that out helps nobody.
_MAX_RETRY_AFTER_SECONDS = 30.0


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """The provider's own requested wait, when it gave a usable one.

    Only the delta-seconds form is read. `Retry-After` may also carry an
    HTTP-date, which needs parsing and a clock comparison to be worth
    anything; when it is not a plain number this returns None and the caller
    falls back to its own backoff rather than guessing.
    """
    raw = response.headers.get("retry-after", "").strip()
    try:
        return min(max(float(raw), 0.0), _MAX_RETRY_AFTER_SECONDS)
    except ValueError:
        return None


def _retry_delay(exc: Exception, attempt: int) -> float | None:
    """Seconds to wait before retrying `exc`, or None to give up now.

    The distinction that matters is transient versus settled. A 429 or a 5xx
    says the provider could not answer *this time*; a transport error says we
    never reached it. Both are worth a second attempt.

    Every other 4xx is settled: a wrong or expired key, a malformed request,
    a model name that does not exist. Retrying those spends the same call to
    receive the same answer, and delays the honest `evaluator_failed` the
    operator needs to see.

    A schema rejection is deliberately not handled here -- it is raised after
    this ladder, by `complete_json`. A model that answered with the wrong
    shape did answer; re-asking is a product decision about paid calls, not a
    transport concern.
    """
    if attempt >= _MAX_ATTEMPTS - 1:
        return None

    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status != 429 and status < 500:
            return None
        return _retry_after_seconds(exc.response) or _BACKOFF_SECONDS[attempt]

    # ConnectError, ReadTimeout, ConnectTimeout, RemoteProtocolError and the
    # rest share this base. Named by base class rather than individually for
    # the same reason `evaluate_characteristic` catches broadly: the cost of
    # missing one is a whole characteristic of the run.
    if isinstance(exc, httpx.TransportError):
        return _BACKOFF_SECONDS[attempt]

    return None


class ByokClient:
    """Cloud evaluator. Holds the key in memory only; never returned to a client."""

    def __init__(self, provider: str, api_key: str, model: str) -> None:
        if provider not in _ENDPOINTS:
            raise ValueError(f"unsupported BYOK provider: {provider}")
        self._provider = provider
        self._api_key = api_key
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    def _request(self, prompt: str, schema_json: str) -> tuple[dict, dict]:
        instruction = (
            f"{prompt}\n\nRespond with JSON only, matching this schema:\n{schema_json}"
        )
        if self._provider == "anthropic":
            return (
                {
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                {
                    "model": self._model,
                    "max_tokens": 4096,
                    "messages": [{"role": "user", "content": instruction}],
                },
            )
        return (
            {"Authorization": f"Bearer {self._api_key}"},
            {
                "model": self._model,
                "messages": [{"role": "user", "content": instruction}],
                "response_format": {"type": "json_object"},
            },
        )

    @staticmethod
    def _extract(provider: str, body: dict) -> str:
        if provider == "anthropic":
            return body["content"][0]["text"]
        return body["choices"][0]["message"]["content"]

    async def _post(self, headers: dict, payload: dict) -> str:
        """One completion's worth of HTTP, retried while the failure is transient.

        The retry is logged at warning level on every attempt. A silent retry
        would hide a key that is rate-limited on every run behind a run that
        merely looks slow, and "it worked, eventually, twice as often as you
        think" is exactly the kind of quiet the rest of this codebase refuses.
        """
        for attempt in range(_MAX_ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=300) as client:
                    response = await client.post(
                        _ENDPOINTS[self._provider], headers=headers, json=payload
                    )
                    response.raise_for_status()
                    return self._extract(self._provider, response.json())
            except Exception as exc:
                delay = _retry_delay(exc, attempt)
                if delay is None:
                    raise
                logger.warning(
                    "%s call failed (%s: %s); retrying in %.1fs, attempt %d of %d",
                    self._provider,
                    type(exc).__name__,
                    exc,
                    delay,
                    attempt + 2,
                    _MAX_ATTEMPTS,
                )
                await asyncio.sleep(delay)

        # Unreachable while `_retry_delay` refuses to retry the final
        # attempt, which is the guard that makes the loop terminate. Stated
        # rather than assumed: relax that guard and the loop would otherwise
        # fall out returning None, and the caller would try to parse it as a
        # completion. A loud failure here beats a JSON error three frames up.
        raise RuntimeError("BYOK retry loop ended without a result or an error")

    async def complete_json[T: BaseModel](self, prompt: str, schema: type[T]) -> T:
        headers, payload = self._request(prompt, json.dumps(schema.model_json_schema()))
        text = await self._post(headers, payload)

        try:
            return schema.model_validate(json.loads(text))
        except (ValidationError, json.JSONDecodeError, KeyError) as exc:
            raise LLMValidationError(
                f"{self._model} returned a response the schema rejected: {exc}"
            ) from exc
