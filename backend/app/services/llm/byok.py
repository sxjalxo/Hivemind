import json

import httpx
from pydantic import BaseModel, ValidationError

from app.services.llm.base import LLMValidationError

_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/chat/completions",
}


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

    async def complete_json[T: BaseModel](self, prompt: str, schema: type[T]) -> T:
        headers, payload = self._request(prompt, json.dumps(schema.model_json_schema()))
        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(
                _ENDPOINTS[self._provider], headers=headers, json=payload
            )
            response.raise_for_status()
            text = self._extract(self._provider, response.json())

        try:
            return schema.model_validate(json.loads(text))
        except (ValidationError, json.JSONDecodeError, KeyError) as exc:
            raise LLMValidationError(
                f"{self._model} returned a response the schema rejected: {exc}"
            ) from exc
