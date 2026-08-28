import json

import httpx
from pydantic import BaseModel, ValidationError

from app.config import get_settings
from app.services.llm.base import LLMValidationError

# Measured on the dev machine (RTX 5060, 8GB VRAM) with `llama3.1:8b`:
# num_ctx=32768 -> `ollama ps` reports a 34%/66% CPU/GPU split (silent
# spill, ~3.5x slower per call). num_ctx=16384 still spills (16%/84%).
# num_ctx=8192 -> 100% GPU. The seed corpus never produces command output
# (all seed events have empty `output`), and `seed_output_head_lines` /
# `seed_output_tail_lines` (20/20) bound any real captured output that
# does appear, so compacted session prompts stay well under 8192 tokens
# in the common case. 8192 also matches this model's Ollama default.
_NUM_CTX = 8192


class OllamaClient:
    def __init__(self, host: str, model: str, temperature: float) -> None:
        self._host = host.rstrip("/")
        self._model = model
        self._temperature = temperature

    @property
    def model_name(self) -> str:
        return self._model

    async def complete_json[T: BaseModel](self, prompt: str, schema: type[T]) -> T:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "format": schema.model_json_schema(),
            "options": {"temperature": self._temperature, "num_ctx": _NUM_CTX},
        }
        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(f"{self._host}/api/generate", json=payload)
            response.raise_for_status()
            body = response.json()

        try:
            return schema.model_validate(json.loads(body["response"]))
        except (ValidationError, json.JSONDecodeError, KeyError) as exc:
            raise LLMValidationError(
                f"{self._model} returned a response the schema rejected: {exc}"
            ) from exc


async def ollama_health() -> tuple[str, str | None]:
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.ollama_host.rstrip('/')}/api/tags")
            response.raise_for_status()
            models = [m["name"] for m in response.json().get("models", [])]
    except Exception as exc:  # noqa: BLE001
        return "disconnected", str(exc)[:200]

    if settings.ollama_model not in models:
        return "degraded", f"{settings.ollama_model} not pulled; run: ollama pull {settings.ollama_model}"
    return "connected", settings.ollama_model
