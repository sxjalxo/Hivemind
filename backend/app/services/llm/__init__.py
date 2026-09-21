from app.config import get_settings
from app.services.llm.base import LLMClient, LLMValidationError
from app.services.llm.byok import ByokClient
from app.services.llm.ollama import OllamaClient

__all__ = [
    "LLMClient",
    "LLMValidationError",
    "get_local_client",
    "get_recommendation_client",
]


def get_local_client() -> LLMClient:
    settings = get_settings()
    return OllamaClient(
        settings.ollama_host, settings.ollama_model, settings.ollama_temperature
    )


def get_recommendation_client() -> tuple[LLMClient, str]:
    """The client for the ANALYSIS pipeline's recommendation stage, and its tier.

    Falls back to the local model when no BYOK key is configured. Degraded
    output, never a failed run — the tier is recorded so the UI can mark it.

    **Not the realism evaluator**, despite both being "the better model if we
    have one". This was called `get_evaluator_client`, which made it read as
    the client for the thing this system calls the evaluator, whose contract
    is the exact opposite: `app.services.evaluation.runs._evaluator_client`
    returns None rather than fall back, because the source paper measured
    sub-70b models as returning only superficial realism critique and a
    shallow-but-plausible verdict is the failure the whole system exists to
    prevent. Two functions, one plausible name, opposite answers to "what if
    there is no key" — the kind of pair where the wrong import type-checks,
    runs, and produces a confident wrong number.

    Advice about what a defender should do next is a different matter: a
    local-model suggestion is worth having and is labelled `local` so nobody
    mistakes its tier.
    """
    settings = get_settings()
    if settings.byok_api_key and settings.byok_provider and settings.byok_model:
        return (
            ByokClient(settings.byok_provider, settings.byok_api_key, settings.byok_model),
            "cloud",
        )
    return get_local_client(), "local"
