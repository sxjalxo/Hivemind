from app.config import get_settings
from app.services.llm.base import LLMClient, LLMValidationError
from app.services.llm.byok import ByokClient
from app.services.llm.ollama import OllamaClient

__all__ = [
    "LLMClient",
    "LLMValidationError",
    "get_evaluator_client",
    "get_local_client",
]


def get_local_client() -> LLMClient:
    settings = get_settings()
    return OllamaClient(
        settings.ollama_host, settings.ollama_model, settings.ollama_temperature
    )


def get_evaluator_client() -> tuple[LLMClient, str]:
    """Return the evaluator and its tier.

    Falls back to the local model when no BYOK key is configured. Degraded
    output, never a failed run — the tier is recorded so the UI can mark it.
    """
    settings = get_settings()
    if settings.byok_api_key and settings.byok_provider and settings.byok_model:
        return (
            ByokClient(settings.byok_provider, settings.byok_api_key, settings.byok_model),
            "cloud",
        )
    return get_local_client(), "local"
