from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    es_url: str = "http://localhost:9200"
    es_index: str = "honeypot-events"
    pg_dsn: str = "postgresql+asyncpg://hivemind:hivemind@localhost:5432/hivemind"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_temperature: float = 0.3

    byok_provider: str | None = None
    byok_api_key: str | None = None
    byok_model: str | None = None

    seed_output_head_lines: int = 20
    seed_output_tail_lines: int = 20

    cors_origins: list[str] = ["http://localhost:8080"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
