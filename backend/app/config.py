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

    # Caps on the attacker-similarity aggregation. A terms aggregation returns
    # at most `size` buckets and reports nothing about what it dropped, so
    # these are paired with an explicit completeness check: a profile whose
    # command set was truncated withholds its similarity scores rather than
    # computing them from the surviving subset. Raise them (env:
    # ATTACKER_COMMAND_CARDINALITY_LIMIT / ATTACKER_IP_CARDINALITY_LIMIT)
    # rather than accepting a truncated score.
    attacker_command_cardinality_limit: int = 2000
    attacker_ip_cardinality_limit: int = 500


@lru_cache
def get_settings() -> Settings:
    return Settings()
