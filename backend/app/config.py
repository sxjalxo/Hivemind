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

    # The cloud evaluator. `byok_provider` must be one of the providers
    # `app.services.llm.byok.ByokClient` implements (`anthropic`, `openai`);
    # anything else raises `ValueError` when the client is constructed.
    #
    # That check is deliberately NOT repeated as a validator here. These
    # settings are loaded once for the whole process, by everything from the
    # dashboard to session analysis, and rejecting the value at load time
    # would turn one mistyped evaluator env var into a total application
    # failure -- far past the blast radius of the feature it configures.
    # Instead `runs._evaluate` lets the ValueError surface and reports the run
    # as `evaluator_status=evaluator_failed`, which is what a misconfiguration
    # is. It must never read as `unavailable`: that means "no evaluator was
    # configured", i.e. we never tried, and it would make a wrong provider
    # indistinguishable from an empty .env.
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

    # The agent's target is a fixed compose service name, never a
    # user-supplied address: there must be no code path from an HTTP request
    # to an arbitrary host, or the agent becomes an attack tool.
    evaluation_target_host: str = "cowrie"
    evaluation_ssh_port: int = 2222
    evaluation_capture_interface: str = "eth0"
    evaluation_agent_max_commands: int = 40
    evaluation_agent_max_seconds: int = 120
    # Cowrie's shipped userdb accepts `root` with any password except a
    # handful of blacklisted ones. These are credentials FOR a honeypot, not
    # a secret: the whole point of the target is that anyone can log into it.
    evaluation_ssh_username: str = "root"
    evaluation_ssh_password: str = "hivemind-evaluation"
    # The container `reset` clears and `honeypot_fingerprint` inspects. A
    # compose-derived name, never caller-supplied.
    evaluation_container_name: str = "hivemind-cowrie-1"
    evaluation_nmap_timeout_seconds: int = 120
    evaluation_capture_timeout_seconds: int = 30
    # NOTE: none of the evaluation_* settings above are covered by
    # `evaluation_config_fingerprint`, which describes the probe set, chain
    # set, rulebook and agent budget only. Two runs against different targets,
    # interfaces or timeouts fingerprint identically. See
    # app.services.evaluation.fingerprints for why that boundary is drawn
    # there and what else it leaves uncovered.


@lru_cache
def get_settings() -> Settings:
    return Settings()
