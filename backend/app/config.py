from functools import lru_cache

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class HoneypotTarget(BaseModel):
    """One honeypot the evaluation subsystem may be pointed at.

    Server-side settings, never request input -- the containment rule below
    is unchanged: a caller names a honeypot id, and the address it resolves
    to was written by whoever configured the deployment.

    The password has a default because Cowrie accepts any password; it is
    not a per-honeypot secret, and demanding one per entry would put a
    credential in the map for no gain.
    """

    host: str
    ssh_port: int = 2222
    ssh_username: str = "root"
    ssh_password: str = "hivemind-evaluation"
    container_name: str
    capture_interface: str = "eth0"


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
    # Per-honeypot targets, keyed by honeypot id. Empty by default, and while
    # it is empty the single evaluation_* target below serves every honeypot --
    # one decoy needs no map. Once it holds anything, an unmapped id is
    # REFUSED rather than falling back: evaluating honeypot A under honeypot
    # B's label files every score, finding and fingerprint against the wrong
    # decoy, which is the mis-attribution the target fingerprint exists to
    # catch and is better prevented than detected.
    evaluation_targets: dict[str, HoneypotTarget] = {}

    evaluation_target_host: str = "cowrie"
    evaluation_ssh_port: int = 2222
    evaluation_capture_interface: str = "eth0"
    # Where the packet capture runs.
    #
    # Empty: run `tcpdump` directly on this host. That only observes the
    # honeypot if the host shares its network -- it does NOT when the honeypot
    # is a container reached through a published port, and a capture that sees
    # nothing reports "no traffic", which is a false claim rather than an
    # absent one.
    #
    # Set: run tcpdump from this image inside the honeypot container's own
    # network namespace, so `evaluation_capture_interface` is the honeypot's
    # interface and the packets counted are genuinely its own. Required on
    # Windows and macOS, where Docker's network is not on the host.
    evaluation_capture_image: str = "nicolaka/netshoot"
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
    # NOTE: `evaluation_config_fingerprint` describes the probe set, chain
    # set, rulebook and agent budget only -- none of the evaluation_* settings
    # above are in it.
    #
    # The target is the exception, and it is covered by the OTHER fingerprint:
    # `evaluation_target_host`, `evaluation_ssh_port`, `evaluation_ssh_username`
    # and `evaluation_container_name` are hashed into `honeypot_fingerprint`,
    # because they name the thing under test rather than the question we asked
    # of it. `evaluation_ssh_password` deliberately is not.
    #
    # `evaluation_capture_interface`, `evaluation_capture_image` and the
    # nmap/capture timeouts ARE covered, via `fingerprints.Apparatus`. They
    # are measurement apparatus -- they change what a run can FIND without
    # changing the honeypot -- so they sit in the config fingerprint, with the
    # probe set and the budget.
    #
    # What remains uncovered is the scoring and compaction ALGORITHMS.
    # `scoring.py` is pure functions with no constants to hash, so a change to
    # how a fraction is computed moves no fingerprint at all. Result-deciding
    # constants elsewhere (`agent.PER_COMMAND_TIMEOUT_SECONDS`, nmap's
    # `_EXPECTED_SERVICES`, the rulebook's text filters) are hashed by value;
    # regex compile flags are not. Git revision is still the extra key when
    # reading a trend across a code change.
    #
    # See app.services.evaluation.fingerprints for why the boundary is drawn
    # where it is.


@lru_cache
def get_settings() -> Settings:
    return Settings()
