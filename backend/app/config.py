from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class HoneypotTarget(BaseModel):
    """One honeypot the evaluation subsystem may be pointed at.

    Server-side settings, never request input -- the containment rule below
    is unchanged: a caller names a honeypot id, and the address it resolves
    to was written by whoever configured the deployment.

    The password has a default because Cowrie accepts any password; it is
    not a per-honeypot secret, and demanding one per entry would put a
    credential in the map for no gain. That reasoning is about Cowrie and
    stops where Cowrie does, so a non-`cowrie` target must state its own --
    see `_a_generic_target_states_its_own_password`.

    `kind` is the one field that is not merely an address. It declares what
    the thing at the other end IS, and three parts of a run read it:

      * **Container introspection.** `reset` clears evaluation-created state
        with `docker exec <container> /cowrie/cowrie-env/bin/python3`, and
        `honeypot_fingerprint` digests `cowrie.cfg` the same way. Neither
        path exists on anything that is not this Cowrie image.
      * **Chain verification.** Chains are confirmed by reading the commands
        back out of Cowrie's own log via Elasticsearch, filtered on
        `event.action: cowrie.command.input`. A target that is not Cowrie
        writes no such events, so nothing can be verified.
      * **Whether a command is simulated.** Cowrie's shell backend emulates
        every command: `rm -rf /root/.ssh` touches nothing real. That is the
        ONLY reason the attack chains are safe to run, and it stops being
        true the moment the target is a real host.

    `generic` is the conservative value in all three: skip what cannot work,
    and never execute a chain step with real side effects. Declaring a real
    machine `cowrie` is what would be dangerous, so a real machine is the
    thing an operator has to describe accurately -- and `generic` is what
    they get if they describe nothing.

    ponytail: one field covers all three because today they move together.
    A Cowrie running the `proxy` backend forwards commands to a real host --
    it would be Cowrie-introspectable but NOT simulating. Declare such a
    deployment `generic`: it loses container reset and the cfg digest, which
    is the safe direction. Split `kind` into separate capability flags if
    that configuration ever becomes real here.
    """

    kind: Literal["cowrie", "generic"] = "cowrie"
    host: str
    ssh_port: int = 2222
    ssh_username: str = "root"
    ssh_password: str = "hivemind-evaluation"
    # Optional because a generic target need not be a container at all (a
    # VM, a bare host). Required for `cowrie`, where reset and the
    # fingerprint both need something to `docker exec` into -- enforced
    # below rather than by the type, so the error names the reason.
    container_name: str | None = None
    capture_interface: str = "eth0"
    # The packet-capture SIDECAR for this honeypot -- a container compose
    # declares with `network_mode: service:<this honeypot>`, which the backend
    # `docker exec`s tcpdump into. None means no capture, and that is the
    # honest answer for a target that has no sidecar rather than a reason to
    # capture on the host, which would watch an interface the honeypot's
    # traffic never crosses and report zero packets as a finding.
    #
    # A sidecar rather than `docker run`: creating a container is the one
    # Docker operation equivalent to root on the host, and this was the only
    # thing that needed one. See `app.services.evaluation.container`.
    capture_container: str | None = None

    @model_validator(mode="after")
    def _cowrie_needs_a_container(self) -> "HoneypotTarget":
        if self.kind == "cowrie" and not self.container_name:
            raise ValueError(
                "a 'cowrie' target needs container_name: reset and the honeypot "
                "fingerprint both work by `docker exec` into it. Set it, or "
                "declare the target kind 'generic' if it is not a container."
            )
        return self

    @model_validator(mode="after")
    def _a_generic_target_states_its_own_password(self) -> "HoneypotTarget":
        """`ssh_password`'s default is a Cowrie fact, not a universal one.

        The default is defensible for Cowrie: it accepts any password, the
        credential is not a secret, and the whole point of the decoy is that
        anyone can log in. It is indefensible for anything else. A `generic`
        entry that omits the field would silently authenticate with the
        string "hivemind-evaluation" against a real machine -- failing, and
        failing in the shape of a honeypot that refused a login rather than
        a config that was never finished.

        So the field is required exactly where its default stops being true.
        Note the agent only ever authenticates by password (`look_for_keys`
        and `allow_agent` are both False in `agent._Session`), so there is no
        key-based path this would be standing in the way of.
        """
        omitted = "ssh_password" not in self.model_fields_set
        if self.kind != "cowrie" and (omitted or not self.ssh_password):
            raise ValueError(
                f"a {self.kind!r} target needs an explicit ssh_password: the default "
                f"exists because Cowrie accepts any password, which is not true of "
                f"anything else, and a silent wrong credential looks like the target "
                f"rejecting a login rather than a setting nobody filled in."
            )
        return self

    @property
    def simulates_commands(self) -> bool:
        """Whether a command sent here has real side effects.

        False means the attack chains' destructive steps must not run. See
        `kind` -- this is a derivation, not a second knob, so the two can
        never be configured into disagreement.
        """
        return self.kind == "cowrie"

    @property
    def has_own_event_log(self) -> bool:
        """Whether this target writes the Cowrie events chain read-back needs."""
        return self.kind == "cowrie"


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

    # --- Authentication (Clerk) ---------------------------------------
    #
    # Set `clerk_issuer` and every /api route requires a valid Clerk session
    # token. Leave it unset and the API is OPEN -- which is what it has always
    # been, and is a defensible default only for a backend bound to localhost.
    #
    # Fail-open is a deliberate, uncomfortable choice and it is made visible
    # rather than quiet: `main.lifespan` logs a WARNING naming the setting on
    # every unauthenticated startup, and `GET /api/status` reports an
    # `authentication` row as `disconnected` so the UI shows it too. The
    # alternative -- fail closed by default -- would mean a fresh clone could
    # not run at all until someone created a Clerk app, which is a real cost
    # for a research tool whose normal deployment is one operator on one
    # machine. The moment this backend is reachable from anywhere else, this
    # must be set. See the README.
    #
    # The issuer is the Clerk Frontend API origin, e.g.
    # https://humorous-donkey-63.clerk.accounts.dev -- it is NOT a secret (it
    # is derivable from the publishable key every browser already holds).
    clerk_issuer: str | None = None
    # Defaults to `{clerk_issuer}/.well-known/jwks.json`; override only for a
    # proxied or self-hosted Frontend API.
    clerk_jwks_url: str | None = None
    # `azp` (authorized party) values a token may carry -- the origins your
    # frontend is served from. Clerk recommends checking this so a token
    # minted for another application on the same instance cannot be replayed
    # against this API. Empty disables the check; `cors_origins` is the
    # sensible value and is what the README tells you to use.
    clerk_authorized_parties: list[str] = []
    # Tolerance for clock skew between this host and Clerk, in seconds.
    # Clerk session tokens are short-lived (60s by default), so a host clock a
    # few seconds fast rejects every token with "not yet valid" -- a failure
    # that looks like a broken integration rather than a wrong clock.
    clerk_leeway_seconds: int = 30

    @property
    def auth_enabled(self) -> bool:
        return bool(self.clerk_issuer)

    @property
    def jwks_url(self) -> str:
        if self.clerk_jwks_url:
            return self.clerk_jwks_url
        return f"{(self.clerk_issuer or '').rstrip('/')}/.well-known/jwks.json"

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
    # The capture sidecar for the single legacy target. Compose declares it
    # (service `capture`) sharing the honeypot's network namespace. Empty
    # disables the capture entirely, which reports nothing rather than
    # reporting a host-side capture that sees none of the honeypot's traffic.
    evaluation_capture_container: str = "hivemind-capture-1"
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
