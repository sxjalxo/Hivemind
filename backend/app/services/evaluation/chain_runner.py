"""Executing the attack chains, and verifying them from the honeypot's own log.

Extracted from `runs.py`. Chain verification is its own concern and a large
one: executing the steps is the easy half, and proving which log entries are
OURS is the half that decides whether a result means anything.

Two rules shape everything here, and neither is negotiable:

**A chain is only verified when every step was read back.** `verify_chain`
hardcodes `not_observed` for a missing technique, justified by "the commands
WERE executed and the rules WERE applied". That justification fails when the
read-back could not complete, so a chain whose commands never arrived is
OMITTED -- left `unknown` by absence, which scoring excludes from both sides
of the fraction -- rather than scored as absent. Feeding a partial command
list to the verifier would score our own ingest lag as a honeypot defect.

**The read-back is scoped to the session WE opened**, found via the agent's
per-session nonce. This is a live sensor: a real attacker running `cd /tmp`
inside our time window would otherwise complete a chain and put a foreign
event id into `evaluation_chain_steps`, where it is cited as this run's
evidence. If the session id cannot be determined the read-back is not
attempted at all -- an unscoped one would attribute somebody else's command
to this run, and evidence provenance is the promise the whole system rests
on.

`run_chains` stays reachable as `runs._run_chains`: the orchestrator assigns
it to that name the way it does every other seam, so the test suite patches
it exactly as before. The functions BELOW it are patched on this module,
because this is where they are called from.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db.models import ModuleStatus
from app.es.client import get_es
from app.services.compaction import CompactedCommand
from app.services.evaluation import agent as agent_module
from app.services.evaluation.agent import EvaluationTarget
from app.services.evaluation.state import ChainRun, iso
from app.services.evaluation.static import chains as chains_module
from app.services.evaluation.static.chains import ChainStepResult

logger = logging.getLogger(__name__)


# --- chain read-back ---------------------------------------------------
#
# Reset deliberately PRESERVES cowrie.json (it is the source of every session
# this whole system analyses), and does not restart Cowrie. So the log still
# holds run A's commands when run B starts, and the read-back must be scoped
# or run B verifies its chains against run A's events.
CHAIN_INGEST_TIMEOUT_SECONDS = 30.0


CHAIN_INGEST_POLL_SECONDS = 1.0


# Cowrie stamps `@timestamp` from the container's clock and Filebeat ships
# asynchronously. The window is widened by this much on both sides so a small
# clock offset cannot drop a command that really was executed -- being
# narrow here would blame the honeypot for our own skew. Over-inclusion is
# then closed off separately: only commands whose text is one of the chain's
# own declared steps are fed to `verify_chain`.
CHAIN_CLOCK_SKEW_SECONDS = 5

# One Elasticsearch page of read-back. A chain is three steps, so this is
# headroom; reaching it is reported rather than scored as an unobserved step.
_MAX_READ_BACK_EVENTS = 1000


async def run_chains(target: EvaluationTarget, honeypot_id: str) -> ChainRun:
    """Execute the predefined chains, then verify them from Cowrie's own log.

    Chains are fixed ids from `chains.yaml`, never caller-supplied command
    sequences: `EvaluationTarget` is built from settings only, so there is no
    path from an HTTP request to an arbitrary command against an arbitrary
    host.

    The SSH primitives come from `agent`'s own seams so chain execution
    inherits the same bounded exit-status wait a probe gets (Cowrie can leave
    a channel open without ever sending an exit status; see
    `agent.PER_COMMAND_TIMEOUT_SECONDS`).

    A chain is only verified when every one of its steps was found in the
    read-back window. A chain whose commands never arrived is OMITTED, and the
    stage reports TIMEOUT. `verify_chain` hardcodes `not_observed` for a
    missing technique, justified by "the commands WERE executed and the rules
    WERE applied" -- that justification fails when we could not read the log
    at all, and feeding it a partial command list would score our own ingest
    lag as a honeypot defect. Omitting the chain leaves it `unknown` by
    absence, which scoring excludes from both numerator and denominator.

    The read-back is scoped to the SOURCE PORT of the session opened here, so
    a concurrent attacker session cannot complete one of our chains. If that
    port cannot be determined the read-back is not attempted at all: an
    unscoped one would attribute somebody else's command to this run, and
    evidence provenance is the promise this whole system rests on.
    """
    loaded = chains_module.load_chains()
    if not loaded:
        return ChainRun(results=[], module_status=ModuleStatus.SKIPPED, detail="no chains configured")

    refused = [chain.id for chain in loaded if chain.destructive]
    if not target.simulates_commands:
        # The chains are only safe because Cowrie emulates every command.
        # Against a real host their steps are what they read as: an SSH
        # directory deleted, an attacker key appended to authorized_keys, a
        # downloaded script executed. Nothing else in this subsystem stops
        # that -- containment keeps a CALLER from choosing the address, and
        # says nothing about what we do once an operator has configured one.
        #
        # SKIPPED, and every chain fact stays absent. `verify_chain` hardcodes
        # `not_observed` for a missing technique, justified by "the commands
        # WERE executed" -- which is exactly what did not happen here, so the
        # justification fails and the facts must not be manufactured.
        loaded = tuple(chain for chain in loaded if not chain.destructive)
        if not loaded:
            return ChainRun(
                results=[],
                module_status=ModuleStatus.SKIPPED,
                detail=(
                    f"target does not simulate commands (kind={target.kind!r}), so "
                    f"chain(s) {', '.join(refused)} were NOT executed: their steps have "
                    f"real side effects on a host that runs them. No non-destructive "
                    f"chain is configured, so attack_possibilities is left unestablished "
                    f"rather than scored from chains that never ran."
                ),
            )

    if not target.has_own_event_log:
        # Execution is only half a chain; the other half is reading the
        # commands back out of the honeypot's OWN log, which is what ties a
        # chain step to a `cowrie_event_id` a reader can open. A target that
        # writes no such events can never supply that, so running the steps
        # would spend the time and produce nothing citable.
        return ChainRun(
            results=[],
            module_status=ModuleStatus.SKIPPED,
            detail=(
                f"target kind={target.kind!r} writes no honeypot-side command log, so a "
                f"chain could be executed but never verified or cited; chains were not "
                f"run rather than run unverifiably"
            ),
        )

    started = datetime.now(timezone.utc)
    async with agent_module._open_session(target) as session:
        marker = session.marker
        for chain in loaded:
            for step in chain.steps:
                await agent_module._execute(session, step)
    finished = datetime.now(timezone.utc)

    session_id = await discover_cowrie_session_id(honeypot_id, marker, started, finished)
    if session_id is None:
        # The commands WERE executed; we simply cannot prove which log entries
        # are ours. Every chain is left unverified -- `unknown` by absence,
        # excluded from numerator and denominator alike -- rather than
        # verified from events that may belong to another session.
        return ChainRun(
            results=[],
            module_status=ModuleStatus.ERROR,
            detail=(
                "could not determine the honeypot-side session id for the chain session, "
                "so the read-back could not be scoped to it; chains were left unverified "
                "rather than verified from events that may belong to another session"
            ),
        )

    wanted = {step for chain in loaded for step in chain.steps}
    found = await read_back_commands(honeypot_id, started, finished, wanted, session_id)

    results: list[ChainStepResult] = []
    incomplete: list[str] = []
    for chain in loaded:
        if any(step not in found for step in chain.steps):
            incomplete.append(chain.id)
            continue
        results.extend(chains_module.verify_chain(chain, [found[step] for step in chain.steps]))

    if incomplete:
        return ChainRun(
            results=results,
            module_status=ModuleStatus.TIMEOUT,
            detail=(
                f"commands for chain(s) {', '.join(incomplete)} were not indexed within "
                f"{CHAIN_INGEST_TIMEOUT_SECONDS}s; those chains were left unverified rather "
                f"than scored as absent"
            ),
        )
    return ChainRun(results=results, module_status=ModuleStatus.COMPLETED)


async def discover_cowrie_session_id(
    honeypot_id: str, marker: str, start: datetime, end: datetime
) -> str | None:
    """Cowrie's own session id for the shell WE opened, or None.

    This is what scopes the chain read-back to our session. Without it, a real
    attacker running `cd /tmp` or `chmod 777 xmrig` inside our window would
    complete a chain's `found` set and put a FOREIGN `cowrie_event_id` into
    `evaluation_chain_steps`, where it is then cited as this run's evidence.

    We find it by looking up the per-session nonce the agent already writes
    after every command (see `agent._execute`). That nonce is generated here
    and appears in no other session, so the document carrying it is ours by
    construction -- it cannot be guessed, reused, or coincidentally matched.

    The local TCP port would be knowable without any lookup, and was used
    first, but it is simply not the port Cowrie records: the honeypot is
    reached through a published container port, so Docker re-originates the
    connection and Cowrie sees the proxy's port, not ours. Measured on this
    deployment -- we opened from 11024, Cowrie logged 39108 -- which silently
    matched nothing and left every chain unverified. Cowrie's session id has
    no such gap between what we can observe and what it records.

    Returns None if the nonce never arrives within the ingest deadline. The
    caller must NOT fall back to an unscoped read-back.
    """
    settings = get_settings()
    deadline = time.monotonic() + CHAIN_INGEST_TIMEOUT_SECONDS
    while True:
        result = await get_es().search(
            index=settings.es_index,
            query={
                "bool": {
                    "filter": [
                        {"term": {"honeypot.id": honeypot_id}},
                        {"term": {"event.action": "cowrie.command.input"}},
                        {"term": {"labels.seeded": False}},
                        # Exact-match subfield: the analysed `text` field would
                        # tokenise the nonce apart.
                        {"wildcard": {"process.command_line.keyword": f"*{marker}*"}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": iso(start - timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                                    "lte": iso(end + timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                                }
                            }
                        },
                    ]
                }
            },
            size=1,
        )
        for hit in result["hits"]["hits"]:
            session_id = (hit["_source"].get("session") or {}).get("id")
            if session_id:
                return str(session_id)
        if time.monotonic() >= deadline:
            logger.warning(
                "chain session nonce never reached the index; leaving every chain unverified"
            )
            return None
        await asyncio.sleep(CHAIN_INGEST_POLL_SECONDS)


async def search_commands(
    honeypot_id: str, start: datetime, end: datetime, session_id: str
) -> list[dict]:
    """Cowrie command events for ONE honeypot session inside ONE time window.

    Every filter here is load-bearing:

      * `honeypot.id` -- another sensor's traffic is not this run's.
      * `labels.seeded: false` -- the demo corpus is indexed into the same
        index and its synthetic timestamps must never verify a live chain.
      * `session.id` -- Cowrie's own id for the shell WE opened, found via
        the per-session nonce (see `discover_cowrie_session_id`). This is the
        only filter that separates us from a concurrent attacker: this is a
        live sensor, and the time window and honeypot id are both things a
        real session shares with us. Without it, a stranger's `cd /tmp` inside
        our window completes the `dropper` chain and its event id is stored
        and cited as our evidence.
      * the `@timestamp` range -- this is what stops run B reading run A's
        commands. Reset preserves cowrie.json by design, so the log is NOT
        empty when a run starts, and a session id identifies one shell rather
        than one run, so time still has to separate two of OUR OWN runs. Kept
        as defence in depth alongside the session id.
    """
    settings = get_settings()
    result = await get_es().search(
        index=settings.es_index,
        query={
            "bool": {
                "filter": [
                    {"term": {"honeypot.id": honeypot_id}},
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"term": {"labels.seeded": False}},
                    {"term": {"session.id": session_id}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": iso(start - timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                                "lte": iso(end + timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                            }
                        }
                    },
                ]
            }
        },
        sort=[{"@timestamp": "asc"}],
        size=_MAX_READ_BACK_EVENTS,
    )
    hits = result["hits"]["hits"]
    total = result["hits"].get("total", {}).get("value", len(hits))
    if total > len(hits):
        # A chain step whose command sits past the cap reads as never observed,
        # which this half reports as a honeypot that failed to record it. That
        # is a verdict about the decoy drawn from a limit of ours, so it has to
        # be visible rather than inferred from a surprising score.
        logger.warning(
            "chain read-back truncated at %d of %d events for session %s: a step "
            "beyond the cap would be scored as unobserved",
            len(hits),
            total,
            session_id,
        )
    return hits


async def read_back_commands(
    honeypot_id: str, start: datetime, end: datetime, wanted: set[str], session_id: str
) -> dict[str, CompactedCommand]:
    """Poll until every wanted command is indexed, or the deadline passes.

    Filebeat tails cowrie.json asynchronously, so a command executed a moment
    ago is not yet searchable. Polling rather than sleeping a fixed interval
    keeps the common case fast and the slow case honest: on timeout the caller
    reports TIMEOUT rather than treating the gap as a honeypot failure.
    """
    deadline = time.monotonic() + CHAIN_INGEST_TIMEOUT_SECONDS
    found: dict[str, CompactedCommand] = {}
    while True:
        for hit in await search_commands(honeypot_id, start, end, session_id):
            source = hit["_source"]
            # The same session scoping the query already applies, re-checked
            # here on the document itself. The query filter is the efficient
            # half; this one is the half that cannot be silently lost by a
            # mapping or pipeline change (an unmapped field makes a term
            # filter match nothing -- or, on a differently shaped index,
            # everything). An event we cannot attribute to our own session is
            # not ours.
            if (source.get("session") or {}).get("id") != session_id:
                continue
            process = source.get("process") or {}
            command = process.get("command_line")
            # Only the chain's own declared steps. The window is deliberately
            # widened for clock skew, and without this an unrelated command
            # that happened to land inside it could credit the honeypot with a
            # technique its chain never exercised.
            if not command or command not in wanted or command in found:
                continue
            found[command] = CompactedCommand(
                event_id=hit["_id"],
                timestamp=source.get("@timestamp", ""),
                command=command,
                # NOTE: no live `cowrie.command.input` document carries
                # `process.output` (the ingest pipeline maps no such field),
                # so this is always None on the chain path. Harmless today --
                # `chains.verify_chain` matches on command text -- but a
                # future output-matching rule would silently never fire for
                # chains. Fix it here, not in the rulebook.
                output_excerpt=process.get("output"),
            )
        if len(found) >= len(wanted) or time.monotonic() >= deadline:
            return found
        await asyncio.sleep(CHAIN_INGEST_POLL_SECONDS)


def as_chain_run(returned: object) -> ChainRun:
    if isinstance(returned, ChainRun):
        return returned
    return ChainRun(results=list(returned or []))
