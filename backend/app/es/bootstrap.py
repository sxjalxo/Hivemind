import json
import logging
from pathlib import Path

from app.config import get_settings
from app.es.client import get_es

logger = logging.getLogger(__name__)

PIPELINE_ID = "cowrie-ecs"
TEMPLATE_ID = "honeypot-events"
ILM_POLICY_ID = "honeypot-events"

_INFRA = Path(__file__).resolve().parents[3] / "infra" / "elasticsearch"


def _load(relative: str) -> dict:
    return json.loads((_INFRA / relative).read_text(encoding="utf-8"))


async def install_ingest_pipeline() -> None:
    body = _load("pipelines/cowrie-ecs.json")
    await get_es().ingest.put_pipeline(
        id=PIPELINE_ID,
        description=body["description"],
        processors=body["processors"],
        on_failure=body.get("on_failure"),
    )


async def install_ilm_policy() -> None:
    """Install the rollover policy. Rollover only -- see the policy file."""
    body = _load("ilm-policy.json")
    await get_es().ilm.put_lifecycle(name=ILM_POLICY_ID, policy=body["policy"])


async def _ensure_write_target() -> None:
    """Make sure there is somewhere to write, without ever migrating data.

    Three states, and the middle one is the whole reason this function is not
    two lines:

    **Alias already exists.** Nothing to do; ILM owns it from here.

    **A CONCRETE index named `es_index` exists.** Every deployment that
    predates rollover. This does NOT migrate it, and the choice is
    deliberate: converting it means reindexing into a new index and deleting
    the original, and doing that unattended on every startup -- to captured
    attacker telemetry, which is the research data -- is exactly the
    irreversible act rollover was chosen to avoid. It logs what to run
    instead, and the index keeps working as it always has, just without
    rollover.

    **Neither exists.** A fresh deployment: create the first backing index
    with the write alias, which is the shape ILM needs. Note the index is
    created explicitly rather than left to auto-creation on first write --
    auto-creation would make a concrete index named after the alias, landing
    straight in the middle state above.

    `exists_alias` is checked FIRST because `indices.exists` resolves aliases
    too and would answer True for both of the first two states.
    """
    settings = get_settings()
    es = get_es()
    alias = settings.es_index

    if await es.indices.exists_alias(name=alias):
        return

    if await es.indices.exists(index=alias):
        logger.warning(
            "index lifecycle is NOT active: %r is a concrete index, not a rollover "
            "alias, so it will grow without bound. Nothing here will convert it "
            "automatically -- that means reindexing and deleting the original, "
            "which is not something to do unattended to captured telemetry. Run "
            "`python -m scripts.migrate_to_rollover` from backend/ when you are "
            "ready; it verifies document counts before it removes anything.",
            alias,
        )
        return

    await es.indices.create(
        index=f"{alias}-000001", aliases={alias: {"is_write_index": True}}
    )
    logger.info("created %s-000001 behind the write alias %s", alias, alias)


async def install_index_template() -> None:
    body = _load("index-template.json")
    await get_es().indices.put_index_template(
        name=TEMPLATE_ID,
        index_patterns=body["index_patterns"],
        template=body["template"],
        priority=body["priority"],
    )
    await _ensure_write_target()


async def bootstrap_es() -> None:
    """Install the pipeline, policy and template. Idempotent — safe every startup.

    The ILM policy goes in BEFORE the template: the template names the policy
    in `index.lifecycle.name`, and an index created against a policy that does
    not exist yet is parked in an ILM error state rather than rolling over.
    """
    await install_ingest_pipeline()
    await install_ilm_policy()
    await install_index_template()
