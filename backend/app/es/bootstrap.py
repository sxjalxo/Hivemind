import json
from pathlib import Path

from app.config import get_settings
from app.es.client import get_es

PIPELINE_ID = "cowrie-ecs"
TEMPLATE_ID = "honeypot-events"

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


async def install_index_template() -> None:
    body = _load("index-template.json")
    await get_es().indices.put_index_template(
        name=TEMPLATE_ID,
        index_patterns=body["index_patterns"],
        template=body["template"],
        priority=body["priority"],
    )
    index = get_settings().es_index
    if not await get_es().indices.exists(index=index):
        await get_es().indices.create(index=index)


async def bootstrap_es() -> None:
    """Install the pipeline and template. Idempotent — safe on every startup."""
    await install_ingest_pipeline()
    await install_index_template()
