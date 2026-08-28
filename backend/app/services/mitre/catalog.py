import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel

_CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "attack-enterprise-techniques.json"


class CatalogEntry(BaseModel):
    id: str
    name: str
    tactic: str


@lru_cache
def load_catalog() -> dict[str, CatalogEntry]:
    """Load the pinned ATT&CK subset. Pinned for offline reproducibility."""
    raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    return {t["id"]: CatalogEntry.model_validate(t) for t in raw["techniques"]}


def is_known_technique(technique_id: str) -> bool:
    """Gate for LLM-proposed ids. An unknown id is a hallucination."""
    return technique_id in load_catalog()
