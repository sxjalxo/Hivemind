from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

_PROBES_PATH = Path(__file__).resolve().parent / "probes.yaml"


class Probe(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    characteristic: str
    command: str
    # The canonical fact this probe establishes. Contradiction detection
    # compares two completed probes that name the SAME fact; probes naming
    # different facts are independent and can never contradict each other.
    establishes: str | None = None
    expect_absent: bool = False


@lru_cache
def _raw() -> dict:
    return yaml.safe_load(_PROBES_PATH.read_text(encoding="utf-8"))


@lru_cache
def load_probes() -> tuple[Probe, ...]:
    return tuple(Probe(**entry) for entry in _raw()["probes"])


PROBE_SET_VERSION: str = str(_raw()["version"])
