from pydantic import BaseModel

from app.services.evaluation.sanity import Observation


class ModuleOutcome(BaseModel):
    """What one evaluation module (agent, nmap, tcpdump) established.

    `module_status` is deliberately separate from each observation's own
    fact_status: a module that timed out leaves its facts `unknown`, and
    scoring must never read a failed module's facts as negative evidence.
    """

    module: str
    module_status: str
    detail: str | None = None
    observations: list[Observation]
