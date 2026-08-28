from app.serialization import CamelModel


class Honeypot(CamelModel):
    id: str
    name: str
    type: str
    os: str
    interaction_level: str
    ip: str
    status: str
    active_sessions: int
    events: int
    last_activity: str
    risk: str
    sensor: str | None = None
    location: str | None = None
