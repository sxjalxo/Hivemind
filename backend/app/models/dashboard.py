from app.serialization import CamelModel


class DashboardKpi(CamelModel):
    id: str
    label: str
    value: int
    trend_pct: float
    trend_direction: str
    tone: str


class TimelinePoint(CamelModel):
    t: str
    events: int
    high_risk: int


class NamedValue(CamelModel):
    name: str
    value: int


class RiskBucket(CamelModel):
    level: str
    value: int


class TopAttacker(CamelModel):
    ip: str
    country: str
    events: int
    sessions: int
    risk: str
    last_seen: str


class TopCommand(CamelModel):
    command: str
    count: int
    technique_id: str | None = None


class DashboardData(CamelModel):
    kpis: list[DashboardKpi]
    timeline: list[TimelinePoint]
    classifications: list[NamedValue]
    risk_distribution: list[RiskBucket]
    top_attackers: list[TopAttacker]
    top_commands: list[TopCommand]
