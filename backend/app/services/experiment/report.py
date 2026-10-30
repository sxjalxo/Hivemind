"""The persona experiment's report (R3): built from the recorded data, rendered as text."""

import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from app.services import sensor_changes
from app.services.experiment.read import Block, blocks_as_run, coverage, read_sessions, window
from app.services.experiment.schedule import STOCK, Schedule
from app.services.experiment.sessions import (
    PRIMARY,
    Tally,
    arch_mix,
    assign,
    metrics,
    script_metrics,
    technique_mix,
)
from app.services.experiment.stats import SAMPLES, holm, permutation_p, smallest_p

VIEWS = (("session_view", "per session"), ("script_view", "one vote per script"))
_ALL = (*PRIMARY, "duration_median_s")


@dataclass
class BlockRow:
    block: Block
    hours_covered: int
    hours_total: int
    tally: Tally
    excluded: str | None
    session_view: dict[str, float] | None
    script_view: dict[str, float] | None


@dataclass
class Report:
    schedule: Schedule
    now: datetime
    window: tuple[datetime, datetime]
    events_read: int
    rows: list[BlockRow]
    changes: list  # SensorChange rows inside the window
    tests: (
        dict[str, dict[str, tuple[float, float, bool]]] | None
    )  # view -> metric -> (p, holm, exhaustive)
    secondary: dict[str, dict[str, dict[str, float]]]  # arm -> {"techniques": .., "archs": ..}


def exclusion(block: Block, arms: set[str], covered: int, total: int, tally: Tally) -> str | None:
    """Why a block is left out of the analysis, or None when it is included."""
    if not block.opened_by_deployment:
        return "did not start with a deployment"
    if block.arm not in arms:
        return f"{block.arm or 'no persona'} is not an arm of the schedule"
    if block.hours < 24:
        return f"shorter than 24 h ({block.hours:.1f} h)"
    if covered * 2 < total:
        return f"coverage below one half ({covered} of {total} hours)"
    if not tally.sessions:
        return "no logged-in session"
    return None


def _tests(included: list[BlockRow]) -> dict | None:
    by_arm = Counter(row.block.arm for row in included)
    if sum(1 for n in by_arm.values() if n >= 2) < 2:
        return None
    labels = [row.block.arm for row in included]
    out = {}
    for view, _ in VIEWS:
        raw = {m: permutation_p([getattr(r, view)[m] for r in included], labels) for m in PRIMARY}
        adjusted = holm({m: p for m, (p, _) in raw.items()})
        out[view] = {m: (raw[m][0], adjusted[m], raw[m][1]) for m in PRIMARY}
    return out


def _secondary(included: list[BlockRow]) -> dict:
    pooled: dict[str, list] = {}
    for row in included:
        pooled.setdefault(row.block.arm, []).extend(row.tally.sessions)
    return {
        arm: {"techniques": technique_mix(sessions), "archs": arch_mix(sessions)}
        for arm, sessions in pooled.items()
    }


async def build(schedule: Schedule, now: datetime) -> Report:
    start, end = window(schedule, now)
    blocks = await blocks_as_run(schedule, now)
    sessions, events_read = await read_sessions(schedule.sensor, start, end)
    tallies = assign(sessions, [(b.start, b.end) for b in blocks])
    rows = []
    for block, tally in zip(blocks, tallies, strict=True):
        covered, total = await coverage(schedule.sensor, block.start, block.end)
        reason = exclusion(block, set(schedule.arms), covered, total, tally)
        rows.append(
            BlockRow(
                block,
                covered,
                total,
                tally,
                reason,
                None if reason else metrics(tally.sessions),
                None if reason else script_metrics(tally.sessions),
            )
        )
    changes = [c for c in await sensor_changes.history(schedule.sensor) if start <= c.at < end]
    included = [row for row in rows if row.excluded is None]
    return Report(
        schedule,
        now,
        (start, end),
        events_read,
        rows,
        changes,
        _tests(included),
        _secondary(included),
    )


def _t(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%d %H:%MZ")


def render(r: Report) -> str:
    s = r.schedule
    arms = list(dict.fromkeys(s.arms))  # schedule order, once each
    included = [row for row in r.rows if row.excluded is None]
    lines = []
    if r.now < s.end:
        lines.append("INTERIM -- the schedule is not finished")
    lines += [
        (
            f"Persona experiment on {s.sensor}: {len(s.arms)} blocks of {s.block_days} days, "
            f"{_t(s.start)} -> {_t(s.end)}"
        ),
        f"Window analysed: {_t(r.window[0])} -> {_t(r.window[1])}; {r.events_read} events read",
        "",
        (
            "Blocks as they ran (sessions by first event; 'cut' = still running at the switch; "
            "'no-login' = never logged in)"
        ),
        (
            f"  {'#':>2} {'arm':<11} {'start':<17} {'end':<17} {'hours':>6} {'covered':>9} "
            f"{'logged-in':>9} {'cut':>5} {'no-login':>8}  status"
        ),
    ]
    for i, row in enumerate(r.rows, 1):
        b, t = row.block, row.tally
        lines.append(
            f"  {i:>2} {b.arm or '-':<11} {_t(b.start):<17} {_t(b.end):<17} {b.hours:>6.1f} "
            f"{f'{row.hours_covered}/{row.hours_total}':>9} {len(t.sessions):>9} {t.cut:>5} "
            f"{t.not_logged_in:>8}  {row.excluded or 'included'}"
        )
    lines += ["", "Sensor changes inside the window (possible confounds)"]
    lines += [f"  {_t(c.at)} {c.kind}: {c.detail}" for c in r.changes] or ["  none"]

    for view, title in VIEWS:
        lines += ["", f"Metrics by arm, {title}: mean of block values [min, max]"]
        means: dict[str, dict[str, float]] = {}
        for arm in arms:
            values = [getattr(row, view) for row in included if row.block.arm == arm]
            if not values:
                lines.append(f"  {arm:<11} no included block")
                continue
            means[arm] = {m: statistics.fmean(v[m] for v in values) for m in _ALL}
            cells = [
                f"{m} {means[arm][m]:.3f} [{min(v[m] for v in values):.3f}, "
                f"{max(v[m] for v in values):.3f}]"
                for m in _ALL
            ]
            lines.append(f"  {arm:<11} n={len(values)}  " + "  ".join(cells))
        if STOCK in means:
            for arm in (a for a in arms if a in means and a != STOCK):
                diffs = "  ".join(f"{m} {means[arm][m] - means[STOCK][m]:+.3f}" for m in PRIMARY)
                lines.append(f"  {arm} - stock: {diffs}")

    lines += ["", "Primary metrics per included block, per session"]
    for i, row in enumerate(r.rows, 1):
        if row.excluded is None:
            cells = "  ".join(f"{m} {row.session_view[m]:.3f}" for m in PRIMARY)
            lines.append(f"  {i:>2} {row.block.arm:<11} {cells}")

    lines += ["", "Permutation test (blocks relabelled across arms, each arm's block count kept)"]
    if r.tests is None:
        lines.append("  not enough blocks: fewer than two arms with two included blocks each")
    else:
        for view, title in VIEWS:
            for m in PRIMARY:
                p, adjusted, exhaustive = r.tests[view][m]
                how = "exhaustive" if exhaustive else f"{SAMPLES} random relabellings, seed 0"
                lines.append(f"  {title:<20} {m:<15} p={p:.4f}  holm={adjusted:.4f}  ({how})")
        sizes = list(Counter(row.block.arm for row in included).values())
        exhaustive = r.tests[VIEWS[0][0]][PRIMARY[0]][2]  # same blocks, so same for every test
        floor = smallest_p(sizes) if exhaustive else 1 / (SAMPLES + 1)
        lines.append(f"  smallest attainable p with these block counts: {floor:.4g}")
        lines.append(
            "  With three blocks per arm only a large effect can reach significance; "
            "a high p-value is not evidence of no effect."
        )

    lines += ["", "Secondary, pooled over each arm's included blocks (descriptive)"]
    for arm in arms:
        if arm not in r.secondary:
            continue
        mix = r.secondary[arm]
        top = sorted(mix["techniques"].items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        lines.append(f"  {arm}")
        lines.append("    techniques: " + (", ".join(f"{t} {v:.2f}" for t, v in top) or "none"))
        lines.append(
            "    download architectures: "
            + (", ".join(f"{a} {v:.2f}" for a, v in mix["archs"].items()) or "no downloads")
        )
    return "\n".join(lines) + "\n"
