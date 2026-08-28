from app.config import get_settings
from app.models.event import HoneypotEvent
from app.serialization import CamelModel

UNTRUSTED_BEGIN = "----- BEGIN UNTRUSTED DATA -----"
UNTRUSTED_END = "----- END UNTRUSTED DATA -----"


class CompactedCommand(CamelModel):
    event_id: str
    timestamp: str
    command: str
    output_excerpt: str | None = None
    repeat_count: int = 1


class CompactedSession(CamelModel):
    session_id: str
    attacker_ip: str
    started_at: str
    duration_seconds: int
    failed_logins: int
    successful_login: bool
    username: str | None
    commands: list[CompactedCommand]
    downloads: list[str]


def _truncate_output(output: str | None) -> str | None:
    if not output:
        return None
    settings = get_settings()
    lines = output.splitlines()
    head, tail = settings.seed_output_head_lines, settings.seed_output_tail_lines
    if len(lines) <= head + tail:
        return output
    omitted = len(lines) - head - tail
    return "\n".join(
        lines[:head] + [f"... {omitted} lines omitted ..."] + lines[-tail:]
    )


def compact(events: list[HoneypotEvent]) -> CompactedSession:
    """Reduce a session to a deterministic, token-bounded summary.

    Truncation only ever removes output *within* an event. Every retained
    command keeps its Elasticsearch document id, so it stays citable.
    """
    if not events:
        raise ValueError("cannot compact an empty session")

    first = events[0]
    commands: list[CompactedCommand] = []
    downloads: list[str] = []
    failed_logins = 0
    successful_login = False
    username: str | None = None

    for event in events:
        action = event.event.action
        if action == "cowrie.login.failed":
            failed_logins += 1
        elif action == "cowrie.login.success":
            successful_login = True
        if event.user and event.user.name and username is None:
            username = event.user.name

        if action == "cowrie.command.input" and event.process and event.process.command_line:
            text = event.process.command_line
            if commands and commands[-1].command == text:
                commands[-1].repeat_count += 1
                continue
            commands.append(
                CompactedCommand(
                    event_id=event.id,
                    timestamp=event.timestamp,
                    command=text,
                    output_excerpt=_truncate_output(
                        event.process.output if event.process else None
                    ),
                )
            )
        elif action == "cowrie.session.file_download":
            downloads.append(event.id)

    last = events[-1]
    from datetime import datetime

    def parse(ts: str) -> datetime:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    return CompactedSession(
        session_id=first.session.id,
        attacker_ip=first.source.ip,
        started_at=first.timestamp,
        duration_seconds=int((parse(last.timestamp) - parse(first.timestamp)).total_seconds()),
        failed_logins=failed_logins,
        successful_login=successful_login,
        username=username,
        commands=commands,
        downloads=downloads,
    )


def render_untrusted_block(compacted: CompactedSession) -> str:
    """Render attacker-controlled text inside an explicit untrusted fence.

    Commands are attacker-authored and may contain text designed to look
    like instructions. The fence plus the prompt's framing tells the model
    to treat everything inside as data.
    """
    lines = [
        UNTRUSTED_BEGIN,
        f"session_id: {compacted.session_id}",
        f"attacker_ip: {compacted.attacker_ip}",
        f"failed_logins: {compacted.failed_logins}",
        f"successful_login: {compacted.successful_login}",
        "commands:",
    ]
    for command in compacted.commands:
        suffix = f" (repeated {command.repeat_count}x)" if command.repeat_count > 1 else ""
        lines.append(f"  - event_id: {command.event_id}")
        lines.append(f"    timestamp: {command.timestamp}")
        lines.append(f"    command: {command.command}{suffix}")
        if command.output_excerpt:
            lines.append(f"    output: {command.output_excerpt}")
    lines.append(UNTRUSTED_END)
    return "\n".join(lines)
