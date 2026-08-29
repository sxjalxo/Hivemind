from app.config import get_settings
from app.models.event import HoneypotEvent
from app.serialization import CamelModel
from app.services.chunking import (
    MAX_ITEM_CHARS,
    SESSION_TOKEN_BUDGET,
    chunk_items,
    estimate_tokens,
    truncate_text,
)

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
    first_event_id: str


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
        first_event_id=first.id,
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


def chunk_session(
    compacted: CompactedSession, budget_tokens: int = SESSION_TOKEN_BUDGET
) -> list[CompactedSession]:
    """Split an oversized session into chunks that each fit the model's window.

    Every chunk is a full `CompactedSession` -- same session metadata
    (attacker_ip, login state, ...), a subset of `commands` -- so a stage
    analyzing one chunk in isolation still has the context it needs to
    reason about the commands it was given. A normal, well-under-budget
    session always comes back as a single chunk equal to the input, so
    this is a no-op for the common case.

    A single command whose own rendering already exceeds the budget (a
    pathologically long line, e.g. a base64 blob) is explicitly truncated
    (see `app.services.chunking.truncate_text`) before chunking -- an
    atomic command cannot be split across two LLM calls the way a list of
    commands can be regrouped, so bounding its text is the only way to
    keep it from silently overflowing on its own.
    """

    def render_group(commands: list[CompactedCommand]) -> str:
        return render_untrusted_block(compacted.model_copy(update={"commands": commands}))

    bounded: list[CompactedCommand] = []
    for command in compacted.commands:
        if estimate_tokens(render_group([command])) > budget_tokens:
            bounded.append(
                command.model_copy(
                    update={"command": truncate_text(command.command, MAX_ITEM_CHARS)}
                )
            )
        else:
            bounded.append(command)

    groups = chunk_items(bounded, render_group, budget_tokens)
    return [compacted.model_copy(update={"commands": group}) for group in groups]
