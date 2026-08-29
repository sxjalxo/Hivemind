from app.services.chunking import (
    MAX_ITEM_CHARS,
    SESSION_TOKEN_BUDGET,
    chunk_items,
    estimate_tokens,
    truncate_text,
)
from app.services.compaction import CompactedCommand, CompactedSession, chunk_session


def _session(commands: list[CompactedCommand]) -> CompactedSession:
    return CompactedSession(
        session_id="synthetic-01",
        attacker_ip="203.0.113.9",
        started_at="2026-08-20T10:00:00Z",
        duration_seconds=120,
        failed_logins=0,
        successful_login=True,
        username="root",
        commands=commands,
        downloads=[],
        first_event_id="synthetic-01-000",
    )


def _command(event_id: str, text: str) -> CompactedCommand:
    return CompactedCommand(event_id=event_id, timestamp="2026-08-20T10:00:05Z", command=text)


def test_estimate_tokens_rounds_up_and_is_nonzero_for_nonempty_text() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcde") == 2


def test_truncate_text_is_a_noop_under_the_limit() -> None:
    text = "wget http://example.com/x"
    assert truncate_text(text, max_chars=1000) == text


def test_truncate_text_keeps_head_and_tail_with_a_visible_marker() -> None:
    blob = "A" * 20000
    text = f"echo {blob} > payload.bin"
    truncated = truncate_text(text, max_chars=1000)

    assert len(truncated) < len(text)
    assert truncated.startswith("echo AAAA")
    assert truncated.endswith("payload.bin")
    assert "omitted" in truncated
    assert "explicitly bounded" in truncated


def test_chunk_items_keeps_a_small_input_in_one_chunk() -> None:
    items = ["a", "b", "c"]
    chunks = chunk_items(items, render=lambda xs: " ".join(xs), budget_tokens=1000)
    assert chunks == [["a", "b", "c"]]


def test_chunk_items_splits_when_rendered_size_exceeds_budget() -> None:
    # Each item renders to roughly 25 tokens (100 chars / 4); a budget of 40
    # tokens per chunk should force a new chunk every ~1-2 items.
    items = [f"item-{i}-" + "x" * 90 for i in range(6)]
    chunks = chunk_items(items, render=lambda xs: "\n".join(xs), budget_tokens=40)

    assert len(chunks) > 1
    # Every item survives, in order, across the chunks.
    flattened = [item for chunk in chunks for item in chunk]
    assert flattened == items


def test_chunk_items_never_produces_an_empty_chunk_when_items_given() -> None:
    items = list(range(50))
    chunks = chunk_items(items, render=lambda xs: str(xs), budget_tokens=30)
    assert all(chunk for chunk in chunks)


def test_chunk_items_of_empty_list_returns_one_empty_chunk() -> None:
    assert chunk_items([], render=lambda xs: "", budget_tokens=100) == [[]]


def test_chunk_session_returns_a_single_chunk_for_a_normal_session() -> None:
    session = _session([_command("e-1", "uname -a"), _command("e-2", "whoami")])
    chunks = chunk_session(session)

    assert len(chunks) == 1
    assert [c.event_id for c in chunks[0].commands] == ["e-1", "e-2"]


def test_chunk_session_splits_a_session_with_many_commands() -> None:
    # Each command is padded to comfortably exceed a few hundred chars;
    # enough of them blow well past SESSION_TOKEN_BUDGET (a few thousand
    # tokens), forcing more than one chunk.
    commands = [
        _command(f"e-{i:03d}", f"cmd{i} " + "x" * 400) for i in range(120)
    ]
    session = _session(commands)
    chunks = chunk_session(session)

    assert len(chunks) > 1

    # No command is lost or duplicated across chunks.
    seen = [c.event_id for chunk in chunks for c in chunk.commands]
    assert seen == [c.event_id for c in commands]

    # Every chunk actually fits the budget.
    from app.services.compaction import render_untrusted_block

    for chunk in chunks:
        assert estimate_tokens(render_untrusted_block(chunk)) <= SESSION_TOKEN_BUDGET


def test_chunk_session_truncates_a_pathologically_long_single_command() -> None:
    blob = "QQ" * 60000  # ~120k chars, alone far exceeds the token budget
    huge = _command("e-huge", f"echo {blob} | base64 -d > payload && chmod +x payload")
    session = _session([_command("e-1", "id"), huge])

    chunks = chunk_session(session)

    # The huge command's event id is preserved -- grounding survives even
    # though its text was truncated.
    all_ids = [c.event_id for chunk in chunks for c in chunk.commands]
    assert all_ids == ["e-1", "e-huge"]

    huge_out = next(
        c for chunk in chunks for c in chunk.commands if c.event_id == "e-huge"
    )
    assert len(huge_out.command) <= MAX_ITEM_CHARS + 200  # + marker text
    assert "omitted" in huge_out.command
    # The command's tail (the actually-executed payload) survives, not just
    # the head -- an attacker's real action often comes after the padding.
    assert huge_out.command.endswith("chmod +x payload")
