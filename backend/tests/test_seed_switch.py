"""`seed_corpus_on_startup` gates the startup seeding and nothing else."""

import pytest

from app import main
from app.config import get_settings
from app.main import app
from app.seed import seeder
from app.services.evaluation import runs


class _Closable:
    async def close(self) -> None:
        return None

    async def dispose(self) -> None:
        return None


async def _lifespan_with(monkeypatch, *, enabled: bool, already_seeded: int) -> list[str]:
    calls: list[str] = []

    async def _noop(*args, **kwargs) -> None:
        return None

    async def _seeded_count() -> int:
        return already_seeded

    async def _seed(*args, **kwargs) -> int:
        calls.append("seed")
        return 0

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: get_settings().model_copy(update={"seed_corpus_on_startup": enabled}),
    )
    monkeypatch.setattr(main, "bootstrap_es", _noop)
    monkeypatch.setattr(main, "get_es", lambda: _Closable())
    monkeypatch.setattr(main, "get_engine", lambda: _Closable())
    monkeypatch.setattr(runs, "reconcile_orphaned_runs_at_startup", _noop)
    monkeypatch.setattr(seeder, "seeded_count", _seeded_count)
    monkeypatch.setattr(seeder, "seed", _seed)

    async with main.lifespan(app):
        pass
    return calls


async def test_an_unseeded_index_is_seeded_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await _lifespan_with(monkeypatch, enabled=True, already_seeded=0) == ["seed"]


async def test_the_switch_off_stops_seeding_even_on_an_empty_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The case the switch exists for: a fresh live deployment, nothing seeded.
    assert await _lifespan_with(monkeypatch, enabled=False, already_seeded=0) == []


async def test_an_existing_corpus_is_left_alone_either_way(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert await _lifespan_with(monkeypatch, enabled=True, already_seeded=51) == []
