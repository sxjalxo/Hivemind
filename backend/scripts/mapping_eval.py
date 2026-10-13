"""Precision and recall of ATT&CK mapping: the rulebook alone, and rulebook + model.

Runs `mapper.map_techniques` -- the same function an analysis uses -- over the
labelled sessions in `mapping_corpus.yaml`, N times, and scores each run against
the labels. Nothing is written: no analysis row, no evidence, no enrichment. It
needs Ollama (or a BYOK key with --byok) and nothing else.

    python -m scripts.mapping_eval              # 3 runs, local model
    python -m scripts.mapping_eval --runs 5 --byok

Two things the output keeps apart, because merging them would flatter the system:

* `seed` cases are what the rules were written against; `heldout` cases are not.
  Rule recall on seed cases is high by construction.
* Rules are deterministic, so their score is one number. The model's is reported
  across runs as mean, min and max -- one run's score is an anecdote.

The labels are drafts until the team has reviewed them (see the corpus header).
"""

import argparse
import asyncio
import statistics
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.config import get_settings
from app.services.compaction import CompactedCommand
from app.services.llm import get_local_client
from app.services.llm.byok import ByokClient
from app.services.mitre.mapper import map_techniques

CORPUS = Path(__file__).with_name("mapping_corpus.yaml")


@dataclass(frozen=True)
class Case:
    id: str
    origin: str
    commands: list[str]
    expected: frozenset[str]


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __add__(self, other: "Counts") -> "Counts":
        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    @property
    def precision(self) -> float | None:
        # None, not 0 or 1, when nothing was predicted: there is no precision to report.
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


def score(expected: frozenset[str], predicted: set[str]) -> Counts:
    """Set comparison of technique ids for one session. Pure."""
    return Counts(
        tp=len(expected & predicted),
        fp=len(predicted - expected),
        fn=len(expected - predicted),
    )


def load_corpus(path: Path = CORPUS) -> list[Case]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        Case(c["id"], c["origin"], list(c["commands"]), frozenset(c["expected"]))
        for c in raw["cases"]
    ]


def _commands(case: Case) -> list[CompactedCommand]:
    return [
        CompactedCommand(
            event_id=f"{case.id}-{i}", timestamp=f"2026-01-01T00:00:{i:02d}Z", command=c
        )
        for i, c in enumerate(case.commands)
    ]


def _fmt(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.2f}"


def _spread(values: list[float | None]) -> str:
    present = [v for v in values if v is not None]
    if not present:
        return "n/a"
    return f"{statistics.mean(present):.2f} (min {min(present):.2f}, max {max(present):.2f})"


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--byok", action="store_true", help="use the configured BYOK model")
    args = parser.parse_args()

    settings = get_settings()
    if args.byok:
        if not (settings.byok_provider and settings.byok_api_key and settings.byok_model):
            raise SystemExit("--byok needs BYOK_PROVIDER, BYOK_API_KEY and BYOK_MODEL set")
        client = ByokClient(settings.byok_provider, settings.byok_api_key, settings.byok_model)
    else:
        client = get_local_client()

    cases = load_corpus()
    origins = sorted({c.origin for c in cases})
    rules: dict[str, Counts] = {o: Counts() for o in origins}
    combined: dict[str, list[Counts]] = {o: [] for o in origins}
    rejected_per_run: list[int] = []

    for run in range(args.runs):
        per_origin = {o: Counts() for o in origins}
        rejected = 0
        for case in cases:
            result = await map_techniques(_commands(case), client)
            predicted = {t.technique_id for t in result.techniques}
            by_rule = {t.technique_id for t in result.techniques if t.source == "rule"}
            per_origin[case.origin] += score(case.expected, predicted)
            rejected += result.rejected
            if run == 0:  # rules are deterministic: one pass is the whole answer
                rules[case.origin] += score(case.expected, by_rule)
        for origin in origins:
            combined[origin].append(per_origin[origin])
        rejected_per_run.append(rejected)
        print(f"run {run + 1}/{args.runs} done", flush=True)

    print(f"\nmodel: {client.model_name}   runs: {args.runs}   cases: {len(cases)}")
    print("labels: DRAFT until reviewed (see mapping_corpus.yaml)\n")
    for origin in origins:
        n = sum(1 for c in cases if c.origin == origin)
        r = rules[origin]
        print(f"[{origin}] {n} cases")
        print(f"  rules only      precision {_fmt(r.precision)}  recall {_fmt(r.recall)}")
        print(
            f"  rules + model   precision {_spread([c.precision for c in combined[origin]])}"
            f"  recall {_spread([c.recall for c in combined[origin]])}"
        )
    print(f"\nmodel proposals rejected by the evidence/catalog gates per run: {rejected_per_run}")


if __name__ == "__main__":
    asyncio.run(_main())
