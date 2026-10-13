"""The degradation matrix's repeat-run summary. Pure: no runs are executed."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

_SPEC = importlib.util.spec_from_file_location(
    "run_degradation_matrix",
    Path(__file__).resolve().parents[1] / "scripts" / "run_degradation_matrix.py",
)
matrix = importlib.util.module_from_spec(_SPEC)
sys.modules["run_degradation_matrix"] = matrix
_SPEC.loader.exec_module(matrix)


def _run(**scores):
    return SimpleNamespace(
        category_scores=[
            SimpleNamespace(characteristic=c, deterministic_score=v) for c, v in scores.items()
        ],
        findings=[],
    )


def test_spread_is_computed_over_established_scores_only():
    runs = [_run(sanity=1.0, file_system=0.333), _run(sanity=0.667, file_system=None)]
    summary = matrix.stability(runs)

    mean, low, high, established, n = summary["sanity"]
    assert (round(mean, 4), low, high, established, n) == (0.8335, 0.667, 1.0, 2, 2)
    # One unestablished run is counted in n, never averaged in as a zero.
    assert summary["file_system"] == (0.333, 0.333, 0.333, 1, 2)


def test_a_characteristic_never_established_reports_none_not_zero():
    assert matrix.stability([_run(), _run()])["context"] == (None, None, None, 0, 2)
