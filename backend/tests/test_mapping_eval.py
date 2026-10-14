"""The mapping-evaluation harness's arithmetic and corpus. No model needed."""

import importlib.util
import sys
from pathlib import Path

from app.services.mitre.catalog import load_catalog

_SPEC = importlib.util.spec_from_file_location(
    "mapping_eval", Path(__file__).resolve().parents[1] / "scripts" / "mapping_eval.py"
)
me = importlib.util.module_from_spec(_SPEC)
sys.modules["mapping_eval"] = me
_SPEC.loader.exec_module(me)


def test_scoring_counts_hits_extras_and_misses():
    counts = me.score(frozenset({"T1082", "T1105"}), {"T1105", "T1496"})
    assert (counts.tp, counts.fp, counts.fn) == (1, 1, 1)
    assert counts.precision == 0.5 and counts.recall == 0.5


def test_nothing_predicted_has_no_precision_rather_than_a_perfect_one():
    counts = me.score(frozenset({"T1082"}), set())
    assert counts.precision is None
    assert counts.recall == 0.0


def test_a_mentions_only_case_turns_any_prediction_into_a_false_positive():
    counts = me.score(frozenset(), {"T1105"})
    assert (counts.tp, counts.fp, counts.fn) == (0, 1, 0)
    assert counts.recall is None


def test_counts_add_up_across_sessions():
    total = me.Counts(1, 2, 3) + me.Counts(4, 5, 6)
    assert (total.tp, total.fp, total.fn) == (5, 7, 9)


def test_every_label_is_in_the_pinned_catalog_and_every_case_id_is_unique():
    """A catalog change that drops an id must fail here, not quietly score as a miss."""
    cases = me.load_corpus()
    catalog = load_catalog()
    assert [c.id for c in cases] == list(dict.fromkeys(c.id for c in cases))
    outside = [(c.id, t) for c in cases for t in c.expected if t not in catalog]
    assert outside == []
    assert {c.origin for c in cases} <= {"seed", "tuned", "heldout"}
