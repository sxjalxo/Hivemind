"""The persona experiment's permutation test and Holm correction (R3). Pure."""

import pytest

from app.services.experiment.stats import holm, permutation_p, relabelings, smallest_p, spread


def test_spread_is_the_between_arm_sum_of_squares() -> None:
    # arm means 1.5 and 3.5 around 2.5: 2 * 1 + 2 * 1
    assert spread([1, 2, 3, 4], ["a", "a", "b", "b"]) == pytest.approx(4.0)
    assert spread([1, 2, 3, 4], ["a", "b", "b", "a"]) == pytest.approx(0.0)


def test_relabelings_keep_each_arms_block_count() -> None:
    assert relabelings([2, 2]) == 6
    assert relabelings([3, 3, 3, 3]) == 369_600


def test_a_hand_computed_exhaustive_p_value() -> None:
    # Six relabelings of [1, 2, 3, 4] into two pairs; spreads 4, 4, 1, 1, 0, 0.
    assert permutation_p([1, 2, 3, 4], ["a", "a", "b", "b"]) == (pytest.approx(2 / 6), True)


def test_a_clean_separation_reaches_the_smallest_possible_p() -> None:
    # C(6, 3) = 20 relabelings; only the observed split and its mirror are as extreme.
    assert permutation_p([1, 1, 1, 9, 9, 9], list("aaabbb")) == (pytest.approx(2 / 20), True)


def test_identical_values_give_p_one() -> None:
    assert permutation_p([5.0] * 6, list("aabbcc"))[0] == pytest.approx(1.0)


def test_too_many_relabelings_fall_back_to_seeded_random_ones() -> None:
    values, labels = [1, 1, 1, 9, 9, 9], list("aaabbb")
    p, exhaustive = permutation_p(values, labels, limit=10, samples=2_000, seed=0)
    assert exhaustive is False
    assert 0 < p < 0.2
    assert permutation_p(values, labels, limit=10, samples=2_000, seed=0)[0] == p  # repeatable


def test_holm_steps_down_and_stays_monotone() -> None:
    adjusted = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adjusted == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
    assert holm({"a": 0.6, "b": 0.7}) == pytest.approx({"a": 1.0, "b": 1.0})


def test_the_smallest_attainable_p_counts_label_swaps_of_equal_arms() -> None:
    assert smallest_p([3, 3]) == pytest.approx(2 / 20)
    assert smallest_p([3, 3, 3, 3]) == pytest.approx(24 / 369_600)
    assert smallest_p([2, 3]) == pytest.approx(1 / 10)
