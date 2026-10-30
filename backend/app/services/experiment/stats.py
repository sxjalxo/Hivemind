"""The persona experiment's test (R3): a permutation test over blocks, Holm across metrics.

The block is the unit: each included block gives one value per metric, and the
question is whether the arms' means differ more than relabelling the blocks at
random (keeping each arm's block count) makes them differ. Pure, stdlib only.
"""

import math
import random
from collections import Counter, defaultdict
from itertools import combinations

EXHAUSTIVE_LIMIT = 500_000
SAMPLES = 100_000


def spread(values: list[float], labels: list[str]) -> float:
    """Between-arm sum of squares: over arms, n * (arm mean - overall mean)^2."""
    overall = sum(values) / len(values)
    sums: dict[str, float] = defaultdict(float)
    counts: Counter[str] = Counter()
    for value, label in zip(values, labels, strict=True):
        sums[label] += value
        counts[label] += 1
    return sum(n * (sums[a] / n - overall) ** 2 for a, n in counts.items())


def relabelings(sizes: list[int]) -> int:
    """How many ways blocks can be relabelled keeping each arm's count (a multinomial)."""
    total = math.factorial(sum(sizes))
    for size in sizes:
        total //= math.factorial(size)
    return total


def smallest_p(sizes: list[int]) -> float:
    """The smallest p the exhaustive test can reach for these arm block counts.

    The observed split is always as extreme as itself, and so is every relabelling that
    only swaps the labels of equal-sized arms (the spread is unchanged by that).
    """
    ties = 1
    for count in Counter(sizes).values():
        ties *= math.factorial(count)
    return ties / relabelings(sizes)


def _assignments(indices: tuple[int, ...], sizes: list[int]):
    """Every split of `indices` into groups of the given sizes, in order."""
    if len(sizes) == 1:
        yield [indices]
        return
    for chosen in combinations(indices, sizes[0]):
        rest = tuple(i for i in indices if i not in chosen)
        for tail in _assignments(rest, sizes[1:]):
            yield [chosen, *tail]


def permutation_p(
    values: list[float],
    labels: list[str],
    *,
    limit: int = EXHAUSTIVE_LIMIT,
    samples: int = SAMPLES,
    seed: int = 0,
) -> tuple[float, bool]:
    """p-value of the observed spread; returns (p, whether every relabelling was tried).

    Exhaustive when there are at most `limit` relabellings, counting the observed one,
    so p is never 0. Otherwise `samples` seeded shuffles and p = (hits + 1) / (samples + 1).
    """
    observed = spread(values, labels)
    floor = observed - 1e-12 * max(1.0, abs(observed))  # float noise must not lose a tie
    arms = sorted(set(labels))
    sizes = [labels.count(a) for a in arms]
    if relabelings(sizes) <= limit:
        hits = total = 0
        relabelled = list(labels)
        for groups in _assignments(tuple(range(len(values))), sizes):
            for arm, group in zip(arms, groups, strict=True):
                for i in group:
                    relabelled[i] = arm
            total += 1
            hits += spread(values, relabelled) >= floor
        return hits / total, True
    rng = random.Random(seed)
    shuffled = list(labels)
    hits = 0
    for _ in range(samples):
        rng.shuffle(shuffled)
        hits += spread(values, shuffled) >= floor
    return (hits + 1) / (samples + 1), False


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-adjusted p-values: step-down, kept monotone, capped at 1."""
    ordered = sorted(pvalues.items(), key=lambda kv: kv[1])
    out: dict[str, float] = {}
    running = 0.0
    for rank, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (len(ordered) - rank) * p))
        out[name] = running
    return out
