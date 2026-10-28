"""The kNN baseline: a majority vote of the nearest memory Flows, in the space the `Selector` measures (docs/jevids-design.md, D10).

In reading order:

- `parse_neighbours`: `--neighbours`, a fixed K or `matched:k`.
- `KNNDetector`: `predict` finds the K nearest Flows of the whole visible memory and lets them vote.
- `matched_count`: how many Examples the `Selector` gives Jev at k per Category for the same memory, the K of the matched variant.

If this vote matches Jev IDS, Jev adds nothing to the neighbours it is shown. Two values of K were fixed on 2026-10-28, before any kNN
result: K = 4, a plain nearest-neighbour vote, and `matched:4`, as many neighbours as Jev reads at k = 4, so both read the same number of
Flows. The kNN reads the values in full, like the forests, and is deterministic, so it runs with one seed.
"""

import time
from collections import Counter
from collections.abc import Sequence
from typing import Any

import numpy as np

from jev_ids.dataset import Flow
from jev_ids.selector import Space

MATCHED = "matched:"


def parse_neighbours(text: str) -> tuple[int, bool]:
    """`4` -> (4, False), a fixed K; `matched:4` -> (4, True), K = the Examples the `Selector` gives Jev at k = 4."""
    matched = text.startswith(MATCHED)
    value = int(text.removeprefix(MATCHED))
    if value < 1:
        raise ValueError(f"neighbours {text!r}: at least 1")
    return value, matched


def matched_count(categories: Sequence[str], points: np.ndarray, k: int) -> int:
    """The Examples the `Selector` gives Jev: per Category, k or its number of distinct points, since MMR never takes an exact copy."""
    labels = np.asarray(categories)
    return sum(min(k, len(np.unique(points[labels == category], axis=0))) for category in set(categories))


class KNNDetector:
    """Judges a Flow by the Categories of its nearest Flows in the memory it is given."""

    name = "knn"
    prompt_hash = None  # the vote reads no prompt
    record = "full"  # it measures the values themselves, never rounded (D7)

    def __init__(self, space: Space, benign: str, neighbours: str) -> None:
        """Keep the space, the benign label and K.

        Args:
            space: the `Selector`'s space, standardised on the pool.
            benign: the card's benign Category; p_attack is the share of neighbours outside it.
            neighbours: `parse_neighbours`' text.
        """
        self.space = space
        self.benign = benign
        self.k, self.matched = parse_neighbours(neighbours)
        self.model = f"knn-{neighbours.replace(':', '-')}"

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """The K nearest Examples vote: the most frequent Category wins, a tie going to the Category of the nearest tied neighbour.

        Equal distances keep the memory's order. Latency covers the distances and the vote, not the encoding of the memory.
        """
        if not examples:
            raise ValueError("the kNN needs a memory to vote from: run it at k = all")
        points = self.space.points(examples)
        categories = [example.category for example in examples]
        count = matched_count(categories, points, self.k) if self.matched else self.k
        started = time.perf_counter()
        distance = np.linalg.norm(points - self.space.points([flow])[0], axis=1)
        order: list[int] = np.argsort(distance, kind="stable")[:count].tolist()
        nearest = [categories[index] for index in order]
        votes = Counter(nearest)
        top = max(votes.values())
        category = next(name for name in nearest if votes[name] == top)
        return {
            "p_attack": sum(name != self.benign for name in nearest) / len(nearest),
            "category_pred": category,
            "neighbours": len(nearest),
            "latency_ms": (time.perf_counter() - started) * 1000,
        }
