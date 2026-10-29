"""The `Selector` of Jev IDS: which Examples of each Category one Flow gets (docs/jevids-design.md, D6).

In reading order:

- `Space`: Flows as points, the features standardised with the pool's mean and standard deviation, Protocol one-hot.
- `unit_rank`: values as ranks scaled to [0, 1], ties sharing their mean rank.
- `difficulty`: how hard a memory Flow was for Jev, from the row it produced.
- `Selector`: per Category, a score (similarity + recency + difficulty) and maximal marginal relevance (MMR) over the visible memory.
- `mmr`: the picking itself, over one Category's candidates.

Everything is deterministic: the same memory and the same Flow give the same Examples, so repetitions measure Jev's own variation.
"""

import math
import random
from collections.abc import Mapping, Sequence

import numpy as np

from jev_ids.dataset import Flow
from jev_ids.detectors.random_forest import Encoder, Vocabulary
from jev_ids.records import Prediction
from jev_ids.stream import Memory, end_of

# Weighting MMR with λ, half on the score and half on not repeating what was already chosen, a value fixed in D6 and never tuned.
LAMBDA = 0.5
# Scoring the difficulty of a Flow Jev never answered, a pool Flow or a judged one whose call failed.
UNKNOWN_DIFFICULTY = 0.5


class Space:
    """Flows as points: numeric features standardised with the pool's mean and standard deviation, Protocol one-hot as 0 or 1.

    A numeric feature that never varies in the pool keeps its scale of 1, so it adds no distance and no division by zero. The one-hot
    columns are left as they are, so two Flows of different Protocols are at least √2 apart on them.
    """

    def __init__(self, vocabulary: Vocabulary, pool: Sequence[Flow]) -> None:
        """Encode the pool once and take its mean and standard deviation per numeric feature."""
        self.encoder = Encoder(vocabulary)
        matrix = self.encoder.matrix(pool)
        n_one_hot = sum(len(values) for values in vocabulary.values())
        n_numeric = matrix.shape[1] - n_one_hot
        std = matrix[:, :n_numeric].std(axis=0)
        self.mean = np.concatenate([matrix[:, :n_numeric].mean(axis=0), np.zeros(n_one_hot)])
        self.scale = np.concatenate([np.where(std > 0, std, 1.0), np.ones(n_one_hot)])

    def points(self, flows: Sequence[Flow]) -> np.ndarray:
        """The Flows as standardised rows, in order."""
        return (self.encoder.matrix(flows) - self.mean) / self.scale


def unit_rank(values: np.ndarray) -> np.ndarray:
    """Each value's rank scaled to [0, 1]: 0 for the smallest, 1 for the largest, equal values sharing their mean rank; one value gets 1."""
    if len(values) == 1:
        return np.ones(1)
    order = np.argsort(values, kind="stable")
    ranks = np.empty(len(values))
    ranks[order] = np.arange(len(values))
    _, groups = np.unique(values, return_inverse=True)
    mean_ranks = np.bincount(groups, weights=ranks) / np.bincount(groups)
    return mean_ranks[groups] / (len(values) - 1)


def difficulty(row: Prediction | None) -> float:
    """1 when Jev got the Category wrong, 1 − |2·p_attack − 1| when right, 0.5 when Jev never answered (a pool Flow, a failed call).

    Wrong means `category_pred` differs from the true Category, the same error the `KController` reacts to (D5).
    A confident error scores 1, not 0, which is why a wrong answer is set apart from the formula.

    Args:
        row: the row Jev produced for the Flow, or None for a pool Flow.

    Returns:
        The difficulty, in [0, 1].
    """
    if row is None or row.get("error") is not None or row.get("p_attack") is None:
        return UNKNOWN_DIFFICULTY
    if row.get("category_pred") != row["category_true"]:
        return 1.0
    return 1.0 - abs(2.0 * float(row["p_attack"]) - 1.0)


class Selector:
    """Chooses ceil(k_c) Examples of each Category for one Flow, by score and MMR over the memory visible to it."""

    def __init__(self, space: Space) -> None:
        """Keep the space the distances are measured in."""
        self.space = space

    def choose(self, memory: Memory, flow: Flow, step: int, k: Mapping[str, float]) -> list[Flow]:
        """The Examples for `flow` at `step`: ceil(k[c]) per Category c, or fewer when the Category has fewer distinct candidates.

        The final order is a shuffle seeded by the Flow alone, so no Detector sees
        the Examples grouped by Category and a repetition sees the same request.

        Args:
            memory: the labeled Flows the step may use.
            flow: the Flow to judge.
            step: the position of `flow` in the stream.
            k: the Examples wanted per Category, rounded up when fractional.

        Returns:
            The chosen Examples, shuffled.
        """
        target = self.space.points([flow])[0]
        chosen: list[Flow] = []
        for category in memory.categories:
            candidates = memory.visible(category, step, end_of(flow))
            if candidates and k.get(category, 0) > 0:
                chosen += self.pick(memory, target, candidates, math.ceil(k[category]))
        random.Random(f"{flow.row_id}:order").shuffle(chosen)  # noqa: S311  seeded, not secret
        return chosen

    def pick(self, memory: Memory, target: np.ndarray, candidates: Sequence[Flow], count: int) -> list[Flow]:
        """`count` of one Category's candidates: the score of each, then MMR."""
        points = self.space.points(candidates)
        similarity = unit_rank(-np.linalg.norm(points - target, axis=1))
        recency = unit_rank(np.asarray([end_of(candidate).timestamp() for candidate in candidates]))
        hardness = np.asarray([difficulty(memory.rows.get(candidate.row_id)) for candidate in candidates])
        return [candidates[index] for index in mmr(points, similarity + recency + hardness, count)]


def mmr(points: np.ndarray, score: np.ndarray, count: int) -> list[int]:
    """The indexes of up to `count` points, each maximising λ·score/3 − (1 − λ)·(its highest redundancy with those already chosen).

    Redundancy is 1 / (1 + distance), in [0, 1]. A point at distance 0 from a chosen one, an exact copy, is never chosen: it would tell
    Jev nothing new and cost tokens, so a Category with only copies left gets fewer Examples. Ties go to the earlier index.

    Args:
        points: the candidates as standardised rows.
        score: each candidate's similarity + recency + difficulty.
        count: how many points to choose at most.

    Returns:
        The chosen indexes, in the order they were chosen.
    """
    redundancy = np.zeros(len(points))
    eligible = np.ones(len(points), dtype=bool)
    chosen: list[int] = []
    while len(chosen) < count and eligible.any():
        value = np.where(eligible, LAMBDA * score / 3 - (1 - LAMBDA) * redundancy, -np.inf)
        best = int(np.argmax(value))
        chosen.append(best)
        distance = np.linalg.norm(points - points[best], axis=1)
        redundancy = np.maximum(redundancy, 1 / (1 + distance))
        eligible &= distance > 0
    return chosen
