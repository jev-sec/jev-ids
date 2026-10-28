"""The Random Forest baseline.

In reading order:

- `vocabulary`: the values every symbolic feature takes in the pool, so the one-hot encoding is fixed for the whole run.
- `feature_vector`: one Flow as numbers, numeric features first, then one column per known symbolic value.
- `Encoder`: Flows as a matrix, each Flow encoded once; both forests encode through it.
- `RandomForestDetector`: `predict` fits one forest of 100 trees with a fixed seed per cell, on that cell's Examples and one class per
  Category, then judges one Flow with it.

`p_attack = 1 - P(benign)`, the Verdict is taken at the shared threshold like every Detector, and the training time is repeated in every row
of the cell.
"""

import time
from collections.abc import Sequence
from typing import Any

import numpy as np
from sklearn.ensemble import (  # pyright: ignore[reportMissingTypeStubs]
    RandomForestClassifier,
)

from jev_ids.dataset import Config, Flow

N_ESTIMATORS = 100
RANDOM_STATE = 0

# Feature index -> the sorted values it takes in the pool, one entry per symbolic feature, in card order.
Vocabulary = dict[int, tuple[str, ...]]


def vocabulary(flows: Sequence[Flow], config: Config) -> Vocabulary:
    """The sorted values of each symbolic feature of the card, by feature index.

    Taken from the whole pool and not from the Examples of a cell, so that every cell of a run encodes a Flow the same way whatever k was
    drawn.
    """
    indexes: list[int] = [config["features"].index(name) for name in config["symbolic"]]
    seen: dict[int, set[str]] = {index: set() for index in indexes}
    for flow in flows:
        values = flow.attribute_values
        for index in indexes:
            seen[index].add(values[index])
    return {index: tuple(sorted(seen[index])) for index in indexes}


def feature_vector(flow: Flow, vocabulary: Vocabulary) -> list[float]:
    """The numeric features as floats, in order, then the symbolic ones one-hot.

    A symbolic value absent from the pool becomes all zeros, the equivalent of scikit-learn's `handle_unknown="ignore"`, so a split Flow
    never breaks the forest.
    """
    values = flow.attribute_values
    numeric = [float(value) for index, value in enumerate(values) if index not in vocabulary]
    one_hot: list[float] = []
    for index, known_values in vocabulary.items():
        one_hot.extend(float(known == values[index]) for known in known_values)
    return numeric + one_hot


class Encoder:
    """Flows as the rows of a matrix, each Flow encoded once and kept.

    A stream refits the forests at every step on nearly the same memory, up to about 90,000 Flows; encoding them all again took about 2 s
    a step, longer than many of the fits. Flows are frozen, so a Flow is its own key.
    """

    def __init__(self, vocabulary: Vocabulary) -> None:
        """Keep the vocabulary; no Flow is encoded yet."""
        self.vocabulary = vocabulary
        self._rows: dict[Flow, np.ndarray] = {}

    def matrix(self, flows: Sequence[Flow]) -> np.ndarray:
        """The Flows as one row each, in order."""
        rows: list[np.ndarray] = []
        for flow in flows:
            row = self._rows.get(flow)
            if row is None:
                row = self._rows[flow] = np.asarray(feature_vector(flow, self.vocabulary), dtype=float)
            rows.append(row)
        return np.vstack(rows)


class RandomForestDetector:
    """Judges Flows with a RandomForestClassifier fitted on the cell's Examples."""

    name = "random_forest"
    prompt_hash = None  # the forest reads no prompt

    def __init__(self, vocabulary: Vocabulary, benign: str, jobs: int = 1) -> None:
        """Keep the encoding and the benign label; fitting waits for `predict`.

        Args:
            vocabulary: the symbolic values of the pool (see `vocabulary`).
            benign: the card's benign category, whose probability gives p_attack.
            jobs: CPU cores a fit may use, scikit-learn's `n_jobs` (-1 for all); the fixed random_state makes the forest the same for any
                value.
        """
        self.encoder = Encoder(vocabulary)
        self.benign = benign
        self.jobs = jobs
        self.model = f"sklearn-random-forest-{N_ESTIMATORS}"
        self.fit_count = 0
        # The run loop hands the same Examples list to every rep of a cell, so the forest is fitted once per list (by identity) and
        # the training time is repeated in every row of that cell.
        self._fitted_on_examples_id: int | None = None
        self._forest: Any = None
        self._train_time_ms = 0.0

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow: p_attack = 1 - P(benign), the most probable Category, timings.

        A cell's first Flow fits a fresh forest on the Examples, labeled by Category, and times the fit; the rest of the cell reuses it.
        Latency is the wall clock around `predict_proba` alone.
        """
        if self._fitted_on_examples_id != id(examples):
            if not examples:
                raise ValueError("the Random Forest needs k >= 1: nothing to train at k = 0")
            matrix = self.encoder.matrix(examples)
            labels = np.asarray([example.category for example in examples])
            self._forest = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE, n_jobs=self.jobs)
            started = time.perf_counter()
            self._forest.fit(matrix, labels)
            self._train_time_ms = (time.perf_counter() - started) * 1000
            self._fitted_on_examples_id = id(examples)
            self.fit_count += 1
        matrix = self.encoder.matrix([flow])
        started = time.perf_counter()
        row: list[float] = self._forest.predict_proba(matrix)[0].tolist()
        latency_ms = (time.perf_counter() - started) * 1000
        probabilities = dict(zip((str(label) for label in self._forest.classes_), row, strict=True))
        return {
            "p_attack": 1.0 - probabilities.get(self.benign, 0.0),
            "category_pred": max(probabilities, key=lambda name: probabilities[name]),
            "latency_ms": latency_ms,
            "train_time_ms": self._train_time_ms,
        }
