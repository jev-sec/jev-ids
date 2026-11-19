"""The Random Forest baseline.

In reading order:

- `ForestDetector`: what the Random Forest and the Isolation Forest share, the encoding and one fit per cell.
- `RandomForestDetector`: `predict` fits one forest of 100 trees with a fixed seed per cell,
  on that cell's Examples and one class per Category, then judges one Flow with it.

`p_attack = 1 - P(benign)`, the Verdict is taken at the shared threshold like every Detector,
and the training time is repeated in every row of the cell.
"""

import time
from collections.abc import Sequence
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier  # pyright: ignore[reportMissingTypeStubs]  scikit-learn ships no type stubs

from jev_ids.dataset import Encoder, Flow, Vocabulary

N_ESTIMATORS = 100
RANDOM_STATE = 0


class ForestDetector:
    """What both forests share: the encoding of the pool, the benign label and one timed fit per Examples list."""

    # Storing no prompt hash, because a forest reads no prompt.
    prompt_hash = None
    # Feeding the forest the values themselves, never rounded (docs/jevids-design.md, D7).
    record = "full"

    def __init__(self, vocabulary: Vocabulary, benign: str, jobs: int = 1) -> None:
        """Keep the encoding and the benign label; fitting waits for `predict`.

        Args:
            vocabulary: the symbolic values of the pool (see `dataset.vocabulary`).
            benign: the card's benign category.
            jobs: CPU cores a fit may use, scikit-learn's `n_jobs` (-1 for all).
                The fixed `random_state` makes the forest the same for any value.
        """
        self.encoder = Encoder(vocabulary)
        self.benign = benign
        self.jobs = jobs
        self.fit_count = 0
        # Fitting the forest once per Examples list (by identity), since the run loop hands the same list
        # to every rep of a cell, and repeating the training time in every row of that cell.
        self._fitted_on_examples_id: int | None = None
        self._forest: Any = None
        self._train_time_ms = 0.0


class RandomForestDetector(ForestDetector):
    """Judges Flows with a RandomForestClassifier fitted on the cell's Examples."""

    name = "random_forest"
    model = f"sklearn-random-forest-{N_ESTIMATORS}"

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow: p_attack = 1 - P(benign), the most probable Category, timings.

        A cell's first Flow fits a fresh forest on the Examples, labeled by Category, and times the fit.
        The rest of the cell reuses it. Latency is the wall clock around `predict_proba` alone.

        Args:
            flow: the Flow to judge.
            examples: the cell's Examples, which train the forest.

        Returns:
            The row fields `p_attack`, `category_pred`, `latency_ms` and `train_time_ms`.
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
