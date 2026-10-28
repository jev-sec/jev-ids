"""The Isolation Forest baseline: anomaly detection fitted on benign traffic alone.

In reading order:

- `IsolationForestDetector`: `predict` fits one forest per cell on the benign Examples only, then scores one Flow with it.

The forest never sees an attack: it learns what normal traffic looks like and flags what is far from it, the classical anomaly-detection
setting of intrusion detection (Liu, Ting and Zhou, "Isolation Forest", ICDM 2008). A Detector that uses no labeled attack has no place on
the k axis, so it runs at k = all only and stands as a horizontal reference line, like the Random Forest at k = all. Flows are encoded
exactly as the Random Forest encodes them.

p_attack is the paper's anomaly score s: near 1 for a Flow that a few random cuts isolate, near 0 for one that takes as many cuts as the
deepest normal traffic, 0.5 for one that is no easier to isolate than average, which makes the shared 0.5 cut the paper's own threshold.
scikit-learn's `score_samples` returns -s ("the opposite of the anomaly score defined in the original paper"), so the sign is flipped here.
"""

import time
from collections.abc import Sequence
from typing import Any

from sklearn.ensemble import IsolationForest  # pyright: ignore[reportMissingTypeStubs]

from jev_ids.dataset import Flow
from jev_ids.detectors.random_forest import Encoder, Vocabulary

N_ESTIMATORS = 100
RANDOM_STATE = 0


class IsolationForestDetector:
    """Scores Flows with an IsolationForest fitted on the benign Examples of the cell."""

    name = "isolation_forest"
    prompt_hash = None  # the forest reads no prompt
    record = "full"  # the forest reads the values themselves, never rounded (docs/jevids-design.md, D7)

    def __init__(self, vocabulary: Vocabulary, benign: str, jobs: int = 1) -> None:
        """Keep the encoding and the benign label; fitting waits for `predict`.

        Args:
            vocabulary: the symbolic values of the pool (see `random_forest.vocabulary`).
            benign: the card's benign category, the only one the forest is fitted on.
            jobs: CPU cores a fit may use, scikit-learn's `n_jobs` (-1 for all); the fixed random_state makes the forest the same for any
                value.
        """
        self.encoder = Encoder(vocabulary)
        self.benign = benign
        self.jobs = jobs
        self.model = f"sklearn-isolation-forest-{N_ESTIMATORS}"
        self.fit_count = 0
        # Fitted once per Examples list (by identity), as the Random Forest is, so every rep of a cell reuses the same forest.
        self._fitted_on_examples_id: int | None = None
        self._forest: Any = None
        self._train_flows = 0
        self._train_time_ms = 0.0

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow: p_attack = the anomaly score, the benign Flows fitted on, timings.

        A cell's first Flow fits a fresh forest on the benign Examples alone and times the fit; the rest of the cell reuses it. An
        unsupervised Detector names no Category, so the row carries none. Latency is the wall clock around `score_samples` alone.
        """
        if self._fitted_on_examples_id != id(examples):
            benign = [example for example in examples if example.category == self.benign]
            if not benign:
                raise ValueError("the Isolation Forest needs benign Examples to learn from: run it at k = all")
            matrix = self.encoder.matrix(benign)
            self._forest = IsolationForest(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE, n_jobs=self.jobs)
            started = time.perf_counter()
            self._forest.fit(matrix)
            self._train_time_ms = (time.perf_counter() - started) * 1000
            self._train_flows = len(benign)
            self._fitted_on_examples_id = id(examples)
            self.fit_count += 1
        matrix = self.encoder.matrix([flow])
        started = time.perf_counter()
        anomaly_score = -float(self._forest.score_samples(matrix)[0])
        return {
            "p_attack": anomaly_score,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "train_flows": self._train_flows,
            "train_time_ms": self._train_time_ms,
        }
