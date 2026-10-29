"""Isolation Forest detector: benign-only fit, once per Examples object, the anomaly score as p_attack."""

import pytest

from jev_ids.dataset import Flow
from jev_ids.detectors import isolation_forest, random_forest
from tests.helpers import CONFIG


def flow(row_id: int, category: str, bytes_: str) -> Flow:
    """A Flow of CONFIG: `a` is bytes_, `b` (symbolic) is always tcp, `c` is 0."""
    return Flow(row_id, f"{bytes_},tcp,0", category, category != "normal")


# Placing benign traffic between 300 and 331 bytes and the two attacks of the pool far below it.
NORMALS = [flow(index, "normal", str(300 + index)) for index in range(32)]
ATTACKS = [flow(32, "dos", "0"), flow(33, "probe", "2")]
POOL = NORMALS + ATTACKS
VOCABULARY = random_forest.vocabulary(POOL, CONFIG)


def test_predict_fits_on_the_benign_examples_once_and_scores_the_far_flow_higher() -> None:
    detector = isolation_forest.IsolationForestDetector(VOCABULARY, "normal")
    examples = list(POOL)

    normal = detector.predict(NORMALS[3], examples)
    attack = detector.predict(flow(99, "dos", "1"), examples)
    second = detector.predict(NORMALS[5], examples)

    assert detector.fit_count == 1
    assert (detector.name, detector.model) == ("isolation_forest", f"sklearn-isolation-forest-{isolation_forest.N_ESTIMATORS}")
    assert detector.prompt_hash is None
    assert set(normal) == {"p_attack", "latency_ms", "train_flows", "train_time_ms"}
    # Fitting on the 32 benign Flows of the list alone, whatever else it held.
    assert normal["train_flows"] == 32
    assert 0.0 <= normal["p_attack"] < attack["p_attack"] <= 1.0
    assert normal["train_time_ms"] == second["train_time_ms"] > 0
    assert normal["latency_ms"] > 0
    detector.predict(NORMALS[0], list(POOL))
    assert detector.fit_count == 2


def test_fit_needs_benign_examples() -> None:
    detector = isolation_forest.IsolationForestDetector(VOCABULARY, "normal")
    with pytest.raises(ValueError, match="benign Examples"):
        detector.predict(NORMALS[0], ATTACKS)
