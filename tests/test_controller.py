"""The `KController`: error, success and an absent Category, and the hook that feeds it the returned rows."""

import math
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from jev_ids import controller, selector, stream
from jev_ids.detectors.random_forest import vocabulary
from tests.helpers import CONFIG, make_flow, make_prediction

CATEGORIES: list[str] = CONFIG["categories"]


def row(category: str, predicted: str | None, **overrides: object) -> dict[str, object]:
    return make_prediction(1, int(category != "normal"), 0.9, category_true=category, category_pred=predicted, **overrides)


def test_an_error_doubles_k_up_to_eight() -> None:
    kc = controller.KController(CATEGORIES)
    assert kc.k == {
        "normal": 1.0,
        "dos": 1.0,
        "probe": 1.0,
    }
    for expected in (2.0, 4.0, 8.0, 8.0):
        kc.feedback(row("dos", "normal"))
        assert kc.k["dos"] == expected
    # Counting a missing Category answer as an error too.
    kc.feedback(row("probe", None))
    assert kc.k["probe"] == 2.0
    # Tripling k instead under β = 3, a value of stage 6's sensitivity check.
    tripled = controller.KController(CATEGORIES, beta=3.0)
    for expected in (3.0, 8.0):
        tripled.feedback(row("dos", "normal"))
        assert tripled.k["dos"] == expected


def test_a_success_removes_one_over_k_down_to_one() -> None:
    kc = controller.KController(CATEGORIES)
    kc.k["dos"] = 8.0
    kc.feedback(row("dos", "dos"))
    assert kc.k["dos"] == pytest.approx(7.875)
    # Removing about one Example every k successes, so four successes take k from 4 to 2.88.
    kc.k["dos"] = 4.0
    for _ in range(4):
        kc.feedback(row("dos", "dos"))
    assert kc.k["dos"] == pytest.approx(2.8834, abs=1e-4)
    kc.k["dos"] = 1.0
    kc.feedback(row("dos", "dos"))
    assert kc.k["dos"] == 1.0


def test_an_absent_category_and_a_failed_call_change_nothing() -> None:
    kc = controller.KController(CATEGORIES)
    kc.feedback(row("dos", "normal"))
    # Changing the k of the true Category alone, so the predicted one and the absent one keep theirs.
    assert (kc.k["normal"], kc.k["probe"]) == (1.0, 1.0)
    kc.feedback(row("dos", None, error="HTTP 500"))
    assert kc.k["dos"] == 2.0


def test_the_hook_reacts_when_the_label_comes_back_at_t_plus_d() -> None:
    start = datetime(2017, 7, 3, 12, 0)
    pool = [replace(make_flow(index, category, value=str(index)), end=start) for index, category in enumerate(["normal", "dos", "dos"])]
    memory = stream.Memory(pool, CATEGORIES, 2)
    hook = controller.Controlled(
        selector.Selector(selector.Space(vocabulary(pool, CONFIG), pool)).choose, controller.KController(CATEGORIES)
    )
    flows = [replace(make_flow(100 + step, "dos", value="1"), end=start + timedelta(minutes=step + 1)) for step in range(3)]
    k_seen: list[float] = []
    for step, flow in enumerate(flows):
        examples, fields = hook(memory, flow, step)
        k_seen.append(fields["k_by_category"]["dos"])
        memory.add(flow, row("dos", "normal"))
        # Giving `ceil(k)` dos Examples, never more than the two distinct dos points (the judged Flows copy pool row 1).
        assert len([example for example in examples if example.category == "dos"]) == min(2, math.ceil(fields["k_by_category"]["dos"]))
    # Delaying the labels by D = 2, so at step t the first `t - 1` rows are back and the error judged at step 0 raises k at step 2 only.
    assert k_seen == [1.0, 1.0, 2.0]
