"""The `Selector`: the space, the ranks, the difficulty, MMR and the Examples it gives one Flow."""

from dataclasses import replace
from datetime import datetime, timedelta

import numpy as np
import pytest

from jev_ids import selector, stream
from jev_ids.dataset import Flow
from jev_ids.detectors.random_forest import vocabulary
from tests.helpers import CONFIG, make_flow, make_prediction

START = datetime(2017, 7, 3, 12, 0)


def at(flow: Flow, minute: int) -> Flow:
    """The Flow ending `minute` minutes after START."""
    return replace(flow, end=START + timedelta(minutes=minute))


def test_unit_rank_scales_ranks_to_the_unit_interval_and_shares_ties() -> None:
    assert selector.unit_rank(np.asarray([5.0, 1.0, 3.0])).tolist() == [1.0, 0.0, 0.5]
    assert selector.unit_rank(np.asarray([2.0, 2.0, 7.0])).tolist() == [0.25, 0.25, 1.0]
    assert selector.unit_rank(np.asarray([4.0])).tolist() == [1.0]


def test_difficulty_of_a_wrong_a_right_and_an_unanswered_flow() -> None:
    # Passing None for a pool Flow.
    assert selector.difficulty(None) == 0.5
    assert selector.difficulty(make_prediction(1, 1, None, error="HTTP 500")) == 0.5
    # Scoring a wrong Category 1, however confident Jev was.
    assert selector.difficulty(make_prediction(1, 1, 0.99, category_pred="probe")) == 1.0
    # Scoring a right Category hard near `p_attack = 0.5` and easy near 0 or 1.
    assert selector.difficulty(make_prediction(1, 1, 0.5, category_pred="dos")) == 1.0
    assert selector.difficulty(make_prediction(1, 1, 1.0, category_pred="dos")) == 0.0
    assert selector.difficulty(make_prediction(2, 0, 0.25, category_pred="normal")) == pytest.approx(0.5)


def test_space_standardises_numbers_and_leaves_the_one_hot_columns() -> None:
    pool = [make_flow(0, "normal", value="0"), make_flow(1, "normal", value="2")]
    space = selector.Space(vocabulary(pool, CONFIG), pool)
    # Standardising `a` and `c` with mean 1 and standard deviation 1, and giving the symbolic `b` one column per pool value.
    assert space.points(pool).tolist() == [[-1.0, -1.0, 1.0, 0.0], [1.0, 1.0, 0.0, 1.0]]
    constant = [make_flow(0, "normal", value="3"), make_flow(1, "normal", value="3")]
    assert selector.Space(vocabulary(constant, CONFIG), constant).points(constant).tolist() == [[0.0, 0.0, 1.0]] * 2


def test_two_identical_flows_are_never_chosen_together() -> None:
    # Running the proof of stage 3 (docs/jevids-design.md), where index 1 copies index 0 and scores higher and index 2 is near both.
    # The copy is skipped even though the formula alone would prefer it, and with nothing but copies left the Category gets fewer Examples.
    points = np.asarray([[0.0, 0.0], [0.0, 0.0], [0.01, 0.0]])
    assert selector.mmr(points, np.asarray([3.0, 2.9, 2.0]), 2) == [0, 2]
    assert selector.mmr(points[:2], np.asarray([2.0, 3.0]), 2) == [1]


def test_mmr_trades_score_for_diversity() -> None:
    # Preferring a far point with a lower score over a near copy of the best point.
    points = np.asarray([[0.0, 0.0], [0.01, 0.0], [10.0, 0.0]])
    assert selector.mmr(points, np.asarray([3.0, 2.9, 2.0]), 2) == [0, 2]
    assert selector.mmr(points, np.asarray([3.0, 2.9, 2.0]), 9) == [0, 2, 1]


def test_choose_gives_ceil_k_per_category_from_the_visible_memory_only() -> None:
    pool = [
        at(make_flow(0, "normal", value="1"), 0),
        at(make_flow(1, "normal", value="5"), 1),
        at(make_flow(2, "normal", value="9"), 2),
        at(make_flow(3, "dos", value="8"), 3),
        # Ending after the Flow under test, in its future.
        at(make_flow(4, "dos", value="2"), 30),
    ]
    memory = stream.Memory(pool, CONFIG["categories"], 1)
    chooser = selector.Selector(selector.Space(vocabulary(pool, CONFIG), pool))
    flow = at(make_flow(100, "dos", value="9"), 10)
    k_by_category = {
        "normal": 1.5,
        "dos": 4,
        "probe": 4,
    }
    chosen = chooser.choose(memory, flow, 0, k_by_category)
    assert sorted(example.row_id for example in chosen) == [1, 2, 3]
    # Choosing the nearest and newest normal Flow first, row 2 (value 9, minute 2), then row 1 over the far and old row 0.
    assert chooser.choose(memory, flow, 0, {"normal": 1}) == [pool[2]]
    zero_k = {
        "normal": 0,
        "dos": 0,
    }
    assert chooser.choose(memory, flow, 0, zero_k) == []
    # Choosing deterministically, so the same memory and Flow give the same request.
    k_without_probe = {
        "normal": 1.5,
        "dos": 4,
    }
    assert chooser.choose(memory, flow, 0, k_without_probe) == chosen


def test_a_judged_flow_jev_got_wrong_is_preferred() -> None:
    pool = [at(make_flow(0, "normal", value="4"), 0)]
    memory = stream.Memory(pool, CONFIG["categories"], 1)
    easy = at(make_flow(50, "normal", value="4.5"), 2)
    hard = at(make_flow(51, "normal", value="3.5"), 1)
    memory.add(hard, make_prediction(51, 0, 0.9, category_pred="dos", category_true="normal"))
    memory.add(easy, make_prediction(50, 0, 0.0, category_pred="normal", category_true="normal"))
    chooser = selector.Selector(selector.Space(vocabulary(pool, CONFIG), pool))
    flow = at(make_flow(100, "normal", value="4"), 10)
    # Choosing the wrong one of two equally near judged Flows, although the right one is newer.
    assert chooser.choose(memory, flow, 2, {"normal": 1}) == [hard]
