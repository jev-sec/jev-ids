"""The kNN baseline: K, the vote, its tie rule and the matched K."""

import numpy as np
import pytest

from jev_ids.detectors import knn
from jev_ids.detectors.random_forest import vocabulary
from jev_ids.selector import Space
from tests.helpers import CONFIG, make_flow

MEMORY = [
    make_flow(0, "normal", value="1"),
    make_flow(1, "normal", value="2"),
    make_flow(2, "dos", value="8"),
    make_flow(3, "dos", value="9"),
    make_flow(4, "probe", value="9"),
]


def detector(neighbours: str) -> knn.KNNDetector:
    return knn.KNNDetector(Space(vocabulary(MEMORY, CONFIG), MEMORY), "normal", neighbours)


def test_parse_neighbours_reads_a_fixed_or_a_matched_k() -> None:
    assert knn.parse_neighbours("4") == (4, False)
    assert knn.parse_neighbours("matched:4") == (4, True)
    with pytest.raises(ValueError, match="at least 1"):
        knn.parse_neighbours("0")
    assert detector("matched:4").model == "knn-matched-4"


def test_the_nearest_flows_vote_and_p_attack_is_their_attack_share() -> None:
    near_attack = detector("3").predict(make_flow(9, "dos", value="8"), MEMORY)
    # Taking row 2 (8) first, then rows 3 and 4 (9), equally far, in memory order, so the vote is two dos and one probe.
    assert (near_attack["category_pred"], near_attack["p_attack"], near_attack["neighbours"]) == ("dos", 1.0, 3)
    near_normal = detector("2").predict(make_flow(9, "normal", value="1"), MEMORY)
    assert (near_normal["category_pred"], near_normal["p_attack"]) == ("normal", 0.0)
    with pytest.raises(ValueError, match="k = all"):
        detector("2").predict(MEMORY[0], [])


def test_a_tie_goes_to_the_category_of_the_nearest_tied_neighbour() -> None:
    # Ordering the neighbours of value 5 as 4.9, 5.2, 7 and 7.2, which gives two votes each, so the nearest decides.
    memory = [
        make_flow(0, "normal", value="7"),
        make_flow(1, "dos", value="5.2"),
        make_flow(2, "normal", value="4.9"),
        make_flow(3, "dos", value="7.2"),
    ]
    vote = knn.KNNDetector(Space(vocabulary(memory, CONFIG), memory), "normal", "4")
    assert vote.predict(make_flow(9, "dos", value="5"), memory)["category_pred"] == "normal"
    swapped = [make_flow(flow.row_id, "dos" if flow.category == "normal" else "normal", value=flow.attribute_values[0]) for flow in memory]
    assert vote.predict(make_flow(9, "dos", value="5"), swapped)["category_pred"] == "dos"


def test_matched_count_follows_the_selector() -> None:
    points = np.asarray([[0.0], [0.0], [1.0], [2.0], [3.0]])
    categories = ["normal", "normal", "dos", "dos", "probe"]
    # Counting one distinct normal point (two copies), two dos points and one probe point, so at k = 4 the Selector would give 1 + 2 + 1.
    assert knn.matched_count(categories, points, 4) == 4
    assert knn.matched_count(categories, points, 1) == 3
    assert detector("matched:1").predict(make_flow(9, "dos", value="8"), MEMORY)["neighbours"] == 3
