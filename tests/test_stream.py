"""The stream: its order, the memory's clock and delay, the random Examples and one cell end to end."""

import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from jev_ids import records, run, selector, stream
from jev_ids.controller import KController
from jev_ids.dataset import Flow
from jev_ids.detectors import jev
from jev_ids.detectors.random_forest import vocabulary
from tests.helpers import CONFIG, JEV_PROMPT, make_flow

CATEGORIES: list[str] = CONFIG["categories"]
START = datetime(2017, 7, 3, 12, 0)


def at(flow: Flow, minute: int) -> Flow:
    """The Flow ending `minute` minutes after START."""
    return replace(flow, end=START + timedelta(minutes=minute))


# Filling the pool with a normal Flow per minute from 0 to 9, a dos Flow at minutes 2 and 8, and a probe Flow at minute 5.
POOL = [at(make_flow(i, "normal", value=str(i)), i) for i in range(10)] + [
    at(make_flow(20, "dos"), 2),
    at(make_flow(21, "dos"), 8),
    at(make_flow(22, "probe"), 5),
]
# Giving the split out of order, so its Flows end at minutes 7, 3, 4 and 6.
FLOWS = [
    at(make_flow(100, "dos", value="7"), 7),
    at(make_flow(101, "normal", value="7"), 3),
    at(make_flow(102, "dos", value="7", novel_attack=True), 4),
    at(make_flow(103, "dos", value="7", novel_attack=True), 6),
]
NAMES = {
    100: "DoS Hulk",
    101: "BENIGN",
    102: "DoS Slowhttptest",
    103: "DoS Slowhttptest",
}


class Recorder:
    """A Detector that answers the truth and keeps every (Flow, Examples) it was given."""

    name = "recorder"

    def __init__(self) -> None:
        self.calls: list[tuple[Flow, list[Flow]]] = []

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        self.calls.append((flow, list(examples)))
        return {
            "p_attack": float(flow.is_attack),
            "category_pred": flow.category,
        }


def run_cell(tmp_path: Path, k: int | None, delay: int = 1) -> tuple[Recorder, list[records.Prediction]]:
    recorder = Recorder()
    memory = stream.Memory(POOL, CATEGORIES, delay, NAMES)
    stream.stream_cell(
        tmp_path,
        recorder,
        memory,
        FLOWS,
        {
            "k": k,
            "seed": 0,
            "repetition": 0,
            "delay": delay,
        },
    )
    return recorder, records.read_predictions(tmp_path)


def test_the_stream_follows_the_end_of_each_flow() -> None:
    assert [flow.row_id for flow in stream.in_stream_order(FLOWS)] == [101, 102, 103, 100]
    with pytest.raises(ValueError, match="only a dataset with timestamps"):
        stream.in_stream_order([make_flow(1, "normal")])


def test_the_memory_never_returns_a_flow_from_the_future() -> None:
    memory = stream.Memory(POOL, CATEGORIES, delay=1)
    now = START + timedelta(minutes=5)
    # Keeping the probe Flow hidden, because it ends at minute 5 exactly and `visible` shows only Flows that end before `now`.
    assert [flow.row_id for flow in memory.visible("normal", 0, now)] == [0, 1, 2, 3, 4]
    assert [flow.row_id for flow in memory.visible("dos", 0, now)] == [20]
    assert memory.visible("probe", 0, now) == []
    assert len(memory.everything(0, now)) == 6


@pytest.mark.parametrize("delay", [1, 3])
def test_a_judged_flow_enters_the_memory_exactly_d_steps_later(delay: int) -> None:
    memory = stream.Memory([], CATEGORIES, delay)
    now = START + timedelta(hours=1)
    judged = at(make_flow(50, "dos"), 0)
    # Judging the Flow at step 0.
    memory.add(judged, {"p_attack": 1.0})
    for step in range(delay):
        assert memory.visible("dos", step, now) == []
    assert memory.visible("dos", delay, now) == [judged]
    with pytest.raises(ValueError, match="one step after"):
        stream.Memory([], CATEGORIES, 0)


def test_random_examples_take_k_per_category_or_all_and_replay() -> None:
    memory = stream.Memory(POOL, CATEGORIES, delay=1)
    # Taking the Flow that ends at minute 7, before which normal 0 to 6, dos 20 and probe 22 have ended.
    flow = FLOWS[0]
    two, nine = dict.fromkeys(CATEGORIES, 2), dict.fromkeys(CATEGORIES, 9)
    examples = stream.random_examples(memory, flow, 0, two, seed=0)
    assert sorted(example.category for example in examples) == ["dos", "normal", "normal", "probe"]
    assert all(example.end is not None and example.end < flow.end for example in examples if flow.end)
    assert examples == stream.random_examples(memory, flow, 0, two, seed=0)
    assert {example.row_id for example in stream.random_examples(memory, flow, 0, nine, seed=0)} == {0, 1, 2, 3, 4, 5, 6, 20, 22}
    # Drawing ceil(k_c) per Category when the `KController` gives each Category its own k.
    uneven = stream.random_examples(
        memory,
        flow,
        0,
        {
            "normal": 2.5,
            "dos": 1.0,
            "probe": 1.0,
        },
        seed=0,
    )
    assert sorted(example.category for example in uneven) == ["dos", "normal", "normal", "normal", "probe"]


def test_a_cell_sees_only_the_past_and_writes_one_row_per_step(tmp_path: Path) -> None:
    recorder, rows = run_cell(tmp_path, k=9, delay=2)
    for step, (flow, examples) in enumerate(recorder.calls):
        judged_before = [seen.row_id for seen, _ in recorder.calls[: max(0, step - 1)]]
        assert flow.end is not None
        for example in examples:
            assert example.row_id in judged_before or (example.end is not None and example.end < flow.end)
    # Checking that Flow 100 (step 3) sees Flow 101 (step 0) and Flow 102 (step 1) and misses Flow 103 (step 2).
    assert {example.row_id for example in recorder.calls[3][1]} >= {101, 102}
    assert 103 not in {example.row_id for example in recorder.calls[3][1]}
    assert [(row["row_id"], row["step"], row["delay"]) for row in rows] == [(101, 0, 2), (102, 1, 2), (103, 2, 2), (100, 3, 2)]
    # Counting Flow 103 as a first contact. It follows Flow 102 of the same novel name, but with D = 2 that label is not back yet.
    assert [row["first_contact"] for row in rows] == [None, True, True, None]
    assert [row["first_contact"] for row in run_cell(tmp_path / "d1", k=9, delay=1)[1]] == [None, True, False, None]


def test_a_pool_flow_judged_in_a_stream_is_never_its_own_example(tmp_path: Path) -> None:
    # Judging pool Flows through the Selector and the KController, as the validation stream of D9 does. A Flow ends exactly at its
    # own `now`, so the clock keeps its pool copy out, although that copy would be the nearest candidate.
    recorder = Recorder()
    memory = stream.Memory(POOL, CATEGORIES, 1, NAMES)
    chooser = selector.Selector(selector.Space(vocabulary(POOL, CONFIG), POOL))
    cell = {
        "k": 1,
        "seed": 0,
        "repetition": 0,
        "delay": 1,
    }
    stream.stream_cell(tmp_path, recorder, memory, POOL, cell, run.choose_with(chooser, 1, CATEGORIES, controller=KController(CATEGORIES)))
    assert len(recorder.calls) == len(POOL)
    assert all(flow.row_id not in {example.row_id for example in examples} for flow, examples in recorder.calls)


def test_no_attack_name_reaches_a_request(tmp_path: Path) -> None:
    recorder, _ = run_cell(tmp_path, k=9)
    for flow, examples in recorder.calls:
        body = json.dumps(jev.request_body(JEV_PROMPT["text"], flow, examples))
        assert not any(name in body for name in NAMES.values() if name != "BENIGN")


def test_a_forest_gets_the_whole_memory_at_every_step(tmp_path: Path) -> None:
    recorder, rows = run_cell(tmp_path, k=None)
    lists = [examples for _, examples in recorder.calls]
    # Ending step 0 at minute 3 with normal 0 to 2 and dos 20. Step 1 adds normal 3 and the returned Flow 101.
    assert {example.row_id for example in lists[0]} == {0, 1, 2, 20}
    assert {example.row_id for example in lists[1]} == {0, 1, 2, 3, 20, 101}
    # Ending step 2 at minute 6 with normal 0 to 5, dos 20, probe 22, and the returned Flows 101 and 102.
    assert {example.row_id for example in lists[2]} == {0, 1, 2, 3, 4, 5, 20, 22, 101, 102}
    assert [row["n_examples"] for row in rows] == [len(examples) for examples in lists]


def test_a_choose_hook_replaces_the_random_draw(tmp_path: Path) -> None:
    recorder = Recorder()
    memory = stream.Memory(POOL, CATEGORIES, 1, NAMES)
    seen: list[int] = []

    def choose(memory: stream.Memory, flow: Flow, step: int) -> tuple[list[Flow], dict[str, Any]]:
        seen.append(step)
        return memory.visible("probe", step, stream.end_of(flow)), {"hook": step}

    stream.stream_cell(
        tmp_path,
        recorder,
        memory,
        FLOWS,
        {
            "k": 4,
            "seed": 0,
            "repetition": 0,
            "delay": 1,
        },
        choose,
    )
    assert seen == [0, 1, 2, 3]
    # Expecting only the probe Flow, which ends at minute 5, and only for the Flows ending after it.
    assert [[example.row_id for example in examples] for _, examples in recorder.calls] == [[], [], [22], [22]]
    assert memory.rows[101]["category_true"] == "normal"
    assert [row["hook"] for row in records.read_predictions(tmp_path)] == [0, 1, 2, 3]
