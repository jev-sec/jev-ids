"""The stream: its order, the memory's clock and delay, the random Examples and one cell end to end."""

import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from jev_ids import records, stream
from jev_ids.dataset import Flow
from jev_ids.detectors import jev
from tests.helpers import CONFIG, JEV_PROMPT, make_flow

CATEGORIES: list[str] = CONFIG["categories"]
START = datetime(2017, 7, 3, 12, 0)


def at(flow: Flow, minute: int) -> Flow:
    """The Flow ending `minute` minutes after START."""
    return replace(flow, end=START + timedelta(minutes=minute))


# Pool: a normal Flow per minute from 0 to 9, a dos Flow at minutes 2 and 8, a probe Flow at minute 5.
POOL = [at(make_flow(i, "normal", value=str(i)), i) for i in range(10)] + [
    at(make_flow(20, "dos"), 2),
    at(make_flow(21, "dos"), 8),
    at(make_flow(22, "probe"), 5),
]
# The split, given out of order: it ends at minutes 7, 3, 4, 6.
FLOWS = [
    at(make_flow(100, "dos", value="7"), 7),
    at(make_flow(101, "normal", value="7"), 3),
    at(make_flow(102, "dos", value="7", novel_attack=True), 4),
    at(make_flow(103, "dos", value="7", novel_attack=True), 6),
]
NAMES = {100: "DoS Hulk", 101: "BENIGN", 102: "DoS Slowhttptest", 103: "DoS Slowhttptest"}


class Recorder:
    """A Detector that answers the truth and keeps every (Flow, Examples) it was given."""

    name = "recorder"

    def __init__(self) -> None:
        self.calls: list[tuple[Flow, list[Flow]]] = []

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        self.calls.append((flow, list(examples)))
        return {"p_attack": float(flow.is_attack), "category_pred": flow.category}


def run_cell(tmp_path: Path, k: int | None, delay: int = 1) -> tuple[Recorder, list[records.Prediction]]:
    recorder = Recorder()
    memory = stream.Memory(POOL, CATEGORIES, delay, NAMES)
    stream.stream_cell(tmp_path, recorder, memory, FLOWS, {"k": k, "seed": 0, "repetition": 0, "delay": delay})
    return recorder, records.read_predictions(tmp_path)


def test_the_stream_follows_the_end_of_each_flow() -> None:
    assert [flow.row_id for flow in stream.in_stream_order(FLOWS)] == [101, 102, 103, 100]
    with pytest.raises(ValueError, match="only a dataset with timestamps"):
        stream.in_stream_order([make_flow(1, "normal")])


def test_the_memory_never_returns_a_flow_from_the_future() -> None:
    memory = stream.Memory(POOL, CATEGORIES, delay=1)
    now = START + timedelta(minutes=5)
    # The probe Flow ends at minute 5 exactly: not before now, so not visible.
    assert [flow.row_id for flow in memory.visible("normal", 0, now)] == [0, 1, 2, 3, 4]
    assert [flow.row_id for flow in memory.visible("dos", 0, now)] == [20]
    assert memory.visible("probe", 0, now) == []
    assert len(memory.everything(0, now)) == 6


@pytest.mark.parametrize("delay", [1, 3])
def test_a_judged_flow_enters_the_memory_exactly_d_steps_later(delay: int) -> None:
    memory = stream.Memory([], CATEGORIES, delay)
    now = START + timedelta(hours=1)
    judged = at(make_flow(50, "dos"), 0)
    memory.add(judged, {"p_attack": 1.0})  # judged at step 0
    for step in range(delay):
        assert memory.visible("dos", step, now) == []
    assert memory.visible("dos", delay, now) == [judged]
    with pytest.raises(ValueError, match="one step after"):
        stream.Memory([], CATEGORIES, 0)


def test_random_examples_take_k_per_category_or_all_and_replay() -> None:
    memory = stream.Memory(POOL, CATEGORIES, delay=1)
    flow = FLOWS[0]  # ends at minute 7: normal 0 to 6, dos 20, probe 22
    examples = stream.random_examples(memory, flow, 0, 2, seed=0)
    assert sorted(example.category for example in examples) == ["dos", "normal", "normal", "probe"]
    assert all(example.end is not None and example.end < flow.end for example in examples if flow.end)
    assert examples == stream.random_examples(memory, flow, 0, 2, seed=0)
    assert {e.row_id for e in stream.random_examples(memory, flow, 0, 9, seed=0)} == {0, 1, 2, 3, 4, 5, 6, 20, 22}


def test_a_cell_sees_only_the_past_and_writes_one_row_per_step(tmp_path: Path) -> None:
    recorder, rows = run_cell(tmp_path, k=9, delay=2)
    for step, (flow, examples) in enumerate(recorder.calls):
        judged_before = [seen.row_id for seen, _ in recorder.calls[: max(0, step - 1)]]
        assert flow.end is not None
        for example in examples:
            assert example.row_id in judged_before or (example.end is not None and example.end < flow.end)
    # Flow 100 (step 3) sees Flow 101 (step 0) and Flow 102 (step 1), not Flow 103 (step 2).
    assert {e.row_id for e in recorder.calls[3][1]} >= {101, 102}
    assert 103 not in {e.row_id for e in recorder.calls[3][1]}
    assert [(row["row_id"], row["step"], row["delay"]) for row in rows] == [(101, 0, 2), (102, 1, 2), (103, 2, 2), (100, 3, 2)]
    # Flow 103 comes after Flow 102 of the same novel name, but with D = 2 that label is not back yet.
    assert [row["first_contact"] for row in rows] == [None, True, True, None]
    assert [row["first_contact"] for row in run_cell(tmp_path / "d1", k=9, delay=1)[1]] == [None, True, False, None]


def test_no_attack_name_reaches_a_request(tmp_path: Path) -> None:
    recorder, _ = run_cell(tmp_path, k=9)
    for flow, examples in recorder.calls:
        body = json.dumps(jev.request_body(JEV_PROMPT["text"], flow, examples))
        assert not any(name in body for name in NAMES.values() if name != "BENIGN")


def test_a_forest_gets_the_whole_memory_refitted_every_hundred_steps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stream, "REFIT_EVERY", 2)
    recorder, rows = run_cell(tmp_path, k=None)
    lists = [examples for _, examples in recorder.calls]
    assert lists[0] == lists[1] != lists[2] == lists[3]
    # Step 2 ends at minute 6: normal 0 to 5, dos 20, probe 22, and Flows 101 and 102 came back.
    assert {e.row_id for e in lists[2]} == {0, 1, 2, 3, 4, 5, 20, 22, 101, 102}
    assert [row["n_examples"] for row in rows] == [len(examples) for examples in lists]
