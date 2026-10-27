"""Jev IDS as a stream: Flows judged in the order they end, with a memory that grows as their labels come back.

In reading order:

- `in_stream_order`: a split in the order its Flows end.
- `Memory`: what has happened before a Flow, by Category: the pool Flows that ended before it and the judged Flows whose label came back.
- `random_examples`: k Examples per Category, drawn at random from the memory for one Flow (line 0 of docs/jevids-design.md).
- `split_names`: the attack name of every row of a split, for `first_contact` only.
- `stream_cell`: one (k, seed, rep) cell over the stream, one call and one appended row per Flow.

The design is docs/jevids-design.md, D3 and D4. Step t judges the t-th Flow to end. The pool Flows a step may use are those that ended
before the Flow under test; a judged Flow comes back with its true Category D steps later, so with D = 1 the Flow judged at step t is
in the memory at step t + 1. Feedback is complete: every judged Flow comes back, missed attacks included. The forests see the same memory,
refitted every REFIT_EVERY steps, so they get the same past and the same feedback as Jev. Attack names stay out of every request: the
memory holds Flows, which carry the Category only, and the names read from the split serve the `first_contact` field alone.
"""

import bisect
import csv
import random
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from jev_ids.dataset import Flow
from jev_ids.records import Prediction, append_prediction, complete_prediction

# How often, in steps, the forests are refitted on the memory; a refit per Flow would cost minutes per step on the whole pool.
REFIT_EVERY = 100


class Predictor(Protocol):
    """What the stream needs from a Detector."""

    name: str

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]: ...  # noqa: D102  documented by each Detector


def end_of(flow: Flow) -> datetime:
    """When a Flow ended; a dataset without timestamps cannot be streamed."""
    if flow.end is None:
        raise ValueError(f"row {flow.row_id} has no `end`: only a dataset with timestamps can be streamed")
    return flow.end


def in_stream_order(flows: Sequence[Flow]) -> list[Flow]:
    """The Flows in the order they end, ties broken by row_id (D3)."""
    return sorted(flows, key=lambda flow: (end_of(flow), flow.row_id))


class Memory:
    """The labeled Flows a step may use, by Category.

    Pool Flows are kept sorted by end, so the ones that ended before a moment are a prefix found by bisection. Judged Flows are kept in the
    order they were judged, with Jev's answer, and the first `step - delay + 1` of them have come back at `step`.
    """

    def __init__(self, pool: Sequence[Flow], categories: Sequence[str], delay: int, names: Mapping[int, str] | None = None) -> None:
        """Index the pool by Category and end; nothing has been judged yet. `names` (row_id -> attack name) serves `first_contact` only."""
        if delay < 1:
            raise ValueError(f"delay D = {delay}: a label comes back one step after its Flow at the earliest")
        self.delay = delay
        self.categories = tuple(categories)
        self._pool = {category: in_stream_order([flow for flow in pool if flow.category == category]) for category in self.categories}
        self._pool_ends = {category: [end_of(flow) for flow in flows] for category, flows in self._pool.items()}
        self.judged: list[tuple[Flow, Prediction]] = []
        self.names = dict(names or {})

    def add(self, flow: Flow, prediction: Prediction) -> None:
        """Record the Flow judged at step len(judged), with the row it produced; it comes back D steps later."""
        self.judged.append((flow, prediction))

    def returned(self, step: int) -> list[tuple[Flow, Prediction]]:
        """The judged Flows whose label has come back by `step`, in the order they were judged."""
        return self.judged[: max(0, step - self.delay + 1)]

    def visible(self, category: str, step: int, now: datetime) -> list[Flow]:
        """The Flows of one Category usable at `step`, judging a Flow that ended at `now`: older pool Flows, then returned ones."""
        ended = bisect.bisect_left(self._pool_ends[category], now)
        returned = [flow for flow, _ in self.returned(step) if flow.category == category]
        return self._pool[category][:ended] + returned

    def first_contact(self, flow: Flow, step: int) -> bool | None:
        """For a novel attack, whether no Flow of its attack name has come back by `step`; None for any other Flow or an unknown name."""
        name = self.names.get(flow.row_id)
        if not flow.novel_attack or name is None:
            return None
        return all(self.names.get(seen.row_id) != name for seen, _ in self.returned(step))

    def everything(self, step: int, now: datetime) -> list[Flow]:
        """Every Flow usable at `step`, all Categories together: what the forests are fitted on."""
        return [flow for category in self.categories for flow in self.visible(category, step, now)]


def random_examples(memory: Memory, flow: Flow, step: int, k: int, seed: int) -> list[Flow]:
    """Draw k Examples per Category at random from the memory for this Flow, or all of a Category when it has fewer.

    The draw is seeded by the seed, the Flow and the Category, so a cell can be replayed, and shuffled once more so no Detector sees the
    Examples grouped by Category.
    """
    chosen: list[Flow] = []
    for category in memory.categories:
        candidates = memory.visible(category, step, end_of(flow))
        rng = random.Random(f"{seed}:{flow.row_id}:{category}")  # noqa: S311  seeded, not secret
        chosen += rng.sample(candidates, min(k, len(candidates)))
    random.Random(f"{seed}:{flow.row_id}:order").shuffle(chosen)  # noqa: S311  seeded, not secret
    return chosen


def split_names(path: Path) -> dict[int, str]:
    """row_id -> attack name, from the split's `raw_label` trace column; empty when the split has none."""
    with path.open(encoding="utf-8", newline="") as handle:
        return {int(row["row_id"]): row["raw_label"] for row in csv.DictReader(handle) if row.get("raw_label")}


def stream_cell(
    run_dir: Path,
    detector: Predictor,
    memory: Memory,
    flows: Sequence[Flow],
    cell: dict[str, Any],
) -> None:
    """One cell: every Flow in stream order, its Examples from the memory, one call and one appended row, then the progress line.

    `cell["k"]` is k Examples per Category for Jev, or None for a forest, which gets the whole memory, refitted every REFIT_EVERY steps.
    A novel attack's row says whether it met its attack name for the first time (`first_contact`): no Flow of that name had come back yet.
    """
    errors = 0
    forest_examples: list[Flow] = []
    for step, flow in enumerate(in_stream_order(flows)):
        if cell["k"] is not None:
            examples = random_examples(memory, flow, step, cell["k"], cell["seed"])
        else:
            if step % REFIT_EVERY == 0:
                forest_examples = memory.everything(step, end_of(flow))
            examples = forest_examples
        fields = {**cell, "step": step, "n_examples": len(examples), "first_contact": memory.first_contact(flow, step)}
        prediction = complete_prediction(detector.predict(flow, examples), flow, fields)
        append_prediction(run_dir, prediction)
        memory.add(flow, prediction)
        errors += int(prediction.get("error") is not None)
    print(f"k={cell['k']} seed={cell['seed']} rep={cell['repetition']} delay={memory.delay} flows={len(flows)} errors={errors}")
