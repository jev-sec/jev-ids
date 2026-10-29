"""The `KController` of Jev IDS: how many Examples each Category gets, by mirrored AIMD (docs/jevids-design.md, D5).

In reading order:

- `KController`: one k per Category, raised on an error and lowered on a success, as the labels come back.
- `Controlled`: a chooser (the `Selector`, or the random draw in the ablation without it) asked for ceil(k_c) Examples per Category,
  the hook a stream cell calls at every step.

TCP grows its window slowly and halves it on loss; in an IDS the costly error is too few Examples, so the rule is mirrored: multiplicative
increase on error, additive decrease on success. The controller reacts when a label comes back, at t + D, not when the Flow is judged.
"""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from jev_ids.dataset import Flow
from jev_ids.records import Prediction
from jev_ids.stream import Memory

# Naming what `Controlled` asks for the Examples of one Flow, either `Selector.choose` or `random_examples` bound to the cell's seed.
Pick = Callable[[Memory, Flow, int, Mapping[str, float]], list[Flow]]

# The values of D5, fixed before any stream result.
K_START = 1.0
K_MIN = 1.0
K_MAX = 8.0
BETA = 2.0  # multiplicative increase on error, varied over 1.5, 2 and 3 in stage 6's sensitivity check only
ALPHA = 1.0  # additive decrease on success, spread over a window of k_c successes


class KController:
    """One k per Category, while a Category without feedback keeps its k."""

    def __init__(self, categories: Sequence[str], beta: float = BETA) -> None:
        """Every Category starts at K_START, and an error multiplies its k by `beta`."""
        self.k = dict.fromkeys(categories, K_START)
        self.beta = beta

    def feedback(self, row: Prediction) -> None:
        """React to one returned row. An error multiplies the k of its true Category by beta (up to K_MAX), a success removes ALPHA / k.

        An error is `category_pred` differing from the true Category, and k never falls below K_MIN.
        A failed call (`error`) is ignored, because Jev gave no answer to judge.
        """
        if row.get("error") is not None:
            return
        category = row["category_true"]
        k = self.k[category]
        if row.get("category_pred") != category:
            self.k[category] = min(K_MAX, self.beta * k)
        else:
            self.k[category] = max(K_MIN, k - ALPHA / k)


class Controlled:
    """A chooser with a `KController` per stream cell. At each step the newly returned rows update k, then `pick` chooses the Examples."""

    def __init__(self, pick: Pick, controller: KController) -> None:
        """The cell's own fresh controller, before any row has come back."""
        self.pick = pick
        self.controller = controller
        self.seen = 0

    def __call__(self, memory: Memory, flow: Flow, step: int) -> tuple[list[Flow], dict[str, Any]]:
        """The Examples for `flow` and, for its row, the k of every Category at this step (`k_by_category`, before the ceiling)."""
        returned = memory.returned(step)
        for _, row in returned[self.seen :]:
            self.controller.feedback(row)
        self.seen = len(returned)
        k = dict(self.controller.k)
        return self.pick(memory, flow, step, k), {"k_by_category": {name: round(value, 4) for name, value in k.items()}}
