"""JevIDS: intrusion detection with Jev, a System One Model, on a stream whose labels come back late, against its baselines.

The package, in reading order:

- `dataset`: the card of a dataset, the shared CSV shape, the Flow and the compact record.
- `stream`: a split judged in the order its Flows end, with a memory that grows as labels come back D steps later.
- `controller`: the `KController`, k per Category by mirrored AIMD.
- `selector`: the `Selector`, Examples by score and MMR, plus the nearest benign Flow.
- `run`: one run of one Detector over one split, cell by cell, as a stream when a delay is given.
- `detectors/`: `jev` (TypeSafe's Jev through its SDK), `llm` (Claude Sonnet 5.5 through an Agno Agent),
  `random_forest`, `isolation_forest` and `knn` (scikit-learn and the `Selector`'s distance).
- `fusion`: the alarm of the full JevIDS, from its Jev runs and its matched kNN run.
- `records`: the Prediction row and the three files of a run.
- `metrics`: summary tables and paired comparisons computed from those rows.
- `cli`: the `run`, `redo-errors`, `metrics`, `compare`, `threshold` and `fuse` subcommands.
"""

from pathlib import Path

# Pointing at the repository root, the folder that holds `data/`, `prompts/`, `results/`, `prices.json` and `.env`.
ROOT = Path(__file__).resolve().parent.parent
