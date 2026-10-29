"""The Prediction row and the three files of a run.

A Prediction is a plain dict, one line of `results/<run_id>/predictions.jsonl`.

In reading order:

- `complete_prediction`: joins what a Detector measured with what only the run loop knows
  (the cell, the Flow's truth, the Verdict, a request id and a timestamp) into one row.
- `write_config`, `append_prediction`, `read_predictions`: the run directory
  and its `config.json`, `predictions.jsonl` and `responses.jsonl`.

A Detector's dict holds only what it measured (`p_attack`, `category_pred`, `latency_ms`, `usage`, `error`, ...),
so rows of different Detectors carry different keys and a reader takes an optional key with `.get`.
The key `raw`, the provider's whole answer, goes to responses.jsonl, which git ignores, and never reaches predictions.jsonl.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jev_ids.dataset import Flow

# Keeping the threshold next to the field it fills and outside the detectors,
# because every Detector takes its Verdict at the same point (CONTEXT.md, "Verdict").
VERDICT_THRESHOLD = 0.5

Prediction = dict[str, Any]


def complete_prediction(measured: dict[str, Any], flow: Flow, cell_fields: dict[str, Any]) -> Prediction:
    """One row: the cell, the Flow's truth, the Verdict, then what was measured.

    `is_attack`, `category_true` and `novel_attack` are copied from the Flow so the metrics never need the split file again.
    `classification_verdict` is the Verdict at VERDICT_THRESHOLD, or None when the call failed and there is no p_attack; the metrics count
    such a row as `normal` (fail-open). `request_id` is a client UUID that keys the raw answer in responses.jsonl.

    Args:
        measured: what the Detector measured for the Flow (`p_attack`, `category_pred`, `latency_ms`, `usage`, `error`, ...).
        flow: the Flow judged, whose truth the row copies.
        cell_fields: the fields of the cell, shared by each of its rows.

    Returns:
        The complete row, ready for `append_prediction`.
    """
    p_attack = measured.get("p_attack")
    return {
        **cell_fields,
        "row_id": flow.row_id,
        "is_attack": int(flow.is_attack),
        "classification_verdict": None if p_attack is None else int(p_attack >= VERDICT_THRESHOLD),
        "category_true": flow.category,
        "novel_attack": flow.novel_attack,
        **measured,
        "request_id": str(uuid.uuid4()),
        "ts_utc": datetime.now(UTC).isoformat(timespec="milliseconds"),
    }


def write_config(run_dir: Path, config: dict[str, Any]) -> None:
    """Create the run directory and write `config.json`, the trace of a run's inputs."""
    run_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(config, indent=2, sort_keys=True, default=str) + "\n"
    (run_dir / "config.json").write_text(text, encoding="utf-8")


def append_prediction(run_dir: Path, prediction: Prediction) -> None:
    """Append one row to predictions.jsonl and its raw answer to responses.jsonl.

    A row is appended right after its call, not at the end of the run, so a crash or a quota error loses at most one Flow.
    A Detector without a raw answer (the Random Forest) writes nothing to responses.jsonl.

    Args:
        run_dir: the run directory, created when missing.
        prediction: the complete row, whose `raw` key, when present, goes to responses.jsonl alone.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    row = {key: value for key, value in prediction.items() if key != "raw"}
    with (run_dir / "predictions.jsonl").open("a", encoding="utf-8") as rows:
        rows.write(json.dumps(row) + "\n")
    if "raw" in prediction:
        response = {
            "request_id": prediction["request_id"],
            "response": prediction["raw"],
        }
        with (run_dir / "responses.jsonl").open("a", encoding="utf-8") as responses:
            responses.write(json.dumps(response) + "\n")


def read_predictions(run_dir: Path) -> list[Prediction]:
    """Every row of a run's predictions.jsonl; an absent file is an empty run.

    A row written before the compact record existed (docs/jevids-design.md, D7) has no `record` and read the values in full, so it gets
    `full` here and groups apart from a compact run. A row written before the `Selector` existed (D6) has no `selection`: its Examples
    were drawn at random, unless it is a forest's (k = all), which gets the whole memory. A row written before the `KController` (D5) has
    no `control`: its k was fixed. A row written before `beta` became an option (stage 6) has none, and under `aimd` its β was D5's 2.

    Args:
        run_dir: the run directory.

    Returns:
        The rows in file order, each completed by `default_fields`.
    """
    path = run_dir / "predictions.jsonl"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        rows: list[Prediction] = [json.loads(line) for line in handle if line.strip()]
    return [default_fields(row) | row for row in rows]


def default_fields(row: Prediction) -> Prediction:
    """What a row written before stages 2 to 4 and 6 lacks: `record`, `selection`, `control` and `beta` as they were then."""
    chosen = row.get("k") is not None
    return {
        "record": "full",
        "selection": "random" if chosen else None,
        "control": "fixed" if chosen else None,
        # Giving an `aimd` row the β of D5, the only one before stage 6. The literal avoids importing the controller into the records.
        "beta": 2.0 if row.get("control") == "aimd" else None,
    }
