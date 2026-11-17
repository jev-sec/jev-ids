"""The Fusion: Jev and the matched kNN on one Stream, as one Detector (docs/jevids-design.md, "2026-11-17: the Fusion").

In reading order:

- `percentile_in`: where a p_attack falls among the p_attack one Detector gave on the validation stream.
- `fuse`: the Fusion run, built from a Jev run and a matched kNN run of the same Stream.

Each Flow gets two p_attack, Jev's and the matched kNN's. Each becomes its percentile among that Detector's p_attack on the validation
stream, ties at the mid rank, so both read on one scale from 0 to 1. The Fusion's p_attack is the plain mean of the two percentiles, and
its Cut is taken on the fused validation stream by `metrics.best_threshold`, as Jev's is (D9).

Jev and the kNN never read each other's answers. The `Selector` and the `KController` read Jev's own rows, and the kNN reads only the
Categories of the memory, which come back whatever any Detector said. So one Stream judged twice, once by each Detector, joined by
`row_id`, gives every row a run of both together would give, and the Fusion is built from the two finished runs at no cost.
A Flow Jev failed on keeps its error and no p_attack, because what the Fusion does without Jev's answer is still open.
"""

from bisect import bisect_left, bisect_right
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

from jev_ids.records import VERDICT_THRESHOLD, Prediction, append_prediction, read_predictions, write_config

# Naming the fields that place a row in one Stream, which the two runs must share row for row.
STREAM_FIELDS = ("dataset", "split", "delay")


def percentile_in(values: Sequence[float]) -> Callable[[float], float]:
    """The share of `values` below a p_attack, counting the values equal to it as half below."""
    ordered = sorted(values)
    return lambda value: (bisect_left(ordered, value) + bisect_right(ordered, value)) / 2 / len(ordered)


def fuse(jev_dirs: Sequence[Path], knn_dir: Path, calibration: tuple[Sequence[Path], Path], results_dir: Path) -> Path:
    """Write the Fusion run of a Stream from its Jev runs and its matched kNN run.

    A missing p_attack in an answered row counts as 0. Jev's percentiles come from every answered row of its validation runs, every seed
    together, and the kNN's from every row of its validation run. To fuse the validation stream itself, pass its runs both ways.

    Args:
        jev_dirs: the Jev runs of the Stream, one or more seeds.
        knn_dir: the matched kNN run of the same Stream, deterministic and so judged once.
        calibration: the Jev runs and the matched kNN run of the validation stream.
        results_dir: where the Fusion run directory is created.

    Returns:
        The Fusion run directory, whose rows copy Jev's with the fused `p_attack` and the two it came from.
    """
    calibration_jev = [row.get("p_attack") or 0 for path in calibration[0] for row in read_predictions(path) if row.get("error") is None]
    jev_percentile = percentile_in(calibration_jev)
    knn_percentile = percentile_in([row.get("p_attack") or 0 for row in read_predictions(calibration[1])])
    jev_rows = [row for path in jev_dirs for row in read_predictions(path)]
    knn_rows = {row["row_id"]: row for row in read_predictions(knn_dir)}

    # Refusing no Jev row, two runs of different Streams or a Jev Flow the kNN never judged, because the join by `row_id` would mix them.
    if not jev_rows:
        raise ValueError(f"no Jev row in {', '.join(str(path) for path in jev_dirs)}")
    for row in jev_rows:
        knn_row = knn_rows.get(row["row_id"])
        if knn_row is None or any(row.get(field) != knn_row.get(field) for field in STREAM_FIELDS):
            raise ValueError(f"row {row['row_id']}: the kNN run {knn_dir.name} judged no such Flow on the same Stream")

    # Naming the run as `run` does, `<UTC timestamp>-<dataset>-fusion-<split>`, and tracing it to the four runs it reads.
    started = datetime.now(UTC)
    run_id = f"{started:%Y%m%dT%H%M%S.%fZ}-{jev_rows[0]['dataset']}-fusion-{jev_rows[0]['split']}"
    run_dir = results_dir / run_id
    sources = {
        "jev": [path.name for path in jev_dirs],
        "knn": knn_dir.name,
        "calibration_jev": [path.name for path in calibration[0]],
        "calibration_knn": calibration[1].name,
    }
    write_config(run_dir, {"run_id": run_id, "detector": "fusion", "sources": sources, "started_at": started.isoformat(timespec="seconds")})

    # Copying each Jev row, with the fused p_attack in place of Jev's and both originals kept beside it.
    for row in jev_rows:
        fused: Prediction = {**row, "run_id": run_id, "detector": "fusion", "model": f"{row['model']}+{knn_rows[row['row_id']]['model']}"}
        if row.get("error") is None:
            jev, knn = row.get("p_attack") or 0, knn_rows[row["row_id"]].get("p_attack") or 0
            score = mean([jev_percentile(jev), knn_percentile(knn)])
            fused |= {
                "p_attack": score,
                "p_attack_jev": jev,
                "p_attack_knn": knn,
                "classification_verdict": int(score >= VERDICT_THRESHOLD),
            }
        append_prediction(run_dir, fused)
    print(f"done: {run_dir}")
    return run_dir
