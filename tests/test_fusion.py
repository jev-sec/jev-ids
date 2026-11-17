"""The Fusion of a Jev run and a matched kNN run, through the `fuse` subcommand."""

import json
from pathlib import Path

import pytest

from jev_ids import cli, fusion, records
from tests.helpers import make_prediction


def write_run(run_dir: Path, p_attacks: dict[int, float | None], **overrides: str) -> str:
    """A run of one row per `row_id`, attacks at even ids, a None p_attack being a failed call; its directory as text."""
    for row_id, p_attack in p_attacks.items():
        failed = {"error": "x"} if p_attack is None else {}
        records.append_prediction(run_dir, make_prediction(row_id, int(row_id % 2 == 0), p_attack, **failed, **overrides))
    return str(run_dir)


def test_fuse_averages_the_validation_percentiles(tmp_path: Path) -> None:
    jev = write_run(tmp_path / "jev", {1: 0.1, 2: 0.5, 3: 0.9, 4: 0.9, 5: None})
    knn = write_run(tmp_path / "knn", {1: 0.0, 2: 0.0, 3: 0.5, 4: 1.0, 5: 0.5}, detector="knn", model="knn-matched-4")
    argv = ["fuse", jev, "--knn", knn, "--calibration-jev", jev, "--calibration-knn", knn, "--results-dir", str(tmp_path / "out")]
    assert cli.main(argv) == 0
    (run_dir,) = (tmp_path / "out").iterdir()
    rows = {row["row_id"]: row for row in records.read_predictions(run_dir)}
    # Placing Jev's 0.1 at (0 + 1) / 2 of its 4 answered values and the kNN's 0.0 at (0 + 2) / 2 of its 5, which average to 0.1625.
    assert rows[1]["p_attack"] == pytest.approx((0.125 + 0.2) / 2)
    # Placing Jev's tied 0.9 at (2 + 4) / 2 of 4 and the kNN's 0.5 at (2 + 4) / 2 of 5, and keeping both originals beside the fused value.
    assert (rows[3]["p_attack"], rows[3]["p_attack_jev"], rows[3]["p_attack_knn"]) == (pytest.approx(0.675), 0.9, 0.5)
    assert (rows[3]["detector"], rows[3]["model"], rows[3]["classification_verdict"]) == ("fusion", "m+knn-matched-4", 1)
    # Falling back on the kNN's 0.5 alone, at (2 + 4) / 2 of 5, when Jev's call failed, with Jev's error kept apart.
    assert (rows[5]["p_attack"], rows[5]["fallback"], rows[5]["error"], rows[5]["error_jev"]) == (pytest.approx(0.6), True, None, "x")
    assert (rows[3]["fallback"], rows[3]["error_jev"]) == (False, None)
    stored = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert stored["sources"] == {"jev": ["jev"], "knn": "knn", "calibration_jev": ["jev"], "calibration_knn": "knn"}


def test_fuse_refuses_runs_of_different_streams(tmp_path: Path) -> None:
    jev = Path(write_run(tmp_path / "jev", {1: 0.1}))
    knn = Path(write_run(tmp_path / "knn", {1: 0.0}, split="other"))
    with pytest.raises(ValueError, match="judged no such Flow"):
        fusion.fuse([jev], knn, ([jev], knn), tmp_path / "out")
    with pytest.raises(ValueError, match="no Jev row"):
        fusion.fuse([tmp_path / "empty"], knn, ([jev], knn), tmp_path / "out")
