"""CLI wiring for the run, redo-errors, metrics, compare, sign-test and threshold subcommands."""

from pathlib import Path

import pytest

from jev_ids import cli, records, run
from tests.helpers import make_prediction


def test_missing_arguments_and_removed_commands_are_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])
    with pytest.raises(SystemExit):  # --dataset is required
        cli.main(["run", "--detector", "jev", "--split", "pilot"])
    for removed in ("download", "split"):
        with pytest.raises(SystemExit):
            cli.main([removed])


def test_run_builds_a_spec_from_the_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[run.RunSpec] = []

    def fake_run(spec: run.RunSpec) -> Path:
        seen.append(spec)
        return Path("x")

    monkeypatch.setattr(run, "run_from_spec", fake_run)
    card = "data/x/dataset.json"
    argv = ["run", "--dataset", card, "--detector", "random_forest", "--split", "smoke"]
    argv += ["--k", "1,all", "--seeds", "1", "--reps", "3", "--model", "m", "--results-dir", "results/paper"]
    assert cli.main(argv) == 0
    expected = run.RunSpec(
        "random_forest", Path(card), "smoke", (1, None), (1,), reps=3, model_id="m", results_dir=Path("results/paper"), jobs=-1
    )
    assert seen == [expected]
    argv = ["run", "--dataset", card, "--detector", "jev", "--split", "pilot"]
    assert cli.main(argv) == 0
    assert seen[1].k_values == (0, 1, 2, 4, 8)
    assert seen[1].seeds == (0, 1, 2)
    assert seen[1].model_id is None
    assert seen[1].results_dir == run.RESULTS_DIR
    redone: list[Path] = []
    monkeypatch.setattr(run, "redo_errors", redone.append)
    assert cli.main(["redo-errors", "results/paper/x"]) == 0
    assert redone == [Path("results/paper/x")]


def test_metrics_prints_one_csv_over_every_run_given(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records.append_prediction(tmp_path / "a", make_prediction(1, 1, 0.9))
    # The second run reports one usage field the first lacks: the header is the union of the rows' keys, in order of first appearance.
    other = make_prediction(2, 0, 0.1, detector="random_forest", usage={"duration": 2.0})
    records.append_prediction(tmp_path / "b", other)
    assert cli.main(["metrics", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("dataset,detector,model,split,delay,record,selection,control,k,cells,flows,predictions,f1_mean,")
    assert lines[0].endswith(",cost_usd_per_1m,latency_ms_mean,latency_ms_median,latency_ms_p95,duration_mean")
    assert len(lines) == 3
    # After recall_known come recall_dos, recall_known_dos and recall_novel_dos (the first run's only attack is a known dos), the alert
    # counts, then the two areas, which a single-class cell leaves empty, then the error rate; the second run has no attack, so its
    # category columns stay empty.
    assert (
        lines[1] == "test,jev,m,internal,,full,random,fixed,1,1,1,1,1.0,1.0,1.0,,1.0,,,1.0,1.0,,0.0,0.0,,,0.0,,100.0,10.0,,,,,500.0,500.0,,"
    )
    assert lines[2] == "test,random_forest,m,internal,,full,random,fixed,1,1,1,1,,,,,,,,,,,0.0,0.0,,,0.0,,,,,,,,500.0,500.0,,2.0"
    assert cli.main(["metrics", str(tmp_path / "empty")]) == 0
    assert capsys.readouterr().out == ""


def test_compare_selects_the_subset_cuts_to_ks_and_prints_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = [make_prediction(0, 1, 1.0, novel_attack=True), make_prediction(1, 1, 0.0)]
    b = [
        make_prediction(0, 1, 0.0, novel_attack=True, k=None),
        make_prediction(1, 1, 1.0, k=None),
    ]
    for prediction in [*a, *b]:
        records.append_prediction(tmp_path / prediction["detector"], prediction)
    # Side B is two directories: one per k, as parallel runs write them.
    records.append_prediction(tmp_path / "jev-k0", make_prediction(0, 1, 0.0, novel_attack=True, k=0))
    argv = ["compare", "--a", str(tmp_path / "jev"), "--b", str(tmp_path / "jev"), str(tmp_path / "jev-k0")]
    argv += ["--subset", "novel", "--k-a", "1", "--k-b", "all"]
    assert cli.main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "k_a,k_b,seed,repetition,pairs,discordant,a_correct,b_correct,mcnemar_p,f1_a,f1_b"
    assert lines[1] == "1,,0,0,1,1,1,0,1.0,1.0,0.0"
    with pytest.raises(SystemExit, match="come together"):
        cli.main(["compare", "--a", "a", "--b", "b", "--k-a", "0"])


def test_sign_test_prints_every_subset_with_holm_p(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records.append_prediction(tmp_path / "a", make_prediction(0, 1, 1.0, novel_attack=True))
    records.append_prediction(tmp_path / "b", make_prediction(0, 1, 0.0, novel_attack=True))
    assert cli.main(["sign-test", "--a", str(tmp_path / "a"), "--b", str(tmp_path / "b")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "subset,k,flows,a_better,b_better,sign_p,holm_p"
    # The known subset holds no flow, so only `all` and `novel` give a row, and Holm caps both adjusted p-values at 1.
    assert lines[1:] == ["all,1,1,1,0,1.0,1.0", "novel,1,1,1,0,1.0,1.0"]


def test_threshold_prints_the_cut_and_metrics_and_compare_take_verdicts_again(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    validation = tmp_path / "validation"
    records.append_prediction(validation, make_prediction(1, 1, 0.3, split="validation"))
    records.append_prediction(validation, make_prediction(2, 0, 0.1, split="validation"))
    assert cli.main(["threshold", str(validation)]) == 0
    assert capsys.readouterr().out.splitlines() == ["threshold,f1_mean,f1_mean_at_0.5", "0.3,1.0,0.0"]
    # Cutting at 0.3 turns the attack's Verdict into an alert, so F1 goes from 0 to 1.
    assert cli.main(["metrics", str(validation), "--threshold", "0.3"]) == 0
    header, values = capsys.readouterr().out.splitlines()
    assert dict(zip(header.split(","), values.split(","), strict=True))["f1_mean"] == "1.0"
    # Comparing the same run at 0.5 (A) and at 0.3 (B) leaves one discordant pair, which B gets right.
    assert cli.main(["compare", "--a", str(validation), "--b", str(validation), "--threshold-b", "0.3"]) == 0
    assert capsys.readouterr().out.splitlines()[1] == "1,1,0,0,2,1,0,1,1.0,0.0,1.0"
