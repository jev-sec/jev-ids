"""CLI wiring for the run, redo-errors, metrics, compare, sign-test and threshold subcommands."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from jev_ids import cli, records, run
from tests.helpers import CONFIG, make_flow, make_prediction, make_train, write_dataset


def test_missing_arguments_and_removed_commands_are_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])
    # Leaving out `--dataset`, which `run` requires.
    with pytest.raises(SystemExit):
        cli.main(["run", "--detector", "jev", "--split", "pilot"])
    for removed in ("download", "split"):
        with pytest.raises(SystemExit):
            cli.main([removed])


def test_run_builds_a_spec_from_the_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    splits = {
        "pool": make_train(CONFIG["categories"]),
        "smoke": [make_flow(9, "dos", value="1")],
    }
    card = write_dataset(tmp_path / "data", CONFIG, splits)
    results = tmp_path / "results"
    argv = ["run", "--dataset", str(card), "--detector", "random_forest", "--split", "smoke"]
    argv += ["--k", "1,all", "--seeds", "1", "--reps", "3", "--model", "m", "--results-dir", str(results)]
    assert cli.main(argv) == 0
    (run_dir,) = results.iterdir()
    stored = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    expected = run.RunSpec("random_forest", card, "smoke", (1, None), (1,), reps=3, model_id="m", results_dir=results, jobs=-1)
    assert stored["spec"] == json.loads(json.dumps(asdict(expected), default=str))
    # Reading the defaults of a jev run from the parser `main` uses, because running Jev needs the network.
    args = cli.build_parser().parse_args(["run", "--dataset", str(card), "--detector", "jev", "--split", "pilot"])
    assert (args.k, args.seeds, args.model, args.results_dir) == ((0, 1, 2, 4, 8), (0, 1, 2), None, run.RESULTS_DIR)
    # Completing the run in place, which judges nothing because it holds neither an error row nor a missing Flow.
    assert cli.main(["redo-errors", str(run_dir)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == f"redone: 0 error rows and 0 missing flows of {run_dir}"


def test_metrics_prints_one_csv_over_every_run_given(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records.append_prediction(tmp_path / "a", make_prediction(1, 1, 0.9))
    # Giving the second run one usage field the first lacks, so the header is the union of the rows' keys, in order of first appearance.
    other = make_prediction(2, 0, 0.1, detector="random_forest", usage={"duration": 2.0})
    records.append_prediction(tmp_path / "b", other)
    assert cli.main(["metrics", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("dataset,detector,model,split,delay,record,selection,control,beta,k,cells,flows,predictions,f1_mean,")
    assert lines[0].endswith(",cost_usd_per_1m,latency_ms_mean,latency_ms_median,latency_ms_p95,duration_mean")
    assert len(lines) == 3
    # Expecting `recall_dos`, `recall_known_dos` and `recall_novel_dos` after `recall_known`
    # (the first run's only attack is a known dos), then the alert counts, then the two areas, which a single-class cell leaves empty,
    # then the error rate. The second run has no attack, so its category columns stay empty.
    assert (
        lines[1]
        == "test,jev,m,internal,,full,random,fixed,,1,1,1,1,1.0,1.0,1.0,,1.0,,,1.0,1.0,,0.0,0.0,,,0.0,,100.0,10.0,,,,,500.0,500.0,,"
    )
    assert lines[2] == "test,random_forest,m,internal,,full,random,fixed,,1,1,1,1,,,,,,,,,,,0.0,0.0,,,0.0,,,,,,,,500.0,500.0,,2.0"
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
    # Splitting side B over two directories, one per k, as parallel runs write them.
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
    # Skipping the known subset, which holds no flow, so only `all` and `novel` give a row, and Holm caps both adjusted p-values at 1.
    assert lines[1:] == ["all,1,1,1,0,1.0,1.0", "novel,1,1,1,0,1.0,1.0"]
    # Cutting B at 0.0 turns its miss into an alert, so the Flow ties and favours neither run.
    assert cli.main(["sign-test", "--a", str(tmp_path / "a"), "--b", str(tmp_path / "b"), "--threshold-b", "0.0"]) == 0
    assert capsys.readouterr().out.splitlines()[1] == "all,1,1,0,0,1.0,1.0"


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
