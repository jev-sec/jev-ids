"""The run loop: files, order, guards, the committed prompt files and the Examples."""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from jev_ids import ROOT, dataset, records, run
from jev_ids.detectors import jev
from jev_ids.detectors.isolation_forest import IsolationForestDetector
from jev_ids.detectors.random_forest import RandomForestDetector
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, make_train, write_dataset

CATEGORIES: list[str] = CONFIG["categories"]
TRAIN = make_train(["normal", "normal", "dos", "dos", "probe", "probe"])
FLOWS = [
    make_flow(100, "normal", value="7"),
    make_flow(101, "dos", value="7", novel_attack=True),
    make_flow(102, "probe", value="7"),
]
NSL_KDD = ROOT / "data" / "nsl-kdd" / "dataset.json"


class FakeDetector(jev.JevDetector):
    """Answers `p_attack = is_attack` without any request, and counts its calls."""

    def __init__(self) -> None:
        super().__init__(JEV_PROMPT)
        self.name = "fake"
        self.model = "fake-1"
        self.calls: list[tuple[int, int]] = []

    def predict(self, flow: dataset.Flow, examples: Sequence[dataset.Flow]) -> dict[str, Any]:
        self.calls.append((flow.row_id, len(examples)))
        return {
            "p_attack": float(flow.is_attack),
            "category_pred": flow.category,
            "latency_ms": 1.0,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 1,
            },
            "raw": {"echo": flow.row_id},
        }


@pytest.fixture
def card(tmp_path: Path) -> Path:
    """A dataset on disk: TRAIN is the pool and FLOWS the `smoke` split."""
    return write_dataset(
        tmp_path / "data",
        CONFIG,
        {
            "pool": TRAIN,
            "smoke": FLOWS,
        },
    )


def smoke_spec(
    card: Path,
    detector: str = "fake",
    k_values: tuple[int | None, ...] = (0,),
    reps: int = 1,
) -> run.RunSpec:
    """A smoke-split spec writing next to the dataset."""
    return run.RunSpec(
        detector=detector,
        dataset=card,
        split="smoke",
        k_values=k_values,
        seeds=(0,),
        reps=reps,
        results_dir=card.parent.parent.parent / "results",
    )


def test_execute_covers_every_cell_in_order_and_writes_the_three_files(card: Path, capsys: pytest.CaptureFixture[str]) -> None:
    detector = FakeDetector()
    config = dataset.load_config(card)
    spec = smoke_spec(card, k_values=(0, 1), reps=2)

    run_dir = run.execute(spec, detector, config, FLOWS, TRAIN)

    predictions = records.read_predictions(run_dir)
    assert len(predictions) == 2 * 1 * 2 * 3
    # Expecting k outermost, then rep, then the Flows, with 3 Examples at k = 1.
    zero_shot = [(100, 0), (101, 0), (102, 0)]
    one_shot = [(100, 3), (101, 3), (102, 3)]
    assert detector.calls == zero_shot * 2 + one_shot * 2
    assert {prediction["n_examples"] for prediction in predictions} == {0, 3}
    shared = {
        *("run_id", "dataset", "detector", "model", "split", "prompt_hash", "record", "selection", "control", "beta"),
        *("k", "seed", "repetition", "n_examples", "row_id", "is_attack", "classification_verdict"),
        *("category_true", "novel_attack", "p_attack", "category_pred"),
        *("latency_ms", "usage", "request_id", "ts_utc"),
    }
    assert all(set(prediction) == shared for prediction in predictions)
    assert {
        (prediction["dataset"], prediction["detector"], prediction["prompt_hash"], prediction["record"]) for prediction in predictions
    } == {("test", "fake", "h", "compact")}
    assert run_dir.name.endswith("-test-fake-smoke")
    responses = (run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(responses) == len(predictions)
    assert json.loads(responses[0])["request_id"] == predictions[0]["request_id"]
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert config_json["spec"]["k_values"] == [0, 1]
    assert config_json["spec"]["record"] == "compact"
    assert config_json["spec"]["dataset"] == str(card)
    assert config_json["dataset"] == {
        "name": "test",
        "sha256": config["sha256"],
    }
    split_sha256 = hashlib.sha256((card.parent / "splits" / "smoke.csv").read_bytes()).hexdigest()
    assert config_json["split"] == {
        "name": "smoke",
        "sha256": split_sha256,
    }
    assert (config_json["model"], config_json["prompt_hash"]) == ("fake-1", "h")
    # Expecting the full commit id, with `-dirty` appended while the tree has uncommitted changes.
    assert re.fullmatch(r"[0-9a-f]{40}(-dirty)?", config_json["code_commit"])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "k=0 seed=0 rep=0 flows=3 errors=0"
    # Expecting one line per cell, then `done:`.
    assert len(lines) == 4 + 1


def test_redo_errors_judges_the_failed_and_the_missing_flows_in_their_cells(card: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Running the Random Forest, which `redo_errors` builds again from config.json without any network.
    run_dir = run.run_from_spec(smoke_spec(card, "random_forest", k_values=(1, 2)))
    before = records.read_predictions(run_dir)
    # Turning both rows of Flow 101 into quota errors, then cutting the last row,
    # as a run interrupted before the last Flow of the k = 2 cell would leave it.
    failed = [prediction | {"error": "429 RESOURCE_EXHAUSTED"} if prediction["row_id"] == 101 else prediction for prediction in before]
    interrupted = failed[:-1]
    (run_dir / "predictions.jsonl").write_text("".join(json.dumps(prediction) + "\n" for prediction in interrupted), encoding="utf-8")

    assert run.redo_errors(run_dir) == run_dir

    after = records.read_predictions(run_dir)
    # Expecting six rows again, none with an error. The kept ones come first, then the two redone and the one missing,
    # in cell order and split order, with their cell's fields and the right number of Examples.
    assert len(after) == len(before) and all(prediction.get("error") is None for prediction in after)
    kept = [prediction for prediction in interrupted if not prediction.get("error")]
    assert after[: len(kept)] == kept
    redone = after[len(kept) :]
    expected = [(1, 101, 3), (2, 101, 6), (2, 102, 6)]
    assert [(prediction["k"], prediction["row_id"], prediction["n_examples"]) for prediction in redone] == expected
    # Expecting the original verdicts back, because the redo draws the original Examples and the forest has a fixed random_state.
    assert [prediction["p_attack"] for prediction in redone] == [before[index]["p_attack"] for index in (1, 4, 5)]
    run_fields = ("run_id", "dataset", "detector", "model", "split", "prompt_hash")
    assert {tuple(prediction[field] for field in run_fields) for prediction in after} == {
        (run_dir.name, "test", "random_forest", before[0]["model"], "smoke", None)
    }
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert [(entry["error_rows"], entry["missing_flows"]) for entry in config_json["redone"]] == [(2, 1)]
    lines = capsys.readouterr().out.splitlines()
    assert lines[-3:] == [
        "k=1 seed=0 rep=0 flows=1 errors=0",
        "k=2 seed=0 rep=0 flows=2 errors=0",
        f"redone: 2 error rows and 1 missing flows of {run_dir}",
    ]
    # Refusing a run whose config.json names another model or prompt, because one run_id would then mix two experiments.
    config_json |= {
        "model": "fake-1",
        "prompt_hash": "h",
    }
    (run_dir / "config.json").write_text(json.dumps(config_json), encoding="utf-8")
    with pytest.raises(ValueError, match="fake-1"):
        run.redo_errors(run_dir)


def test_predictions_carry_the_truth_and_the_verdict(card: Path) -> None:
    config = dataset.load_config(card)
    run_dir = run.execute(smoke_spec(card), FakeDetector(), config, FLOWS, TRAIN)
    by_row = {prediction["row_id"]: prediction for prediction in records.read_predictions(run_dir)}
    assert (by_row[100]["is_attack"], by_row[100]["classification_verdict"]) == (0, 0)
    assert (by_row[101]["is_attack"], by_row[101]["classification_verdict"]) == (1, 1)
    assert (by_row[101]["category_true"], by_row[101]["novel_attack"]) == ("dos", True)


def test_run_from_spec_reads_the_dataset_and_fits_the_forest_on_the_pool(
    card: Path,
) -> None:
    # Running end to end from disk with the one Detector that needs no network.
    run_dir = run.run_from_spec(smoke_spec(card, "random_forest", k_values=(1, None), reps=2))
    predictions = records.read_predictions(run_dir)
    assert len(predictions) == 2 * 2 * 3
    assert {prediction["n_examples"] for prediction in predictions} == {3, len(TRAIN)}
    assert {prediction["prompt_hash"] for prediction in predictions} == {None}
    assert all(prediction["classification_verdict"] in (0, 1) for prediction in predictions)
    assert all(prediction["train_time_ms"] > 0 for prediction in predictions)
    # Expecting no responses.jsonl, because the forest has no raw answer.
    assert not (run_dir / "responses.jsonl").exists()


def test_build_detector_knows_the_five_names(card: Path) -> None:
    config = dataset.load_config(card)
    forest = run.build_detector(run.RunSpec("random_forest", card, "smoke", (1,), (0,)), config)
    assert isinstance(forest, RandomForestDetector)
    # Expecting feature `b` at index 1, where every TRAIN attribute equals its row index.
    assert forest.encoder.vocabulary == {1: ("0", "1", "2", "3", "4", "5")}
    assert forest.benign == "normal"
    isolation = run.build_detector(run.RunSpec("isolation_forest", card, "smoke", (None,), (0,)), config)
    assert isinstance(isolation, IsolationForestDetector)
    assert (isolation.encoder.vocabulary, isolation.benign) == (forest.encoder.vocabulary, "normal")
    nsl_kdd = dataset.load_config(NSL_KDD)
    jev_spec = run.RunSpec("jev", NSL_KDD, "smoke", (0,), (0,))
    judge = run.build_detector(jev_spec, nsl_kdd)
    assert judge.name == "jev"
    assert len(judge.prompt_hash or "") == 64
    deepseek_spec = run.RunSpec("llm:deepseek", NSL_KDD, "smoke", (0,), (0,))
    deepseek = run.build_detector(deepseek_spec, nsl_kdd)
    assert (deepseek.name, deepseek.model) == ("llm:deepseek", "deepseek-flash")
    terra_spec = run.RunSpec("llm:openai", NSL_KDD, "smoke", (0,), (0,), model_id="gpt-5.6-terra")
    assert run.build_detector(terra_spec, nsl_kdd).model == "gpt-5.6-terra"
    with pytest.raises(NotImplementedError):
        run.build_detector(run.RunSpec("unknown", card, "smoke", (0,), (0,)), config)


def test_run_dir_name_has_timestamp_dataset_detector_and_split(card: Path) -> None:
    run_dir = run.execute(smoke_spec(card, "llm:deepseek"), FakeDetector(), dataset.load_config(card), FLOWS, TRAIN)
    # Expecting the colon of `llm:deepseek` as a dash in the name, because a colon is not a path character.
    assert re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-test-llm-deepseek-smoke", run_dir.name)


def test_k_all_is_for_the_forests_only_and_each_forest_has_its_k_guard() -> None:
    with pytest.raises(ValueError, match="only meaningful for the forests and the kNN"):
        run.check_spec(run.RunSpec("jev", NSL_KDD, "smoke", (None,), (0,)), "jev")
    with pytest.raises(ValueError, match="starts at k = 1"):
        run.check_spec(run.RunSpec("random_forest", NSL_KDD, "smoke", (0, 1), (0,)), "random_forest")
    with pytest.raises(ValueError, match="k = all only"):
        run.check_spec(run.RunSpec("isolation_forest", NSL_KDD, "smoke", (1, None), (0,)), "isolation_forest")
    run.check_spec(run.RunSpec("isolation_forest", NSL_KDD, "smoke", (None,), (0,)), "isolation_forest")


def test_sample_examples_is_balanced_nested_and_deterministic() -> None:
    k1 = run.sample_examples(TRAIN, 1, 0, CATEGORIES)
    k2 = run.sample_examples(TRAIN, 2, 0, CATEGORIES)
    assert len(k1) == 3
    assert len(k2) == 6
    for category in CATEGORIES:
        assert sum(example.category == category for example in k2) == 2
    assert {example.row_id for example in k1} <= {example.row_id for example in k2}
    assert run.sample_examples(TRAIN, 2, 0, CATEGORIES) == k2
    assert run.sample_examples(TRAIN, 0, 0, CATEGORIES) == []
    with pytest.raises(ValueError, match="k = 3 asked"):
        run.sample_examples(TRAIN, 3, 0, CATEGORIES)
    # Drawing no Examples from a Category held out of the pool.
    assert run.sample_examples(TRAIN, 1, 0, [*CATEGORIES, "r2l"]) == k1


def test_load_prompt_hashes_the_bytes(tmp_path: Path) -> None:
    path = tmp_path / "p.md"
    path.write_bytes(b"abc")
    sha256 = hashlib.sha256(b"abc").hexdigest()
    assert run.load_prompt(path) == {
        "text": "abc",
        "sha256": sha256,
    }


@pytest.mark.parametrize("name", ["nsl-kdd", "cicids2017"])
def test_each_committed_prompt_pair_matches_its_card(name: str) -> None:
    config = dataset.load_config(ROOT / "data" / name / "dataset.json")
    body = json.loads(run.load_prompt(ROOT / "prompts" / name / "jev.json")["text"])
    assert body["model"] == "jev-1.13.0"
    assert list(body["state"]["categories"]) == config["categories"]
    assert body["state"]["columns"] == ",".join(config["features"])
    assert set(body["questions"]) == {"is_attack", "category"}
    assert all("`flows.under_test`" in question["instructions"] for question in body["questions"].values())
    text = run.load_prompt(ROOT / "prompts" / name / "llm.md")["text"]
    # Checking that the same task text, Categories and columns reach every Detector.
    # The Markdown layout around them belongs to the prompt's author.
    assert body["state"]["instructions"] in text
    assert all(f"- `{category}`:" in text for category in config["categories"])
    assert f"\n{body['state']['columns']}\n" in text
    assert text.count("{examples}") == 1
    assert "JSON" in text


def test_selection_is_score_in_a_stream_random_outside_and_none_for_the_forests() -> None:
    stream_spec = run.RunSpec("jev", NSL_KDD, "smoke", (4,), (0,), delay=1)
    assert run.selection_of(stream_spec, "jev") == "score"
    assert run.selection_of(replace(stream_spec, selection="random"), "jev") == "random"
    assert run.selection_of(replace(stream_spec, delay=None), "jev") == "random"
    assert run.selection_of(stream_spec, "random_forest") is None
    run.check_spec(replace(stream_spec, selection="random"), "jev")
    with pytest.raises(ValueError, match="needs a stream"):
        run.check_spec(replace(stream_spec, delay=None, selection="score"), "jev")
    with pytest.raises(ValueError, match="selection"):
        run.check_spec(replace(stream_spec, selection="best"), "jev")
    assert run.choose_with(None, 4, ["normal"]) is None


def test_a_stream_run_gives_jev_the_selector_s_examples(card: Path) -> None:
    start = datetime(2017, 7, 3, 12, 0)
    train = [replace(flow, end=start + timedelta(minutes=index)) for index, flow in enumerate(TRAIN)]
    flows = [replace(flow, end=start + timedelta(minutes=10 + index)) for index, flow in enumerate(FLOWS)]
    detector = FakeDetector()
    spec = replace(smoke_spec(card, k_values=(1,)), delay=1)
    run_dir = run.execute(spec, detector, dataset.load_config(card), flows, train)
    rows = records.read_predictions(run_dir)
    assert {(row["selection"], row["record"]) for row in rows} == {("score", "compact")}
    # Expecting one Example per Category from the pool, then the returned Flows of each Category join the candidates.
    assert [n_examples for _, n_examples in detector.calls] == [3, 3, 3]
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert (config_json["spec"]["selection"], config_json["selection"]) == (None, "score")


def test_the_knn_needs_its_neighbours_and_the_whole_memory(card: Path) -> None:
    config = dataset.load_config(card)
    spec = run.RunSpec("knn", card, "smoke", (None,), (0,), delay=1, neighbours="matched:4")
    detector = run.build_detector(spec, config)
    assert (detector.name, detector.model, detector.record) == ("knn", "knn-matched-4", "full")
    assert run.selection_of(spec, "knn") is None
    with pytest.raises(ValueError, match="--neighbours"):
        run.build_detector(replace(spec, neighbours=None), config)
    run.check_spec(spec, "knn")
    with pytest.raises(ValueError, match="k = all"):
        run.check_spec(replace(spec, k_values=(4,)), "knn")


@pytest.mark.parametrize("selection", ["score", "random"])
def test_aimd_needs_a_stream_from_k_one_and_writes_k_per_category(card: Path, selection: str) -> None:
    # Running the full system (score) and stage 6's ablation without the `Selector` (random), both under the `KController`.
    spec = replace(smoke_spec(card, k_values=(1,)), delay=1, control="aimd", selection=selection, beta=3.0)
    run.check_spec(spec, "jev")
    # Refusing a β other than 2 without the `KController` it belongs to.
    wrongs = (replace(spec, k_values=(4,)), replace(spec, delay=None), replace(spec, control="x"))
    for wrong in (*wrongs, replace(spec, control="fixed", k_values=(4,))):
        with pytest.raises(ValueError, match="control|stream|beta"):
            run.check_spec(wrong, "jev")
    start = datetime(2017, 7, 3, 12, 0)
    train = [replace(flow, end=start + timedelta(minutes=index)) for index, flow in enumerate(TRAIN)]
    flows = [replace(flow, end=start + timedelta(minutes=10 + index)) for index, flow in enumerate(FLOWS)]
    detector = FakeDetector()
    run_dir = run.execute(spec, detector, dataset.load_config(card), flows, train)
    rows = records.read_predictions(run_dir)
    assert {(row["control"], row["selection"], row["beta"]) for row in rows} == {("aimd", selection, 3.0)}
    # Expecting every k to stay at k_min = 1 and one Example per Category, because the fake detector is always right.
    assert all(set(row["k_by_category"].values()) == {1.0} for row in rows)
    assert [n_examples for _, n_examples in detector.calls] == [3, 3, 3]
