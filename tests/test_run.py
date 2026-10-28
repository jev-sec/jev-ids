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
            "usage": {"input_tokens": 10, "output_tokens": 1},
            "raw": {"echo": flow.row_id},
        }


@pytest.fixture
def card(tmp_path: Path) -> Path:
    """A dataset on disk: TRAIN is the pool and FLOWS the `smoke` split."""
    return write_dataset(tmp_path / "data", CONFIG, {"pool": TRAIN, "smoke": FLOWS})


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
    # k outermost, then rep, then the Flows; 3 Examples at k = 1.
    zero_shot = [(100, 0), (101, 0), (102, 0)]
    one_shot = [(100, 3), (101, 3), (102, 3)]
    assert detector.calls == zero_shot * 2 + one_shot * 2
    assert {p["n_examples"] for p in predictions} == {0, 3}
    shared = {
        *("run_id", "dataset", "detector", "model", "split", "prompt_hash", "record", "selection"),
        *("k", "seed", "repetition", "n_examples", "row_id", "is_attack", "classification_verdict"),
        *("category_true", "novel_attack", "p_attack", "category_pred"),
        *("latency_ms", "usage", "request_id", "ts_utc"),
    }
    assert all(set(p) == shared for p in predictions)
    assert {(p["dataset"], p["detector"], p["prompt_hash"], p["record"]) for p in predictions} == {("test", "fake", "h", "compact")}
    assert run_dir.name.endswith("-test-fake-smoke")
    responses = (run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(responses) == len(predictions)
    assert json.loads(responses[0])["request_id"] == predictions[0]["request_id"]
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert config_json["spec"]["k_values"] == [0, 1]
    assert config_json["spec"]["record"] == "compact"
    assert config_json["spec"]["dataset"] == str(card)
    assert config_json["dataset"] == {"name": "test", "sha256": config["sha256"]}
    split_sha256 = hashlib.sha256((card.parent / "splits" / "smoke.csv").read_bytes()).hexdigest()
    assert config_json["split"] == {"name": "smoke", "sha256": split_sha256}
    assert (config_json["model"], config_json["prompt_hash"]) == ("fake-1", "h")
    # The full commit id, `-dirty` appended while the tree has uncommitted changes.
    assert re.fullmatch(r"[0-9a-f]{40}(-dirty)?", config_json["code_commit"])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "k=0 seed=0 rep=0 flows=3 errors=0"
    assert len(lines) == 4 + 1  # one line per cell, then `done:`


def test_redo_errors_judges_the_failed_and_the_missing_flows_in_their_cells(
    card: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FlakyDetector(FakeDetector):
        """Fails Flow 101 once, on every cell of the first pass, and answers from then on."""

        def predict(self, flow: dataset.Flow, examples: Sequence[dataset.Flow]) -> dict[str, Any]:
            if flow.row_id == 101 and (flow.row_id, len(examples)) not in self.calls:
                self.calls.append((flow.row_id, len(examples)))
                return {"error": "429 RESOURCE_EXHAUSTED"}
            return super().predict(flow, examples)

    detector = FlakyDetector()
    config = dataset.load_config(card)
    run_dir = run.execute(smoke_spec(card, k_values=(0, 1)), detector, config, FLOWS, TRAIN)
    before = records.read_predictions(run_dir)
    assert [(p["k"], p["row_id"]) for p in before if p.get("error")] == [(0, 101), (1, 101)]
    # An interrupted run: the last Flow of the k = 1 cell was never judged.
    interrupted = before[:-1]
    (run_dir / "predictions.jsonl").write_text("".join(json.dumps(p) + "\n" for p in interrupted), encoding="utf-8")

    def same_detector(spec: run.RunSpec, config: dataset.Config) -> run.Detector:
        return detector

    monkeypatch.setattr(run, "build_detector", same_detector)

    assert run.redo_errors(run_dir) == run_dir

    after = records.read_predictions(run_dir)
    # Six rows again, none with an error: the kept ones first, then the two redone and the one missing, in cell order and split order,
    # with their cell's fields and the right number of Examples.
    assert len(after) == len(before) and all(p.get("error") is None for p in after)
    kept = [p for p in interrupted if not p.get("error")]
    assert after[: len(kept)] == kept
    redone = after[len(kept) :]
    expected = [(0, 101, 0, 1.0), (1, 101, 3, 1.0), (1, 102, 3, 1.0)]
    assert [(p["k"], p["row_id"], p["n_examples"], p["p_attack"]) for p in redone] == expected
    assert {(p["run_id"], p["dataset"], p["detector"], p["model"], p["split"], p["prompt_hash"]) for p in after} == {
        (run_dir.name, "test", "fake", "fake-1", "smoke", "h")
    }
    assert detector.calls[-3:] == [(101, 0), (101, 3), (102, 3)]
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert [(entry["error_rows"], entry["missing_flows"]) for entry in config_json["redone"]] == [(2, 1)]
    lines = capsys.readouterr().out.splitlines()
    assert lines[-3:] == [
        "k=0 seed=0 rep=0 flows=1 errors=0",
        "k=1 seed=0 rep=0 flows=2 errors=0",
        f"redone: 2 error rows and 1 missing flows of {run_dir}",
    ]
    # Another model or prompt under the same run_id would mix two experiments.
    detector.model = "fake-2"
    with pytest.raises(ValueError, match="fake-1"):
        run.redo_errors(run_dir)


def test_predictions_carry_the_truth_and_the_verdict(card: Path) -> None:
    config = dataset.load_config(card)
    run_dir = run.execute(smoke_spec(card), FakeDetector(), config, FLOWS, TRAIN)
    by_row = {p["row_id"]: p for p in records.read_predictions(run_dir)}
    assert (by_row[100]["is_attack"], by_row[100]["classification_verdict"]) == (0, 0)
    assert (by_row[101]["is_attack"], by_row[101]["classification_verdict"]) == (1, 1)
    assert (by_row[101]["category_true"], by_row[101]["novel_attack"]) == ("dos", True)


def test_run_from_spec_reads_the_dataset_and_fits_the_forest_on_the_pool(
    card: Path,
) -> None:
    # End to end from disk with the one Detector that needs no network.
    run_dir = run.run_from_spec(smoke_spec(card, "random_forest", k_values=(1, None), reps=2))
    predictions = records.read_predictions(run_dir)
    assert len(predictions) == 2 * 2 * 3
    assert {p["n_examples"] for p in predictions} == {3, len(TRAIN)}
    assert {p["prompt_hash"] for p in predictions} == {None}
    assert all(p["classification_verdict"] in (0, 1) for p in predictions)
    assert all(p["train_time_ms"] > 0 for p in predictions)
    assert not (run_dir / "responses.jsonl").exists()  # the forest has no raw answer


def test_build_detector_knows_the_five_names(card: Path) -> None:
    config = dataset.load_config(card)
    forest = run.build_detector(run.RunSpec("random_forest", card, "smoke", (1,), (0,)), config)
    assert isinstance(forest, RandomForestDetector)
    # Feature `b` sits at index 1; every TRAIN attribute equals its row index.
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
    # The colon of `llm:deepseek` is not a path character, so the name carries it as a dash.
    assert re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-test-llm-deepseek-smoke", run_dir.name)


def test_k_all_is_for_the_forests_only_and_each_forest_has_its_k_guard() -> None:
    with pytest.raises(ValueError, match="only meaningful for the Random Forest"):
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
    # A Category held out of the pool contributes no Examples.
    assert run.sample_examples(TRAIN, 1, 0, [*CATEGORIES, "r2l"]) == k1


def test_load_prompt_hashes_the_bytes(tmp_path: Path) -> None:
    path = tmp_path / "p.md"
    path.write_bytes(b"abc")
    sha256 = hashlib.sha256(b"abc").hexdigest()
    assert run.load_prompt(path) == {"text": "abc", "sha256": sha256}


@pytest.mark.parametrize("name", ["nsl-kdd", "cicids2017"])
def test_each_committed_prompt_pair_matches_its_card(name: str) -> None:
    config = dataset.load_config(ROOT / "data" / name / "dataset.json")
    body = json.loads(run.load_prompt(ROOT / "prompts" / name / "jev.json")["text"])
    assert body["model"] == "jev-1.13.0"
    assert list(body["state"]["categories"]) == config["categories"]
    assert body["state"]["columns"] == ",".join(config["features"])
    assert set(body["questions"]) == {"is_attack", "category"}
    assert all("`flows.under_test`" in q["instructions"] for q in body["questions"].values())
    text = run.load_prompt(ROOT / "prompts" / name / "llm.md")["text"]
    # The same task text, Categories and columns reach every Detector; the Markdown layout around them belongs to the prompt's author.
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
    # One Example per Category from the pool, then the returned Flows of each Category join the candidates.
    assert [n for _, n in detector.calls] == [3, 3, 3]
    config_json = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    assert (config_json["spec"]["selection"], config_json["selection"]) == (None, "score")
