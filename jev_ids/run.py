"""One run: a Detector over one split, cell by cell, Flow by Flow.

In reading order:

- `RunSpec`: what the CLI resolved for one run.
- `load_prompt`: any prompt file as text plus its sha256; Jev and the LLMs load their files (`jev.json`, `llm.md`) through it alike.
- `build_detector` and `check_spec`: the Detector named in the spec, and the two combinations of Detector and k that would only waste calls.
- `sample_examples`: k Examples per Category, seeded and nested across k.
- `execute` and `judge`: the loop itself, cell by cell and Flow by Flow, and the three files of the run; with a delay D, each cell is a
  stream instead (`jev_ids/stream.py`).
- `run_from_spec`: the CLI entry that strings the above together.
- `redo_errors`: the other CLI entry, completing a run: its error rows are judged again and its missing Flows for the first time.

The loop runs k outermost, then seed, then rep, then every Flow of the split, so the prompt prefix stays constant for as long as possible
and provider prefix caches get their best chance. One request judges one Flow (B = 1). A call that fails ends as a row with `error`, never
as a crash, and the run goes on.
"""

import hashlib
import itertools
import json
import random
import subprocess
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jev_ids import ROOT, dataset
from jev_ids.dataset import Config, Flow
from jev_ids.detectors import random_forest
from jev_ids.detectors.isolation_forest import IsolationForestDetector
from jev_ids.detectors.jev import JevDetector
from jev_ids.detectors.knn import KNNDetector
from jev_ids.detectors.llm import LLMDetector
from jev_ids.detectors.random_forest import RandomForestDetector
from jev_ids.records import append_prediction, complete_prediction, read_predictions, write_config
from jev_ids.selector import Selector, Space
from jev_ids.stream import Choose, Memory, split_names, stream_cell

RESULTS_DIR = ROOT / "results"
SELECTIONS = ("random", "score")
# The Detectors that get the whole memory (k = all) instead of chosen Examples.
WHOLE_MEMORY = ("random_forest", "isolation_forest", "knn")

# The detectors share no base class; the run loop only needs `name`, `model`, `prompt_hash` and `predict`, which each of them has.
Detector = JevDetector | LLMDetector | RandomForestDetector | IsolationForestDetector | KNNDetector


@dataclass(frozen=True)
class RunSpec:
    """Everything the CLI resolved for one run; a parameter bundle, nothing more.

    Attributes:
        detector: `jev`, `llm:deepseek`, `llm:openai`, `llm:gemini`, `random_forest` or `isolation_forest`.
        dataset: the card of the dataset, `data/<name>/dataset.json`.
        split: the split to judge, a file under `data/<name>/splits/`.
        k_values: Examples per Category to try; None means the whole pool (the forests).
        seeds: the seeds of the Example draws.
        reps: how often each (k, seed) cell is repeated, for stability.
        model_id: the provider model, for the LLM detectors; None means default.
        results_dir: where run directories are created.
        jobs: CPU cores each forest fit may use (-1 for all); the forests come out the same for any value, so it is not part of the
            experiment.
        delay: the feedback delay D in steps for a stream run (docs/jevids-design.md, D4); None judges every Flow against one fixed draw
            of Examples, the protocol of the first paper.
        record: how Jev and the LLMs read a Flow's values, `full` or `compact` (`dataset.RECORDS`, docs/jevids-design.md, D7); the
            forests always read them in full.
        selection: how a stream gives Jev and the LLMs their Examples, `random` (line 0) or `score` (the `Selector`, D6); None means
            `score` for a stream and `random` otherwise, the only choice the protocol of the first paper has.
        neighbours: K of the kNN, a number or `matched:k` (`knn.parse_neighbours`); None for every other Detector.
    """

    detector: str
    dataset: Path
    split: str
    k_values: tuple[int | None, ...]
    seeds: tuple[int, ...]
    reps: int = 1
    model_id: str | None = None
    results_dir: Path = RESULTS_DIR
    delay: int | None = None
    jobs: int = 1
    record: str = "compact"
    selection: str | None = None
    neighbours: str | None = None


def load_prompt(path: Path) -> dict[str, Any]:
    """A prompt file as `text`, plus the `sha256` of its bytes.

    The hash goes into config.json and into every row as `prompt_hash`, so any change of wording is visible in the records.
    """
    raw_bytes = path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    return {"text": raw_bytes.decode("utf-8"), "sha256": sha256}


def build_detector(spec: RunSpec, config: Config) -> Detector:
    """The Detector named in the spec; Jev and the LLMs get their prompt file."""
    prompts = ROOT / "prompts" / config["name"]
    if spec.detector == "jev":
        return JevDetector(load_prompt(prompts / "jev.json"), spec.record)
    if spec.detector in ("llm:deepseek", "llm:openai", "llm:gemini"):
        provider = spec.detector.removeprefix("llm:")
        return LLMDetector(load_prompt(prompts / "llm.md"), provider, spec.model_id, spec.record)
    if spec.detector in ("random_forest", "isolation_forest"):
        # The one-hot vocabulary comes from the whole pool, never from the Examples, and both forests encode a Flow the same way.
        pool = dataset.load_split(config["dir"] / "pool.csv", config)
        forest = RandomForestDetector if spec.detector == "random_forest" else IsolationForestDetector
        return forest(random_forest.vocabulary(pool, config), config["benign"], spec.jobs)
    if spec.detector == "knn":
        if spec.neighbours is None:
            raise ValueError("the kNN needs --neighbours: a number, or matched:k")
        pool = dataset.load_split(config["dir"] / "pool.csv", config)
        return KNNDetector(Space(random_forest.vocabulary(pool, config), pool), config["benign"], spec.neighbours)
    raise NotImplementedError(f"detector {spec.detector!r} is not implemented")


def check_spec(spec: RunSpec, detector_name: str) -> None:
    """Refuse what would waste calls.

    k = all exists only for the two forests and the kNN; the Random Forest cannot train on nothing at k = 0, and the Isolation Forest
    (benign Flows alone) and the kNN (the whole memory) run at k = all only.
    """
    if None in spec.k_values and detector_name not in WHOLE_MEMORY:
        raise ValueError("k = all is only meaningful for the forests and the kNN")
    if detector_name == "random_forest" and 0 in spec.k_values:
        raise ValueError("the Random Forest starts at k = 1")
    if detector_name in ("isolation_forest", "knn") and spec.k_values != (None,):
        raise ValueError(f"the {detector_name} runs at k = all only")
    if spec.selection is not None and (spec.selection not in SELECTIONS or (spec.delay is None and spec.selection == "score")):
        raise ValueError(f"selection {spec.selection!r}: `random` or `score`, and `score` needs a stream (--delay)")


def selection_of(spec: RunSpec, detector_name: str) -> str | None:
    """How the Examples are chosen: None for the forests (the whole memory), else the spec's choice, `score` in a stream by default."""
    if detector_name in WHOLE_MEMORY:
        return None
    if spec.selection is not None:
        return spec.selection
    return "score" if spec.delay is not None else "random"


def sample_examples(train: Sequence[Flow], k: int, seed: int, categories: Sequence[str]) -> list[Flow]:
    """Draw k Examples per Category, at random within each Category.

    Each Category is shuffled by a random stream seeded with `seed` and its name, and its first k Flows are taken; so for one seed the draws
    are nested across k (the Examples of k = 4 are among those of k = 8) and independent of the other Categories. The final order is one
    more seeded shuffle, shared by every Detector, so no Detector sees the Examples grouped by Category. A Category with no Flow in the pool
    (held out as novel) contributes nothing; one with fewer than k Flows raises.
    """
    chosen: list[Flow] = []
    for category in categories:
        pool = [flow for flow in train if flow.category == category]
        if 0 < len(pool) < k:
            raise ValueError(f"category {category!r}: {len(pool)} flows, k = {k} asked")
        random.Random(f"{seed}:{category}").shuffle(pool)  # noqa: S311  # seeded, not secret
        chosen.extend(pool[:k])
    random.Random(f"{seed}:order").shuffle(chosen)  # noqa: S311  # seeded, not secret
    return chosen


def execute(spec: RunSpec, detector: Detector, config: Config, flows: Sequence[Flow], train: Sequence[Flow]) -> Path:
    """Run `detector` over `flows` with Examples drawn from `train`; the run directory.

    `config.json` is written first, with what is needed to trace the run to its exact inputs: the resolved spec, the card's name and hash,
    the prompt hash. Then each (k, seed, rep) cell judges every Flow of the split, one call and one row each, and closes with a progress
    line counting the Flows judged and the rows that came back with an error.
    """
    check_spec(spec, detector.name)
    # `<UTC timestamp>-<dataset>-<detector>-<split>` names the directory under results/; the timestamp keeps its microseconds so that runs
    # launched together (one k each, in parallel) never share a directory, and the colon of `llm:openai` is not a path character.
    started = datetime.now(UTC)
    run_id = f"{started:%Y%m%dT%H%M%S.%fZ}-{spec.dataset.parent.name}-{spec.detector.replace(':', '-')}-{spec.split}"
    run_dir = spec.results_dir / run_id
    # The commit the code was at, with `-dirty` when the working tree had uncommitted changes, so a run can be traced to its exact code;
    # the split file is hashed for the same reason, because the card's hash does not cover the Flows that were judged.
    commit = ["git", "describe", "--always", "--dirty", "--abbrev=40", "--exclude=*"]
    described = subprocess.run(commit, capture_output=True, text=True, cwd=ROOT, check=False)  # noqa: S603 constant arguments
    split_path = config["dir"] / "splits" / f"{spec.split}.csv"
    write_config(
        run_dir,
        {
            "run_id": run_id,
            "spec": asdict(spec),
            "detector": detector.name,
            "model": detector.model,
            "dataset": {"name": config["name"], "sha256": config["sha256"]},
            "split": {"name": spec.split, "sha256": hashlib.sha256(split_path.read_bytes()).hexdigest()},
            "prompt_hash": detector.prompt_hash,
            "selection": selection_of(spec, detector.name),
            "code_commit": described.stdout.strip(),
            "started_at": started.isoformat(timespec="seconds"),
        },
    )
    # The fields every row of this run shares; a cell adds k, seed, rep and the number of Examples. `record` is in every row because the
    # prompt hash does not change with it: the same template is filled with full or compact values.
    run_fields: dict[str, Any] = {
        "run_id": run_id,
        "dataset": config["name"],
        "detector": detector.name,
        "model": detector.model,
        "split": spec.split,
        "prompt_hash": detector.prompt_hash,
        "record": detector.record,
        "selection": selection_of(spec, detector.name),
    }
    if spec.delay is not None:
        execute_stream(spec, detector, config, (flows, train), run_fields)
        print(f"done: {run_dir}")
        return run_dir
    for k, seed in itertools.product(spec.k_values, spec.seeds):
        # Drawn once per (k, seed) and reused by every rep, so the Random Forest keeps its fit across the repetitions. k = None is
        # the whole pool.
        examples = list(train) if k is None else sample_examples(train, k, seed, config["categories"])
        for repetition in range(spec.reps):
            judge(
                run_dir,
                detector,
                flows,
                examples,
                {**run_fields, "k": k, "seed": seed, "repetition": repetition, "n_examples": len(examples)},
            )
    print(f"done: {run_dir}")
    return run_dir


def execute_stream(
    spec: RunSpec,
    detector: Detector,
    config: Config,
    data: tuple[Sequence[Flow], Sequence[Flow]],
    run_fields: dict[str, Any],
) -> None:
    """Every (k, seed, rep) cell as a stream over the split (`data` is the split and the pool), each with a fresh memory.

    With the `score` selection the `Selector` gives every Category ceil(k) Examples; its space is built once for the run, because it only
    depends on the pool.
    """
    flows, train = data
    run_dir = spec.results_dir / run_fields["run_id"]
    assert spec.delay is not None  # noqa: S101  execute only streams with a delay
    names = split_names(config["dir"] / "splits" / f"{spec.split}.csv")
    selector = Selector(Space(random_forest.vocabulary(train, config), train)) if run_fields["selection"] == "score" else None
    for k, seed, repetition in itertools.product(spec.k_values, spec.seeds, range(spec.reps)):
        # A fresh memory per cell: what one cell learned must not leak into the next.
        memory = Memory(train, config["categories"], spec.delay, names)
        cell = {**run_fields, "k": k, "seed": seed, "repetition": repetition, "delay": spec.delay}
        stream_cell(run_dir, detector, memory, flows, cell, choose_with(selector, k, config["categories"]))


def choose_with(selector: Selector | None, k: int | None, categories: Sequence[str]) -> Choose | None:
    """The `Selector` at k Examples per Category, as `stream_cell` calls it; None keeps the stream's own random draw or whole memory."""
    if selector is None or k is None:
        return None
    k_by_category = dict.fromkeys(categories, float(k))
    return lambda memory, flow, step: selector.choose(memory, flow, step, k_by_category)


def judge(run_dir: Path, detector: Detector, flows: Sequence[Flow], examples: Sequence[Flow], cell: dict[str, Any]) -> None:
    """One cell: judge every Flow with the cell's Examples, one call and one appended row each, then print the progress line."""
    errors = 0
    for flow in flows:
        prediction = complete_prediction(detector.predict(flow, examples), flow, cell)
        append_prediction(run_dir, prediction)
        errors += int(prediction.get("error") is not None)
    print(f"k={cell['k']} seed={cell['seed']} rep={cell['repetition']} flows={len(flows)} errors={errors}")


def run_from_spec(spec: RunSpec) -> Path:
    """The CLI entry: load the card, the split and the pool, build the detector, run."""
    config = dataset.load_config(spec.dataset)
    flows = dataset.load_split(config["dir"] / "splits" / f"{spec.split}.csv", config)
    train = dataset.load_split(config["dir"] / "pool.csv", config)
    return execute(spec, build_detector(spec, config), config, flows, train)


def redo_errors(run_dir: Path) -> Path:
    """Complete a run in place: its error rows are judged again and the Flows it never judged, for the first time.

    The spec comes back from `config.json`, so the directory is the only argument. The rows without error are kept and rewritten first.
    Then every (k, seed, rep) cell of the spec is walked as `execute` walks it, with the very Examples of the original draw, and the
    Flows of the split without a kept row in that cell are judged and appended, error or not, so a second pass can follow a first. That
    covers a run interrupted midway (a cell half done, cells never started) as much as one finished with quota errors. The detector must
    still be the same model on the same prompt, or the rows would mix two experiments under one run_id. `responses.jsonl` keeps the raw
    answers of the failed calls, and `config.json` gains a `redone` entry per pass.
    """
    stored = json.loads((run_dir / "config.json").read_text("utf-8"))
    fields: dict[str, Any] = stored["spec"]
    if fields.get("delay") is not None:
        # The memory of a stream depends on every earlier row, so a Flow judged again would see another past than its neighbours did.
        raise ValueError(f"{run_dir.name} is a stream run: judge it again from the start instead")
    spec = RunSpec(
        detector=fields["detector"],
        dataset=Path(fields["dataset"]),
        split=fields["split"],
        k_values=tuple(fields["k_values"]),
        seeds=tuple(fields["seeds"]),
        reps=fields["reps"],
        model_id=fields["model_id"],
        results_dir=Path(fields["results_dir"]),
        # A run made before the compact record existed read the values in full.
        record=fields.get("record", "full"),
        selection=fields.get("selection"),
        neighbours=fields.get("neighbours"),
    )
    config = dataset.load_config(spec.dataset)
    flows = dataset.load_split(config["dir"] / "splits" / f"{spec.split}.csv", config)
    train = dataset.load_split(config["dir"] / "pool.csv", config)
    detector = build_detector(spec, config)
    if (detector.model, detector.prompt_hash) != (stored["model"], stored["prompt_hash"]):
        raise ValueError(f"{run_dir.name} was run with {stored['model']} on prompt {stored['prompt_hash'][:8]}; the code now gives another")
    rows = read_predictions(run_dir)
    kept = [row for row in rows if row.get("error") is None]
    (run_dir / "predictions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in kept), encoding="utf-8")
    run_fields = {key: stored[key] for key in ("run_id", "detector", "model", "prompt_hash")} | {
        "dataset": config["name"],
        "split": spec.split,
    }
    # A Flow is done when its cell holds a kept row for it; everything else in the cell (an error row or no row at all) is judged now.
    done = {(row["k"], row["seed"], row["repetition"], row["row_id"]) for row in kept}
    judged = 0
    # Every cell of the spec, in the order `execute` walks them; `sample_examples` is deterministic, so the draw is the original one.
    for k, seed, repetition in itertools.product(spec.k_values, spec.seeds, range(spec.reps)):
        examples = list(train) if k is None else sample_examples(train, k, seed, config["categories"])
        cell = {**run_fields, "k": k, "seed": seed, "repetition": repetition, "n_examples": len(examples)}
        todo = [flow for flow in flows if (k, seed, repetition, flow.row_id) not in done]
        judged += len(todo)
        if todo:
            judge(run_dir, detector, todo, examples, cell)
    errors = len(rows) - len(kept)
    redone = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "error_rows": errors, "missing_flows": judged - errors}
    stored["redone"] = [*stored.get("redone", []), redone]
    write_config(run_dir, stored)
    print(f"redone: {redone['error_rows']} error rows and {redone['missing_flows']} missing flows of {run_dir}")
    return run_dir
