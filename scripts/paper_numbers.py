"""Every number of the paper, from the runs of the zero-day battery, written to results/paper/numbers.json.

Each run is found through the stamp `make` left in results/zeroday-<dataset>/v2-done/. The Fusion runs are built with
`jev_ids.fusion.fuse` from each Jev run and the matched kNN run of the same delay, with the percentiles of the validation stream
at D = 200. Every detector is read on all 2,000 Flows of its Stream, a missing p_attack as 0, at one cut per dataset shared by
every detector, and by its ROC-AUC and PR-AUC, which need no cut. The cut is the D9 rule of `jev_ids.metrics.best_threshold` on
the Jev-IDS run of the validation stream, so the test stream never shapes it. A block bootstrap over the stream order gives each
F1, ROC-AUC and PR-AUC a 95% interval and each paired comparison an interval for the difference.
"""

import csv
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import scipy.stats  # pyright: ignore[reportMissingTypeStubs]  SciPy ships no type stubs
import sklearn.metrics  # pyright: ignore[reportMissingTypeStubs]  scikit-learn ships no type stubs

from jev_ids.fusion import fuse
from jev_ids.metrics import best_threshold, mcnemar_exact
from jev_ids.records import Prediction, read_predictions

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "paper" / "numbers.json"
PRICE = 0.042e-6
BASELINES = ("rf", "if", "knn4", "knnmatched")
DATASETS = {
    "cicids2017": "paper-v3",
    "trustlab": "paper",
}
# Naming the stamps of the Jev runs, the lines of `make zeroday-jev`. CIC-IDS2017 repeats D = 50 and D = 1 over three seeds,
# TRUSTLab over one, and both run the ablations at D = 200.
ABLATIONS = [f"{config}-d200-s{seed}" for config in ("fixedk1", "noctl") for seed in (0, 1, 2)] + ["nosel-d200-s0", "randomk4-d200-s0"]
JEV_LINES = {
    "cicids2017": [f"full-d{delay}-s{seed}" for delay in (200, 50, 1) for seed in (0, 1, 2)] + ABLATIONS,
    "trustlab": [f"full-d200-s{seed}" for seed in (0, 1, 2)] + ["full-d50-s0", "full-d1-s0"] + ABLATIONS,
}
# Resampling the novel and the benign Flows apart, in blocks of 25 consecutive Flows of the Stream, 2,000 times, so every replicate
# keeps both counts and the Flows judged close together, whose Memory overlaps, stay together.
BLOCK = 25
REPLICATES = 2000
FloatArray = npt.NDArray[np.float64]
IntArray = npt.NDArray[np.int64]
# Reading SciPy and scikit-learn as Any, because neither ships type stubs.
STATS: Any = scipy.stats
AREAS: Any = sklearn.metrics


def stamp(dataset: str, name: str) -> Path:
    """The run directory a stamp of the zero-day battery names."""
    base = ROOT / "results" / f"zeroday-{dataset}"
    return base / (base / "v2-done" / name).read_text(encoding="utf-8").strip()


def only_dir(path: Path) -> Path:
    """The single run directory inside a results folder."""
    (run,) = [child for child in path.iterdir() if child.is_dir()]
    return run


def p(row: Prediction) -> float:
    """The p_attack of a row, 0 when missing."""
    return row.get("p_attack") or 0


def usage_of(row: Prediction) -> dict[str, Any]:
    """The usage a row's call reported, empty when it reported none."""
    return row.get("usage") or {}


def novel(rows: list[Prediction]) -> list[Prediction]:
    """The novel Flows at first contact."""
    return [row for row in rows if row["novel_attack"] and row.get("first_contact")]


def caught(rows: list[Prediction], cut: float) -> set[int]:
    """The row_id of the novel Flows whose score reaches the cut."""
    return {row["row_id"] for row in novel(rows) if p(row) >= cut}


def f1_novel(rows: list[Prediction], cut: float) -> float:
    """The F1 at a cut over the novel Flows at first contact and the benign Flows, the other attacks left out."""
    hits = len(caught(rows, cut))
    alarms = sum(p(row) >= cut for row in rows if not row["is_attack"])
    return 2 * hits / (2 * hits + alarms + len(novel(rows)) - hits)


def measure(rows: list[Prediction], cut: float, names: dict[int, str]) -> dict[str, Any]:
    """Novel recall at the cut, per name, the counts at the cut over every Flow, and the ROC-AUC and PR-AUC of novel against benign."""
    benign = [row for row in rows if not row["is_attack"]]
    attacks = [row for row in rows if row["is_attack"]]
    alarms = sum(p(row) >= cut for row in benign)
    hits = sum(p(row) >= cut for row in attacks)
    known = [row for row in attacks if not row["novel_attack"]]
    # Sweeping the cut in steps of 0.01 and adding the cut of the dataset, so curves and best cuts include the operating point
    sweep = {f"{step / 100:.2f}": f1_novel(rows, step / 100) for step in range(1, 100)} | {f"{cut:.4f}": f1_novel(rows, cut)}
    out: dict[str, Any] = {
        "rows": len(rows),
        "benign": len(benign),
        "novel_n": len(novel(rows)),
        "fa_cut": alarms,
        "f1_cut": 2 * hits / (2 * hits + alarms + len(attacks) - hits),
        "f1_novel_cut": f1_novel(rows, cut),
        "f1_novel_sweep": dict(sorted(sweep.items(), key=lambda pair: float(pair[0]))),
        "at_cut": sum(p(row) == cut for row in rows),
        "roc_auc": AREAS.roc_auc_score([row["is_attack"] for row in benign + novel(rows)], [p(row) for row in benign + novel(rows)]),
        "pr_auc": AREAS.average_precision_score(
            [row["is_attack"] for row in benign + novel(rows)], [p(row) for row in benign + novel(rows)]
        ),
        "roc_auc_all": AREAS.roc_auc_score([row["is_attack"] for row in rows], [p(row) for row in rows]),
        "known_recall_cut": sum(p(row) >= cut for row in known) / len(known),
        "attack_recall_cut": hits / len(attacks),
        "errors": sum(row.get("error") is not None or row.get("fallback", False) for row in rows),
    }
    ids = caught(rows, cut)
    out["novel_cut"] = len(ids)
    names_cut: dict[str, list[int]] = {}
    for row in novel(rows):
        cell = names_cut.setdefault(names[row["row_id"]], [0, 0])
        cell[0] += row["row_id"] in ids
        cell[1] += 1
    out["names_cut"] = names_cut
    tokens: list[int] = [usage_of(row).get("input_tokens", 0) for row in rows]
    out["tokens_per_flow"] = sum(tokens) / len(rows)
    out["usd"] = sum(tokens) * PRICE
    examples = [row["n_examples"] for row in rows if row.get("n_examples") is not None]
    out["examples_per_flow"] = sum(examples) / len(examples) if examples else None
    return out


def mcnemar(a: list[Prediction], b: list[Prediction], cut: float) -> dict[str, Any]:
    """Paired exact McNemar on the novel Flows at first contact."""
    hits_a, hits_b = caught(a, cut), caught(b, cut)
    return {"only_a": len(hits_a - hits_b), "only_b": len(hits_b - hits_a), "p": mcnemar_exact(len(hits_a - hits_b), len(hits_b - hits_a))}


def block_indices(sizes: tuple[int, int]) -> IntArray:
    """The Flow indices of every replicate, circular blocks of BLOCK drawn in each class with a fixed seed, so pairs share them."""
    generator, offset = np.random.default_rng(0), 0
    parts: list[IntArray] = []
    for size in sizes:
        starts = generator.integers(0, size, (REPLICATES, -(-size // BLOCK)))
        parts.append(offset + ((starts[:, :, None] + np.arange(BLOCK)) % size).reshape(REPLICATES, -1)[:, :size])
        offset += size
    return np.concatenate(parts, axis=1)


def resampled(rows: list[Prediction], cut: float) -> tuple[list[int], FloatArray, FloatArray, FloatArray]:
    """The Stream order of the novel and benign Flows, and the novel F1, ROC-AUC and PR-AUC of each bootstrap replicate over them."""
    attacks = sorted(novel(rows), key=lambda row: row["step"])
    kept = attacks + sorted((row for row in rows if not row["is_attack"]), key=lambda row: row["step"])
    indices = block_indices((len(attacks), len(kept) - len(attacks)))
    labels = np.array([row["is_attack"] for row in kept])[indices]
    scores = np.array([p(row) for row in kept])[indices]
    positives = labels.sum(axis=1)
    hits = (labels * (scores >= cut)).sum(axis=1)
    alarms = ((1 - labels) * (scores >= cut)).sum(axis=1)
    f1 = 2 * hits / (2 * hits + alarms + positives - hits)
    auc = ((STATS.rankdata(scores, axis=1) * labels).sum(axis=1) - positives * (positives + 1) / 2) / (positives * (len(kept) - positives))
    # Computing the average precision of each replicate the way scikit-learn does, so the point value and the replicates agree.
    # Sorting every replicate by descending score, a Flow takes the precision reached at the end of its group of tied scores,
    # and the average precision is the mean of that precision over the novel Flows.
    ranking = np.argsort(-scores, axis=1, kind="stable")
    sorted_scores, sorted_labels = np.take_along_axis(scores, ranking, axis=1), np.take_along_axis(labels, ranking, axis=1)
    precision = sorted_labels.cumsum(axis=1) / np.arange(1, len(kept) + 1)
    group_end = np.where(np.diff(sorted_scores, axis=1, append=-1) != 0, np.arange(len(kept)), len(kept))
    group_end = np.minimum.accumulate(group_end[:, ::-1], axis=1)[:, ::-1]
    average_precision = (sorted_labels * np.take_along_axis(precision, group_end, axis=1)).sum(axis=1) / positives
    return [row["row_id"] for row in kept], f1, auc, average_precision


def interval(values: FloatArray) -> list[float]:
    """The 95% percentile interval of a bootstrap sample."""
    return np.percentile(values, [2.5, 97.5]).tolist()


def calibration_runs(dataset: str) -> dict[str, Path]:
    """The Jev and matched kNN runs of the validation stream, whose scores the Fusion turns into percentiles."""
    return {"jev": only_dir(ROOT / "results" / f"zeroday-{dataset}-dev"), "knn": only_dir(ROOT / "results" / f"zeroday-{dataset}-dev-knn")}


def delay_of(label: str) -> str:
    """The delay D a line or run name carries, as text."""
    return label.split("-d")[1].split("-", maxsplit=1)[0]


def add_line(state: dict[str, Any], label: str, path: Path, names: dict[int, str]) -> None:
    """Measure one detector at the cut of its dataset and keep its rows for the tests."""
    rows = read_predictions(path)
    state["rows"][label] = rows
    order, f1, auc, average_precision = resampled(rows, state["cut"])
    state["boot"][label] = (order, f1, auc, average_precision)
    state["lines"][label] = measure(rows, state["cut"], names) | {
        "run": path.name,
        "f1_novel_ci": interval(f1),
        "roc_auc_ci": interval(auc),
        "pr_auc_ci": interval(average_precision),
    }


def tests_of(state: dict[str, Any]) -> dict[str, Any]:
    """McNemar and bootstrap of each full Fusion against RF, matched kNN, its Jev, Sonnet and its ablations, and of each Jev against RF."""
    rows, cut = state["rows"], state["cut"]
    tests: dict[str, Any] = {}
    pairs: list[tuple[str, str]] = []
    for label in state["lines"]:
        if label.startswith("fusion/full"):
            delay = delay_of(label)
            pairs += [(label, rival) for rival in (f"rf/d{delay}", f"knnmatched/d{delay}", label.replace("fusion/", "jev/"))]
        elif label.startswith("jev/full"):
            pairs.append((label, f"rf/d{delay_of(label)}"))
        seed = label.rsplit("-s", maxsplit=1)[-1]
        if "full-d200-s" in label and f"sonnet/d200-s{seed}" in state["lines"]:
            pairs.append((label, f"sonnet/d200-s{seed}"))
        # Pairing the full Fusion with each ablation of the same seed, so Section 8 rests on paired evidence
        if label.startswith("fusion/full-d200-s"):
            ablations = (label.replace("full", config) for config in ("fixedk1", "noctl", "nosel", "randomk4"))
            pairs += [(label, rival) for rival in ablations if rival in state["lines"]]
    for label, rival in pairs:
        (order, f1, auc, precision), (rival_order, rival_f1, rival_auc, rival_precision) = state["boot"][label], state["boot"][rival]
        # Refusing a pair whose Streams hold different Flows, because the shared replicates would then mix them.
        if order != rival_order:
            raise ValueError(f"{label} and {rival} judge different Flows")
        tests[f"{label} vs {rival}"] = mcnemar(rows[label], rows[rival], cut) | {
            "f1_diff_ci": interval(f1 - rival_f1),
            "auc_diff_ci": interval(auc - rival_auc),
            "pr_diff_ci": interval(precision - rival_precision),
        }
    return tests


def calibrated_cut(dataset: str, calibration: dict[str, Path]) -> dict[str, float]:
    """The D9 cut of the Jev-IDS run of the validation stream, whose percentiles come from that same stream."""
    out = ROOT / "results" / f"zeroday-{dataset}-fused" / "validation"
    runs = ([calibration["jev"]], calibration["knn"])
    fused = only_dir(out) if out.exists() else fuse(*runs, runs, out)
    return best_threshold(read_predictions(fused))


def bursts(rows: list[Prediction], names: dict[int, str]) -> dict[str, Any]:
    """The Stream positions of each attack name, with its category, whether it is novel and its Flows judged at first contact."""
    out: dict[str, Any] = {}
    for position, row in enumerate(sorted(rows, key=lambda row: row["step"])):
        if row["is_attack"]:
            name = names[row["row_id"]]
            burst = out.setdefault(
                name, {"category": row["category_true"], "novel": row["novel_attack"], "positions": [], "first_contact": 0}
            )
            burst["positions"].append(position)
            burst["first_contact"] += bool(row.get("first_contact"))
    return out


def dataset_numbers(dataset: str, split: str) -> dict[str, Any]:
    """Every line and test of one dataset."""
    with open(ROOT / "data" / dataset / "splits" / f"{split}.csv", encoding="utf-8") as handle:
        names = {int(row["row_id"]): row["raw_label"] for row in csv.DictReader(handle)}
    calibration = calibration_runs(dataset)
    rule = calibrated_cut(dataset, calibration)
    state: dict[str, Any] = {"rows": {}, "cut": rule["threshold"], "lines": {}, "boot": {}}
    for name in JEV_LINES[dataset]:
        run, knn = stamp(dataset, name), stamp(dataset, f"knnmatched-d{delay_of(name)}")
        out = ROOT / "results" / f"zeroday-{dataset}-fused" / name
        fused = only_dir(out) if out.exists() else fuse([run], knn, ([calibration["jev"]], calibration["knn"]), out)
        add_line(state, f"fusion/{name}", fused, names)
        add_line(state, f"jev/{name}", run, names)
    for delay in (200, 50, 1):
        for base in BASELINES:
            add_line(state, f"{base}/d{delay}", stamp(dataset, f"{base}-d{delay}"), names)
    # Pricing the Sonnet 5.5 runs at 2 USD per million input tokens and 10 per million output tokens.
    for seed in (0, 1, 2):
        label = f"sonnet/d200-s{seed}"
        add_line(state, label, stamp(dataset, f"sonnet-d200-s{seed}"), names)
        usages = [usage_of(row) for row in state["rows"][label]]
        state["lines"][label]["usd"] = sum(usage.get("input_tokens", 0) * 2e-6 + usage.get("output_tokens", 0) * 10e-6 for usage in usages)
    return {
        "cut": state["cut"],
        "cut_rule": rule,
        "lines": state["lines"],
        "tests": tests_of(state),
        "calibration": {"jev": calibration["jev"].name, "knn": calibration["knn"].name},
        "bursts": bursts(state["rows"]["rf/d200"], names),
    }


def main() -> None:
    """Fuse, measure and compare every run of the battery."""
    numbers = {dataset: dataset_numbers(dataset, split) for dataset, split in DATASETS.items()}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(numbers, handle, indent=1, default=str)
    print("written", OUT, file=sys.stderr)


if __name__ == "__main__":
    main()
