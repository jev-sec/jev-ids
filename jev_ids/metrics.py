"""Tables from predictions.jsonl rows: `summarize` one or more runs, `compare` or `sign_test` two, `best_threshold` on validation.

Helpers first (`verdict`, `at_threshold`, `mean`, `ratio`, `rate`, `only_subset`, `only_k`, `group_by_fields`),
then the scores of one set of rows (`recall_by_category`, `ranking`, `scores`), the priced usage (`cost_usd_per_1m`,
`share_used`, `latency`, `usage`), the summary (`summary`, `none_last_key`, `summarize`), the cut of D9 (`best_threshold`)
and the paired comparisons (`mcnemar_exact`, `holm`, `sign_test`, `compare_cell`, `compare`). F1 is the attack class's,
not macro. A row without a Verdict counts as `normal` (fail-open) and ranks lowest, and the CLI turns the dicts into CSV.
"""

import json
import statistics
from collections import defaultdict
from collections.abc import Iterable, Sequence
from math import comb
from typing import Any

import sklearn.metrics  # pyright: ignore[reportMissingTypeStubs]  scikit-learn ships no type stubs

from jev_ids import ROOT
from jev_ids.records import VERDICT_THRESHOLD, Prediction

PRICES_PATH = ROOT / "prices.json"
PredictionPair = tuple[Prediction, Prediction]


def verdict(prediction: Prediction) -> int:
    """The Verdict of a row; without one (a failed call) it counts as normal."""
    return int(prediction.get("classification_verdict") or 0)


def at_threshold(predictions: Iterable[Prediction], threshold: float) -> list[Prediction]:
    """The rows with every Verdict taken again at p_attack ≥ `threshold` (D9), while a failed call still has none.

    Nothing in a stream reads the Verdict. The `Selector` reads p_attack and the Category, and the `KController` reads the Category.
    A new cut therefore changes no Example, and the rows of a finished run can be cut again.

    Args:
        predictions: the rows of one or more runs.
        threshold: the cut on p_attack at or above which a row raises an alert.

    Returns:
        A copy of each row with its `classification_verdict` taken again, None where p_attack is missing.
    """
    return [
        {
            **prediction,
            "classification_verdict": None if prediction.get("p_attack") is None else int(prediction["p_attack"] >= threshold),
        }
        for prediction in predictions
    ]


def mean(values: Iterable[float | None]) -> float | None:
    """Mean of the values present; None when all are missing."""
    present = [value for value in values if value is not None]
    return statistics.fmean(present) if present else None


def ratio(numerator: float, denominator: float) -> float | None:
    """A share, or None when the denominator is zero."""
    return None if denominator == 0 else numerator / denominator


def rate(rows: Sequence[Prediction]) -> float | None:
    """Share of the rows that raised an alert: the recall, over attacks."""
    return ratio(sum(verdict(prediction) for prediction in rows), len(rows))


def only_subset(predictions: Sequence[Prediction], subset: str) -> list[Prediction]:
    """`all` the rows, only the `novel` attacks or only the `known` ones."""
    if subset == "all":
        return list(predictions)
    novel = subset == "novel"
    return [prediction for prediction in predictions if prediction["is_attack"] == 1 and prediction["novel_attack"] == novel]


def only_k(predictions: Iterable[Prediction], k: int | None) -> list[Prediction]:
    """The rows of one k; None is k = all (the Random Forest on the whole pool)."""
    return [prediction for prediction in predictions if prediction["k"] == k]


def group_by_fields(predictions: Iterable[Prediction], fields: Sequence[str]) -> dict[tuple[Any, ...], list[Prediction]]:
    """The rows sharing the given fields, keyed by their values."""
    groups: dict[tuple[Any, ...], list[Prediction]] = defaultdict(list)
    for prediction in predictions:
        groups[tuple(prediction.get(field) for field in fields)].append(prediction)
    return dict(groups)


def recall_by_category(attacks: Sequence[Prediction]) -> dict[str, float | None]:
    """Recall over each attack Category present, on all its rows, on its known ones and on its novel ones.

    One F1 hides that the Categories differ in kind: in NSL-KDD, dos and probe leave a statistical trace while r2l and u2r look like
    normal sessions, so the paper reports `recall_known_<category>` and `recall_novel_<category>` beside it (Table 3).

    Args:
        attacks: the attack rows to score.

    Returns:
        The three recalls of each Category, keyed `recall_<category>`, `recall_known_<category>` and `recall_novel_<category>`.
    """
    recalls: dict[str, float | None] = {}
    for (category,), members in sorted(group_by_fields(attacks, ("category_true",)).items()):
        recalls[f"recall_{category}"] = rate(members)
        recalls[f"recall_known_{category}"] = rate([prediction for prediction in members if not prediction["novel_attack"]])
        recalls[f"recall_novel_{category}"] = rate([prediction for prediction in members if prediction["novel_attack"]])
    return recalls


def ranking(rows: Sequence[Prediction]) -> dict[str, float | None]:
    """PR-AUC (average precision) and ROC-AUC of p_attack against the truth, free of the 0.5 cut.

    Both need an attack and a normal among the rows, else None. A row without p_attack (a failed call) ranks lowest, the fail-open of
    `verdict`. Average precision is scikit-learn's estimate of the area under the precision-recall curve.

    Args:
        rows: the rows to rank, each with its truth `is_attack` and its p_attack.

    Returns:
        `pr_auc` and `roc_auc`, both None when the rows lack an attack or a normal.
    """
    truth = [prediction["is_attack"] for prediction in rows]
    if set(truth) != {0, 1}:
        return {
            "pr_auc": None,
            "roc_auc": None,
        }
    p_attack = [prediction.get("p_attack") or 0.0 for prediction in rows]
    # Reaching the two scorers through `Any`, as the forests are reached, because scikit-learn ships no type stubs.
    areas: Any = sklearn.metrics
    return {
        "pr_auc": float(areas.average_precision_score(truth, p_attack)),
        "roc_auc": float(areas.roc_auc_score(truth, p_attack)),
    }


def scores(rows: Sequence[Prediction]) -> dict[str, float | None]:
    """Attack-class F1, precision, the recalls, the alert counts, the two areas and the error rate of the rows."""
    attacks = [prediction for prediction in rows if prediction["is_attack"] == 1]
    # Counting the alerts on attacks, which are the true positives.
    hits = sum(verdict(prediction) for prediction in attacks)
    alerts = sum(verdict(prediction) for prediction in rows)
    return {
        "f1": ratio(2 * hits, alerts + len(attacks)),
        "precision": ratio(hits, alerts),
        "recall": rate(attacks),
        "recall_novel": rate(only_subset(rows, "novel")),
        "recall_known": rate(only_subset(rows, "known")),
        # Scoring, for stream runs only, the novel attacks judged before any Flow of their attack name came back and those judged after.
        "recall_novel_first_contact": rate([prediction for prediction in rows if prediction.get("first_contact") is True]),
        "recall_novel_after_feedback": rate([prediction for prediction in rows if prediction.get("first_contact") is False]),
        **recall_by_category(attacks),
        "false_alarms": alerts - hits,
        "missed_attacks": len(attacks) - hits,
        **ranking(rows),
        # Counting the rows without a Verdict, which are the calls that failed.
        "error_rate": ratio(sum(prediction.get("classification_verdict") is None for prediction in rows), len(rows)),
    }


def cost_usd_per_1m(row: Prediction, prices: dict[str, Any]) -> float | None:
    """List cost in USD of 1M calls like this row: tokens × the per-1M-token prices.

    OpenAI and DeepSeek count reasoning inside `output_tokens`, while Gemini reports it apart in `reasoning_tokens`
    and bills it as output, so a price entry with `reasoning_outside_output` adds those tokens at the output rate.

    Args:
        row: one row, with its `model` and the `usage` its call reported.
        prices: the per-1M-token prices of each model, the `models` table of prices.json.

    Returns:
        The cost in USD, or None when the model has no price or the usage has no `input_tokens`.
    """
    tokens: dict[str, Any] = row.get("usage", {})
    price: dict[str, Any] | None = prices.get(row.get("model", ""))
    if price is None or "input_tokens" not in tokens:
        return None
    # Taking the cached tokens, which are part of the input and billed at their own rate.
    cached = tokens.get("cache_read_tokens", 0)
    reasoning = tokens.get("reasoning_tokens", 0) if price.get("reasoning_outside_output") else 0
    return (
        (tokens["input_tokens"] - cached) * price["input"]
        + cached * price["cached_input"]
        + (tokens.get("output_tokens", 0) + reasoning) * price["output"]
    )


def share_used(usages: Sequence[dict[str, Any]], name: str) -> float | None:
    """Share of the calls whose usage has a positive `name`; None when no call reports the field."""
    reported = [usage_of_call[name] for usage_of_call in usages if name in usage_of_call]
    return ratio(sum(tokens > 0 for tokens in reported), len(usages)) if reported else None


def latency(rows: Sequence[Prediction]) -> dict[str, float | None]:
    """Mean latency of every call, and the median and 95th percentile of the successful ones.

    The median and the 95th percentile cover only the calls that returned a Verdict, the successful requests the paper's Table 5 reports.
    A few stalled requests lasted minutes, so the paper reads these two and the mean only describes the whole run.

    Args:
        rows: the rows of one group.

    Returns:
        `latency_ms_mean`, `latency_ms_median` and `latency_ms_p95`, each None when too few calls report a latency.
    """
    # Keeping the latency of the successful calls. `statistics.quantiles` (exclusive method) needs two values for the 95th percentile.
    latencies = [
        prediction["latency_ms"]
        for prediction in rows
        if prediction.get("classification_verdict") is not None and prediction.get("latency_ms") is not None
    ]
    return {
        "latency_ms_mean": mean(prediction.get("latency_ms") for prediction in rows),
        "latency_ms_median": statistics.median(latencies) if latencies else None,
        "latency_ms_p95": statistics.quantiles(latencies, n=20)[-1] if len(latencies) > 1 else None,
    }


def usage(rows: Sequence[Prediction], prices: dict[str, Any]) -> dict[str, float | None]:
    """Mean of every number in the rows' usage, how often Gemini thinks and reads from cache, cost per 1M Flows and latency.

    Gemini thinks and reads from cache on only part of the calls, so the paper reports how often each happens
    and the reasoning per call that thinks. Detectors without these fields leave the three columns empty.

    Args:
        rows: the rows of one group.
        prices: the per-1M-token prices of each model, the `models` table of prices.json.

    Returns:
        The mean of every numeric usage field, the two shares, the reasoning per thinking call, the cost per 1M Flows and the latencies.
    """
    usages: list[dict[str, Any]] = [prediction.get("usage", {}) for prediction in rows]
    # Collecting every key that holds a number in at least one row. Detectors report different token fields, so the columns follow the rows.
    counted = sorted({name for usage_of_call in usages for name, value in usage_of_call.items() if isinstance(value, int | float)})
    return {
        **{f"{name}_mean": mean(usage_of_call.get(name) for usage_of_call in usages) for name in counted},
        "reasoning_share": share_used(usages, "reasoning_tokens"),
        "reasoning_tokens_when_used_mean": mean(
            usage_of_call["reasoning_tokens"] for usage_of_call in usages if usage_of_call.get("reasoning_tokens", 0) > 0
        ),
        "cache_read_share": share_used(usages, "cache_read_tokens"),
        "cost_usd_per_1m": mean(cost_usd_per_1m(prediction, prices) for prediction in rows),
        **latency(rows),
    }


def summary(members: Sequence[Prediction], prices: dict[str, Any]) -> dict[str, Any]:
    """Counts, every score averaged over the (seed, rep) cells, sd of F1 and usage."""
    cells = [scores(cell) for cell in group_by_fields(members, ("seed", "repetition")).values()]
    # Keeping the F1 of every cell for the mean ± sd the paper reports. A cell whose F1
    # is undefined stays out of the spread, and a single cell gives no spread at all.
    f1_values = [cell["f1"] for cell in cells if cell["f1"] is not None]
    return {
        "cells": len(cells),
        "flows": len({prediction["row_id"] for prediction in members}),
        "predictions": len(members),
        **{f"{name}_mean": mean(cell[name] for cell in cells) for name in cells[0]},
        "f1_sd": statistics.stdev(f1_values) if len(f1_values) > 1 else None,
        **usage(members, prices),
    }


def none_last_key(values: Sequence[Any]) -> tuple[Any, ...]:
    """Sort key that puts None (k = all, or a row without dataset) last."""
    return tuple((value is None, 0 if value is None else value) for value in values)


def summarize(predictions: Iterable[Prediction]) -> list[dict[str, Any]]:
    """One row per (dataset, detector, model, split, delay, record, selection, control, beta, k), k = all last.

    delay is None outside a stream, and beta is None outside the `KController`.

    Args:
        predictions: the rows of one or more runs.

    Returns:
        The grouping fields of each row followed by its `summary`.
    """
    prices: dict[str, Any] = json.loads(PRICES_PATH.read_text("utf-8"))["models"]
    fields = ("dataset", "detector", "model", "split", "delay", "record", "selection", "control", "beta", "k")
    groups = group_by_fields(predictions, fields)
    return [
        {
            **dict(zip(fields, key, strict=True)),
            **summary(groups[key], prices),
        }
        for key in sorted(groups, key=none_last_key)
    ]


def best_threshold(predictions: Sequence[Prediction]) -> dict[str, float]:
    """The cut on p_attack with the highest F1 averaged over the (seed, rep) cells, chosen on the validation stream (D9).

    The candidates are VERDICT_THRESHOLD (0.5) and every p_attack present, because F1 only changes
    where the cut passes a row. A tie goes to the candidate nearest 0.5, so the cut moves only as far
    as F1 asks. Rows of any split but `validation` are refused, so a test split never shapes the cut.

    Args:
        predictions: the rows of the validation stream.

    Returns:
        The chosen `threshold`, the `f1_mean` at it and the `f1_mean_at_0.5` at `VERDICT_THRESHOLD`.
    """
    if any(prediction["split"] != "validation" for prediction in predictions):
        raise ValueError("the cut is chosen on the validation stream only (docs/jevids-design.md, D9)")
    candidates = {VERDICT_THRESHOLD} | {prediction["p_attack"] for prediction in predictions if prediction.get("p_attack") is not None}
    # Scoring each candidate as the summary does, with the F1 of every cell at that cut and then their mean.
    f1_means: dict[float, float] = {}
    for threshold in candidates:
        cells = group_by_fields(at_threshold(predictions, threshold), ("seed", "repetition")).values()
        f1_means[threshold] = mean(scores(cell)["f1"] for cell in cells) or 0.0
    best = max(candidates, key=lambda threshold: (f1_means[threshold], -abs(threshold - VERDICT_THRESHOLD)))
    return {
        "threshold": best,
        "f1_mean": f1_means[best],
        "f1_mean_at_0.5": f1_means[VERDICT_THRESHOLD],
    }


def mcnemar_exact(a_correct: int, b_correct: int) -> float:
    """Exact two-sided binomial test that the discordant pairs split evenly."""
    # Counting the discordant pairs, which gives p = 1 when there is none.
    total = a_correct + b_correct
    tail = sum(comb(total, i) for i in range(min(a_correct, b_correct) + 1)) / 2**total
    return min(1.0, 2 * tail)


def holm(p_values: Sequence[float]) -> list[float]:
    """Holm's step-down adjustment of a family of p-values, returned in the input order.

    The i-th smallest p of m is multiplied by `m - i + 1` and capped at 1, and the running maximum keeps the adjusted values monotone.

    Args:
        p_values: the family of p-values, in any order.

    Returns:
        The adjusted p-values, each at the position of its raw one.
    """
    adjusted = [0.0] * len(p_values)
    running_maximum = 0.0
    for rank, index in enumerate(sorted(range(len(p_values)), key=lambda index: p_values[index])):
        running_maximum = max(running_maximum, min(1.0, (len(p_values) - rank) * p_values[index]))
        adjusted[index] = running_maximum
    return adjusted


def sign_test(run_a: Sequence[Prediction], run_b: Sequence[Prediction]) -> list[dict[str, Any]]:
    """Flow-level exact sign test of run A against run B, one table row per k both runs share.

    The seeds of a Flow are not independent observations, so the Flow is the unit. For each Flow judged by both
    runs at that k, the seeds in which A is right are counted against the seeds in which B is right. A Flow with
    more seeds right in A favors A, the reverse favors B, and a tie is left out. The exact two-sided binomial
    test on the two counts is the same test `mcnemar_exact` runs on discordant pairs, here applied to Flows.

    Args:
        run_a: the rows of run A.
        run_b: the rows of run B.

    Returns:
        One dict per shared k, k = all last, with the Flows both runs judged, `a_better`, `b_better` and the exact `sign_p`.
    """
    table: list[dict[str, Any]] = []
    for k in sorted(
        {prediction["k"] for prediction in run_a} & {prediction["k"] for prediction in run_b}, key=lambda k: none_last_key([k])
    ):
        # Counting, for each Flow, the seeds in which each run gave the right Verdict.
        right_a: dict[int, int] = defaultdict(int)
        right_b: dict[int, int] = defaultdict(int)
        for prediction in only_k(run_a, k):
            right_a[prediction["row_id"]] += verdict(prediction) == prediction["is_attack"]
        for prediction in only_k(run_b, k):
            right_b[prediction["row_id"]] += verdict(prediction) == prediction["is_attack"]
        flows = right_a.keys() & right_b.keys()
        a_better = sum(right_a[flow] > right_b[flow] for flow in flows)
        b_better = sum(right_a[flow] < right_b[flow] for flow in flows)
        table.append(
            {
                "k": k,
                "flows": len(flows),
                "a_better": a_better,
                "b_better": b_better,
                "sign_p": mcnemar_exact(a_better, b_better),
            }
        )
    return table


def compare_cell(pairs: Sequence[PredictionPair]) -> dict[str, Any]:
    """Counts over the pairs; only the discordant ones tell A from B."""
    discordant = [(row_a, row_b) for row_a, row_b in pairs if verdict(row_a) != verdict(row_b)]
    a_correct = sum(verdict(row_a) == row_a["is_attack"] for row_a, _ in discordant)
    b_correct = len(discordant) - a_correct
    return {
        "pairs": len(pairs),
        "discordant": len(discordant),
        "a_correct": a_correct,
        "b_correct": b_correct,
        "mcnemar_p": mcnemar_exact(a_correct, b_correct),
        "f1_a": scores([row_a for row_a, _ in pairs])["f1"],
        "f1_b": scores([row_b for _, row_b in pairs])["f1"],
    }


def compare(
    run_a: Sequence[Prediction], run_b: Sequence[Prediction], across_k: tuple[int | None, int | None] | None = None
) -> list[dict[str, Any]]:
    """One table row per (k of A, k of B, seed, rep) over the pairs of run A and run B, the per-seed McNemar test of the paper.

    A pair is a row of A and a row of B that judged the same Flow in the same cell, with the same k, seed and repetition.

    Args:
        run_a: the rows of run A.
        run_b: the rows of run B.
        across_k: `(k_a, k_b)` cuts the runs to those k first and lets the pairs cross k, which is how zero-shot Jev meets
            the Random Forest at k = all (None). None, the default, pairs rows within the same k only.

    Returns:
        One dict per table row, with its k of A, k of B, seed and repetition and the counts of `compare_cell`.
    """
    # Choosing what a row of A and a row of B share to form a pair, the Flow (`row_id`) and the cell (k, seed, repetition).
    # Across k, each run is first reduced to one k (A to k_a, B to k_b) and k leaves the list, so the same Flow at two different k pairs up.
    if across_k is None:
        pair_fields = ("row_id", "k", "seed", "repetition")
    else:
        run_a, run_b = only_k(run_a, across_k[0]), only_k(run_b, across_k[1])
        pair_fields = ("row_id", "seed", "repetition")

    # Indexing each run by those fields, with one key per Flow judged in a cell holding the single row the run wrote for it. The comparison
    # table has one row per (k of A, k of B, seed, repetition), and `pairs_by_table_row` collects the pairs that fall into each of them.
    rows_a_by_cell, rows_b_by_cell = group_by_fields(run_a, pair_fields), group_by_fields(run_b, pair_fields)
    pairs_by_table_row: dict[tuple[Any, ...], list[PredictionPair]] = defaultdict(list)

    # Pairing up the runs. A cell judged by both gives one pair (A's row, B's row), filed under its table row,
    # and a cell only one run judged is dropped, because a paired test needs both Verdicts on the same Flow.
    for cell in rows_a_by_cell:
        if cell in rows_b_by_cell:
            row_a, row_b = rows_a_by_cell[cell][0], rows_b_by_cell[cell][0]
            pairs_by_table_row[(row_a["k"], row_b["k"], row_a["seed"], row_a["repetition"])].append((row_a, row_b))

    # Returning one dict per table row with the counts of `compare_cell`,
    # ascending in (k of A, k of B, seed, repetition) with k = all (None) last.
    return [
        {
            "k_a": k_a,
            "k_b": k_b,
            "seed": seed,
            "repetition": repetition,
            **compare_cell(pairs_by_table_row[(k_a, k_b, seed, repetition)]),
        }
        for k_a, k_b, seed, repetition in sorted(pairs_by_table_row, key=none_last_key)
    ]
