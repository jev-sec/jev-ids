"""Summary metrics and paired comparisons over synthetic rows."""

import statistics
from collections.abc import Sequence
from typing import Any

import pytest

from jev_ids import metrics
from jev_ids.records import Prediction
from tests.helpers import make_prediction

# The `models` entries of prices.json used below.
DEEPSEEK = {"input": 0.30, "cached_input": 0.006, "output": 1.20}
JEV = {"input": 0.042, "cached_input": 0.042, "output": 0.0}
GEMINI = {"input": 0.75, "cached_input": 0.075, "output": 3.75, "reasoning_outside_output": True}
PRICES = {"deepseek-flash": DEEPSEEK, "jev-1.13.0": JEV, "gemini-3.6-flash": GEMINI}


def make(  # noqa: PLR0913
    row_id: int,
    is_attack: int,
    p_attack: float | None,
    *,
    k: int | None = 1,
    seed: int = 0,
    repetition: int = 0,
    novel: bool = False,
    error: str | None = None,
    detector: str = "jev",
    split: str = "internal",
) -> Prediction:
    return make_prediction(
        row_id,
        is_attack,
        p_attack,
        detector=detector,
        split=split,
        k=k,
        n_examples=0 if k is None else 3 * k,
        seed=seed,
        repetition=repetition,
        novel_attack=novel,
        error=error,
        usage={} if error else {"input_tokens": 100, "output_tokens": 10},
        request_id=f"q{row_id}-{seed}-{repetition}",
    )


# tp = rows 1 and 6, fp = row 5, fn = rows 2 and 3 (the error row counts as normal), tn = row 4; rows 1 and 2 are the novel attacks, 3 and 6
# the known.
CELL = [
    make(1, 1, 0.9, novel=True),
    make(2, 1, 0.2, novel=True),
    make(3, 1, None, error="HTTP 429"),
    make(4, 0, 0.1),
    make(5, 0, 0.7),
    make(6, 1, 0.8),
]


def test_scores_count_a_row_without_verdict_as_normal_and_as_an_error() -> None:
    scores = metrics.scores(CELL)
    assert scores["precision"] == pytest.approx(2 / 3)
    assert scores["recall"] == pytest.approx(2 / 4)
    assert scores["f1"] == pytest.approx(4 / 7)
    assert scores["recall_novel"] == 0.5
    assert scores["recall_known"] == 0.5
    assert scores["error_rate"] == pytest.approx(1 / 6)
    empty = metrics.scores([make(4, 0, 0.1)])
    assert (empty["f1"], empty["recall_novel"], empty["error_rate"]) == (None, None, 0)
    assert (empty["pr_auc"], empty["roc_auc"]) == (None, None)


def test_at_threshold_takes_every_verdict_again_and_keeps_failed_calls_without_one() -> None:
    assert [row["classification_verdict"] for row in metrics.at_threshold(CELL, 0.15)] == [1, 1, None, 0, 1, 1]
    # Leaving the rows given untouched, so line 3 and line 4 are read from the same run.
    assert [row["classification_verdict"] for row in CELL] == [1, 0, None, 0, 1, 1]


def test_best_threshold_takes_the_best_mean_f1_and_reads_the_validation_stream_only() -> None:
    # Giving each seed two attacks and two normal Flows. At 0.3 both cells have F1 0.8, the best mean of every candidate.
    rows = [
        make(row_id, is_attack, p_attack, seed=seed, split="validation")
        for row_id, is_attack, p_attack, seed in [
            (1, 1, 0.9, 0),
            (2, 1, 0.3, 0),
            (3, 0, 0.2, 0),
            (4, 0, 0.6, 0),
            (1, 1, 0.8, 1),
            (2, 1, 0.4, 1),
            (3, 0, 0.1, 1),
            (4, 0, 0.35, 1),
        ]
    ]
    best = metrics.best_threshold(rows)
    assert best["threshold"] == 0.3
    assert best["f1_mean"] == pytest.approx(0.8)
    assert best["f1_mean_at_0.5"] == pytest.approx((1 / 2 + 2 / 3) / 2)
    # Keeping 0.5 when another cut only ties it, as 0.9 does here with F1 1.
    tie = [make(1, 1, 0.9, split="validation"), make(2, 0, 0.2, split="validation")]
    assert metrics.best_threshold(tie)["threshold"] == 0.5
    with pytest.raises(ValueError, match="validation stream only"):
        metrics.best_threshold([make(1, 1, 0.9, split="pilot")])


def test_scores_break_recall_down_by_category_and_rank_p_attack_without_the_cut() -> None:
    rows = [
        make(1, 1, 0.9, novel=True),  # dos, novel, hit
        make(2, 1, 0.4),  # dos, known, miss
        make(3, 1, 0.7),  # probe, known, hit
        make(4, 0, 0.1),
        make(5, 0, 0.6),  # false alarm
    ]
    rows[2]["category_true"] = "probe"
    scores = metrics.scores(rows)
    assert (scores["recall_dos"], scores["recall_known_dos"], scores["recall_novel_dos"]) == (0.5, 0.0, 1.0)
    assert (scores["recall_probe"], scores["recall_known_probe"], scores["recall_novel_probe"]) == (1.0, 1.0, None)
    assert (scores["false_alarms"], scores["missed_attacks"]) == (1, 1)
    # Ranked by p_attack: 0.9 (attack), 0.7 (attack), 0.6 (normal), 0.4 (attack), 0.1 (normal). Average precision is the mean of the
    # precision at each attack, 1, 1 and 3/4; ROC-AUC is the share of (attack, normal) pairs ranked right, 5 of 6.
    assert scores["pr_auc"] == pytest.approx((1 + 1 + 3 / 4) / 3)
    assert scores["roc_auc"] == pytest.approx(5 / 6)
    # A failed call ranks lowest: it becomes the worst-ranked attack, and both areas drop.
    rows[0]["p_attack"] = None
    assert metrics.scores(rows)["roc_auc"] == pytest.approx(3 / 6)
    # The keys of one cell come in a fixed order, categories sorted, so the summary columns are stable.
    assert list(scores)[:7] == [
        "f1",
        "precision",
        "recall",
        "recall_novel",
        "recall_known",
        "recall_novel_first_contact",
        "recall_novel_after_feedback",
    ]
    # Rows that are not from a stream carry no `first_contact`.
    assert (scores["recall_novel_first_contact"], scores["recall_novel_after_feedback"]) == (None, None)
    rows[0]["first_contact"], rows[0]["p_attack"] = True, 0.9
    assert metrics.scores(rows)["recall_novel_first_contact"] == 1.0
    assert list(scores)[7:] == [
        "recall_dos",
        "recall_known_dos",
        "recall_novel_dos",
        "recall_probe",
        "recall_known_probe",
        "recall_novel_probe",
        "false_alarms",
        "missed_attacks",
        "pr_auc",
        "roc_auc",
        "error_rate",
    ]


def test_cost_usd_per_1m_prices_the_usage_at_list_price() -> None:
    # 1,001 input tokens of Jev: 42.042 USD per 1M such calls, the gateway's own `marketCost` of the pilot row (4.2042e-05 USD) times
    # 10⁶.
    jev_row = make_prediction(1, 1, 0.9, model="jev-1.13.0")
    jev_row["usage"] = {"input_tokens": 1001, "output_tokens": 77}
    assert metrics.cost_usd_per_1m(jev_row, PRICES) == pytest.approx(42.042)
    # Cached input tokens are a subset of the input and pay the cache rate.
    cached = make_prediction(2, 1, 0.9, model="deepseek-flash")
    cached["usage"] = {"input_tokens": 1000, "cache_read_tokens": 800, "output_tokens": 20}
    expected = 200 * 0.30 + 800 * 0.006 + 20 * 1.20
    assert metrics.cost_usd_per_1m(cached, PRICES) == pytest.approx(expected)
    # Gemini reports reasoning apart from output_tokens and bills it as output; the other providers already count it inside.
    thinking = make_prediction(4, 1, 0.9, model="gemini-3.6-flash")
    thinking["usage"] = {"input_tokens": 800, "output_tokens": 18, "reasoning_tokens": 109}
    assert metrics.cost_usd_per_1m(thinking, PRICES) == pytest.approx(800 * 0.75 + (18 + 109) * 3.75)
    cached["usage"]["reasoning_tokens"] = 500  # DeepSeek: already inside output_tokens, so nothing changes
    assert metrics.cost_usd_per_1m(cached, PRICES) == pytest.approx(expected)
    # No usage (the Random Forest, or an error row) or no list price: no cost.
    assert metrics.cost_usd_per_1m({"model": "deepseek-flash"}, PRICES) is None
    unpriced = make_prediction(3, 1, 0.9, model="m")
    assert metrics.cost_usd_per_1m(unpriced, PRICES) is None


def test_usage_averages_every_number_present_and_ignores_the_rest() -> None:
    rows = [make(1, 1, 0.9), make(2, 1, None, error="boom")]
    for row in rows:
        row["model"] = "deepseek-flash"
    # An Agno row carries more than tokens; its nested details are not numbers.
    rows[0]["usage"] |= {"duration": 2.5, "details": {"model": []}}
    summary = metrics.usage(rows, PRICES)
    assert summary["input_tokens_mean"] == 100.0
    assert summary["output_tokens_mean"] == 10.0
    assert summary["duration_mean"] == 2.5
    assert "details_mean" not in summary
    assert summary["cost_usd_per_1m"] == pytest.approx(100 * 0.30 + 10 * 1.20)
    assert summary["latency_ms_mean"] == 500.0
    # A row without any usage or latency (the Random Forest) gives only missing values.
    assert set(metrics.usage([{"is_attack": 1}], PRICES).values()) == {None}
    assert metrics.mean([]) is None


def test_summarize_keeps_full_and_compact_records_apart() -> None:
    # Line 0 and line 1 share every other field, prompt hash included, so only `record` tells them apart.
    rows = [make_prediction(1, 1, 0.9, record="full"), make_prediction(1, 1, 0.9, record="compact")]
    assert [row["record"] for row in metrics.summarize(rows)] == ["compact", "full"]


def test_summarize_has_one_row_per_group_averaged_over_cells() -> None:
    predictions = [
        make(1, 1, 0.9, seed=0),
        make(2, 0, 0.1, seed=0),
        make(1, 1, 0.4, seed=1),
        make(2, 0, 0.1, seed=1),
        make(1, 1, None, k=0, error="boom"),
    ]
    for prediction in predictions:
        prediction["model"] = "jev-1.13.0"
    zero_shot, one_shot = metrics.summarize(predictions)
    assert (zero_shot["k"], one_shot["k"]) == (0, 1)
    assert list(one_shot)[:10] == ["dataset", "detector", "model", "split", "delay", "record", "selection", "control", "beta", "k"]
    assert one_shot["dataset"] == "test"
    assert (one_shot["cells"], one_shot["flows"], one_shot["predictions"]) == (2, 2, 4)
    # The seed 0 cell has F1 = 1 and the seed 1 cell F1 = 0.
    assert one_shot["f1_mean"] == pytest.approx(0.5)
    assert one_shot["f1_sd"] == pytest.approx(statistics.stdev([1.0, 0.0]))
    # A single cell has no spread at all.
    assert zero_shot["f1_sd"] is None
    assert one_shot["recall_known_mean"] == 0.5
    assert one_shot["recall_novel_mean"] is None
    assert one_shot["cost_usd_per_1m"] == pytest.approx(100 * 0.042)
    assert zero_shot["error_rate_mean"] == 1.0
    assert zero_shot["cost_usd_per_1m"] is None
    assert zero_shot["f1_sd"] is None


def test_summarize_orders_k_all_last_and_groups_old_rows_without_dataset() -> None:
    old = make(1, 1, 0.9, k=None)
    del old["dataset"]
    rows = metrics.summarize([old, make(1, 1, 0.9, k=16)])
    assert [(row["dataset"], row["k"]) for row in rows] == [("test", 16), (None, None)]
    assert metrics.summarize([]) == []


def test_select_keeps_novel_or_known_attacks() -> None:
    rows = [make(0, 1, 1.0, novel=True), make(1, 1, 0.0), make(2, 0, 0.0)]
    assert [p["row_id"] for p in metrics.only_subset(rows, "all")] == [0, 1, 2]
    assert [p["row_id"] for p in metrics.only_subset(rows, "novel")] == [0]
    assert [p["row_id"] for p in metrics.only_subset(rows, "known")] == [1]


def runs() -> tuple[list[Prediction], list[Prediction]]:
    """Flows 0..5 are attacks, 6..9 normals. A is right where B is wrong on 0, 1, 2 and 6; B is right where A is wrong on 3; both are wrong
    on 5 and 7.
    """
    a_pred = {0: 1, 1: 1, 2: 1, 3: 0, 4: 1, 5: 0, 6: 0, 7: 1, 8: 0, 9: 0}
    b_pred = {0: 0, 1: 0, 2: 0, 3: 1, 4: 1, 5: 0, 6: 1, 7: 1, 8: 0, 9: 0}
    a = [make(i, int(i < 6), float(a_pred[i]), k=0, detector="a") for i in range(10)]
    b = [make(i, int(i < 6), float(b_pred[i]), k=0, detector="b") for i in range(10)]
    return a, b


def cells_of(rows: Sequence[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """(k_a, k_b, repetition, pairs) of each compare row."""
    return [(r["k_a"], r["k_b"], r["repetition"], r["pairs"]) for r in rows]


def test_compare_pairs_by_flow_k_seed_and_rep_and_drops_unmatched() -> None:
    a, b = runs()
    assert cells_of(metrics.compare([*a, make(99, 1, 1.0, k=8)], b)) == [(0, 0, 0, 10)]


def test_compare_with_ks_pairs_across_k_and_keeps_reps_apart() -> None:
    a, b = runs()
    a_rep1 = [make(p["row_id"], p["is_attack"], p["p_attack"], k=0, repetition=1) for p in a]
    b_all = [make(p["row_id"], p["is_attack"], p["p_attack"], k=None) for p in b]
    b_all += [make(p["row_id"], p["is_attack"], p["p_attack"], k=None, repetition=1) for p in b]
    assert metrics.compare(a_rep1, b_all) == []  # without ks the k must match
    rows = metrics.compare([*a, *a_rep1], b_all, across_k=(0, None))
    assert cells_of(rows) == [(0, None, 0, 10), (0, None, 1, 10)]


def test_mcnemar_exact_is_two_sided_and_one_without_discordance() -> None:
    assert metrics.mcnemar_exact(0, 0) == 1.0
    assert metrics.mcnemar_exact(5, 5) == 1.0
    assert metrics.mcnemar_exact(5, 1) == 0.21875
    assert metrics.mcnemar_exact(4, 1) == pytest.approx(2 * 6 / 32)
    assert metrics.mcnemar_exact(10, 0) == pytest.approx(2 / 1024)


def test_compare_orders_k_and_fills_every_field() -> None:
    a, b = runs()
    a_k8 = [make(i, 1, 1.0, k=8, detector="a") for i in range(2)]
    b_k8 = [make(i, 1, 0.0, k=8, detector="b") for i in range(2)]
    results = metrics.compare([*a_k8, *a], [*b_k8, *b])
    assert [(r["k_a"], r["k_b"], r["repetition"]) for r in results] == [(0, 0, 0), (8, 8, 0)]
    first = results[0]
    assert list(first) == ["k_a", "k_b", "seed", "repetition", "pairs", "discordant", "a_correct", "b_correct", "mcnemar_p", "f1_a", "f1_b"]
    assert (first["pairs"], first["discordant"]) == (10, 5)
    assert (first["a_correct"], first["b_correct"]) == (4, 1)
    assert first["mcnemar_p"] == pytest.approx(2 * 6 / 32)
    assert first["f1_a"] == pytest.approx(8 / 11)
    assert first["f1_b"] == pytest.approx(4 / 10)


def test_compare_pairs_old_rows_with_new_ones_and_unrelated_runs_give_nothing() -> None:
    a, b = runs()
    # Rows written before the `dataset` field existed still pair with new rows.
    old = [dict(p) for p in a]
    for p in old:
        del p["dataset"]
    assert len(metrics.compare(old, b)) == 1
    # Another split shares no row_id: nothing to pair, as with an empty run.
    assert metrics.compare(a, [make(99, 1, 1.0, split="hard")]) == []
    assert metrics.compare(a, []) == []


def test_usage_reads_median_and_p95_latency_of_successful_calls_only() -> None:
    rows = [make(i, 1, 0.9) for i in range(1, 21)]
    for index, row in enumerate(rows, start=1):
        row["latency_ms"] = float(index)
    failed = make(99, 1, None, error="HTTP 504")
    failed["latency_ms"] = 10_000.0
    summary = metrics.usage([*rows, failed], PRICES)
    assert summary["latency_ms_median"] == 10.5
    assert summary["latency_ms_p95"] == pytest.approx(statistics.quantiles(range(1, 21), n=20)[-1])
    # A single successful call has a median but no 95th percentile.
    assert metrics.usage(rows[:1], PRICES)["latency_ms_p95"] is None


def test_holm_multiplies_by_rank_keeps_order_and_caps_at_one() -> None:
    assert metrics.holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert metrics.holm([0.5, 0.9]) == [1.0, 1.0]
    assert metrics.holm([]) == []


def test_sign_test_counts_flows_by_seeds_right_and_drops_ties() -> None:
    # Flow 1: A right in both seeds, B in one. Flow 2: both right in both seeds (a tie). Flow 3: B right in both, A in none.
    run_a = [make(1, 1, 1.0, seed=0), make(1, 1, 1.0, seed=1), make(2, 0, 0.0, seed=0), make(2, 0, 0.0, seed=1)]
    run_a += [make(3, 1, 0.0, seed=0), make(3, 1, 0.0, seed=1)]
    run_b = [make(1, 1, 1.0, seed=0), make(1, 1, 0.0, seed=1), make(2, 0, 0.0, seed=0), make(2, 0, 0.0, seed=1)]
    run_b += [make(3, 1, 1.0, seed=0), make(3, 1, 1.0, seed=1), make(4, 1, 1.0, k=8)]
    assert metrics.sign_test(run_a, run_b) == [{"k": 1, "flows": 3, "a_better": 1, "b_better": 1, "sign_p": 1.0}]


def test_usage_reports_how_often_gemini_thinks_and_reads_from_cache() -> None:
    rows = [make(i, 1, 0.9) for i in range(4)]
    rows[0]["usage"] |= {"reasoning_tokens": 200, "cache_read_tokens": 50}
    rows[1]["usage"] |= {"reasoning_tokens": 100}
    rows[2]["usage"] |= {"reasoning_tokens": 0}
    summary = metrics.usage(rows, PRICES)
    assert summary["reasoning_share"] == 0.5
    assert summary["reasoning_tokens_when_used_mean"] == 150.0
    assert summary["cache_read_share"] == 0.25
    # A Detector that never reports these fields leaves them empty.
    assert metrics.usage(rows[3:], PRICES)["reasoning_share"] is None
