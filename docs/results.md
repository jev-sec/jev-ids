# Results

Paper split of NSL-KDD (2,000 flows, 300 of them zero-day attacks), 3 seeds, k in {0, 1, 2, 4, 8}; runs of 2026-09-22 in `results/paper/`.
Jev is `jev-1.13.0` through the TypeSafe SDK; Gemini is `gemini-3.6-flash` on Vertex AI through Agno. Prices are the list prices in
`prices.json` on that date.

## Terms

- **k**: labeled example flows per category placed in the prompt before the flow to judge. k = 0 is no example; k = 8 is 8 normal, 8 dos,
  8 probe, 8 r2l and 8 u2r flows, each with its label.
- **Zero-day attack**: a flow whose attack type is absent from the example pool (`novel_attack` in the split), so no k can show an example
  of it. **Known attack**: an attack type present in the pool.
- **Flow favoring a detector**: a flow that detector judged right in more of the three seeds than the other. The seeds of a flow are
  not independent, so the flow is the unit of the paired test, and a flow both detectors judged right equally often is a tie.
- **p**: exact two-sided sign test on the flows favoring each detector, the probability of a split at least this uneven if both
  detectors were equally good. The 15 Jev-Gemini tests (three cuts, five k) are Holm-adjusted together. Below 0.05 the difference is
  not chance.

## Reading

Gemini 3.6 Flash is the best detector on F1 over all flows at every k (sign test, adjusted p < 0.001), and on known-type attacks. Jev is
second, with the same precision (0.94 to 0.97 against 0.94 to 0.95), 4.3 to 6.7 times lower median latency and 10 to 25 times lower
cost. On zero-day attacks Jev has the highest mean recall from k = 1 to k = 8 among those that keep precision above 0.8, a difference
the paired test confirms only at k = 1 and 2. The Random Forest catches more zero-day attacks only by alerting on 32 to 87% of the
normal flows. The Isolation Forest is the conservative reference: precision 0.97, recall 0.62.

## One metric, three attack sets

Every panel below uses the same metric: the attack-class score over a flow set that always holds the 874 normal flows of each seed plus
one group of attacks: all 1,126, the 826 of types present in the example pool ("known"), or the 300 of types absent from it
("zero-day"). A false alarm on normal traffic therefore lowers F1 and precision in every panel; the panels differ only in which attacks
count. An F1 over zero-day attacks alone, without the normal flows, would have no false alarms in it and would rank detectors as recall
does, which is why it is not used here.

![F1 by k for the three attack sets](results-f1-three-sets.svg)

![Recall and precision by k for the three attack sets](results-recall-precision.svg)

| Detector         | k   | F1 all | F1 known | F1 zero-day | Precision all | Precision zero-day | Recall all | Recall known | Recall zero-day |
| ---------------- | --- | ------ | -------- | ----------- | ------------- | ------------------ | ---------- | ------------ | --------------- |
| Jev              | 0   | 0.782  | 0.787    | 0.735       | 0.972         | 0.897              | 0.654      | 0.665        | 0.622           |
| Jev              | 1   | 0.856  | 0.857    | 0.789       | 0.953         | 0.838              | 0.778      | 0.790        | 0.747           |
| Jev              | 2   | 0.846  | 0.845    | 0.780       | 0.949         | 0.829              | 0.763      | 0.772        | 0.738           |
| Jev              | 4   | 0.856  | 0.860    | 0.767       | 0.944         | 0.807              | 0.784      | 0.803        | 0.731           |
| Jev              | 8   | 0.854  | 0.860    | 0.756       | 0.942         | 0.804              | 0.783      | 0.805        | 0.721           |
| Gemini 3.6 Flash | 0   | 0.867  | 0.884    | 0.739       | 0.946         | 0.801              | 0.801      | 0.842        | 0.687           |
| Gemini 3.6 Flash | 1   | 0.880  | 0.895    | 0.748       | 0.942         | 0.790              | 0.826      | 0.866        | 0.713           |
| Gemini 3.6 Flash | 2   | 0.869  | 0.887    | 0.732       | 0.943         | 0.788              | 0.806      | 0.849        | 0.684           |
| Gemini 3.6 Flash | 4   | 0.884  | 0.900    | 0.751       | 0.942         | 0.789              | 0.833      | 0.875        | 0.717           |
| Gemini 3.6 Flash | 8   | 0.881  | 0.900    | 0.752       | 0.949         | 0.809              | 0.823      | 0.867        | 0.702           |
| Random Forest    | 1   | 0.748  | 0.685    | 0.443       | 0.598         | 0.286              | 1.000      | 1.000        | 1.000           |
| Random Forest    | 2   | 0.777  | 0.721    | 0.492       | 0.644         | 0.331              | 0.987      | 0.988        | 0.983           |
| Random Forest    | 4   | 0.853  | 0.823    | 0.614       | 0.771         | 0.463              | 0.955      | 0.969        | 0.914           |
| Random Forest    | 8   | 0.865  | 0.838    | 0.642       | 0.794         | 0.496              | 0.950      | 0.964        | 0.912           |
| Random Forest    | all | 0.765  | 0.854    | 0.395       | 0.971         | 0.790              | 0.631      | 0.764        | 0.263           |
| Isolation Forest | all | 0.761  | 0.772    | 0.701       | 0.974         | 0.901              | 0.624      | 0.643        | 0.573           |

## Paired comparison, flow by flow

`jev-ids sign-test` writes this table to `results/paper/sign-test-jev-gemini.csv`. "Known" and "zero-day" hold attack flows only.

| Cut       | k   | Flows | Jev better | Gemini better | Adjusted p |
| --------- | --- | ----- | ---------- | ------------- | ---------- |
| All flows | 0   | 2,000 | 114        | 247           | < 0.001    |
| All flows | 1   | 2,000 | 111        | 208           | < 0.001    |
| All flows | 2   | 2,000 | 131        | 225           | < 0.001    |
| All flows | 4   | 2,000 | 114        | 226           | < 0.001    |
| All flows | 8   | 2,000 | 116        | 218           | < 0.001    |
| Known     | 0   | 826   | 16         | 171           | < 0.001    |
| Known     | 1   | 826   | 17         | 157           | < 0.001    |
| Known     | 2   | 826   | 11         | 158           | < 0.001    |
| Known     | 4   | 826   | 18         | 136           | < 0.001    |
| Known     | 8   | 826   | 15         | 126           | < 0.001    |
| Zero-day  | 0   | 300   | 43         | 67            | 0.084      |
| Zero-day  | 1   | 300   | 53         | 26            | 0.013      |
| Zero-day  | 2   | 300   | 77         | 37            | 0.001      |
| Zero-day  | 4   | 300   | 54         | 55            | 1.000      |
| Zero-day  | 8   | 300   | 69         | 49            | 0.160      |

Gemini wins on all flows and on known attacks at every k. On zero-day attacks Jev wins at k = 1 and 2, and the difference is not
significant at k = 0, 4 and 8. The direction depends on the example draw: `jev-ids compare` runs the exact McNemar test per seed, and on
zero-day attacks at k = 1 two seeds favor Jev (38 against 17 and 31 against 4 discordant flows) while the third favors Gemini (5 against
23, p < 0.001).

## Recall on zero-day attacks, by category

| Detector | k   | Zero-day | Known | Zero-day dos | Zero-day probe | Zero-day r2l | Zero-day u2r |
| -------- | --- | -------- | ----- | ------------ | -------------- | ------------ | ------------ |
| Jev      | 0   | 0.622    | 0.665 | 0.657        | 0.804          | 0.000        | 0.750        |
| Jev      | 1   | 0.747    | 0.790 | 0.811        | 0.926          | 0.151        | 0.633        |
| Jev      | 2   | 0.738    | 0.772 | 0.789        | 0.904          | 0.198        | 0.667        |
| Jev      | 4   | 0.731    | 0.803 | 0.729        | 0.913          | 0.262        | 0.783        |
| Jev      | 8   | 0.721    | 0.805 | 0.729        | 0.897          | 0.222        | 0.800        |
| Gemini   | 0   | 0.687    | 0.842 | 0.649        | 0.962          | 0.087        | 0.767        |
| Gemini   | 1   | 0.713    | 0.866 | 0.734        | 0.958          | 0.071        | 0.650        |
| Gemini   | 2   | 0.684    | 0.849 | 0.684        | 0.958          | 0.000        | 0.700        |
| Gemini   | 4   | 0.717    | 0.875 | 0.709        | 0.994          | 0.008        | 0.817        |
| Gemini   | 8   | 0.702    | 0.867 | 0.689        | 0.981          | 0.008        | 0.800        |

The gap lives in zero-day r2l, where Jev reaches 0.26 recall with examples and Gemini stays near zero. The Random Forest reports 0.91 to
1.00 zero-day recall at the price of 0.60 to 0.79 precision: it calls almost everything an attack.

## Cost and latency

| k   | Cost Jev (USD / 1M flows) | Cost Gemini | Ratio | Latency Jev  | Latency Gemini | Ratio |
| --- | ------------------------- | ----------- | ----- | ------------ | -------------- | ----- |
| 0   | 43                        | 1,068       | 25×   | 300 (382) ms | 1.42 (3.33) s  | 4.7×  |
| 1   | 74                        | 1,651       | 22×   | 307 (383) ms | 1.65 (3.65) s  | 5.4×  |
| 2   | 106                       | 2,409       | 23×   | 302 (368) ms | 2.03 (4.33) s  | 6.7×  |
| 4   | 169                       | 2,869       | 17×   | 314 (390) ms | 1.44 (2.91) s  | 4.6×  |
| 8   | 295                       | 3,035       | 10×   | 325 (412) ms | 1.38 (2.81) s  | 4.3×  |

Latency is the median (95th percentile) of the successful requests, `latency_ms_median` and `latency_ms_p95` in `summary.csv`, and the
latency ratio uses the medians. A few stalled Gemini requests lasted minutes, so the mean (`latency_ms_mean`) overstates a typical call.
Cost is list price for one million flows: the tokens of a call times the per-million-token prices, Gemini's thinking tokens billed as
output. The ratio narrows at k = 8 because Vertex served 4,004 of the 6,269 input tokens from cache at a tenth of the price; Jev has no
cache. Gemini's price is the promotional one through 2026-12-31 and doubles on 2027-01-01. Gemini's latency was measured with five
processes in parallel on a congested day (transient 429, 500, 504 and connection resets, all repaired with `redo-errors`), so it is a
real-day figure, not a floor.

## Reproducing

```bash
make paper-summary
uv run jev-ids compare --a results/paper/*-jev-paper/ --b results/paper/*-llm-gemini-paper/ --subset all
uv run jev-ids compare --a results/paper/*-jev-paper/ --b results/paper/*-llm-gemini-paper/ --subset known
uv run jev-ids compare --a results/paper/*-jev-paper/ --b results/paper/*-llm-gemini-paper/ --subset novel
uv run jev-ids sign-test --a results/paper/*-jev-paper/ --b results/paper/*-llm-gemini-paper/
uv run jev-ids sign-test --a results/paper/*-jev-paper/ --b results/paper/*-random_forest-paper/
```

The three `compare` outputs (McNemar per seed) are saved as `results/paper/compare-jev-gemini-{all,known,novel}.csv`, where
`--subset novel` is the zero-day cut. The two `sign-test` outputs are `results/paper/sign-test-jev-{gemini,random_forest}.csv`.
Every run directory holds `config.json` (spec, hashes of card, split and prompt, code commit, `redone` passes) and `predictions.jsonl`
(one row per flow, k, seed and repetition). `responses.jsonl`, the raw model answers, stays out of git.
