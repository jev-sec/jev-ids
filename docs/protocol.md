# Paper protocol

How the reported numbers of Jev IDS are produced, so that anyone with the repository, the raw NSL-KDD files and the API keys can produce
them again. Everything a run depends on is either committed here or written into the run's `config.json`.

## Question

How well does Jev detect intrusions in NSL-KDD flow records as the number of labeled examples per category (k) grows, against an LLM, a
Random Forest and an unsupervised Isolation Forest, and at what cost and latency per flow.

## Frozen inputs

| Input            | Where                                                                                | Pin                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dataset card     | `data/nsl-kdd/dataset.json`                                                          | sha256 `9198210f…02ee72`, written into every `config.json`                                                                                                                                            |
| Raw files        | `data/raw/nsl-kdd/KDDTrain+.txt`, `KDDTest+.txt` (Kaggle `hassan06/nslkdd`)          | sha256 in `data/nsl-kdd/splits/SOURCE.json`                                                                                                                                                           |
| Pool             | `data/nsl-kdd/pool.csv`, KDDTrain+ converted once by `scripts/prepare_nsl_kdd.py`    | 125,973 flows, not in git                                                                                                                                                                             |
| `paper` split    | `data/nsl-kdd/splits/paper.csv`, drawn by `scripts/draw_split.py` with seed 20260920 | 2,000 flows of KDDTest+ (874 normal, 642 dos, 248 r2l, 213 probe, 23 u2r), 300 of them novel attacks; disjoint from `internal`, `pilot`, `smoke`, `hard` and `mid`; sha256 written into `config.json` |
| Jev request      | `prompts/nsl-kdd/jev.json`                                                           | `prompt_hash` in every row; model `jev-1.13.0`, and every row records the version that answered                                                                                                       |
| LLM instructions | `prompts/nsl-kdd/llm.md`                                                             | `prompt_hash` in every row, model `gemini-3.6-flash` on Vertex AI through Agno, `thinking_level="low"`, temperature 0                                                                                 |
| Forests          | scikit-learn 1.9.1 (`uv.lock`), 100 trees, `random_state = 0`                        | the Isolation Forest is fitted on the 67,343 benign flows of the pool                                                                                                                                 |
| Prices           | `prices.json`                                                                        | list prices per 1M tokens, dated                                                                                                                                                                      |
| Code             | this repository                                                                      | `code_commit` in `config.json`, `-dirty` when the tree had uncommitted changes                                                                                                                        |

A novel attack is a KDDTest+ flow whose attack name never occurs in KDDTrain+ (17 names, 3,750 flows); the detectors never see attack
names, only the five categories. Examples are drawn from the pool, k per category, nested across k within a seed and identical for every
detector (`run.sample_examples`).

## Runs

`make paper` runs the four targets below in sequence and then `make paper-summary`; each target can run alone, in its own terminal. Every
run writes `results/paper/<timestamp>-nsl-kdd-<detector>-paper/` with `config.json`, `predictions.jsonl` (one row per flow, k, seed and
repetition) and, for the API detectors, `responses.jsonl` (raw answers, not in git).

A quota error or a timeout is a row with `error`, not a crash, and an interrupted run keeps every row written so far.
`uv run jev-ids redo-errors results/paper/<run>` completes the run in place: the error rows are judged again and the flows never judged,
for the first time, each in its own cell and with the same examples; the pass is noted under `redone` in `config.json`.

| Target                                                                                                 | Detector                                                                                                                                     | k               | Seeds   | Rows   |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------- | ------ |
| `paper-jev`                                                                                            | `jev`, `jev-1.13.0` through the TypeSafe SDK                                                                                                 | 0, 1, 2, 4, 8   | 0, 1, 2 | 30,000 |
| `paper-llm` (`paper-llm-k0` … `paper-llm-k8`, one run directory per k, run in parallel with `make -j`) | `llm:$(LLM)`, `$(LLM_MODEL)` through Agno: `gemini`, `gemini-3.6-flash` on Vertex AI by default; `LLM=openai LLM_MODEL=gpt-5.6-luna` for GPT | 0, 1, 2, 4, 8   | 0, 1, 2 | 30,000 |
| `paper-random-forest`                                                                                  | `random_forest`, fitted on the examples of each cell                                                                                         | 1, 2, 4, 8, all | 0, 1, 2 | 30,000 |
| `paper-isolation-forest`                                                                               | `isolation_forest`, fitted on the benign pool                                                                                                | all             | 0, 1, 2 | 6,000  |

k stops at 8: on 2026-09-22 the Jev run lost its k = 16 cells when the TypeSafe credits ran out, and the protocol was cut to k <= 8
for every detector instead of buying the cells back (`trimmed` in the two `config.json`). k = all means the whole pool; at k = all the seed changes nothing, and the three seeds are kept so that `compare` can pair the rows with
the other detectors' cells. The verdict of every detector is p_attack ≥ 0.5. A failed call becomes a row with `error` and no verdict,
counted as normal (fail-open) and as the lowest-ranked flow in the areas.

## Tables

```bash
make paper-summary
```

`make paper-summary` writes every table of the paper from `predictions.jsonl`: `summary.csv`, `sign-test-jev-gemini.csv`,
`sign-test-jev-random_forest.csv` and `compare-jev-gemini-{all,known,novel}.csv` in `results/paper/`. Each command also runs alone, for these pairs or others:

```bash
uv run jev-ids sign-test --a results/paper/<jev> --b results/paper/*-llm-gemini-paper/
uv run jev-ids compare --a results/paper/<jev> --b results/paper/*-llm-gemini-paper/ --subset novel
uv run jev-ids compare --a results/paper/<jev> --b results/paper/<random_forest> --k-a 1 --k-b all
uv run jev-ids compare --a results/paper/<jev> --b results/paper/<isolation_forest> --k-a 0 --k-b all
```

`summary.csv` has one row per detector and k: F1, precision and recall of the attack class at the 0.5 cut, recall on novel and on known
attacks, recall per category on all, known and novel attacks (`recall_dos`, `recall_known_dos`, `recall_novel_dos`, …), false alarms
and missed attacks per seed, PR-AUC (average precision) and ROC-AUC of p_attack, the error rate, the mean and sd of F1 over the seeds,
mean tokens, the share of calls with reasoning and with cache reads, list cost per 1M flows, and the mean latency of every call with the
median and 95th percentile of the successful ones. `sign-test` takes the flow as the unit. For each k it counts the flows a detector
judged right in more seeds than the other and runs an exact sign test on all flows, known and novel attacks, Holm-adjusted together.
`compare` pairs two detectors flow by flow within a seed, over as many run directories per side as they were run in, and reports the
discordant pairs, who was right in them and McNemar's exact p; `--k-a`/`--k-b` pair across k, which is how few-shot Jev meets the
forests at k = all. Tables and figures are regenerated from `predictions.jsonl`; none is edited by hand.

## What the protocol does not fix

- Cost is tokens times list price, not what was billed. Gemini is priced at its paid-tier list rate through 2026-12-31, with reasoning
  tokens billed as output, and Jev at TypeSafe's list rate. Both rates are in `prices.json`.
- Latency is the wall clock around the successful HTTP call from the client, TypeSafe's API for Jev and Vertex AI for Gemini,
  without the failed attempts (`retries` counts them). The forests report the time of `predict_proba` or `score_samples` and the fit.
- Provider-side changes. Jev is pinned by the version the answer reports, and Gemini only by its model id.

## Adding a detector

One module under `jev_ids/detectors/` and four lines elsewhere; the package docstring of `jev_ids/detectors/__init__.py` lists them. Then a
`paper-<name>` target above and, if it bills tokens, a `prices.json` entry.
