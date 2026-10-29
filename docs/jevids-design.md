# Jev IDS design decisions

The design of the next version of Jev IDS, agreed on 2026-10-27 before any of it was built or run. It records what was decided, why, the
values fixed in advance, the facts measured on the data that shaped them, the stages that build it and the rules of the experiment. A
value changed after a result has been seen is logged in [Changes after results](#changes-after-results) with the result that prompted it.

## Status

| Item                                    | State                                                                   |
| --------------------------------------- | ----------------------------------------------------------------------- |
| NF-UQ-NIDS-v2 removed                   | Done, commit `1197267`                                                  |
| Improved CIC-IDS2017 integrated         | Done, commit `48dafa3`; splits cut per attack name, replaced in stage 0 |
| Pilot runs of Jev, Random Forest and IF | Done, commit `73de8df`; historical, on the splits before stage 0        |
| Stage 0                                 | Done, commit `3b011d8`                                                  |
| Stage 1                                 | Done, commits `2e4c763` and `b8a0330`; line 0 below                     |
| Stage 2                                 | Done, commit `b1d7001`; line 1 below                                    |
| Stage 3                                 | Done, commits `9419db2`, `2c77f04`, `7654808`; line 2 below             |
| Stage 4                                 | Done, commit `a4a4e04`; line 3 below                                    |
| Stage 5                                 | Done, commits `805d7e4` and `fc0c8c6`, cut 0.64, line 4 below           |
| Stage 6                                 | Not started                                                             |

## Goal

The evaluation of Jev IDS needs more depth, and Jev IDS should be a design with its own decisions rather than Jev applied to flows.
Today every request carries k randomly drawn Examples per Category, the same Examples for every Flow of a cell (`sample_examples`,
`jev_ids/run.py`). Jev bills input tokens only (`prices.json`: `jev-1.13.0`, input 0.042 USD per 1M tokens, output 0), so what a request
costs is what it carries, and what changes from one request to the next is `flows.under_test` and `examples`.

Jev IDS will instead read the Flows in the order they end, remember what it has judged, and decide for every Flow how many Examples each
Category gets (`KController`) and which ones (`Selector`), using only what has already happened and what has already come back as feedback.

```
Flows in order of end ──► Jev judges F_t (one request per Flow)
                               ▲                  │
              k per Category ──┤                  │ at step t + D
                    Examples ──┤                  ▼
                            Memory ◄── F_t with its true label and Jev's answer
```

## Decisions

### D1. CIC-IDS2017 only

NSL-KDD served a simpler first evaluation and is frozen: its code, card, splits and runs stay in the repository, it gets no new run, and
`DATASET` defaults to `cicids2017`. NSL-KDD has no timestamps, so it could not support recency or a time-ordered stream anyway.

### D2. Pool and test cut per (day, attack name)

The current preparation sorts all Flows of an attack name in time and cuts them in half. Every kept attack happens on a single day, so for
attacks this is already a cut within the day; BENIGN spans the five days, and its single cut fell on Wednesday 2017-07-05 at 14:08. The
test side therefore holds no benign Flow before Wednesday afternoon: on Tuesday a Detector answering "attack" to everything is always
right, and the `KController` would get no feedback on BENIGN for a day and a half.

Decision: cut each (day, attack name) group in half in time. Only BENIGN changes in practice. The caps (POOL_CAPS, TEST_CAPS) still apply
per attack name, sampled after the per-day cut. An Example is still never later than a judged Flow of the same attack name, and the novel
attack names still never reach the pool. This changes a decision of the approved integration and invalidates the current splits and pilot
runs, which the new design has to re-run on the same split anyway.

### D3. The stream is ordered by the end of each Flow

A flow record exists only once the flow has ended, so a Flow is judged at `timestamp + Flow Duration`; ties are broken by `row_id`. Flow
Duration is in microseconds: its maximum is 119,999,962 in the pool and 119,999,671 in the test file, which matches a 120 s flow timeout.
That reading is an inference from the values, not stated by the dataset.

### D4. Memory and feedback delay D

The `Memory` holds every labeled Flow that has ended before "now": pool Flows become visible once their end is earlier than the end of the
Flow under test, and a judged Flow enters it D steps after it was judged, with its true Category, its attack name and Jev's whole answer
(`p_attack`, `category_pred`, `confidence`). A step is one Flow of the stream, so with D = 1 the Flow judged at step t is visible when the
Flow at step t + 1 is judged.

The delay stands for the time between a problem slipping through and someone noticing it, so a missed attack is not known at once. D is
the same for every Flow: tying it to Flow Duration was rejected because duration is a property of each attack, not of its discovery
(median Flow Duration in the test file: Portscan under 0.0001 s, BENIGN 0.06 s, DoS Hulk 0.16 s, SSH-Patator 12 s, DoS Slowloris 103 s,
DoS Slowhttptest 108 s), so a scan would be "discovered" a thousand times sooner than a slow DoS. A delay that depends on Jev's verdict was
considered and dropped as unnecessary: with one D for all, the time a Flow enters the memory reveals nothing about whether it was missed.

D is an experimental parameter, reported as scenarios and never tuned: D ∈ {1, 100, 500} Flows (1 is the immediate best case, 500 a
quarter of the 2,000-Flow paper split).

Feedback is assumed complete: every judged Flow eventually gets its true label, missed attacks included, because their impact is noticed
and reported. This is a declared assumption of the paper.

### D5. `KController`: AIMD mirrored, one k per Category

TCP grows its window slowly and halves it on loss, because overshooting is the costly error there. In an IDS the costly error is too few
Examples (a missed attack); too many only costs tokens. So the rule is mirrored: multiplicative increase on error, additive decrease on
success.

```
on feedback for a Flow whose true Category is c:
  error   (category_pred ≠ c):  k_c ← min(k_max, β · k_c)
  correct:                      k_c ← max(k_min, k_c − α / k_c)
Categories without feedback keep their k.
Examples used for c = ceil(k_c), or every visible Example of c when fewer exist.
```

| Parameter    | Value | Meaning                                                                                                  |
| ------------ | ----- | -------------------------------------------------------------------------------------------------------- |
| k₀           | 1     | Start cheap and grow only on evidence of error                                                           |
| k_min, k_max | 1, 8  | The range already measured; k = 8 was the protocol's ceiling                                             |
| β            | 2     | Double on error                                                                                          |
| α            | 1     | One Example less per window of k_c correct Flows: each success removes 1/k_c, as TCP adds 1/cwnd per ACK |

The 1/k_c step replaced a threshold m of "correct appearances per batch" when batches were dropped (D8), and removes one parameter. The
controller reacts when the label arrives, at t + D, not when the Flow is judged. BENIGN has its own k like every other Category. A
sensitivity check with β ∈ {1.5, 2, 3} shows the result does not hinge on one value.

Fixed on 2026-10-28, before line 3 was run (`jev_ids/controller.py`):

- An error is `category_pred` differing from the true Category, a missing Category answer included; a row with `error` is ignored.
- Every stream cell starts a fresh controller at k₀ = 1 for every Category. At each step the rows that came back since the last step
  (`Memory.returned`, the first t − D + 1) update k in the order they were judged, then the `Selector` gives ceil(k_c) Examples per
  Category, or fewer when a Category has fewer distinct candidates.
- Every row carries `k_by_category`, the k of each Category before the ceiling, so the controller's path can be read back.
- `jev-ids run --control aimd --k 1` runs it; `--k` is then k₀ and must be 1, and the selection must be `score`. `control` (`fixed` or
  `aimd`) is written in `config.json` and in every row, `fixed` for rows written before it existed, and `jev-ids metrics` groups by it.

### D6. `Selector`: one score and MMR

For each Category c the `Selector` picks ceil(k_c) Examples among the visible memory Flows of c:

```
score(e) = similarity(e, F_t) + recency(e) + difficulty(e)        equal weights, not tuned
repeat ceil(k_c) times: take the e maximising
    λ · score(e)/3 − (1 − λ) · max over chosen e' of redundancy(e, e')      λ = 0.5
```

- Similarity and recency are ranks within the Category's candidates, scaled to [0, 1]: the nearest Flow and the newest Flow get 1, the
  farthest and the oldest get 0 (a single candidate gets 1). Ranks put the three terms on one scale and need no time constant; an
  exponential decay was rejected because it needs a τ chosen by hand.
- Distance is Euclidean over the features standardised with the pool's mean and standard deviation, Protocol one-hot.
- Difficulty is 1 when Jev was wrong on e, 1 − |2 · p_attack − 1| when it was right, and 0.5 for pool Flows, which Jev never judged.
  The first formula alone scored a confident error as easy, which is why a wrong answer is set to 1.
- Redundancy is 1 / (1 + distance), in [0, 1]. MMR (maximal marginal relevance) keeps near-identical Flows of one burst from filling the
  slots: in CIC-IDS2017 an attack is a burst of a few minutes, so the most recent Flows are often near copies.

The three ideas combined are recency (traffic and attacks drift), difficulty (Flows near the boundary between Categories, right or wrong)
and similarity to the Flow under test. The score is per Flow, so Examples now change from request to request.

Fixed on 2026-10-28, before line 2 was run (`jev_ids/selector.py`):

- An exact copy is never chosen: MMR skips any candidate at distance 0 from an Example already chosen, and a Category left with copies
  only gets fewer Examples. The formula alone does not ensure the proof of stage 3: a copy scoring 0.03 (on 0 to 3) above a near copy at
  distance 0.01 would win. The pool holds 1,195 BENIGN and 1,333 PortScan Flows that have an exact twin.
- Jev was wrong on e when `category_pred` differs from e's true Category, the error the `KController` reacts to (D5).
- Equal distances or ends share their mean rank, so equal Flows get equal terms. Ties in the MMR value go to the earlier candidate (pool
  Flows by end, then returned Flows in the order they were judged).
- The numeric features are standardised with the pool's mean and standard deviation (a constant feature keeps scale 1); the Protocol
  one-hot columns are left as 0 and 1.
- The Examples of a request are shuffled with a seed made of the Flow's row_id only, so repetitions send the same request.
- `jev-ids run --selection random|score` chooses between line 0's draw and the `Selector`; a stream uses `score` by default, and
  `selection` is written in `config.json` and in every row (`None` for the forests, `random` for rows written before it existed).

Checked on real Flows before the run (pilot stream, line 1's seed 0 answers as the memory's rows, k = 4, steps 60, 150 and 250): the
score term λ·score/3 of the chosen Examples lay between 0.20 and 0.48 and the highest redundancy among them between 0.02 and 0.69, so the
two terms of MMR are on comparable scales. Standardised distances to the Flow under test have medians of 2.6 to 9.9, so redundancy is
small (about 0.1 to 0.25) except between near copies, which is where MMR is meant to act. In tight Categories (Botnet: distances 4.54 to
4.58 for most candidates) MMR then reaches for far outliers (distances 52 to 158) after the first pick, because every near candidate is
almost a copy of it. One choice takes 265 ms on average (658 ms at most), 80 s per 300-Flow cell; the space is built in 2 s.

### D7. Compact record, no column removed

Numbers sent to Jev are written with 4 significant digits, not a fixed number of decimals: `Flow Bytes/s` exceeds 10⁶ and some times are
10⁻⁵, so cutting decimals would erase the small values and leave the large ones long. Only the text sent to Jev (and the LLM) changes;
the forests keep the full values. No column is removed: selective column removal adds decisions a reviewer can question.

Fixed on 2026-10-28, before line 1 was run (`dataset.compact_value`):

- A value written as an integer stays as it is, in every column: rounding `20694308` to `20690000` saves no character, and an exponent
  would turn a port such as `44321` into `4.432e+04`. No list of exempt columns is needed.
- Any other number gets 4 significant digits and no exponent: `25160.418777440053` becomes `25160`, `168.86187098953056` becomes `168.9`
  and `0.0000123456` would become `0.00001235`. No non-zero value below 0.001 occurred in 20,000 pool Flows.
- `-1` and `0` are integers and stay; a decimal with an integer value loses its `.0` (`0.0` becomes `0`); text that is not a finite number
  (NSL-KDD's `tcp`, `inf`, `nan`) stays.
- The prompt hash does not change, so the format is recorded as `record` (`full` or `compact`) in `config.json` (`spec.record`) and in
  every row, and `jev-ids metrics` groups by it. `jev-ids run --record full|compact` sets it, `compact` by default; rows written before it
  existed read back as `full`. The forests always write `full`.

Measured before the choice, on 6 pool Flows (one per Category) at k = 0, 24 calls: Jev's `input_tokens` was exactly the number of
characters of the record plus 1,194 in every call, so a character saved is a token saved. Mean characters per record on the pilot:
466 in full, 322 with `.4g` everywhere, 311 with `.4g` and integers kept, 296 in the chosen format; on 5,000 pool Flows, 456 and 290.

### D8. One request per Flow

Judging several Flows per request was dropped to avoid code changes that do not improve the design. An open question would have had to be
settled first anyway: each Flow of a batch needs its own questions, and whether TypeSafe bills the state once or per question was never
verified. Without batches the cost per Flow stays high; the compact record (D7) is the only deliberate token cut, and the `KController`
may save tokens as a side effect.

### D9. Decision threshold tuned on validation

The verdict is p_attack ≥ 0.5 today (`docs/protocol.md`). On the pilot, Jev at k = 8 had PR-AUC 0.989 but precision 0.893, which suggests
the ranking is good and the 0.5 cut is not. The cut is chosen on a validation stream drawn from the pool, as the last stage, because the
dynamic k changes the distribution of p_attack.

Fixed on 2026-10-28, before the validation stream was run:

- Criterion. The cut is the one with the highest F1 averaged over the (seed, rep) cells of the validation stream, the same F1 the line tables report. The candidates are 0.5 and every p_attack in the validation rows, because F1 only changes where the cut passes a row. A tie goes to the candidate nearest 0.5, so the cut moves only as far as F1 asks. A Flow is an attack when p_attack ≥ cut, as it was with 0.5.
- Validation stream. The full system of line 3 (the `Selector`, the mirrored AIMD from k₀ = 1, the compact record) over `splits/validation.csv`, D = 1, seeds 0 to 2. Its Flows stay in the pool, and `Memory.visible` returns only pool Flows that ended before the judged one, so no Flow is its own Example (`test_a_pool_flow_judged_in_a_stream_is_never_its_own_example`).
- Where the cut lives. `jev-ids threshold` prints the cut from the validation runs and refuses rows of any other split, so a test split never shapes it. `jev-ids metrics --threshold` and `--threshold-a/--threshold-b` of `jev-ids compare` and `jev-ids sign-test` take every Verdict again at a cut after the run. The Verdict feeds nothing in a stream (the `Selector` reads p_attack and the Category, the `KController` reads the Category), so a new cut changes no Example. Line 4 is therefore line 3's rows taken again at the cut, with no new call to Jev. The cut is written in line 4 below before line 4 is computed.

### D10. Baselines see what Jev IDS sees

| Baseline         | How                                                                                                                                                                                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Jev, random k    | Stage 1: Examples drawn at random from the visible memory, k = 4 for every Category                                                                                                                                                                                                       |
| Random Forest    | Refitted on the visible memory at every Flow, so it gets the same past and the same feedback as Jev IDS; one seed, since the forest does not depend on it                                                                                                                                 |
| Isolation Forest | Refitted on the benign Flows of the visible memory at every Flow; one seed                                                                                                                                                                                                                |
| kNN              | The same neighbours the `Selector` finds, majority vote; if it matches Jev IDS, Jev adds nothing                                                                                                                                                                                          |
| Jev, k = 1 fixed | The `Selector` at a fixed k = 1, never reacting to errors; the baseline of the `KController`: if it matches Jev IDS, the reaction to errors adds nothing. Also the cheapest Jev, the left end of the cost against F1 curve. Added on 2026-10-28 after line 3, see "Changes after results" |

A forest fitted once on the whole pool would see later pool Flows (the future) and never the feedback; a reviewer could point at either.

The kNN was fixed on 2026-10-28, before any kNN result (`jev_ids/detectors/knn.py`): the K nearest Flows of the whole visible memory, in
the `Selector`'s space, vote; the most frequent Category wins, a tie going to the Category of the nearest tied neighbour; p_attack is the
share of neighbours that are attacks. A vote among the `Selector`'s own Examples was rejected because with k Examples per Category it
always ties. Two K are run and both reported: K = 4 (`--neighbours 4`) and K = the number of Examples the `Selector` gives Jev at k = 4
for the same memory (`--neighbours matched:4`, about 12 on the pilot), so both read the same number of Flows. One seed: the vote is
deterministic.

### Rejected or deferred

| Idea                                    | Why not now                                                                                        |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Several Flows per request               | D8                                                                                                 |
| Removing columns                        | D7                                                                                                 |
| Cascade with a cheap model in front     | Not needed; would add a component to justify                                                       |
| D derived from Flow Duration            | D4                                                                                                 |
| Jev's own label as feedback             | Errors would become Examples that make the next similar error look right; the true label is stored |
| A Jev pass over the pool for difficulty | Costs money and adds a step; pool Flows get 0.5                                                    |
| New NSL-KDD runs                        | D1                                                                                                 |

## Stages

Each stage adds one change, passes `make check`, runs for real and is committed on its own (Conventional Commits, subject ≤ 50
characters, no AI attribution). Lines 0 to 4 form the incremental table.

| Stage            | What changes                                                                                                                                                                                   | Proof                                                                                                                    | Output                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| 0. Data          | Cut per (day, attack name) in `scripts/prepare_cicids2017.py`; `Flow` gets its end time; splits redrawn with seed 20261027; a validation stream from the pool; `DATASET=cicids2017` by default | Tests: every day has benign Flows in the test file; pool before test within each (day, attack name); caps respected      | New pool, test, splits and `SOURCE.json` |
| 1. Stream        | `Memory` and the stream loop; random Examples, k = 4; forests refitted on the memory at every Flow                                                                                             | Tests: the memory never returns a Flow from the future; a Flow enters exactly at t + D; no attack name reaches a request | Line 0: Jev, RF, IF (done)               |
| 2. Record        | 4 significant digits                                                                                                                                                                           | Test: large and small values keep their order of magnitude                                                               | Line 1, with tokens per Flow             |
| 3. `Selector`    | Score and MMR, k = 4                                                                                                                                                                           | Test: two identical Flows are never chosen together                                                                      | Line 2 and the kNN baseline              |
| 4. `KController` | Mirrored AIMD                                                                                                                                                                                  | Tests: error, success and absent Category                                                                                | Line 3                                   |
| 5. Threshold     | Cut tuned on the validation stream                                                                                                                                                             | The test splits are never read                                                                                           | Line 4                                   |
| 6. Final         | The paper split, once: full system, leave-one-out ablation, the baselines of D10 (Jev at a fixed k = 1 included), D ∈ {1, 100, 500}, statistics                                                | McNemar and the Holm-adjusted sign test that already exist                                                               | Final table, cost against F1 curve       |

## Evaluation rules

- Lines 0 to 4 run on the `pilot` split. The values above are fixed now; any change made after a pilot result is logged below.
- Lines 0 to 4 use D = 1, fixed before any stream result: the lines measure the components, and D is varied in stage 6 only. On the
  300-Flow pilot, D = 100 or 500 would hold back a third or more of the stream, so the components would hardly get feedback.
- The validation stream from the pool is used for the threshold only. It holds no novel attacks, because novel attack names never
  enter the pool, so it cannot measure what matters most.
- The `paper` split is read once, in stage 6.
- Every line reports recall on novel attacks separately, at first contact (a novel Flow judged before any Flow of its attack name has
  entered the memory) and after feedback.
- The final ablation removes one component at a time from the full system, because components added one by one interact.
- Timing for stage 6, measured on 2026-10-29. `Selector.choose` over every 20th Flow of the paper stream (the memory holding the pool only, no Detector call, no label of the split read) took 71 ms on average at k = 1 and 90 ms at k = 8 (95th percentile 139 and 182 ms), as on the pilot (68 and 83 ms). The check of D6 measured 265 ms under other conditions (k = 4, line 1's rows in the memory). In the runs themselves a Flow took 0.36 s of wall time on the validation stream and 0.41 s in line 3, of which Jev's latency was 0.23 and 0.26 s. One Jev configuration over the paper split, three seeds and one D therefore takes about 2,000 × 3 × 0.4 s = 40 min.
- Without the `Selector`, the ablation keeps the `KController` and draws ceil(k_c) Examples of each Category at random with the cell's seed (`--selection random --control aimd`). The random draw is the one of line 0, so a fixed k gives the same Examples as before.
- The sensitivity check sets β with `--beta` (1.5, 2 or 3), accepted only under `--control aimd`. Every row carries `beta` (None without the `KController`), and `jev-ids metrics` groups by it. Rows written before the option read as β = 2 under `aimd`, the value D5 fixed.
- Comparisons of cost are made at equal tokens per Flow, or as a cost against F1 curve.

## Notes for implementation

- Attack names never reach a request (`CONTEXT.md`); the memory keeps them for analysis only, and Examples carry the Category.
- The Jev template asks two questions about `flows.under_test`: `is_attack` (`noul`, gives p_attack) and `category` (`choice`, gives the
  Category and a confidence). `request_body` in `jev_ids/detectors/jev.py` fills `flows.under_test` and `examples`.
- A failed call is a row with `error`, counted as normal (fail-open, `docs/protocol.md`). Since stage 1 it enters the memory like any
  judged Flow, with its true Category, because `Memory.add` stores the Flow and its row whatever the row holds. Still to do: the
  `Selector` gives it difficulty 0.5 (no Jev answer, stage 3) and the `KController` ignores it (stage 4). Line 0 had no failed call.
- Each Example costs about 490 input tokens on CIC-IDS2017 before rounding: (25,312 − 1,654) / 48, from the pilot's mean input tokens at
  k = 8 and k = 0.
- In stage 1, seeds drive the random Examples. From stage 3 on the `Selector` is deterministic, and so are the forests (random_state 0,
  the same for every seed), so repetitions measure Jev's own variation alone.
- With the memory tied to the clock, Infiltration - Portscan (Thursday) is judged with no PortScan Example, because the pool's Portscan
  Flows are on Friday. That is a genuine novel attack, not a bug.
- Before stage 3 runs, check that the score and the redundancy terms behave as intended on a handful of real Flows; a scale mismatch
  between them is the most likely silent error.
- Stage 0 split sizes and novel counts (seed 20261027): smoke 5 (2 novel), internal 50 (7), pilot 300 (48), paper 2000 (300). The test
  file holds between 1,815 and 2,402 BENIGN Flows per day.
- `splits/validation.csv` (300 Flows, no novel attack) is drawn from the pool with `draw_split --source pool.csv`. Its Flows stay in the
  pool, so a run over it must keep a Flow from being its own Example; the clock rule of D4 already does this, because a Flow only sees
  pool Flows that ended before it.
- Run every command through make or with `UV_PROJECT_ENVIRONMENT=$HOME/.venvs/jev-ids`, so `uv run` does not create `.venv` in the repo.
- Commit every change, documents included, before a run: `code_commit` in `config.json` ends in `-dirty` whenever the tree has an
  uncommitted change, as the line 0 forests did (an uncommitted status line of this file; the code was `b8a0330`'s).

### State of the code after stage 1

- `jev_ids/stream.py`: `in_stream_order` (D3), `Memory` (D4: pool Flows by Category sorted by end, judged Flows with their rows,
  `returned(step)` = the first `step − D + 1` judged Flows, `visible(category, step, now)`, `everything`, `first_contact`),
  `random_examples` (line 0: k per Category, or all when fewer, seeded by seed, row_id and Category), `split_names` and `stream_cell`.
  The `Selector` (stage 3) replaces `random_examples`; the `KController` (stage 4) decides the k it is called with, per Category.
- `jev_ids/run.py`: `RunSpec.delay` (None keeps the first paper's protocol, one fixed draw per cell) and `RunSpec.jobs`. With a delay,
  `execute` builds a fresh `Memory` per (k, seed, rep) cell and calls `stream_cell`. `redo-errors` refuses a stream run, because a Flow
  judged again would see another past than its neighbours did: a stream run with errors is run again from the start.
- `jev_ids/detectors/random_forest.py`: `Encoder` encodes each Flow once for both forests; `jobs` is scikit-learn's `n_jobs`.
- CLI: `jev-ids run ... --delay D` streams the split (since stage 2, `--record full|compact` sets what Jev and the LLMs read, D7); `--jobs N` sets the cores of a forest fit (default -1, all; the forests are the same
  for any value). Line 0 was run with:

  ```
  jev-ids run --dataset data/cicids2017/dataset.json --split pilot --delay 1 --results-dir results/design-cicids2017 \
    --detector jev --k 4 --seeds 0,1,2
  jev-ids run ... --detector random_forest --k all --seeds 0
  jev-ids run ... --detector isolation_forest --k all --seeds 0
  ```

- Every stream row adds `delay`, `step`, `n_examples` (Examples actually sent, which varies per Flow) and `first_contact` (True or False
  for a novel attack whose name is in the split's `raw_label`, None otherwise) to the fields of `records.complete_prediction`.
- `jev-ids metrics` groups by (dataset, detector, model, split, delay, k) and adds `recall_novel_first_contact` and
  `recall_novel_after_feedback`. `jev-ids compare --k-a 4 --k-b all` pairs Jev with a forest; the forests have seed 0 only, so pairs
  exist for Jev's seed 0 only.
- Run results live in `results/design-cicids2017/`, one directory per run; `responses.jsonl` is git-ignored. The forest runs with a
  refit every 100 Flows were not kept; their numbers are in "Changes after results".

## Data facts behind the decisions

Time span of each attack name in the files of stage 0 (timestamps as in the zip). Before stage 0, BENIGN was cut once over the week: pool
07-03 11:56 to 07-05 14:08, test 07-05 14:08 to 07-07 20:02. The attack time spans did not change.

| Attack name                     | Pool                                      | Test                                   |
| ------------------------------- | ----------------------------------------- | -------------------------------------- |
| BENIGN, each day                | 11:42 to 12:00 until about 15:18 to 16:34 | the rest of the day, until about 20:00 |
| FTP-Patator                     | 07-04 12:19 to 12:49                      | 07-04 12:49 to 13:20                   |
| SSH-Patator (novel)             | none                                      | 07-04 17:09 to 18:11                   |
| DoS Slowloris                   | 07-05 12:48 to 12:59                      | 07-05 12:59 to 13:10                   |
| DoS Slowhttptest (novel)        | none                                      | 07-05 13:15 to 13:35                   |
| DoS Hulk                        | 07-05 13:43 to 13:52                      | 07-05 13:52 to 14:00                   |
| DoS GoldenEye                   | 07-05 14:10 to 14:13                      | 07-05 14:13 to 14:19                   |
| Infiltration - Portscan (novel) | none                                      | 07-06 17:00 to 18:45                   |
| Botnet                          | 07-07 13:04 to 13:38                      | 07-07 13:38 to 14:02                   |
| Portscan                        | 07-07 16:55 to 17:54                      | 07-07 17:54 to 18:23                   |
| DDoS                            | 07-07 18:56 to 19:06                      | 07-07 19:06 to 19:16                   |

Pilot results on the split before stage 0 (300 Flows: 152 benign, 104 known and 44 novel attacks; means over seeds 0 to 2), the reference for
line 0:

| Detector         | k   | F1    | Precision | Recall | Novel recall | False alarms | Cost per 1M Flows |
| ---------------- | --- | ----- | --------- | ------ | ------------ | ------------ | ----------------- |
| Jev              | 0   | 0.630 | 0.910     | 0.482  | 0.477        | 7            | 69 USD            |
| Jev              | 1   | 0.916 | 0.860     | 0.980  | 0.992        | 23.7         | 195 USD           |
| Jev              | 4   | 0.942 | 0.890     | 1.000  | 1.000        | 18.3         | 557 USD           |
| Jev              | 8   | 0.943 | 0.893     | 0.998  | 1.000        | 17.7         | 1,063 USD         |
| Random Forest    | 8   | 0.873 | 0.775     | 1.000  | 1.000        | 43           | ~0                |
| Random Forest    | all | 0.931 | 1.000     | 0.872  | 0.591        | 0            | ~0                |
| Isolation Forest | all | 0.575 | 0.887     | 0.426  | 0.386        | 8            | ~0                |

Jev's F1 is flat from k = 4 to k = 8 while its cost nearly doubles, which is the case for spending Examples per Category. Its remaining
error is false alarms on BENIGN, not missed attacks. The Random Forest at k = all missed all 10 SSH-Patator Flows of seed 0; on the novel
subset Jev at k = 8 beat it in 18 discordant pairs to 0 (McNemar p = 7.6e-6 per seed), while overall the two did not differ (p 0.61 to
0.87).

## Line results

### Line 0: stream, memory, random Examples (pilot, D = 1)

300 Flows, 152 benign, 148 attacks (48 novel). Jev over seeds 0 to 2; the forests over seed 0 only, refitted at every Flow.

| Detector             | F1            | Precision | Recall | Novel recall | Novel, first contact | False alarms | Missed | PR-AUC | Cost per 1M Flows |
| -------------------- | ------------- | --------- | ------ | ------------ | -------------------- | ------------ | ------ | ------ | ----------------- |
| Jev, k = 4 at random | 0.951 ± 0.012 | 0.908     | 0.998  | 1.000        | 9 of 9               | 15.3         | 0.3    | 0.995  | 335 USD           |
| Random Forest        | 0.973         | 1.000     | 0.947  | 0.875        | 1 of 3               | 0            | 8      | 1.000  | ~0                |
| Isolation Forest     | 0.426         | 0.843     | 0.285  | 0.146        | 1 of 3               | 8            | 108    | 0.846  | ~0                |

Jev against the Random Forest on seed 0 (McNemar, discordant Flows): all Flows 8 to 18 for the forest (p = 0.076), novel attacks
6 to 0 for Jev (p = 0.031), known attacks 2 to 0 for Jev (p = 0.5); the forest's advantage is entirely on BENIGN, where Jev raised 18
false alarms on seed 0 and the forest none. With feedback after every Flow, the forest learns each burst from its first Flows; it misses
the start of a new attack (steps 57 and 58 of BruteForce, 126 of DoS, 202 to 210 of PortScan). Jev's 335 USD per 1M Flows is below the
pilot's 557 at k = 4 because early in the week the memory holds few Categories: 12.5 Examples per request on average, not 24. Wall
time: Jev 4 min for 900 calls, the Random Forest 7.2 min (mean fit 1.3 s on 12 cores), the Isolation Forest 1.4 min.

### Line 1: compact record (pilot, D = 1)

Jev, k = 4 at random, seeds 0 to 2, run at commit `b1d7001` (`results/design-cicids2017/20261028T174340.933684Z-cicids2017-jev-pilot`).
The Examples are the same as in line 0 (same seeds, same memory, same number per request), so the record format is the only change.

| Line              | F1            | Precision | Recall | Novel recall | Novel, first contact | False alarms | Missed | PR-AUC | Input tokens per request | Cost per 1M Flows |
| ----------------- | ------------- | --------- | ------ | ------------ | -------------------- | ------------ | ------ | ------ | ------------------------ | ----------------- |
| 0, full record    | 0.951 ± 0.012 | 0.908     | 0.998  | 1.000        | 9 of 9               | 15.3         | 0.3    | 0.995  | 7,975                    | 335 USD           |
| 1, compact record | 0.937 ± 0.011 | 0.883     | 0.998  | 1.000        | 9 of 9               | 20.0         | 0.3    | 0.991  | 5,443                    | 229 USD           |

The compact record cut input tokens per request by 31.7 % and the cost from 335 to 229 USD per 1M Flows, as the character count
predicted. Recall did not move, every novel Flow included (two DoS Flows swapped, one each way). The price was paid on BENIGN: false alarms rose
on every seed (18 to 22, 10 to 16, 18 to 22). McNemar of line 0 against line 1, per seed, all Flows: 6 to 2, 7 to 2 and 7 to 2 for
line 0 (p = 0.29, 0.18, 0.18), not significant on any seed; known attacks 0 to 0, 0 to 1 and 1 to 0; novel attacks no discordant Flow.
Of the 26 discordant Flows over the three seeds, 24 are BENIGN (19 newly flagged, 5 no longer flagged) and 2 DoS (one each way). The
three seeds point the same way, so a small loss of precision from rounding is plausible, but the pilot cannot tell it from noise; the
paper split in stage 6, where the ablation removes the compact record, will.

### Line 2: `Selector` and the kNN baseline (pilot, D = 1)

Jev, k = 4 by score and MMR, compact record, seeds 0 to 2, run at commit `2c77f04`
(`results/design-cicids2017/20261028T183725.833595Z-cicids2017-jev-pilot`). The two kNN runs, seed 0, at commit `7654808`, which only
let the kNN run at k = all: K = 4 in `20261028T184511.643475Z-cicids2017-knn-pilot`, K matched in `20261028T184511.687748Z-cicids2017-knn-pilot`.

| Detector                    | F1            | Precision | Recall | Novel recall | Novel, first contact | False alarms | Missed | PR-AUC | Input tokens per request | Cost per 1M Flows |
| --------------------------- | ------------- | --------- | ------ | ------------ | -------------------- | ------------ | ------ | ------ | ------------------------ | ----------------- |
| Line 1: Jev, k = 4 random   | 0.937 ± 0.011 | 0.883     | 0.998  | 1.000        | 9 of 9               | 20.0         | 0.3    | 0.991  | 5,443                    | 229 USD           |
| Line 2: Jev, k = 4 Selector | 0.970 ± 0.002 | 0.942     | 1.000  | 1.000        | 9 of 9               | 9.3          | 0      | 0.995  | 5,697                    | 239 USD           |
| kNN, K = 4                  | 0.944         | 1.000     | 0.894  | 0.708        | 1 of 3               | 0            | 16     | 0.974  | none                     | ~0                |
| kNN, K matched (12.5)       | 0.898         | 1.000     | 0.815  | 0.458        | 1 of 3               | 0            | 28     | 0.977  | none                     | ~0                |

The `Selector` halved Jev's false alarms (20.0 to 9.3; per seed 22 to 10, 16 to 9, 22 to 9) and missed no attack. McNemar of line 1
against line 2, per seed, all Flows: 1 to 13 (p = 0.002), 3 to 10 (p = 0.09) and 2 to 16 (p = 0.001) for line 2; known attacks one
discordant Flow, for line 2; novel attacks none. The spread over seeds fell from 0.011 to 0.002, as expected once the Examples no longer
depend on the seed. A request carries the same 12.5 Examples on average but 4.7 % more tokens, because the chosen records are longer
than random ones: 239 against 229 USD per 1M Flows.

The kNN does not explain Jev's result. It raises no false alarm but misses attacks, most of them novel: with K = 4 it misses 16 attacks
and 14 of the 48 novel Flows; with as many neighbours as Jev reads it misses 28 and 26. Jev (seed 0) against the kNN, McNemar: K = 4,
all Flows 16 to 10 for Jev (p = 0.33), novel 14 to 0 (p = 0.0001); K matched, all Flows 28 to 10 for Jev (p = 0.005), novel 26 to 0
(p = 3e-8). The matched K gives every request's neighbour count exactly (12.51 on average, as Jev's Examples). On the pilot the plain
K = 4 kNN does not differ significantly from Jev overall, and its only advantage is on BENIGN, as the Random Forest's was in line 0.

### Line 3: `KController` (pilot, D = 1)

Jev, mirrored AIMD from k₀ = 1 with the `Selector`, compact record, seeds 0 to 2, run at commit `a4a4e04`
(`results/design-cicids2017/20261028T185053.038976Z-cicids2017-jev-pilot`).

| Detector                         | F1            | Precision | Recall | Novel recall | Novel, first contact | False alarms | Missed | PR-AUC | Examples per request | Input tokens per request | Cost per 1M Flows |
| -------------------------------- | ------------- | --------- | ------ | ------------ | -------------------- | ------------ | ------ | ------ | -------------------- | ------------------------ | ----------------- |
| Line 2: Jev, k = 4 Selector      | 0.970 ± 0.002 | 0.942     | 1.000  | 1.000        | 9 of 9               | 9.3          | 0      | 0.995  | 12.5                 | 5,697                    | 239 USD           |
| Line 3: Jev, AIMD k and Selector | 0.961 ± 0.006 | 0.925     | 1.000  | 1.000        | 9 of 9               | 12.3         | 0      | 0.998  | 3.6                  | 2,673                    | 112 USD           |

The `KController` cut the Examples per request from 12.5 to 3.6 and the cost by 53 % (239 to 112 USD per 1M Flows) while every attack
was still caught, novel ones included. False alarms rose from 9.3 to 12.3 (per seed 10 to 14, 9 to 13, 9 to 10). McNemar of line 2
against line 3, per seed, all Flows: 9 to 5, 6 to 2 and 5 to 4 for line 2 (p = 0.42, 0.29, 1.0), not significant on any seed; no
discordant known or novel attack. Against the Random Forest (seed 0) line 3 is 8 to 14 overall (p = 0.29) and 6 to 0 on novel attacks
(p = 0.031); against the kNN with K = 4, 16 to 14 overall (p = 0.86) and 14 to 0 on novel attacks (p = 0.0001).

The controller's path: BENIGN rose up to k = 4.6 after false alarms and came back down; DDoS rose to 8 and stayed there (7.6 at the end
of seed 0), because with one Example Jev named 15 DDoS Flows DoS (5 per seed, none in line 2) while still calling them attacks; DoS,
BruteForce and Botnet never left 1. The controller reacts to the Category, so a confusion between two attack Categories costs tokens
without changing the Verdict.

### Line 4: threshold (pilot, D = 1)

The validation stream chose the cut p_attack ≥ 0.64 before line 4 was computed. It is the full system of line 3 run at commit `805d7e4` over the 300 validation Flows (177 BENIGN, 123 attacks, no novel attack), seeds 0 to 2, with no failed call (`results/design-cicids2017/20261028T204508.479115Z-cicids2017-jev-validation`). `jev-ids threshold` picked 0.64 among 91 distinct p_attack values, because Jev reports them to two decimals. On the validation stream the cut raised mean F1 from 0.933 to 0.985 and cut false alarms from 17.7 to 2.3 per seed. It also missed 1.3 attacks per seed where 0.5 missed none, the four attacks of seed 0 with p_attack between 0.60 and 0.62. PR-AUC was 0.999.

Line 4 is line 3's rows taken again at 0.64 (D9), computed only after this paragraph was committed (`fc0c8c6`). Its Examples, tokens and cost are therefore line 3's.

| Detector                         | F1            | Precision | Recall | Novel recall | Novel, first contact | False alarms | Missed | PR-AUC | Examples per request | Input tokens per request | Cost per 1M Flows |
| -------------------------------- | ------------- | --------- | ------ | ------------ | -------------------- | ------------ | ------ | ------ | -------------------- | ------------------------ | ----------------- |
| Line 3: Jev, AIMD k and Selector | 0.961 ± 0.006 | 0.925     | 1.000  | 1.000        | 9 of 9               | 12.3         | 0      | 0.998  | 3.6                  | 2,673                    | 112 USD           |
| Line 4: line 3 at 0.64           | 0.977 ± 0.003 | 0.984     | 0.969  | 0.931        | 6 of 9               | 2.3          | 4.7    | 0.998  | 3.6                  | 2,673                    | 112 USD           |

The cut did on the pilot what it did on the validation stream. Mean F1 rose from 0.961 to 0.977 and false alarms fell from 12.3 to 2.3 per seed, but 4.7 attacks per seed went missed where line 3 missed none, 3.3 of them novel. Novel recall fell from 1.000 to 0.931 and first contact from 9 of 9 to 6 of 9, because the DoS Slowhttptest Flow at first contact scored below 0.64 in every seed. `Infiltration - Portscan` lost 2, 2 and 3 Flows after feedback, DoS Slowloris one known Flow per seed and Portscan one in seed 0. Every missed attack scored between 0.54 and 0.61.

McNemar of line 3 against line 4 over all Flows gives 5 to 11, 4 to 11 and 5 to 8 for line 4 (p = 0.21, 0.12, 0.58), not significant on any seed. On novel attacks line 3 wins 3 to 0, 3 to 0 and 4 to 0 (p = 0.25, 0.25, 0.125). Against the Random Forest (seed 0) line 4 ties 6 to 6 overall (p = 1.0) and leads 5 to 2 on novel attacks (p = 0.45), where line 3 led 6 to 0 (p = 0.031). Against the kNN with K = 4 it leads 13 to 5 overall (p = 0.096) and 12 to 1 on novel attacks (p = 0.0034).

The cut buys precision with novel recall, the measure this design values most. The validation stream could not show that trade, because it holds no novel attack (the limit stated in the evaluation rules). The ablation without the threshold in stage 6 measures it on 300 novel attacks.

## Changes after results

### 2026-10-28: the forests refit at every Flow, not every 100

Seen: line 0 with a refit every 100 Flows gave the Random Forest recall 0.093 (F1 0.170) and the Isolation Forest recall 0.331 (F1 0.483)
against Jev's 0.998. On the 300-Flow pilot, 100 steps span about a day and a half of capture while each attack lasts minutes, so every
refit came before the attack it should have learned: refit at step 0 (Monday, BENIGN only) missed all 32 BruteForce Flows, at step 100
(Tuesday evening) all 65 DoS, at step 200 (Wednesday evening) all 37 PortScan and 3 Botnet.

Changed: the forests refit on the memory at every Flow, the same past Jev sees. This is the forests' best case, not a deployable one: a
fit takes up to 17.5 s on one core at 90,000 Flows, far slower than traffic arrives, while Jev changes only the Examples of a request.
`train_time_ms` in every row reports that cost. Two changes make it affordable and leave every prediction the same: each Flow is encoded
once (`Encoder`), and a fit may use several cores (`--jobs`, -1 for all by default; one fit on the whole pool went from 14.3 s to 3.4 s
with identical predictions). The forests run with one seed, because seeds 0 to 2 gave identical rows: their random_state is fixed and
the memory does not depend on the seed.

### 2026-10-28: a fixed k = 1 control for the `KController`

Seen: in line 3 every Category sat at k = 1 in 76 % of the steps, and the controller added 0.44 Examples per request on average above
k = 1 (3.6 against about 3.1), so line 3's cost cut could come from starting at k₀ = 1 rather than from reacting to errors.

Changed: nothing in the design. One comparison is added, decided before it was run: Jev with the `Selector` at a fixed k = 1
(`--k 1 --control fixed`), seeds 0 to 2, pilot, D = 1. If it matches line 3, the mirrored AIMD adds nothing beyond "one Example per
Category"; if it errs more, the reaction to errors pays for itself.

Result (`results/design-cicids2017/20261028T190345.176385Z-cicids2017-jev-pilot`, commit `a0a45b0`): the fixed k = 1 control matched
line 3. F1 0.964 ± 0.006 against 0.961 ± 0.006, false alarms 11.3 against 12.3, no attack missed by either, novel recall 1.000 and
9 of 9 at first contact for both, PR-AUC 0.998 for both, 3.1 against 3.6 Examples and 106 against 112 USD per 1M Flows. McNemar of
line 3 against the control, per seed, all Flows: 1 to 6, 3 to 4 and 7 to 4 (p = 0.13, 1.0, 0.55); no discordant attack. The one
measurable effect of the controller is on the Category, not the Verdict: DDoS Flows named DoS fell from 22 to 15. On the pilot,
therefore, the cost cut of line 3 comes from k₀ = 1 and the `Selector`, not from the reaction to errors. The pilot gives the controller
few errors to react to (no missed attack in either run, 9 novel Flows at first contact), so this does not settle the question for the
paper split, where 300 novel attacks and D up to 500 test the reaction to errors; it does mean the AIMD cannot be claimed from the pilot.

Decided after this result, on 2026-10-28: the design keeps the mirrored AIMD as fixed in D5, with no change to its error signal, and
stage 6 adds no fixed k = 1 line. The control above stays reported as it is. (Superseded the same day by the decision below.)

Decided later on 2026-10-28, replacing the line above on stage 6: Jev with the `Selector` at a fixed k = 1 becomes a baseline of D10,
the baseline of the `KController`, and runs in stage 6 on the paper split for every D ∈ {1, 100, 500}. It isolates the reaction to
errors, because it differs from the full system in that alone; the leave-one-out ablation without the `KController` (a fixed k = 4)
measures what the controller saves, this baseline whether its reaction to errors improves detection. The AIMD itself stays as fixed in
D5.
