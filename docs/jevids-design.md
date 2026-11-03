# Jev IDS design decisions

The design of the next version of Jev IDS, agreed on 2026-10-27 before any of it was built or run. It records what was decided, why, the
values fixed in advance, the facts measured on the data that shaped them, the stages that build it and the rules of the experiment. A
value changed after a result has been seen is logged in [Changes after results](#changes-after-results) with the result that prompted it.

## Status

| Item                                    | State                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------- |
| NF-UQ-NIDS-v2 removed                   | Done, commit `1197267`                                                    |
| Improved CIC-IDS2017 integrated         | Done, commit `48dafa3`; splits cut per attack name, replaced in stage 0   |
| Pilot runs of Jev, Random Forest and IF | Done, commit `73de8df`; historical, on the splits before stage 0          |
| Stage 0                                 | Done, commit `3b011d8`                                                    |
| Stage 1                                 | Done, commits `2e4c763` and `b8a0330`; line 0 below                       |
| Stage 2                                 | Done, commit `b1d7001`; line 1 below                                      |
| Stage 3                                 | Done, commits `9419db2`, `2c77f04`, `7654808`; line 2 below               |
| Stage 4                                 | Done, commit `a4a4e04`; line 3 below                                      |
| Stage 5                                 | Done, commits `805d7e4` and `fc0c8c6`, cut 0.64, line 4 below             |
| Stage 6                                 | Slots 1 to 12 done, stopped in slot 13 (β) on 2026-11-02, see below       |
| Stage 6 on `paper-v2`                   | Phase 1, paper battery and seed repetitions read on 2026-11-02, see below |

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
- The `paper-v2` split is read by phase 1 and by the paper battery, the two changes of 2026-11-02 ([Changes after results](#changes-after-results)).
- Every line reports recall on novel attacks separately, at first contact (a novel Flow judged before any Flow of its attack name has
  entered the memory) and after feedback.
- The final ablation removes one component at a time from the full system, because components added one by one interact.
- Timing for stage 6, measured on 2026-10-29. `Selector.choose` over every 20th Flow of the paper stream (the memory holding the pool only, no Detector call, no label of the split read) took 71 ms on average at k = 1 and 90 ms at k = 8 (95th percentile 139 and 182 ms), as on the pilot (68 and 83 ms). The check of D6 measured 265 ms under other conditions (k = 4, line 1's rows in the memory). In the runs themselves a Flow took 0.36 s of wall time on the validation stream and 0.41 s in line 3, of which Jev's latency was 0.23 and 0.26 s. One Jev configuration over the paper split, three seeds and one D therefore takes about 2,000 × 3 × 0.4 s = 40 min.
- Without the `Selector`, the ablation keeps the `KController` and draws ceil(k_c) Examples of each Category at random with the cell's seed (`--selection random --control aimd`). The random draw is the one of line 0, so a fixed k gives the same Examples as before.
- The sensitivity check sets β with `--beta` (1.5, 2 or 3), accepted only under `--control aimd`. Every row carries `beta` (None without the `KController`), and `jev-ids metrics` groups by it. Rows written before the option read as β = 2 under `aimd`, the value D5 fixed.
- Comparisons of cost are made at equal tokens per Flow, or as a cost against F1 curve.

### Stage 6 in slots

Fixed on 2026-10-29, before any run on the paper split. Stage 6 runs in 15 slots of 60 to 90 minutes, `make -k stage6-1` to `make -k stage6-15` (`Makefile`), because nobody can watch some 20 hours of runs in one sitting. Each slot chains whole runs, and each run is one line at one D with seeds 0 to 2 (seed 0 alone for the forests and the kNN, D10). The slots go in this order, so the first ones already compare the full system with the baselines at D = 1.

| Slots      | D           | Runs                                                                       | Minutes |
| ---------- | ----------- | -------------------------------------------------------------------------- | ------- |
| 1, 5, 9    | 1, 100, 500 | Full system, Isolation Forest, kNN at K = 4 and at matched:4               | 66      |
| 2, 6, 10   | 1, 100, 500 | Jev at a fixed k = 1, Random Forest                                        | 88      |
| 3, 7, 11   | 1, 100, 500 | Jev at a random k = 4, without the `KController` (`Selector`, fixed k = 4) | 80      |
| 4, 8, 12   | 1, 100, 500 | Without the `Selector`, without the compact record                         | 80      |
| 13, 14, 15 | 1, 100, 500 | β = 1.5 and β = 3                                                          | 80      |

The minutes come from the wall time per Flow measured before, 0.4 s for Jev and, on the pilot, 1.44 s for the Random Forest, 0.29 s for the Isolation Forest and 0.17 s and 0.30 s for the two kNN.

- The ablation without the threshold costs no run, because it is the full system's rows taken at 0.5.
- The full system, the other three ablations and Jev at a fixed k = 1 are read at 0.64, the cut of line 4. Jev at a fixed k = 1 shares the cut because it must differ from the full system in the `KController` alone (D10). The other baselines are read at 0.5, because the cut was tuned on the full system's validation stream and says nothing about another configuration. `jev-ids metrics --threshold` still shows any of them at either cut.
- β runs at every D, so the check also covers the delays where the controller hears of its errors late.
- The rows of a finished slot may be read before the next one starts. Nothing in this plan changes after such a reading, and a change would be logged in [Changes after results](#changes-after-results) with the result that prompted it.
- A slot cut midway loses the run it was in, because a stream run cannot be redone. That run starts again from scratch, and its partial directory goes to the Trash so the metrics never read it.
- Since 2026-11-01, after slot 1, `make -k stage6` runs every slot left in order. A run that ends well leaves a stamp in `results/design-cicids2017/stage6-done/`, and make skips each run that has one, so the same command resumes a cut chain. Slot 1 was stamped by hand after its four runs were checked complete (6,000 rows for Jev, 2,000 for each baseline, no error row).
- On 2026-11-01 the TypeSafe credits ran out at 18:25 UTC, in the run of Jev at a random k = 4 at D = 100, and every later call failed with HTTP 402. That run and the next five runs of Jev went to the Trash with their stamps, and make runs them again. Since then a run with any error row gets no stamp.
- Since 2026-11-01, after slot 6, each Jev run holds one seed, and the seeds of every line and D are those of the table in [Changes after results](#changes-after-results), entry of 2026-11-01. Each stamp holds the name of its run's directory, so `results/design-cicids2017/stage6-done/` maps every line, D and seed to its run.

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

### 2026-11-01: seed 0 alone for the ablations and the β check

Seen: slots 1 to 6 had been run and read (D = 1 in full, and at D = 100 the full system, Jev at a fixed k = 1 and the four baselines) when the TypeSafe credits ran out. The 16 runs of Jev left at three seeds would cost about 16 USD by `prices.json`, and 6.60 USD were added. Across seeds 0 to 2 the F1 of every Jev line had a standard deviation of 0.007 at most. The change below was decided to fit the credits, after those results had been read.

Changed:

- Each Jev run holds one seed, and its stamp is `<line>-d<D>-s<seed>`. The stamps of the runs made before hold three seeds each, so their three stamps name the same directory.
- The full system and Jev at a fixed k = 1 keep seeds 0 to 2 at every D, because they carry the central comparisons. The other Jev lines at D = 100 and 500 and the β check at every D run seed 0 alone (`STAGE6_FEW_SEEDS` in the `Makefile`). The 20 runs left come to about 5.75 USD by `prices.json`.
- Seed 0 of Jev at a random k = 4 at D = 100 was taken back from the run the credits cut, `20261101T181110.948478Z-cicids2017-jev-paper`. Its 2,000 rows had no error, because the HTTP 402 rows began in seed 1 at step 1,448. Each cell starts a fresh memory, so the rows equal those of a run of seed 0 alone. Its `config.json` lists seed 0 and a `salvaged` entry with the seeds first run, and the whole original stays in the Trash.

| Line                                      | D = 1   | D = 100       | D = 500 |
| ----------------------------------------- | ------- | ------------- | ------- |
| Full system                               | 0, 1, 2 | 0, 1, 2       | 0, 1, 2 |
| Jev at a fixed k = 1                      | 0, 1, 2 | 0, 1, 2       | 0, 1, 2 |
| Jev at a random k = 4                     | 0, 1, 2 | 0, taken back | 0       |
| Without the `KController` (fixed k = 4)   | 0, 1, 2 | 0             | 0       |
| Without the `Selector`                    | 0, 1, 2 | 0             | 0       |
| Without the compact record                | 0, 1, 2 | 0             | 0       |
| β = 1.5 and β = 3                         | 0       | 0             | 0       |
| Random Forest, Isolation Forest, both kNN | 0       | 0             | 0       |

Not changed: Jev IDS itself, its parameters, the lines, the delays and the order of the slots. The seeds set how precisely a line is measured, and Jev IDS performs the same with any of them. The runs at D = 1 keep their three seeds, every table reports its `cells`, and the McNemar test compares seed 0 at every D. `make -k stage6 STAGE6_FEW_SEEDS="0 1 2"` adds seeds 1 and 2 later and runs only the seeds still without a stamp.

### 2026-11-02: the nearest benign Flow and paper-v2

Seen: slots 1 to 12 of stage 6 had been run and read, and slot 13 stopped at 1,756 of 2,000 Flows of β = 1.5 at D = 1 for a reason not found (no process alive, no sleep logged). Read at 0.5, the full system at D = 500 raised about 90 false alarms per seed. About three quarters of them were benign TCP Flows to port 80 or 443, and Jev named 71 % of them DoS. A replay of the logged answers with no call rebuilt every request of the full system (0 mismatches in k and in the number of Examples) and found where they came from. Benign web Flows were flagged in 5 % of the requests that showed only benign Examples and in 28 % of those that showed a DoS Example. The benign Example shown next to a false alarm lay at a median distance of 4.28 from it, while the nearest benign Flow in memory lay at 0.64, and 363 benign Flows on average were nearer than the one shown. Similarity enters the score as a rank among about 32,000 benign candidates, and the 400 nearest all score about 0.99, so recency and difficulty chose the benign Example. The `KController` and D did not explain the false alarms, and 26 benign Flows were flagged by every line in every seed at D = 500, the share no Example fixed.

Test of the `Selector` (`results/selector-test-20261102/`, 5.7 M input tokens, about 0.24 USD). The rows are `splits/selector-test.csv`, 400 Flows of `test.csv` that no split held: 200 benign TCP Flows to port 80 or 443 from Wednesday to Friday, when DoS Examples exist, 100 novel attacks and 100 known ones. Each variant ran one stream with Jev, D = 1, the `KController` at β = 2, the compact record and seed 0, with no failed call. V0 is the `Selector` of D6, V1 drops difficulty, V3 keeps similarity alone and V4 adds the nearest benign Flow to V0's Examples. A memory frozen at the pool would give every Flow difficulty 0.5 and make V0 and V1 send the same requests, so each variant had its own memory and controller, and its Examples and tokens differ for that reason too. McNemar compares each variant with V0, Flow by Flow.

| Variant at 0.5          | False alarms of 200 | Recall | Novel recall | Examples | Tokens per Flow | McNemar on benign Flows |
| ----------------------- | ------------------- | ------ | ------------ | -------- | --------------- | ----------------------- |
| V0, D6                  | 28                  | 0.995  | 0.99         | 6.79     | 3,901           |                         |
| V1, no difficulty       | 12                  | 0.985  | 0.98         | 8.15     | 4,361           | p = 0.00086             |
| V3, similarity alone    | 11                  | 0.990  | 0.98         | 3.87     | 2,826           | p = 0.00091             |
| V4, V0 + nearest benign | 8                   | 0.990  | 0.99         | 4.78     | 3,186           | p = 0.000088            |

At 0.64 the false alarms were 4, 1, 3 and 2 and the recall 0.890, 0.915, 0.970 and 0.925. No variant lost an attack V0 caught with a significant McNemar test. Limits: recall sat near its ceiling, D was 1, the benign Flows were web Flows only, one seed ran, and three novel attack names were present (`DoS Slowhttptest`, `Infiltration - Portscan`, `SSH-Patator`). A logistic model fitted on the replays of stage 6 had predicted that V3 and V4 would lose novel recall at D = 500 (0.79 and 0.69), which this test at D = 1 cannot check.

Changed:

- The full system adds the nearest benign Flow in memory to its Examples after MMR, when MMR left it out (`--selection score+nearest`, `Selector(space, anchor)` in `jev_ids/selector.py`). The repository's code rebuilt V4's 400 requests with the same k and number of Examples in every row.
- The paper split has been read, so the new full system is measured on `splits/paper-v2.csv`, 2,000 Flows drawn with seed 20261102 from the rows of `test.csv` that no other split holds (`draw_split --min-novel 250`, 293 novel attacks), read once.
- D takes 1, 250 and 500, equal steps up to a quarter of the 2,000-Flow stream. D = 100 of the paper split has no pair on `paper-v2`.
- The cut is tuned again as D9 fixes it, on the validation stream run with the new `Selector` (`make v2-cut`), and written below before phase 1 runs. The full system and the Jev ablations are read at that cut, the other baselines at 0.5, as in stage 6.
- Fixed before phase 1 runs, every line reports F1 at its cut, false alarms, recall, novel recall at first contact and after feedback, recall at a false positive rate of 1 % and of 5 %, precision at 1 % prevalence, and input tokens per Flow.
- Phase 1 (`make -k v2`, 21 runs, about 2.5 USD by `prices.json`) runs the full system at seeds 0 to 2 and the Random Forest, the Isolation Forest and both kNN at seed 0, at every D.
- Phase 2 (`make -k v2-phase2`, 32 runs, about 9.5 USD) runs the full system without the nearest benign Flow (V0, `--selection score`) and Jev at a fixed k = 1, seeds 0 to 2, then Jev at a random k = 4 and the full system without the `KController`, without the `Selector` and without the compact record, seed 0, at every D, and β = 1.5 and β = 3 at D = 500, seed 0. It runs if the full system beats the Random Forest at D = 500 in F1 or in recall at a false positive rate of 1 %. Whatever runs is reported.
- The kNN at `matched:4` keeps the K of D10, which counts the `Selector`'s Examples at k = 4 without the nearest benign Flow, so it reads at most one Flow fewer than Jev does at k = 4.
- The six β runs of slot 13 on the paper split are not run, because they measure the `Selector` this change replaces. The partial run `20261102T001127.417018Z-cicids2017-jev-paper` has no stamp.

Not changed: the score and its weights, MMR and λ, D4, the values of D5, D7, the criterion of D9, the baselines of D10 and Jev's prompt. The runs of stage 6 on the paper split stay as the first reading, reported with this change.

The cut, written before phase 1 ran. `make v2-cut` ran the new full system over the 300 validation Flows (177 BENIGN, 123 attacks, no novel attack), seeds 0 to 2, at commit `0fa4ee8`, with no failed call (`results/design-cicids2017/20261102T043354.589088Z-cicids2017-jev-validation`). `jev-ids threshold` picked p_attack ≥ 0.58, with mean F1 1.000 against 0.991 at 0.5. At 0.5 the run raised 2, 2 and 3 false alarms per seed and missed no attack, against 17.7 false alarms per seed for the `Selector` of D6 on the same stream. At 0.58 it raised none and missed none. The margin is thin, because the highest benign p_attack was 0.55 and the lowest attack p_attack was 0.58, so 0.58 sits on an attack. The full system and the Jev ablations on `paper-v2` are read at 0.58.

Phase 1, read on 2026-11-02. `make -k v2` ran from 04:39 to 07:01 UTC at commit `90629a2`, with no failed call in the 19 stamped runs (`results/design-cicids2017/v2-done/`). TypeSafe credits ran out (HTTP 402) at row 1,870 of the full system at D = 250, seed 1, so seeds 1 and 2 at D = 250 have no stamp and the partial run `20261102T060811.607409Z-cicids2017-jev-paper-v2` is left out. The stamped Jev runs used 41.3 M input tokens (1.74 USD) and the partial one 5.5 M (0.23 USD). The full system is read at 0.58 and averaged over its seeds, the baselines at 0.5 with seed 0. Precision at 1 % assumes that 1 % of Flows are attacks.

| D   | Line             | Seeds | F1    | False alarms | Recall | Novel, first contact | Novel, after feedback | Recall at FPR 1 % | Recall at FPR 5 % | Precision at 1 % | Tokens per Flow |
| --- | ---------------- | ----- | ----- | ------------ | ------ | -------------------- | --------------------- | ----------------- | ----------------- | ---------------- | --------------- |
| 1   | Full system      | 3     | 0.984 | 1.7          | 0.971  | 1.000                | 0.953                 | 0.995             | 0.999             | 0.86             | 2,950           |
| 1   | Random Forest    | 1     | 0.988 | 1            | 0.978  | 0.333                | 0.952                 | 0.998             | 0.998             | 0.91             | 0               |
| 1   | Isolation Forest | 1     | 0.495 | 75           | 0.354  | 0.333                | 0.328                 | 0.118             | 0.215             | 0.05             | 0               |
| 1   | kNN, k = 4       | 1     | 0.983 | 1            | 0.967  | 0.667                | 0.931                 | 0.985             | 0.985             | 0.91             | 0               |
| 1   | kNN, matched     | 1     | 0.963 | 2            | 0.931  | 0.333                | 0.834                 | 0.988             | 0.988             | 0.83             | 0               |
| 250 | Full system      | 1     | 0.929 | 3            | 0.870  | 0.577                | none                  | 0.960             | 0.999             | 0.75             | 3,092           |
| 250 | Random Forest    | 1     | 0.872 | 0            | 0.773  | 0.290                | none                  | 0.897             | 0.921             | 1.00             | 0               |
| 250 | Isolation Forest | 1     | 0.494 | 75           | 0.353  | 0.328                | none                  | 0.056             | 0.218             | 0.05             | 0               |
| 250 | kNN, k = 4       | 1     | 0.869 | 1            | 0.769  | 0.287                | none                  | 0.787             | 0.787             | 0.89             | 0               |
| 250 | kNN, matched     | 1     | 0.873 | 2            | 0.776  | 0.311                | none                  | 0.793             | 0.793             | 0.80             | 0               |
| 500 | Full system      | 3     | 0.914 | 5            | 0.847  | 0.516                | none                  | 0.931             | 0.999             | 0.64             | 2,909           |
| 500 | Random Forest    | 1     | 0.873 | 0            | 0.774  | 0.294                | none                  | 0.890             | 0.928             | 1.00             | 0               |
| 500 | Isolation Forest | 1     | 0.487 | 74           | 0.346  | 0.328                | none                  | 0.047             | 0.213             | 0.05             | 0               |
| 500 | kNN, k = 4       | 1     | 0.869 | 1            | 0.769  | 0.287                | none                  | 0.787             | 0.787             | 0.89             | 0               |
| 500 | kNN, matched     | 1     | 0.874 | 2            | 0.778  | 0.311                | none                  | 0.793             | 0.793             | 0.80             | 0               |

At D = 1 first contact covers one Flow per novel attack name, 3 in all. At D = 250 and 500 no Flow of a novel name came back before its last Flow in the stream, so all 293 novel attacks met Jev at first contact and the after-feedback column is empty. McNemar compares each seed of the full system with each baseline, Flow by Flow. At D = 1 the full system ties the Random Forest (p from 0.22 to 0.43) and kNN at k = 4 (p from 0.66 to 1), and it beats the matched kNN (p ≤ 2e-5) and the Isolation Forest. At D = 250 and 500 it beats every baseline in every seed with p ≤ 5e-5, and the Random Forest at D = 500 with p from 2.4e-8 to 1e-5. The rule for phase 2 is met at D = 500, in F1 (0.914 against 0.873) and in recall at a false positive rate of 1 % (0.931 against 0.890).

The full system at D = 500 can be set beside stage 6 on the paper split (the `Selector` of D6) at the same cut of 0.58, but the Flows differ, so the comparison is unpaired. Its false alarms fell from 37 to 45 per seed to 4 to 6, and its novel recall fell too. `DoS Slowhttptest` was caught in 0.53 to 0.58 of its Flows against 0.95 to 0.98 (0.79 to 0.83 against 1.00 at 0.5), and in seeds 0 and 2 Jev named some of those Flows BENIGN. `Infiltration - Portscan` (0.29 to 0.31 against 0.36 to 0.37) and `SSH-Patator` (0.66 to 0.75 against 0.67 to 0.68) moved less. The middle half of each novel name's p_attack lies between 0.47 and 0.69 in every seed, around the cut, and at 0.5 the full system at D = 500 caught 0.943 to 0.948 of the attacks with 10 to 12 false alarms. The hypothesis is that the nearest benign Flow pulls this slow web attack toward BENIGN, and phase 2 tests it with V0 on `paper-v2`, the paired comparison. The cut stays at 0.58, as written before phase 1.

### 2026-11-02: D from the bursts and the paper battery

Seen: each novel attack name of `paper-v2` arrives in one burst. `SSH-Patator` holds stream positions 435 to 584, `DoS Slowhttptest` 782 to 898 and `Infiltration - Portscan` 1,344 to 1,515, so each burst spans 116 to 171 positions. At D = 250 and 500 no Flow of a novel name came back before its burst ended, so both delays measured Jev with no Example of the novel attack, and the Random Forest scored F1 0.872 and 0.873 at them. No run covered the delays shorter than a burst, where the Flows of a novel attack come back while it lasts. The TypeSafe credits left also call for fewer runs than phase 2 asked.

Changed:

- D takes 1, then 25, 50 and 100, all shorter than the shortest burst, and 200, longer than the longest. D = 200 is expected to match D = 250 and 500, and the runs of phase 1 at those delays are reported with it. The delays come from the bursts of `paper-v2`, the split they are measured on, and the paper says so.
- The paper battery replaces phase 2 and runs at once, with no rule between them, at seed 0 only. The full system, the four baselines and the full system without the nearest benign Flow (V0, `--selection score`) run at every D. Jev without the `Selector`, at a fixed k = 1, at a fixed k = 4, with the full record and with random Examples at a fixed k = 4 run at D = 1, 50 and 200, and β = 1.5 and β = 3 at D = 200. The runs of phase 1 at D = 1 count.
- `make -k v2-paper-jev` holds the 26 Jev runs, most important first, about 8.2 USD by `prices.json` and the tokens per Flow of stage 6. `make -k v2-paper-baselines` holds the 16 baseline runs, and the two chains may run at the same time.
- Seeds 1 and 2 of any line can run later. With one seed, a gap in F1 below about 0.01 may come from the seed, since seeds 0 to 2 of the full system at D = 500 ranged from 0.911 to 0.920.
- The full system at D = 250 keeps seed 0 alone, and seeds 1 and 2 there leave the plan.

Not changed: Jev IDS, its parameters, the cut of 0.58, the metrics fixed before phase 1, the baselines of D10 and the runs of phase 1.

The paper battery, read on 2026-11-02. `make -k v2-paper-jev` and `make -k v2-paper-baselines` ran side by side from 14:30 to 19:32 UTC at commit `af3a7f3`, with no failed call in the 42 runs. The 26 Jev runs used 200.1 M input tokens (8.40 USD). Every line is read at seed 0, the Jev lines at 0.58 and the baselines at 0.5, so the full system at D = 1 is seed 0 of phase 1. Novel recall carries its number of Flows in brackets. McNemar counts the Flows only the full system got right against those only the line got right, at the same D.

| D   | Line                  | F1    | False alarms | Recall | Novel, first contact | Novel, after feedback | Recall at FPR 1 % | Recall at FPR 5 % | Precision at 1 % | Tokens per Flow | McNemar against the full system |
| --- | --------------------- | ----- | ------------ | ------ | -------------------- | --------------------- | ----------------- | ----------------- | ---------------- | --------------- | ------------------------------- |
| 1   | Full system           | 0.985 | 2            | 0.972  | 1.000 (3)            | 0.945 (290)           | 0.994             | 0.998             | 0.83             | 3,029           |                                 |
| 1   | V0, no nearest benign | 0.979 | 27           | 0.985  | 1.000 (3)            | 0.959 (290)           | 0.937             | 0.989             | 0.27             | 3,300           | 33 / 20, p = 0.098              |
| 1   | Random Forest         | 0.988 | 1            | 0.978  | 0.333 (3)            | 0.952 (290)           | 0.998             | 0.998             | 0.91             | 0               | 16 / 22, p = 0.42               |
| 1   | kNN, k = 4            | 0.983 | 1            | 0.967  | 0.667 (3)            | 0.931 (290)           | 0.985             | 0.985             | 0.91             | 0               | 25 / 21, p = 0.66               |
| 1   | kNN, matched          | 0.963 | 2            | 0.931  | 0.333 (3)            | 0.834 (290)           | 0.988             | 0.988             | 0.83             | 0               | 58 / 17, p = 2.2e-06            |
| 1   | Isolation Forest      | 0.495 | 75           | 0.354  | 0.333 (3)            | 0.328 (290)           | 0.118             | 0.215             | 0.05             | 0               | 687 / 8, p = 1.6e-191           |
| 25  | Full system           | 0.978 | 2            | 0.958  | 0.450 (40)           | 0.960 (253)           | 0.990             | 0.998             | 0.83             | 3,114           |                                 |
| 25  | V0, no nearest benign | 0.972 | 29           | 0.973  | 0.775 (40)           | 0.953 (253)           | 0.938             | 0.996             | 0.26             | 3,245           | 38 / 26, p = 0.17               |
| 25  | Random Forest         | 0.961 | 0            | 0.926  | 0.625 (40)           | 0.826 (253)           | 0.981             | 0.991             | 1.00             | 0               | 61 / 31, p = 0.0023             |
| 25  | kNN, k = 4            | 0.951 | 1            | 0.907  | 0.600 (40)           | 0.771 (253)           | 0.938             | 0.938             | 0.90             | 0               | 79 / 30, p = 3e-06              |
| 25  | kNN, matched          | 0.942 | 2            | 0.892  | 0.600 (40)           | 0.715 (253)           | 0.943             | 0.943             | 0.82             | 0               | 94 / 29, p = 3.4e-09            |
| 25  | Isolation Forest      | 0.494 | 77           | 0.354  | 0.625 (40)           | 0.281 (253)           | 0.030             | 0.214             | 0.05             | 0               | 686 / 19, p = 1e-175            |
| 50  | Full system           | 0.970 | 5            | 0.947  | 0.653 (75)           | 0.940 (218)           | 0.978             | 0.998             | 0.66             | 2,984           |                                 |
| 50  | V0, no nearest benign | 0.971 | 29           | 0.972  | 0.880 (75)           | 0.927 (218)           | 0.929             | 0.991             | 0.26             | 3,339           | 42 / 43, p = 1                  |
| 50  | Random Forest         | 0.947 | 0            | 0.900  | 0.427 (75)           | 0.812 (218)           | 0.971             | 0.977             | 1.00             | 0               | 81 / 40, p = 0.00024            |
| 50  | kNN, k = 4            | 0.934 | 1            | 0.878  | 0.373 (75)           | 0.743 (218)           | 0.908             | 0.908             | 0.90             | 0               | 103 / 39, p = 7.6e-08           |
| 50  | kNN, matched          | 0.925 | 2            | 0.862  | 0.320 (75)           | 0.697 (218)           | 0.913             | 0.913             | 0.82             | 0               | 118 / 38, p = 9.7e-11           |
| 50  | Isolation Forest      | 0.494 | 77           | 0.354  | 0.427 (75)           | 0.294 (218)           | 0.046             | 0.215             | 0.05             | 0               | 676 / 23, p = 5.6e-168          |
| 100 | Full system           | 0.954 | 4            | 0.915  | 0.596 (193)          | 0.960 (100)           | 0.956             | 1.000             | 0.70             | 3,102           |                                 |
| 100 | V0, no nearest benign | 0.943 | 28           | 0.918  | 0.596 (193)          | 0.980 (100)           | 0.831             | 0.953             | 0.25             | 3,259           | 53 / 32, p = 0.029              |
| 100 | Random Forest         | 0.906 | 0            | 0.828  | 0.415 (193)          | 0.580 (100)           | 0.932             | 0.954             | 1.00             | 0               | 120 / 38, p = 4.2e-11           |
| 100 | kNN, k = 4            | 0.898 | 1            | 0.816  | 0.389 (193)          | 0.550 (100)           | 0.841             | 0.841             | 0.89             | 0               | 138 / 44, p = 1.7e-12           |
| 100 | kNN, matched          | 0.892 | 2            | 0.806  | 0.373 (193)          | 0.490 (100)           | 0.847             | 0.847             | 0.81             | 0               | 148 / 43, p = 1.1e-14           |
| 100 | Isolation Forest      | 0.495 | 75           | 0.354  | 0.415 (193)          | 0.160 (100)           | 0.051             | 0.215             | 0.05             | 0               | 655 / 34, p = 3.8e-150          |
| 200 | Full system           | 0.925 | 3            | 0.862  | 0.543 (293)          | none                  | 0.938             | 0.999             | 0.75             | 3,096           |                                 |
| 200 | V0, no nearest benign | 0.929 | 22           | 0.887  | 0.621 (293)          | none                  | 0.805             | 0.949             | 0.29             | 3,351           | 51 / 56, p = 0.7                |
| 200 | Random Forest         | 0.873 | 0            | 0.774  | 0.294 (293)          | none                  | 0.885             | 0.908             | 1.00             | 0               | 126 / 43, p = 1.2e-10           |
| 200 | kNN, k = 4            | 0.869 | 1            | 0.769  | 0.287 (293)          | none                  | 0.787             | 0.787             | 0.89             | 0               | 143 / 54, p = 1.8e-10           |
| 200 | kNN, matched          | 0.873 | 2            | 0.776  | 0.311 (293)          | none                  | 0.793             | 0.793             | 0.80             | 0               | 141 / 57, p = 2.1e-09           |
| 200 | Isolation Forest      | 0.495 | 75           | 0.354  | 0.328 (293)          | none                  | 0.063             | 0.220             | 0.05             | 0               | 615 / 45, p = 6.2e-129          |

| D   | Line          | F1    | False alarms | Recall | Novel, first contact | Novel, after feedback | Recall at FPR 1 % | Recall at FPR 5 % | Precision at 1 % | Tokens per Flow | McNemar against the full system |
| --- | ------------- | ----- | ------------ | ------ | -------------------- | --------------------- | ----------------- | ----------------- | ---------------- | --------------- | ------------------------------- |
| 1   | Full system   | 0.985 | 2            | 0.972  | 1.000 (3)            | 0.945 (290)           | 0.994             | 0.998             | 0.83             | 3,029           |                                 |
| 1   | No `Selector` | 0.925 | 69           | 0.920  | 0.667 (3)            | 0.838 (290)           | 0.603             | 0.891             | 0.12             | 3,510           | 141 / 23, p = 6.8e-22           |
| 1   | Fixed k = 1   | 0.978 | 3            | 0.960  | 1.000 (3)            | 0.934 (290)           | 0.990             | 0.998             | 0.77             | 2,848           | 15 / 2, p = 0.0023              |
| 1   | Fixed k = 4   | 0.990 | 6            | 0.987  | 1.000 (3)            | 0.976 (290)           | 0.995             | 0.999             | 0.63             | 6,033           | 11 / 21, p = 0.11               |
| 1   | Full record   | 0.982 | 2            | 0.966  | 0.667 (3)            | 0.955 (290)           | 0.991             | 0.999             | 0.83             | 3,846           | 18 / 12, p = 0.36               |
| 1   | Random, k = 4 | 0.957 | 75           | 0.988  | 1.000 (3)            | 0.983 (290)           | 0.726             | 0.940             | 0.12             | 5,410           | 83 / 25, p = 1.9e-08            |
| 50  | Full system   | 0.970 | 5            | 0.947  | 0.653 (75)           | 0.940 (218)           | 0.978             | 0.998             | 0.66             | 2,984           |                                 |
| 50  | No `Selector` | 0.935 | 65           | 0.936  | 0.853 (75)           | 0.881 (218)           | 0.620             | 0.907             | 0.13             | 3,490           | 113 / 42, p = 1e-08             |
| 50  | Fixed k = 1   | 0.962 | 3            | 0.930  | 0.693 (75)           | 0.904 (218)           | 0.983             | 1.000             | 0.76             | 2,841           | 29 / 14, p = 0.032              |
| 50  | Fixed k = 4   | 0.978 | 6            | 0.962  | 0.733 (75)           | 0.954 (218)           | 0.981             | 0.999             | 0.62             | 6,021           | 29 / 43, p = 0.12               |
| 50  | Full record   | 0.972 | 3            | 0.948  | 0.680 (75)           | 0.917 (218)           | 0.988             | 0.999             | 0.77             | 3,843           | 20 / 23, p = 0.76               |
| 50  | Random, k = 4 | 0.955 | 73           | 0.982  | 0.973 (75)           | 0.963 (218)           | 0.760             | 0.934             | 0.12             | 5,388           | 82 / 48, p = 0.0036             |
| 200 | Full system   | 0.925 | 3            | 0.862  | 0.543 (293)          | none                  | 0.938             | 0.999             | 0.75             | 3,096           |                                 |
| 200 | No `Selector` | 0.886 | 58           | 0.843  | 0.628 (293)          | none                  | 0.554             | 0.826             | 0.13             | 3,692           | 133 / 59, p = 9.7e-08           |
| 200 | Fixed k = 1   | 0.916 | 4            | 0.849  | 0.532 (293)          | none                  | 0.955             | 0.999             | 0.69             | 2,816           | 31 / 17, p = 0.059              |
| 200 | Fixed k = 4   | 0.928 | 8            | 0.872  | 0.587 (293)          | none                  | 0.915             | 0.989             | 0.53             | 5,899           | 51 / 56, p = 0.7                |
| 200 | Full record   | 0.923 | 3            | 0.860  | 0.546 (293)          | none                  | 0.944             | 0.998             | 0.75             | 4,120           | 37 / 35, p = 0.91               |
| 200 | Random, k = 4 | 0.927 | 69           | 0.926  | 0.771 (293)          | none                  | 0.690             | 0.885             | 0.12             | 5,322           | 76 / 72, p = 0.81               |
| 200 | β = 1.5       | 0.925 | 3            | 0.863  | 0.553 (293)          | none                  | 0.949             | 1.000             | 0.75             | 3,087           | 15 / 16, p = 1                  |
| 200 | β = 3         | 0.930 | 4            | 0.872  | 0.580 (293)          | none                  | 0.947             | 0.998             | 0.69             | 3,103           | 19 / 28, p = 0.24               |

Against the Random Forest the full system ties at D = 1 (p = 0.42) and wins at every longer delay, with p = 0.0023 at D = 25 and p ≤ 2.4e-4 from D = 50, while the gap in F1 grows from 0.017 to 0.052. Both kNN and the Isolation Forest lose at every D ≥ 25. F1 at D = 200 matches D = 250 and 500 of phase 1 for the full system (0.925, 0.929, 0.920) and for the Random Forest (0.873, 0.872, 0.873), as expected once D passes the longest burst. Without the `Selector`, Jev loses at every D with 58 to 69 false alarms (p ≤ 1e-7). At a fixed k = 1 it loses at D = 1 and 50 (p = 0.0023 and 0.032) and ties at D = 200 (p = 0.059). At a fixed k = 4 it ties at every D (p from 0.11 to 0.7) with about twice the tokens per Flow (5,899 to 6,033 against 2,984 to 3,096). The full record ties at every D (p ≥ 0.36) with 3,843 to 4,120 tokens per Flow, so the compact record saves 21 % to 25 %. β = 1.5 and β = 3 tie with β = 2 at D = 200 (p = 1 and 0.24). Random Examples at a fixed k = 4 lose at D = 1 and 50 (p = 1.9e-8 and 0.0036) and tie at D = 200 (p = 0.81), with 69 to 75 false alarms and a recall at a false positive rate of 1 % of 0.69 to 0.76.

V0 sets the nearest benign Flow against the same Flows. It raised 22 to 29 false alarms against 2 to 5, and its recall at a false positive rate of 1 % was 0.805 to 0.938 against 0.938 to 0.994. F1 differed by at most 0.011, McNemar favoured the full system at D = 100 (p = 0.029) and found no difference at the other delays (p ≥ 0.098). V0 caught more novel attacks at first contact at D = 25, 50 and 200 (0.775 against 0.450, 0.880 against 0.653, 0.621 against 0.543) and as many at D = 100 (0.596). The hypothesis written after phase 1 holds in part, because the nearest benign Flow buys most of the drop in false alarms and costs novel recall at first contact. One seed was run, so gaps in F1 below about 0.01 may come from the seed.

The sign test of stage 6 compares the full system with each line at each D, on all Flows, on known attacks and on novel attacks, through `metrics.sign_test` and `metrics.holm`. `jev-ids sign-test` pairs rows by k, and the Jev lines share no k with the baselines, so each side's k was set to one value before the test. With one seed each Flow has one Verdict per line, so the test on all Flows equals McNemar above. Holm runs over the three subsets of each pair, as `jev-ids sign-test` does, and again over all 126 rows of the battery as one family.

- Against the Random Forest, the full system wins on all Flows and on novel attacks at every D ≥ 25 (Holm p ≤ 0.0055), and on known attacks at D = 100 and 200 (Holm p = 0.00098), with ties on known attacks at D ≤ 50. Over the whole family, the win on all Flows holds from D = 50 (p ≤ 0.019) and fails at D = 25 (p = 0.16).
- Against both kNN and the Isolation Forest, it wins on all Flows at every D ≥ 25, also over the whole family (p ≤ 0.00025).
- Without the `Selector`, Jev loses on all Flows at every D, also over the whole family (p ≤ 8.7e-6). On novel attacks at D = 200 it catches more (58 Flows against 33, Holm p = 0.011, family p = 0.76).
- At a fixed k = 1, Jev loses on all Flows at D = 1 (Holm p = 0.007) and on known attacks at D = 1 and 200 (Holm p = 0.023 and 0.0059), and no row holds over the whole family.
- At a fixed k = 4, with the full record and with β = 1.5 or 3, no subset differs at any D (Holm p ≥ 0.067).
- With random Examples at k = 4, Jev loses on all Flows at D = 1 and 50 (Holm p = 5.6e-8 and 0.0073) and catches more novel attacks at D = 50 and 200 (36 Flows against 7 and 72 against 5, family p = 0.00073 and 3.1e-14), at the price of 69 to 75 false alarms.
- V0 differs from the full system in no row over the whole family. With Holm per pair, it catches more known attacks at D = 50 (13 Flows against 2, p = 0.022) and more novel attacks at D = 200 (54 against 31, p = 0.05).

Cost against F1, seed 0, from the tables above. At every D the full system spends 5 % to 10 % more input tokens than Jev at a fixed k = 1 and gains 0.007 to 0.008 in F1. Jev at a fixed k = 4 doubles the tokens (5,899 to 6,033 per Flow) for an F1 at most 0.008 higher, with no subset differing in the sign test. The full record adds 21 % to 25 % of tokens for no difference. Random Examples at k = 4 cost 1.7 to 1.8 times the tokens of the full system and score a lower F1 at D = 1 and 50. The full system therefore sits at the knee of the curve.

The repetitions, read on 2026-11-02. `make -k results/design-cicids2017/v2-done/full-d{25,50,100,200}-s{1,2}` ran seeds 1 and 2 of the full system at D = 25, 50, 100 and 200 from 22:53 UTC on 2026-11-02 to 00:25 UTC on 2026-11-03, with no failed call in the 8 runs. They used 49.2 M input tokens (2.07 USD). Their `config.json` names commit `58d09ce` with the suffix `-dirty`, because this file held an uncommitted edit while they ran, and no code file differed from that commit. The rows at D = 1 and 500 are the three seeds of phase 1. Each seed is read at 0.58 and the Random Forest at 0.5. The sign test is the one above, with Holm over the three subsets of each pair, run for each seed against the one run of the Random Forest.

| D   | F1, seeds 0 / 1 / 2   | F1, mean ± SD | False alarms | Novel recall (293)    | Random Forest F1 | All Flows, Holm p per seed | Novel attacks, Holm p per seed |
| --- | --------------------- | ------------- | ------------ | --------------------- | ---------------- | -------------------------- | ------------------------------ |
| 1   | 0.985 / 0.985 / 0.983 | 0.984 ± 0.001 | 2 / 1 / 2    | 0.945 / 0.966 / 0.949 | 0.988            | 0.91 / 0.53 / 0.44         | 1 / 0.53 / 1                   |
| 25  | 0.978 / 0.975 / 0.973 | 0.975 ± 0.002 | 2 / 2 / 2    | 0.891 / 0.887 / 0.870 | 0.961            | 0.0055 / 0.027 / 0.056     | 0.0055 / 0.0066 / 0.042        |
| 50  | 0.970 / 0.968 / 0.970 | 0.969 ± 0.001 | 5 / 6 / 3    | 0.867 / 0.863 / 0.853 | 0.947            | 4.9e-4 / 0.0014 / 4.3e-4   | 5.7e-6 / 4.8e-6 / 6.1e-5       |
| 100 | 0.954 / 0.950 / 0.957 | 0.954 ± 0.004 | 4 / 4 / 2    | 0.720 / 0.706 / 0.737 | 0.906            | 1.3e-10 / 1.1e-8 / 4.8e-12 | 8.0e-10 / 1.1e-8 / 6.5e-11     |
| 200 | 0.925 / 0.922 / 0.923 | 0.923 ± 0.001 | 3 / 3 / 3    | 0.543 / 0.536 / 0.543 | 0.873            | 3.6e-10 / 1.4e-8 / 1.5e-9  | 4.5e-9 / 6.3e-8 / 3.5e-9       |
| 500 | 0.920 / 0.911 / 0.912 | 0.914 ± 0.005 | 4 / 6 / 5    | 0.549 / 0.505 / 0.495 | 0.873            | 4.8e-8 / 2.1e-5 / 6.0e-6   | 5.2e-9 / 1.9e-6 / 4.5e-6       |

Across seeds 0 to 2 the F1 of the full system has a standard deviation of 0.005 at most and spans 0.009 at most (D = 500). Seed 0 lies within 0.003 of the mean from D = 1 to 200 and 0.006 above it at D = 500. From D = 25 every seed scores a higher F1 than the Random Forest, and the mean gap grows from 0.014 at D = 25 to 0.050 at D = 200. Every seed wins on novel attacks from D = 25 (Holm p ≤ 0.042), on all Flows from D = 50 (Holm p ≤ 0.0014) and on known attacks at D = 100 and 200 (Holm p ≤ 0.031). At D = 25 the win on all Flows holds in seeds 0 and 1 (Holm p = 0.0055 and 0.027) and misses in seed 2 (Holm p = 0.056). At D = 1 the Random Forest scores 0.003 to 0.005 higher in every seed with no difference on all Flows (Holm p ≥ 0.44), and in seed 1 it wins on known attacks (16 Flows against 4, Holm p = 0.035). The other Jev lines keep seed 0 alone, so a gap between two of them smaller than the spread of the full system at their D may come from the seed.
