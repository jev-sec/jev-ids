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
| Stage 1                                 | Stream and memory implemented (`jev_ids/stream.py`); line 0 running     |
| Stages 2 to 6 below                     | Not started                                                             |

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

### D7. Compact record, no column removed

Numbers sent to Jev are written with 4 significant digits, not a fixed number of decimals: `Flow Bytes/s` exceeds 10⁶ and some times are
10⁻⁵, so cutting decimals would erase the small values and leave the large ones long. Only the text sent to Jev (and the LLM) changes;
the forests keep the full values. No column is removed: selective column removal adds decisions a reviewer can question.

### D8. One request per Flow

Judging several Flows per request was dropped to avoid code changes that do not improve the design. An open question would have had to be
settled first anyway: each Flow of a batch needs its own questions, and whether TypeSafe bills the state once or per question was never
verified. Without batches the cost per Flow stays high; the compact record (D7) is the only deliberate token cut, and the `KController`
may save tokens as a side effect.

### D9. Decision threshold tuned on validation

The verdict is p_attack ≥ 0.5 today (`docs/protocol.md`). On the pilot, Jev at k = 8 had PR-AUC 0.989 but precision 0.893, which suggests
the ranking is good and the 0.5 cut is not. The cut is chosen on a validation stream drawn from the pool, as the last stage, because the
dynamic k changes the distribution of p_attack.

### D10. Baselines see what Jev IDS sees

| Baseline         | How                                                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Jev, random k    | Stage 1: Examples drawn at random from the visible memory, k = 4 for every Category                                                                       |
| Random Forest    | Refitted on the visible memory at every Flow, so it gets the same past and the same feedback as Jev IDS; one seed, since the forest does not depend on it |
| Isolation Forest | Refitted on the benign Flows of the visible memory at every Flow; one seed                                                                                |
| kNN              | The same neighbours the `Selector` finds, majority vote; if it matches Jev IDS, Jev adds nothing                                                          |

A forest fitted once on the whole pool would see later pool Flows (the future) and never the feedback; a reviewer could point at either.

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
| 1. Stream        | `Memory` and the stream loop; random Examples, k = 4                                                                                                                                           | Tests: the memory never returns a Flow from the future; a Flow enters exactly at t + D; no attack name reaches a request | Line 0: Jev, RF, IF                      |
| 2. Record        | 4 significant digits                                                                                                                                                                           | Test: large and small values keep their order of magnitude                                                               | Line 1, with tokens per Flow             |
| 3. `Selector`    | Score and MMR, k = 4                                                                                                                                                                           | Test: two identical Flows are never chosen together                                                                      | Line 2 and the kNN baseline              |
| 4. `KController` | Mirrored AIMD                                                                                                                                                                                  | Tests: error, success and absent Category                                                                                | Line 3                                   |
| 5. Threshold     | Cut tuned on the validation stream                                                                                                                                                             | The test splits are never read                                                                                           | Line 4                                   |
| 6. Final         | The paper split, once: full system, leave-one-out ablation, D ∈ {1, 100, 500}, statistics                                                                                                      | McNemar and the Holm-adjusted sign test that already exist                                                               | Final table, cost against F1 curve       |

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
- Comparisons of cost are made at equal tokens per Flow, or as a cost against F1 curve.

## Notes for implementation

- Attack names never reach a request (`CONTEXT.md`); the memory keeps them for analysis only, and Examples carry the Category.
- The Jev template asks two questions about `flows.under_test`: `is_attack` (`noul`, gives p_attack) and `category` (`choice`, gives the
  Category and a confidence). `request_body` in `jev_ids/detectors/jev.py` fills `flows.under_test` and `examples`.
- A failed call is a row with `error`, counted as normal (fail-open, `docs/protocol.md`). Proposed: it enters the memory with its true
  label, difficulty 0.5 and no Jev answer, and the `KController` ignores it. To confirm in stage 1.
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
