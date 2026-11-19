# JevIDS design

JevIDS detects zero-day attacks in a Stream of network flow records whose true labels come back late. This document gives each design decision with its reason, the values fixed before the runs, the battery that measures it and the results. The terms (Flow, Stream, Memory, Cut, First contact) are those of `CONTEXT.md`.

Two Detectors make up the full JevIDS, and the fusion of D12 joins them.

- Jev alone is Jev (TypeSafe's System One Model, `jev-1.13.0`) with the `Selector` (D6), the `KController` (D5) and the compact record (D7). The `Makefile` names its runs `full`.
- The matched kNN is a majority vote of as many neighbours as the `Selector` would give Jev at k = 4 (D10).

```
Flows in order of end ──► Jev alone judges F_t ────┐
                     └──► matched kNN judges F_t ──┴──► fusion: mean of the two percentiles ──► Verdict at the Cut
                               ▲                         │
          k per Category ──────┤                         │ at step t + D
          Examples ────────────┤                         ▼
                             Memory ◄── F_t with its true Category and Jev's answer
```

## Decisions

### D1. Two datasets, CIC-IDS2017 and TRUSTLab

CIC-IDS2017 is read in the relabelled version of Liu et al. (IEEE CNS 2022), five days of a lab network in 2017 with six Categories. TRUSTLab (Villafranca, Tasic and Cano, Frontiers in Computer Science, 2026, doi 10.3389/fcomp.2026.1803271, data at doi 10.82432/10317/21203, CC BY 4.0) adds a recent capture with fifteen attack families. Its traffic is scripted in a lab, and each family was captured in a session of its own, without benign traffic. Both carry timestamps, which a Stream needs.

`scripts/prepare_trustlab.py` writes `data/trustlab/` by these rules, fixed on 2026-11-16 before any stream run on TRUSTLab.

- Each of the 15 families is a Category with one attack name, its own, because the files carry no finer label.
- The card holds 70 columns, renamed to the names of the CIC-IDS2017 card. The TCP-stack columns leave as on CIC-IDS2017 (D7), and the columns TRUSTLab lacks stay out.
- Pool and test follow D2 per UTC day and family, with the caps of `prepare_cicids2017.py` and seed 20261116.
- The novel families come from `random.Random(20261116).sample` of 4 from the 15 sorted names, and DoS and DDoS leave together as twins. The draw gave C2Beaconing, DDoS, DoS, MITM and WebBased, which never reach the pool. An offline probe had been read before this rule, so the rule draws the families with a seed and chooses none of them.
- The prompt describes every family in one line taken from the dataset's README and article.

### D2. Pool and test cut per (day, attack name)

Each (day, attack name) group is sorted in time and cut in half. The earlier half feeds the pool and the later half the test file, so an Example never comes after a judged Flow of its attack name, and every day of the test file holds benign Flows. One cut over the whole week would have left the test side without a benign Flow before Wednesday afternoon. The caps (`POOL_CAPS`, `TEST_CAPS`) apply per attack name after the cut. On CIC-IDS2017 the three novel attack names (`SSH-Patator`, `DoS Slowhttptest` and `Infiltration - Portscan`) never reach the pool, and each of their Categories keeps another name there.

### D3. The stream is ordered by the end of each Flow

A flow record exists only once the flow has ended, so a Flow is judged at `timestamp + Flow Duration`, ties broken by `row_id`. Flow Duration is in microseconds. Its maximum is 119,999,962 in the CIC-IDS2017 pool, which matches a 120 s flow timeout. That reading is an inference from the values, and the dataset does not state it.

### D4. Memory and feedback delay D

The `Memory` holds every labeled Flow that has ended before "now". A pool Flow becomes visible once it ends before the Flow under test ends. A judged Flow enters the Memory D steps after its judgement, with its true Category, its attack name and Jev's whole answer (`p_attack`, `category_pred`, `confidence`). A step is one Flow of the stream, so with D = 1 the Flow judged at step t is visible at step t + 1.

The delay stands for the time between an attack slipping through and someone noticing it. D is the same for every Flow. A D tied to Flow Duration was rejected, because duration is a property of each attack and says nothing about its discovery. Feedback is assumed complete, so every judged Flow eventually gets its true label, missed attacks included. The paper declares this assumption.

D is a scenario, reported and never tuned. Each novel attack name of the CIC-IDS2017 `paper` split arrives in one burst: `SSH-Patator` at positions 414 to 556, `DoS Slowhttptest` at 753 to 849 and `Infiltration - Portscan` at 1,279 to 1,473, so a burst spans 97 to 195 positions. D = 1 is the immediate best case, D = 50 lets a burst's first Flows come back while it lasts, and D = 200 is longer than the longest burst. At D = 1, 50 and 200 the split holds 3, 93 and 309 novel Flows at first contact, and the TRUSTLab split 5, 203 and 338 of its 403.

### D5. `KController`: mirrored AIMD, one k per Category

TCP grows its window slowly and halves it on loss, because overshooting is the costly error there. In an IDS a missed attack costs more than extra tokens, so the rule is mirrored. It multiplies k on an error and lowers it a little on each success.

```
on feedback for a Flow whose true Category is c:
  error   (category_pred ≠ c):  k_c ← min(k_max, β · k_c)
  correct:                      k_c ← max(k_min, k_c − α / k_c)
Categories without feedback keep their k.
Examples used for c = ceil(k_c), or every visible Example of c when fewer exist.
```

| Parameter    | Value | Meaning                                                                           |
| ------------ | ----- | --------------------------------------------------------------------------------- |
| k₀           | 1     | Start cheap and grow only on evidence of error                                    |
| k_min, k_max | 1, 8  | Past k = 4, Jev's F1 stayed flat while its cost doubled                           |
| β            | 2     | Double on error                                                                   |
| α            | 1     | Each success removes 1/k_c, so k drops by one Example per window of k_c successes |

k_max comes from a pilot on CIC-IDS2017 with random Examples. Jev scored F1 0.942 at k = 4 and 0.943 at k = 8, while its cost went from 557 to 1,063 USD per 1M Flows. `uv run jev-ids metrics results/20261027T150927.433285Z-cicids2017-jev-pilot` gives these numbers again. The controller reacts when the label arrives, at t + D. An error is `category_pred` differing from the true Category, a missing Category answer included. A row with `error` is ignored. Every stream cell starts a fresh controller at k₀ = 1 for every Category, and every row carries `k_by_category`, the k of each Category before the ceiling. `jev-ids run --control aimd --k 1` runs it, and `--beta` changes β.

On TRUSTLab the controller meets a limit of the TypeSafe API. With 16 Categories, 10 of them had reached k = 8 by step 1,513 of the `paper` stream, and from there 144, 154 and 155 calls of seeds 0, 1 and 2 failed with HTTP 400 `max_tokens_exceeded`. The largest answered call held 33,047 input tokens. A lower k_max would change this decision, and the user kept it as it is on 2026-11-16. The full JevIDS covers these Flows with the matched kNN (D12).

### D6. `Selector`: one score, MMR and the nearest benign Flow

For each Category c the `Selector` picks ceil(k_c) Examples among the visible Memory Flows of c.

```
score(e) = similarity(e, F_t) + recency(e) + difficulty(e)        equal weights, not tuned
repeat ceil(k_c) times: take the e maximising
    λ · score(e)/3 − (1 − λ) · max over chosen e' of redundancy(e, e')      λ = 0.5
then add the nearest benign Flow of the Memory when the pick left it out
```

- Similarity and recency are ranks within the Category's candidates, scaled to [0, 1]. The nearest and the newest Flow get 1, the farthest and the oldest get 0, and a single candidate gets 1. Equal distances or ends share their mean rank.
- Distance is Euclidean over the features standardised with the pool's mean and standard deviation, with Protocol one-hot. A constant feature keeps scale 1.
- Difficulty is 1 when Jev was wrong on e, 1 − |2 · p_attack − 1| when it was right, and 0.5 for pool Flows and for failed calls.
- Redundancy is 1 / (1 + distance), in [0, 1]. MMR (maximal marginal relevance) keeps near copies of one burst from filling the slots. An exact copy of a chosen Example is never chosen.
- The Examples of a request are shuffled with a seed made of the Flow's `row_id` alone, so the same Flow gets the same request in every run.

The nearest benign Flow joined on 2026-11-02 (`--selection score+nearest`). Without it, similarity entered the score only as a rank among tens of thousands of benign candidates, so recency and difficulty chose a benign Example far from the Flow under test, and benign web Flows were flagged as DoS. On 200 benign web Flows of CIC-IDS2017 it cut false alarms from 28 to 8 (McNemar p = 0.000088), with no significant loss of caught attacks.

### D7. Compact record and the columns every Detector reads

Numbers sent to Jev and to the LLM baseline keep 4 significant digits. A value written as an integer stays as it is, any other number loses its exponent and keeps 4 significant digits, and text that is not a finite number (`inf`, `nan`) stays. `Flow Bytes/s` exceeds 10⁶ and some times are 10⁻⁵, so a fixed number of decimals would erase the small values and leave the large ones long. Jev bills input tokens alone, and its input tokens equal the characters of the record plus a constant, so a character saved is a token saved. The forests and the kNN read the full values. `record` (`full` or `compact`) is written in `config.json` and in every row, and `jev-ids run --record` sets it, `compact` by default.

On 2026-11-15, before the battery of D11, five columns left the cards: `Fwd Header Length`, `Bwd Header Length`, `FWD Init Win Bytes`, `Bwd Init Win Bytes` and `Fwd Seg Size Min`. They describe the TCP stack of the sending host, so a Detector could learn the testbed's hosts instead of the traffic. The list is closed. CIC-IDS2017 keeps 78 columns and TRUSTLab 70. The flow id, both addresses, the ephemeral source port and the timestamp never entered a card.

### D8. One request per Flow

Judging several Flows per request was dropped, because it needs code that does not improve the design and an unverified fact about how TypeSafe bills a shared state. The compact record (D7) is the only deliberate token cut, and the `KController` saves tokens as a side effect.

### D9. Cut and metrics fixed before the test split

A Verdict is `attack` when p_attack ≥ the Cut. The Cut is the candidate with the highest F1 averaged over the (seed, rep) cells of a development stream, among 0.5 and every p_attack in its rows, a tie going to the candidate nearest 0.5. It is taken once per Dataset, on the fused development stream of the full JevIDS (D12), and every Detector is read at it. `jev-ids threshold` computes it and refuses rows of any other split, so a test split never shapes it.

Every attack name of the pool already sits in the Memory, so `scripts/draw_dev.py` builds the development stream by taking some names out of it. It draws 1,000 pool Flows (300 BENIGN, 150 of the held-out names in equal shares and 550 other attacks) and writes `data/<dataset>-dev/` with the split `validation`. The 1,000 Flows leave the Memory too and enter it only through feedback.

- CIC-IDS2017 holds out `DoS Hulk`, the name with the most pool Flows in the only Category with two names in the pool. The draw uses seed 20261115.
- TRUSTLab has one name per Category, so `--held-out` takes the families drawn by `random.Random(20261116).sample` of 3 from the 10 that stay in the pool, closed under the twin rule: DNS, Exploitation and TLSSSL. The draw uses seed 20261116.

Jev alone ran over each development stream at D = 200 with seeds 0, 1 and 2, and the matched kNN once. Fused by D12, they give the Cut 0.2608 on CIC-IDS2017 and 0.377 on TRUSTLab. TRUSTLab's seeds 1 and 2 ran on 2026-11-18, and with seed 0 alone its Cut had been 0.3899.

The claim rests on the novel Flows at first contact, 309 on CIC-IDS2017 and 338 on TRUSTLab at D = 200, set against the benign Flows of the test stream. The primary metric is the ROC-AUC over those Flows, and the secondary one is the PR-AUC, the average precision over the same Flows. Neither needs a Cut. At the Cut the report gives the F1 on them, the novel Flows caught and the false alarms. A missing p_attack counts as 0. On 2026-11-15, before the runs, the recall at a false positive rate of 1 % was named the primary metric. The user set the recall at 1 %, at 5 % and at the Cut side by side on 2026-11-16, after a partial reading of the battery, and on 2026-11-18, after reading the whole battery, replaced them with the ROC-AUC and the F1 at the calibrated Cut. The same day, after those results, the user added the PR-AUC as secondary. It weighs each false alarm by how much it dilutes the precision an analyst sees. It stays secondary because its random floor is the share of novel Flows, 0.228 on CIC-IDS2017 and 0.298 on TRUSTLab at D = 200, which moves with the Dataset and with D. A bootstrap that resamples the novel and the benign Flows apart, in circular blocks of 25 consecutive Flows, 2,000 times, gives the 95 % interval of each F1, each ROC-AUC, each PR-AUC and each difference between two Detectors on the same Flows. McNemar's exact test on the same Flows compares two Detectors Flow by Flow.

The blocks exist because Flows judged close together see almost the same Memory. A fixed seed gives every run of one Dataset and D the same replicates, so a difference between two Detectors is computed replicate by replicate. The interval leaves out the spread across seeds and the choice of the Cut. McNemar's test ignores false alarms, so each comparison also carries the paired bootstrap, and its p values have no correction for multiple comparisons. The report also gives the recall on known attacks and the F1 over all 2,000 Flows, which show whether a Detector trades the attacks it knew for the novel ones.

### D10. Baselines see what Jev sees

| Baseline         | How                                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Random Forest    | Refitted on the visible Memory at every Flow, so it gets the same past and the same feedback                              |
| Isolation Forest | Refitted on the benign Flows of the visible Memory at every Flow                                                          |
| kNN, K = 4       | The 4 nearest Flows of the whole visible Memory, in the `Selector`'s space, vote by majority                              |
| kNN, matched     | The same vote with as many neighbours as the `Selector` gives Jev at k = 4 for the same Memory (`--neighbours matched:4`) |
| Sonnet 5.5       | D13                                                                                                                       |

A refit every 100 steps was tried first. On a 300-Flow pilot, 100 steps spanned about a day and a half of capture while each attack lasts minutes, so each refit came before the attack it should have learned, and the Random Forest's recall fell to 0.093. The refit at every Flow is the forests' best case and too slow to deploy, since a fit takes up to 17.5 s on one core at 90,000 Flows. `train_time_ms` in every row reports that cost. The forests, both kNN and the Isolation Forest are deterministic, so each runs with seed 0 alone. In the kNN the most frequent Category wins, a tie going to the Category of the nearest tied neighbour, and p_attack is the share of neighbours that are attacks.

The matched kNN reads as many Flows as Jev reads Examples, so the gap between the two measures what the language model adds to the Memory.

### D11. The zero-day battery

The battery measures Jev alone, its ablations and the baselines on test splits that no earlier run had read. The runs go to `results/zeroday-<dataset>/`, and a run that ends with no error row leaves a stamp in `v2-done/`.

| Dataset     | Split   | Flows | BENIGN | Novel | Novel at first contact (D = 1 / 50 / 200) |
| ----------- | ------- | ----- | ------ | ----- | ----------------------------------------- |
| CIC-IDS2017 | `paper` | 2,000 | 1,046  | 309   | 3 / 93 / 309                              |
| TRUSTLab    | `paper` | 2,000 | 798    | 403   | 5 / 203 / 338                             |

CIC-IDS2017's `paper` was drawn on 2026-11-15 as `paper-v3`, with seed 20261115 and `--min-novel 250`, from the rows of `test.csv` that earlier splits held out, and renamed on 2026-11-19. TRUSTLab's `paper` was drawn with seed 20261116.

The battery holds 17 Jev runs and 12 baseline runs on CIC-IDS2017, and 13 Jev runs and 12 baseline runs on TRUSTLab, all stamped.

- Jev alone runs at D = 200 with seeds 0, 1 and 2. At D = 1 and 50 it runs with seeds 0, 1 and 2 on CIC-IDS2017 and with seed 0 on TRUSTLab.
- Four ablations run at D = 200 on both datasets. They are the `KController` with random Examples (no `Selector`), the `Selector` at a fixed k = 1 (the `KController`'s reaction to errors removed), the `Selector` at a fixed k = 4 (no `KController`) and random Examples at a fixed k = 4. The two with the `Selector` run with seeds 0, 1 and 2, the two with random Examples with seed 0.
- The Random Forest, the Isolation Forest and both kNN run at D = 1, 50 and 200 with seed 0.

Six TRUSTLab Jev runs hold failed calls of D5, from 42 to 391 of their 2,000 rows. They are Jev alone at every D and seed and the ablation without the `Selector`. `make` withholds the stamp of a run with an error row, so their stamps were added outside `make`. Jev ran on TRUSTLab under a rule fixed before it, that the Random Forest at D = 200 catch fewer than 90 % of the novel Flows at first contact at 1 % or at 5 %. It caught 0 of 338 at 1 %.

### D12. The full JevIDS

Each p_attack of Jev alone and of the matched kNN becomes its percentile among that Detector's p_attack on the development stream, ties at the mid rank. The p_attack of the full JevIDS is the mean of the two percentiles. The Cut is taken on the fused development stream by D9's rule, 0.2608 on CIC-IDS2017 and 0.377 on TRUSTLab, and every Detector is read at it. Jev and the kNN never read each other's answers, so `jev-ids fuse` builds the full JevIDS from a finished run of each over the same Stream, joined by `row_id`, at no cost. When Jev's call fails, the matched kNN's percentile alone is the p_attack, and the row keeps Jev's error as `error_jev` with `fallback` set.

The two Detectors catch different Flows. At the Cut on CIC-IDS2017 Jev alone catches all 309 novel Flows at first contact and the matched kNN 86. On TRUSTLab the matched kNN catches all 87 C2Beaconing Flows and Jev alone 68 to 71, while Jev alone catches 26 to 28 of the 81 DoS Flows and the matched kNN none.

### D13. Sonnet 5.5 as the LLM baseline

`jev-ids run --detector llm:sonnet` judges each Flow with Claude Sonnet 5.5 (`claude-sonnet-5-5`) through one Agno Agent and the Anthropic API, with one call per Flow, no tools and no retry of our own. The settings are effort `low`, thinking `between_tools` (with no tools, the model answers without thinking), no temperature, no prompt cache, at most 1,024 output tokens and a 120 s timeout. The answer is the structured `Judgement` (`verdict`, `category`, `p_attack`), sent as Anthropic's native structured output. The instructions are `prompts/<dataset>/llm.md`, the same column list and Category descriptions Jev reads, with the Examples filled in. A refusal arrives as HTTP 200 with `stop_reason: "refusal"`, and the row records its category as `error`. `prices.json` prices the model at 2 USD per 1M input tokens, 0.10 per 1M cached input tokens and 10 per 1M output tokens. On 2026-11-17 it ran over the same test splits at D = 200 with seeds 0, 1 and 2, with the `Selector` and the `KController` of Jev alone (`--k 1 --control aimd --selection score+nearest`), whose k follows Sonnet's own answers. In seed 0 it read 9.4 Examples per Flow on CIC-IDS2017 and 57.8 on TRUSTLab, against Jev's 5.5 and 58.3. Sonnet is read at the Dataset's Cut, like every other Detector. A refusal counts like any failed call, as p_attack 0. Sonnet refused 9 to 16 calls per run on CIC-IDS2017 and 72 to 79 on TRUSTLab, all with the category `cyber`, and 258 of the 261 fell on attack Flows. Of them, 2 to 6 and 8 to 14 per run fell on novel Flows at first contact.

On CIC-IDS2017 Sonnet's F1 on the novel Flows at first contact is 0.932 to 0.939 and the full JevIDS's 0.937 to 0.946, and the bootstrap interval of the difference contains 0 in every seed. Their ROC-AUC is 0.978 to 0.991 and 0.994 to 0.995, and their PR-AUC 0.971 to 0.980 and 0.975 to 0.978. The interval of the PR-AUC difference contains 0 in every seed, and that of the ROC-AUC difference lies above 0 in seed 0 alone. At the Cut the full JevIDS catches 288 to 291 novel Flows and Sonnet 274 to 278. McNemar's test pairs runs of the same seed. It gives 34 to 17 discordant Flows in seed 0 (p = 0.024), 35 to 20 in seed 1 (p = 0.058) and 31 to 21 in seed 2 (p = 0.21). On TRUSTLab the full JevIDS leads in F1, in ROC-AUC and in PR-AUC in every seed, with an F1 of 0.837 to 0.840 against 0.706 to 0.726, and catches 264 to 266 novel Flows against 192 to 200 (p ≤ 2.6 × 10⁻¹⁷).

A run of 2,000 Flows cost 15.76 to 15.82 USD with Sonnet on CIC-IDS2017 and 51.88 to 52.27 USD on TRUSTLab, against 0.25 and 1.30 to 1.32 USD for Jev at TypeSafe's list price, 62 and 39 to 40 times more. On CIC-IDS2017, where the two tie in F1, Sonnet costs 62 times as much per Flow.

## Evaluation rules

- A test split is read once, after its Cut is written.
- A failed call is a row with `error`, counted as `normal` (fail-open) and as p_attack 0 in every metric. It enters the Memory like any judged Flow, gives difficulty 0.5 and does not feed the `KController`. `redo-errors` keeps the error rows of a stream run, because the later Flows saw them in their Memory. It only resumes an interrupted stream run from the first Flow without a row, with the Memory and the k its stored rows rebuild.
- Attack names never reach a request. The Memory keeps them for analysis, and Examples carry the Category alone.
- Each change made after a result names the result that prompted it.

## Results

Every number of the paper is in `results/paper/numbers.json`, written by `make paper-numbers`. The table reads every Detector at D = 200 and at its Dataset's Cut, over the novel Flows at first contact, 309 on CIC-IDS2017 and 338 on TRUSTLab, and the benign Flows, 1,046 and 798. Rows of Jev alone, of the full JevIDS and of Sonnet 5.5 give seeds 0 / 1 / 2. The TRUSTLab rows count every Flow, so Jev's failed calls score 0 and the full JevIDS falls back on the kNN for them.

| Dataset     | Detector         | ROC-AUC               | PR-AUC                | F1 on novel Flows     | Novel Flows caught | False alarms    |
| ----------- | ---------------- | --------------------- | --------------------- | --------------------- | ------------------ | --------------- |
| CIC-IDS2017 | Full JevIDS      | 0.995 / 0.995 / 0.994 | 0.976 / 0.978 / 0.975 | 0.946 / 0.943 / 0.937 | 291 / 289 / 288    | 15 / 15 / 18    |
| CIC-IDS2017 | Jev alone        | 0.994 / 0.994 / 0.993 | 0.969 / 0.970 / 0.964 | 0.836 / 0.833 / 0.827 | 309 / 309 / 309    | 121 / 124 / 129 |
| CIC-IDS2017 | Random Forest    | 0.836                 | 0.732                 | 0.365                 | 69                 | 0               |
| CIC-IDS2017 | kNN, matched     | 0.648                 | 0.457                 | 0.434                 | 86                 | 1               |
| CIC-IDS2017 | kNN, K = 4       | 0.626                 | 0.423                 | 0.399                 | 77                 | 0               |
| CIC-IDS2017 | Isolation Forest | 0.871                 | 0.517                 | 0.371                 | 309                | 1,046           |
| CIC-IDS2017 | Sonnet 5.5       | 0.978 / 0.982 / 0.991 | 0.971 / 0.980 / 0.980 | 0.932 / 0.935 / 0.939 | 274 / 274 / 278    | 5 / 3 / 5       |
| TRUSTLab    | Full JevIDS      | 0.930 / 0.933 / 0.932 | 0.908 / 0.911 / 0.909 | 0.838 / 0.840 / 0.837 | 264 / 266 / 265    | 28 / 29 / 30    |
| TRUSTLab    | Jev alone        | 0.925 / 0.925 / 0.924 | 0.861 / 0.855 / 0.854 | 0.785 / 0.776 / 0.780 | 263 / 258 / 257    | 69 / 69 / 64    |
| TRUSTLab    | Random Forest    | 0.867                 | 0.796                 | 0.833                 | 256                | 21              |
| TRUSTLab    | kNN, matched     | 0.860                 | 0.818                 | 0.801                 | 254                | 42              |
| TRUSTLab    | kNN, K = 4       | 0.856                 | 0.773                 | 0.788                 | 246                | 40              |
| TRUSTLab    | Isolation Forest | 0.697                 | 0.414                 | 0.539                 | 320                | 529             |
| TRUSTLab    | Sonnet 5.5       | 0.872 / 0.883 / 0.879 | 0.797 / 0.803 / 0.793 | 0.706 / 0.726 / 0.709 | 192 / 200 / 197    | 14 / 13 / 21    |

The ablations below are runs of the full JevIDS at D = 200 with one part of Jev changed, read at the Cut. The two lines without the `Selector` ran seed 0 alone, and the others ran seeds 0 to 2.

On CIC-IDS2017 the full JevIDS reaches a ROC-AUC of 0.994 to 0.995 and an F1 of 0.937 to 0.946. The `Selector` at a fixed k = 1 ties with it in both, and the bootstrap interval of each difference contains 0 in every seed. The `Selector` at a fixed k = 4 falls to an F1 of 0.888 to 0.897, below in every seed, and its run costs 0.48 USD against 0.25. The `KController` with random Examples falls to an F1 of 0.748 and a ROC-AUC of 0.951 with 188 false alarms, and random Examples at a fixed k = 4 to 0.743 and 0.954 with 180.

On TRUSTLab the full JevIDS reaches 0.930 to 0.933 and 0.837 to 0.840. The `Selector` at a fixed k = 1 ties in F1, with 0.831 to 0.838 and 13 to 19 false alarms against 28 to 30, and its ROC-AUC of 0.892 to 0.893 lies below in every seed. Its run costs 0.39 USD against 1.30 to 1.32, with no failed call against 144 to 155. The `Selector` at a fixed k = 4 gives an F1 of 0.810 to 0.824 and a ROC-AUC of 0.903 to 0.906. Without the `Selector` the F1 falls to 0.678 and 0.651, with 223 and 277 false alarms. The `KController` raises k on the Categories Jev misses, so with 16 Categories a request carries 58.3 Examples on average and outgrows TypeSafe's input limit.

## Rejected

| Idea                                    | Why not                                                                                        |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Several Flows per request               | D8                                                                                             |
| D derived from Flow Duration            | D4                                                                                             |
| Jev's own label as feedback             | Its errors would become Examples that make the next similar error look right                   |
| A Jev pass over the pool for difficulty | It costs money and adds a step, so pool Flows get 0.5                                          |
| A lower k_max on TRUSTLab               | It would change D5 after a result, and the fallback of the full JevIDS covers the failed calls |

## Running

Every command runs through `make` or with `UV_PROJECT_ENVIRONMENT=$HOME/.venvs/jev-ids`, so `uv run` creates no `.venv` in the repository. `DATASET` picks `cicids2017` or `trustlab`.

- `make zeroday-cut` runs Jev alone over the development stream, and `make zeroday-knn-cut` the matched kNN. Both feed the Cuts of D9 and D12.
- `make -k zeroday-baselines` runs the 12 baseline runs, at no cost.
- `make -k zeroday-jev` runs the 9 Jev runs, which bill TypeSafe. With `DATASET=trustlab` it would also launch D = 50 and D = 1, which were never planned there. Jev alone and the ablation without the `Selector` can never stamp there, because some calls outgrow TypeSafe's input limit, so it would run them again on every call.
- `jev-ids fuse` builds a run of the full JevIDS, and `jev-ids threshold` reads a Cut.
