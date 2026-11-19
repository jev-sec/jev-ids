<img src="docs/banner.svg" alt="JevIDS banner showing the jev_ids terminal lockup, the tagline &quot;Intrusion detection with a System One Model, on a stream of flows whose labels come back late.&quot;, and the command that streams CIC-IDS2017 through Jev" width="100%" />

# JevIDS

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-0B6B3A?style=flat&labelColor=121917) ![Detector Jev, from TypeSafe](https://img.shields.io/badge/detector-Jev%20%28TypeSafe%29-0B6B3A?style=flat&labelColor=121917) ![Datasets CIC-IDS2017 and TRUSTLab](https://img.shields.io/badge/datasets-CIC--IDS2017%20%C2%B7%20TRUSTLab-0B6B3A?style=flat&labelColor=121917) ![License MIT](https://img.shields.io/badge/license-MIT-0B6B3A?style=flat&labelColor=121917)

**JevIDS detects zero-day attacks in a stream of network flows whose labels come back late. For each flow it shows [TypeSafe's Jev](https://docs.typesafe.ai/introduction) labeled flows it has already seen, from 1 to 8 per category, asks whether the flow under test is an attack, and joins that answer with a nearest-neighbour vote.**

An intrusion detection system (IDS) watches the traffic of a network and raises an alarm when it suspects an attack. JevIDS was tested on two public datasets, CIC-IDS2017 and TRUSTLab, with each label coming back 200 flows after its flow was judged. Its ROC-AUC on the zero-day flows was the highest of the detectors tested, 0.994 to 0.995 on CIC-IDS2017 and 0.930 to 0.933 on TRUSTLab. At an alarm cut calibrated before the test, its F1 on those flows was 0.937 to 0.946 on CIC-IDS2017, where a Random Forest reached 0.365, and 0.837 to 0.840 on TRUSTLab, where the Random Forest reached 0.833. Claude Sonnet 5.5 reached 0.932 to 0.939 and 0.706 to 0.726, at 62 and 39 to 40 times Jev's cost.

[Design](docs/jevids-design.md) · [Glossary](CONTEXT.md) · [The loop](jev_ids/stream.py) · [The fusion](jev_ids/fusion.py)

## The problem

A flow is the summary of one conversation between two computers, such as its packets, bytes, duration and port. Some attacks are new to the system, and the right answer arrives late, because an analyst confirms an attack only after someone investigates it. Here a zero-day flow is one whose attack name never appears in the starting memory, and it is at **first contact** when it is judged before any flow of its attack name has come back with its label. The results count these flows. The delay D is counted in flows, and D = 200 outlasts every zero-day burst in the CIC-IDS2017 test.

## How it works

Jev is a System One Model from TypeSafe. It reads a block of text and answers typed questions with probabilities, so there is no generated text to parse. For each flow JevIDS writes the column names, a description of each category, k labeled examples per category and the flow itself, with each decimal cut to 4 significant digits, and Jev returns p_attack, the probability of an attack, and a category. The **KController** keeps one k per category, starting at 1, doubles it up to 8 when Jev names the wrong category and lowers it by 1/k when Jev is right. The **Selector** prefers examples close to the flow under test, recent ones and ones Jev doubted, and always adds the nearest benign flow. A **matched kNN** lets as many nearest flows vote as the Selector gives Jev at k = 4, at no cost. The **full JevIDS** turns each detector's p_attack into its percentile on a development stream and takes the mean, because the two catch different attacks, and falls back on the kNN when a call to Jev fails. The memory holds the pool flows that ended before the flow under test and every judged flow whose label has come back.

## How it was tested

| Dataset                                                                               | Captured          | Test split           | Benign | Zero-day at first contact, D = 200 | Zero-day attack names                                        |
| ------------------------------------------------------------------------------------- | ----------------- | -------------------- | ------ | ---------------------------------- | ------------------------------------------------------------ |
| CIC-IDS2017, relabelled by Liu et al. (IEEE CNS 2022)                                 | July 2017         | `paper`, 2,000 flows | 1,046  | 309                                | `SSH-Patator`, `DoS Slowhttptest`, `Infiltration - Portscan` |
| TRUSTLab, Cano Baños and Villafranca Albaladejo (Frontiers in Computer Science, 2026) | May and June 2025 | `paper`, 2,000 flows | 798    | 338                                | `C2Beaconing`, `DDoS`, `DoS`, `MITM`, `WebBased`             |

Each attack name's flows of each day were cut in half in time, the earlier half feeding the pool and the later half the test. CIC-IDS2017's zero-day names leave the pool while their categories keep other names, and TRUSTLab's five zero-day families leave it whole. The baselines are a Random Forest, an Isolation Forest trained on benign flows, a kNN with K = 4 and the matched kNN, each refitted at every step on the memory JevIDS sees, and Claude Sonnet 5.5 with the same Selector and KController. Every metric counts the zero-day flows at first contact as positives and the benign test flows as negatives. The ROC-AUC, the primary metric, is the chance that a detector scores a random zero-day flow above a random benign one, 0.5 for a random score. The PR-AUC, the secondary one, weighs each false alarm by how much it dilutes the share of alarms that are real attacks. Neither needs a cut. The alarm cut, 0.2608 on CIC-IDS2017 and 0.377 on TRUSTLab, was calibrated before the test on a development stream, and every detector is read at it, where the F1 weighs the zero-day flows caught against the false alarms. A block bootstrap gives the 95 % intervals and McNemar's exact test compares the catches, as [D9](docs/jevids-design.md#d9-cut-and-metrics-fixed-before-the-test-split) details. Jev alone, the full JevIDS and Sonnet ran with seeds 0, 1 and 2, the deterministic baselines once.

## Results

Zero-day flows at first contact at D = 200, each detector read at its dataset's cut. Three numbers are seeds 0 / 1 / 2.

| Dataset                                  | Detector         | ROC-AUC               | PR-AUC                | F1 on zero-day flows  | Zero-day flows caught | False alarms    |
| ---------------------------------------- | ---------------- | --------------------- | --------------------- | --------------------- | --------------------- | --------------- |
| CIC-IDS2017 (309 zero-day, 1,046 benign) | Full JevIDS      | 0.995 / 0.995 / 0.994 | 0.976 / 0.978 / 0.975 | 0.946 / 0.943 / 0.937 | 291 / 289 / 288       | 15 / 15 / 18    |
|                                          | Jev alone        | 0.994 / 0.994 / 0.993 | 0.969 / 0.970 / 0.964 | 0.836 / 0.833 / 0.827 | 309 / 309 / 309       | 121 / 124 / 129 |
|                                          | Random Forest    | 0.836                 | 0.732                 | 0.365                 | 69                    | 0               |
|                                          | Matched kNN      | 0.648                 | 0.457                 | 0.434                 | 86                    | 1               |
|                                          | kNN, K = 4       | 0.626                 | 0.423                 | 0.399                 | 77                    | 0               |
|                                          | Isolation Forest | 0.871                 | 0.517                 | 0.371                 | 309                   | 1,046           |
|                                          | Sonnet 5.5       | 0.978 / 0.982 / 0.991 | 0.971 / 0.980 / 0.980 | 0.932 / 0.935 / 0.939 | 274 / 274 / 278       | 5 / 3 / 5       |
| TRUSTLab (338 zero-day, 798 benign)      | Full JevIDS      | 0.930 / 0.933 / 0.932 | 0.908 / 0.911 / 0.909 | 0.838 / 0.840 / 0.837 | 264 / 266 / 265       | 28 / 29 / 30    |
|                                          | Jev alone        | 0.925 / 0.925 / 0.924 | 0.861 / 0.855 / 0.854 | 0.785 / 0.776 / 0.780 | 263 / 258 / 257       | 69 / 69 / 64    |
|                                          | Random Forest    | 0.867                 | 0.796                 | 0.833                 | 256                   | 21              |
|                                          | Matched kNN      | 0.860                 | 0.818                 | 0.801                 | 254                   | 42              |
|                                          | kNN, K = 4       | 0.856                 | 0.773                 | 0.788                 | 246                   | 40              |
|                                          | Isolation Forest | 0.697                 | 0.414                 | 0.539                 | 320                   | 529             |
|                                          | Sonnet 5.5       | 0.872 / 0.883 / 0.879 | 0.797 / 0.803 / 0.793 | 0.706 / 0.726 / 0.709 | 192 / 200 / 197       | 14 / 13 / 21    |

The full JevIDS has the highest ROC-AUC on both datasets and the highest PR-AUC on TRUSTLab. Its PR-AUC and F1 tie with Sonnet's on CIC-IDS2017, and its F1 ties with the Random Forest's on TRUSTLab, with the interval of each difference containing 0 in every seed. On CIC-IDS2017 Jev alone ranks the flows almost as well, yet at the cut it flags 121 to 129 benign flows. The three seeds judge the same flows, so they are not independent evidence.

Removing the Selector hurts most. In seed 0 the full JevIDS's ROC-AUC falls from 0.995 to 0.951 on CIC-IDS2017 and from 0.930 to 0.875 on TRUSTLab, and its false alarms rise from 15 to 188 and from 28 to 223. A fixed k = 1 ties with the KController in F1 on both datasets. On TRUSTLab it costs 0.39 USD against 1.30 to 1.32 with no failed call, and its ROC-AUC falls to 0.892 to 0.893.

A run of 2,000 flows cost 0.25 USD with Jev on CIC-IDS2017 and 1.30 to 1.32 USD on TRUSTLab at TypeSafe's list price, with a median call of 0.23 s and 0.29 to 0.30 s. Sonnet cost 62 and 39 to 40 times as much, took 1.82 to 1.92 s per call and refused 9 to 16 calls per run on CIC-IDS2017 and 72 to 79 on TRUSTLab as cyber content.

### Limits worth knowing

- On TRUSTLab, 144 to 155 calls per seed failed near the end of the stream, because ten categories had reached k = 8 and the request outgrew TypeSafe's input limit. None of them fell on a zero-day flow at first contact, and the full JevIDS falls back on the kNN for them.
- The F1 peak on CIC-IDS2017 is narrow. In seed 0 the full JevIDS's F1 is 0.848 at a cut of 0.25, 0.946 at 0.2608 and 0.877 at 0.27, so the F1 depends on a cut taken from another stream.
- Every label comes back, missed attacks included. A real security team confirms only some.
- Jev's cost is TypeSafe's list price, not what was billed.

## Try it

```bash
git clone https://github.com/jev-sec/jev-ids.git
cd jev-ids
uv sync
# .env holds TYPESAFE_API_KEY for Jev and ANTHROPIC_API_KEY for the Sonnet 5.5 baseline.
```

Download `CICIDS2017_improved.zip` from the [relabelled version of Liu et al.](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) into `data/raw/cicids2017/`, or the [TRUSTLab files](https://doi.org/10.82432/10317/21203), and prepare them once. The test splits are committed, so only the pool needs the raw data.

```bash
uv run python -m scripts.prepare_cicids2017
uv run python -m scripts.prepare_trustlab --raw <folder holding the 16 *.csv.gz>
uv run jev-ids run --dataset data/cicids2017/dataset.json --detector jev --split paper --delay 200 --k 1 --control aimd --selection score+nearest --seeds 0
```

A run writes `results/<timestamp>-<dataset>-<detector>-<split>/` with `config.json`, one JSON row per flow in `predictions.jsonl` (verdict, truth, p_attack, category, confidence, the k of every category, latency and tokens) and Jev's raw answers in `responses.jsonl`. A failed call becomes a row with `error`, counted as no alarm.

## Reproduce the paper

Every number and figure of the paper comes from [`results/paper/numbers.json`](results/paper/numbers.json). It holds one entry per dataset, `cicids2017` and `trustlab`, with these keys.

| Key               | What it holds                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cut`, `cut_rule` | The cut on p_attack that every detector shares, and the mean F1 of the validation runs at that cut and at 0.5                                                                                                                                                                                                                                                                      |
| `lines`           | One entry per detector. Jev alone is `jev/<variant>-d<D>-s<seed>`, the full JevIDS `fusion/<variant>-d<D>-s<seed>`, each baseline `<baseline>/d<D>` and Sonnet 5.5 `sonnet/d200-s<seed>`. Each entry gives the F1, ROC-AUC and PR-AUC with their 95% intervals, the counts at the cut, F1 over a sweep of cuts and the cost. `run` names the directory of the run it was read from |
| `tests`           | McNemar's exact test and the bootstrap interval of each difference, one entry per pair of detectors                                                                                                                                                                                                                                                                                |
| `calibration`     | The runs over the development stream that set the cut and the percentiles of the fusion                                                                                                                                                                                                                                                                                            |
| `bursts`          | The stream positions of each attack name, its category and how many of its flows arrive at first contact                                                                                                                                                                                                                                                                           |

The runs themselves stay out of the repository. To produce them again, `DATASET` picks `cicids2017` or `trustlab`. A finished run with no failed call leaves a stamp in `results/zeroday-<dataset>/v2-done/`, so `make -k` runs again only what is missing.

```bash
make zeroday-cut DATASET=cicids2017        # Jev alone over the development stream, for its cut (paid)
make zeroday-knn-cut DATASET=cicids2017    # the matched kNN over the same stream, for the fusion
make -k zeroday-baselines DATASET=cicids2017
make -k zeroday-jev DATASET=cicids2017     # Jev alone and its ablations, 17 paid runs here and 13 on TRUSTLab
make -k zeroday-sonnet DATASET=cicids2017  # Sonnet 5.5, 3 paid runs
make paper-numbers                         # fuses, measures and compares the runs of both datasets
```

On TRUSTLab six Jev runs keep failed calls from Jev's token limit, the full JevIDS at every D and seed and the run without the Selector, so make withholds their stamps. The paper reads them as they are, so write the directory name of each one into its stamp, as in `echo <run directory> > results/zeroday-trustlab/v2-done/full-d50-s0`. `uv run jev-ids metrics <runs>` and `uv run jev-ids compare --a <run> --b <run>` read single runs. [`docs/jevids-design.md`](docs/jevids-design.md) gives every decision, the values fixed before the runs and the full battery.

## The code

| File                                   | Job                                                                                                                                                        |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [cli.py](jev_ids/cli.py)               | `run`, `redo-errors`, `metrics`, `compare`, `threshold` and `fuse`                                                                                         |
| [dataset.py](jev_ids/dataset.py)       | The card, the pool, the splits and the compact record                                                                                                      |
| [stream.py](jev_ids/stream.py)         | The stream, the memory and the labels that come back D flows late                                                                                          |
| [controller.py](jev_ids/controller.py) | The KController                                                                                                                                            |
| [selector.py](jev_ids/selector.py)     | The Selector                                                                                                                                               |
| [fusion.py](jev_ids/fusion.py)         | The full JevIDS, from a run of Jev and a run of the matched kNN                                                                                            |
| [run.py](jev_ids/run.py)               | The loop and the three files of a run                                                                                                                      |
| [records.py](jev_ids/records.py)       | One prediction row                                                                                                                                         |
| [metrics.py](jev_ids/metrics.py)       | Recall at a false alarm rate, F1, cost, latency and the paired tests                                                                                       |
| [detectors/](jev_ids/detectors)        | Jev, the Sonnet 5.5 baseline, the Random Forest, the kNN and the Isolation Forest                                                                          |
| [prompts/](prompts)                    | Per dataset, `jev.json`, the whole request to Jev, and `llm.md`, the instructions of the Sonnet 5.5 baseline                                               |
| [scripts/](scripts)                    | `prepare_<dataset>.py`, `draw_split.py` for the test splits, `draw_dev.py` for the development streams and `paper_numbers.py` for the numbers of the paper |

## Development

```bash
make check
```

Python 3.13+. The gate runs ruff, complexipy, pyright in strict mode, pytest with coverage, vulture, import-linter, pip-audit and jscpd, and `make list` shows each check. Runs make paid API calls and write only under `results/`.

## Team

<table align="center">
  <tr>
    <td align="center" width="220">
      <a href="https://github.com/paulosevero"><img src="https://github.com/paulosevero.png?size=120" width="96" alt="Paulo Severo" /></a><br />
      <b>Paulo Severo</b><br />
      <a href="https://github.com/paulosevero"><code>@paulosevero</code></a>
    </td>
    <td align="center" width="220">
      <a href="https://github.com/sequincozes"><img src="https://github.com/sequincozes.png?size=120" width="96" alt="Silvio Quincozes" /></a><br />
      <b>Silvio Quincozes</b><br />
      <a href="https://github.com/sequincozes"><code>@sequincozes</code></a>
    </td>
    <td align="center" width="220">
      <a href="https://github.com/amandadiasdev"><img src="https://github.com/amandadiasdev.png?size=120" width="96" alt="Amanda Dias" /></a><br />
      <b>Amanda Dias</b><br />
      <a href="https://github.com/amandadiasdev"><code>@amandadiasdev</code></a>
    </td>
  </tr>
</table>

---

[TypeSafe docs](https://docs.typesafe.ai/introduction) · [Jev models and pricing](https://docs.typesafe.ai/models) · [CIC-IDS2017, relabelled](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) · [TRUSTLab data](https://doi.org/10.82432/10317/21203) · [Glossary](CONTEXT.md)
