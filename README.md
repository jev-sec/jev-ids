<img src="docs/banner.svg" alt="Jev IDS banner showing the jev_ids terminal lockup, the tagline &quot;Intrusion detection with a System One Model, on a stream of flows whose labels come back late.&quot;, and the command that streams CIC-IDS2017 through the full system" width="100%" />

# Jev IDS

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-0B6B3A?style=flat&labelColor=121917) ![Detector Jev, from TypeSafe](https://img.shields.io/badge/detector-Jev%20%28TypeSafe%29-0B6B3A?style=flat&labelColor=121917) ![Datasets CIC-IDS2017 and NSL-KDD](https://img.shields.io/badge/datasets-CIC--IDS2017%20%C2%B7%20NSL--KDD-0B6B3A?style=flat&labelColor=121917) ![License MIT](https://img.shields.io/badge/license-MIT-0B6B3A?style=flat&labelColor=121917)

**Intrusion detection on a stream of network flows. For each flow, Jev IDS picks a few labeled flows from what it has already seen and shows them to [TypeSafe's Jev](https://docs.typesafe.ai/introduction) in one request. Jev answers whether the flow is an attack and which kind, in under a quarter of a second, with no text to parse.**

An intrusion detection system (IDS) watches the traffic of a network and raises an alarm when it suspects an attack. Jev IDS does this by showing an AI model, Jev, a few flows whose category is already known and asking it to judge the new one. Two components decide what Jev sees. The KController decides how many examples of each kind of traffic to show, and the Selector decides which ones. In a real network the confirmation that a flow was an attack arrives late, so Jev IDS was measured on CIC-IDS2017, a public benchmark of network attacks, with that confirmation arriving 1 to 200 flows later. With the confirmation one flow late, Jev IDS and the strongest classical detector tested, a Random Forest, are level. From a delay of 25 flows on, each of the three runs of Jev IDS scored a higher F1 than every classical detector, and the lead grows with the delay. Most of the lead comes from zero-day attacks, the ones the system had never seen. With a delay of 200 flows, Jev IDS caught 54% of them and the Random Forest 29%.

[Read the loop](jev_ids/stream.py) · [The request template](prompts/cicids2017/jev.json) · [Design log](docs/jevids-design.md) · [Glossary](CONTEXT.md)

## The problem

A flow is the summary of one conversation between two computers. It records how many packets and bytes went each way, how long the conversation lasted, which port it used and dozens of other measures. In CIC-IDS2017, the dataset used here, each line is one flow, described by 83 columns of measures and by a label that says whether it is normal traffic or which attack it belongs to.

An IDS receives each flow and decides whether it is benign traffic or part of an attack. When it decides attack, it raises an alarm.

Two facts make the task hard. The first is that attacks appear that the system has never seen, the zero-day attacks defined below. A detector that learned only from older examples tends to take a zero-day attack for normal traffic. The second is that the right answer arrives late. A security analyst confirms that a flow was an attack only some time later, when the damage shows or someone investigates. Until then the system keeps judging new flows without knowing whether it got the earlier ones right.

> **Zero-day attack.** In network security, a zero-day attack is one the defenders do not yet know when it happens, so they had zero days to prepare. Here, the zero-day attacks are the three attack names of the test that never appear in the system's starting memory ([How it was tested](#how-it-was-tested)). The system meets them for the first time during the test, with no example of them.

This delay is called D and is counted in flows. With D = 1, the label of a flow comes back just before the next flow is judged. With D = 200, it comes back only after 200 more flows have been judged.

## How it works

Jev is an AI model from TypeSafe, of a kind called a System One Model. It reads a `state`, a block of information, and answers typed questions about it with probabilities, so there is no generated text to parse. Jev IDS puts into the state the instructions, the 83 column names, a description of each category, a few flows whose category is already known (the examples) and the flow to judge. Then it asks two questions. `is_attack` comes back as a probability from 0 to 1, called p_attack. `category` comes back as one of six categories with a confidence. The categories are benign traffic (`BENIGN`) and five families of attack, listed in [How it was tested](#how-it-was-tested).

<img src="docs/verdict.svg" alt="One flow, two typed answers. is_attack, a noul question, returns 0.80, above the 0.58 cut, so the verdict is attack. category, a choice question, returns DoS with confidence 0.89. The flow is the first of a zero-day DoS Slowhttptest burst" width="100%" />

The figure shows one real flow of the test, the first flow of the zero-day attack `DoS Slowhttptest`, as Jev answered it with D = 200. The top bar is p_attack, 0.80, which is above the cut of 0.58, so the verdict is attack. The lower bar splits the probability among the six categories, with 0.91 of it on DoS, and the confidence of 0.89 says how concentrated that split is.

Around that request runs a loop over the stream of flows. The figure below draws it, and the six steps after it follow one flow through it.

<img src="docs/stream.svg" alt="The Jev IDS loop. The memory holds the pool flows that ended before the flow under test and the judged flows whose label came back. The KController sets k per category and the Selector picks the examples, written as compact records. One request goes to Jev, whose p_attack becomes the verdict at 0.58, and the true label returns D flows later to the memory and the KController" width="100%" />

The top row is one step. The flow under test goes to Jev in one request, and the answer becomes a verdict and one row of results. The bottom row is what Jev IDS adds around Jev. The memory feeds the KController and the Selector, which choose the examples that go into the request. The dashed line is the label of each judged flow, which comes back D flows later to the memory and to the KController.

The memory holds the labeled flows a step may draw examples from. These are the flows of the pool, prepared before the test, that ended before the flow under test, and every judged flow whose label has come back.

1. **The flow arrives.** CIC-IDS2017 was recorded by a tool that writes a line when each connection ends, so a real IDS receives a flow only once it has ended. Jev IDS sorts the test flows by the moment each one ended, its start time plus its duration, and judges them one at a time in that order. Each step therefore uses only information that would already have existed at that moment.
2. **The KController decides how many examples.** It keeps one number k for each category. Before each judgement, Jev receives k examples of each category, rounded up. Every k starts at 1.
3. **The Selector decides which examples.** Within each category of the memory, it prefers the flows most similar to the flow under test, the most recent ones and the ones Jev was unsure about. It then picks among them by maximal marginal relevance (MMR), which passes over near-duplicates, so the examples show varied cases. Last, it adds the benign flow nearest to the flow under test when the pick left it out, so Jev always sees the normal traffic closest to it. This last step is called the nearest benign flow.
4. **The compact record shortens the text.** Each decimal value reaches Jev with 4 significant digits, so 25160.418 becomes 25160. Integers such as ports stay as they are, and every column is kept. Text is counted in tokens, pieces of a few letters each, and Jev charges for the tokens it reads, so the compact record saves 21% to 25% of the tokens, and of the cost, with no loss in F1.
5. **Jev answers and Jev IDS decides.** Jev returns p_attack, and Jev IDS raises the alarm when p_attack is at least 0.58. That cut was taken before the test on the `validation` split, a separate stream of 300 flows, and the test flows never tuned it.
6. **The label comes back D flows later.** The judged flow enters the memory with its true category and can serve as an example from then on. The KController compares the true category with the one Jev named. When Jev was wrong, the k of the true category doubles, up to 8. When Jev was right, that k falls by 1/k, down to 1 at the least. Jev IDS thus shows more examples of the categories it gets wrong and spends fewer tokens on the ones it already handles. Every label comes back, missed attacks included.

The KController's rule mirrors the one TCP uses against congestion on the internet (AIMD), which grows the sending window slowly and halves it on a loss. In an IDS the costly mistake is showing too few examples, so the KController grows k fast after an error and shrinks it slowly after a success.

The whole request is one file, [`prompts/cicids2017/jev.json`](prompts/cicids2017/jev.json). Python adds only the flow and the examples, and the file's sha256 travels in every prediction row as `prompt_hash`, so runs that asked different things are never compared as equals. Examples are labeled by category only, and attack names such as `DoS Hulk` never reach a model.

<img src="docs/request.svg" alt="The flow under test and the examples the Selector chose go into one request to Jev, whose state holds instructions, columns, categories, examples and the flow, with two typed questions. The answers come back as p_attack 0.80, verdict attack at the 0.58 cut, and category DoS with confidence 0.89" width="100%" />

On the left are the inputs, the flow under test as a compact record and the examples the Selector chose. In the middle is the request, whose state holds the instructions, the columns, the categories, the examples and the flow, and whose two questions are typed `noul` (a probability) and `choice` (one option with a confidence). On the right are the two answers.

## How it was tested

### The data

The test uses the relabelled CIC-IDS2017 of Liu et al. (IEEE CNS 2022), published by the DistriNet group of KU Leuven. CIC-IDS2017 is public traffic recorded on a lab network over five weekdays, 3 to 7 July 2017, with attacks run by researchers. [`scripts/prepare_cicids2017.py`](scripts/prepare_cicids2017.py) sorts the flows of each label on each day by time and splits them in two halves. The earlier half may become examples, and the later half may be judged. The pool, the memory at the start of the test, is a seeded sample of the earlier half with at most 50,000 benign flows and 10,000 flows per attack name, 88,066 flows in all. The later half, sampled the same way with at most 10,000 benign flows and 1,000 per attack name, holds 19,368 flows. The 2,000 test flows of the `paper-v2` split were drawn from it, 1,020 benign and 980 attacks.

### The categories

| Category   | What the traffic is                                                         | Attack names in the test, with their flows                                                  |
| ---------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| BENIGN     | Normal traffic                                                              | 1,020 flows                                                                                 |
| DoS        | Denial of service, an attempt to bring a server down with too many requests | `DoS Slowloris` 101, `DoS Slowhttptest` 117 (zero-day), `DoS Hulk` 114, `DoS GoldenEye` 118 |
| DDoS       | The same attack, from many machines at once                                 | `DDoS` 87                                                                                   |
| PortScan   | A sweep of a machine's ports in search of open services                     | `Portscan` 106, `Infiltration - Portscan` 89 (zero-day)                                     |
| BruteForce | Guessing passwords by trial and error                                       | `FTP-Patator` 114, `SSH-Patator` 87 (zero-day)                                              |
| Botnet     | Traffic of infected machines that obey a remote controller                  | `Botnet` 47                                                                                 |

### The zero-day attacks

Three attack names never appear in the pool, so every detector meets them for the first time during the test. `SSH-Patator` guesses the passwords of remote logins (BruteForce). `DoS Slowhttptest` brings a web server down with very slow requests (DoS). `Infiltration - Portscan` is a port sweep run from inside the network by a machine already broken into (PortScan). Their categories stay in the pool through the other attack names, so Jev can still be shown examples of DoS, BruteForce and PortScan. Together they hold 293 flows, and those flows measure what matters most, the reaction to an unknown attack.

Each attack name arrives in one burst, a stretch of the stream where its flows come close together, mixed with benign flows. The three zero-day bursts span 116 to 171 flows. D = 1, 25, 50 and 100 are all shorter than the shortest burst, so some labels of a zero-day attack come back while its burst still lasts. D = 200 is longer than the longest burst, so no label of a zero-day attack comes back before its burst ends, and each detector has to recognise the attack without having seen it.

### The detectors compared

Jev IDS is compared with three classical detectors, each a different way of detecting intrusions.

- **Random Forest** (scikit-learn, 100 trees) is supervised detection, which learns from labeled examples of every category. It was the strongest classical detector in this test.
- **kNN** (4 neighbours) takes the flows of the memory nearest to the flow under test, in the same distance the Selector uses, and follows the category of the majority, with no call to Jev. It tests whether Jev adds anything beyond finding similar flows.
- **Isolation Forest** (scikit-learn, 100 trees) is anomaly detection, which learns only what benign traffic looks like and flags what departs from it. It needs no example of an attack, which makes it the natural rival on zero-day attacks.

The three are refitted at every step on the same memory as Jev IDS, the Isolation Forest on its benign flows alone. At each judgement they know exactly what Jev IDS knows at that moment. A model trained once before the test would miss the labels that come back during it, which would favour Jev IDS. A model trained once on all the data would see flows from the future, which would favour the classical detector. Refitting at every step avoids both. The classical detectors raise the alarm at p_attack ≥ 0.5, their usual cut.

### How many runs

Jev can answer slightly differently when it gets the same question twice, so the full system ran three times at each D. The classical detectors use fixed seeds and give the same answers every time, so each ran once. The tables give the mean of the three runs of Jev IDS unless they name a run.

## What the numbers mean

Every judged flow falls into one of four cases. An attack with an alarm is a hit. An attack without an alarm is a missed attack. A benign flow with an alarm is a false alarm. A benign flow without an alarm is a correct silence. The measures below combine these four counts.

- **Recall** is the share of the 980 attacks that raised an alarm, known and zero-day together. Higher is better.
- **Zero-day recall** is the same share over the 293 zero-day flows alone. Higher is better.
- **False alarms** count the benign flows, out of 1,020, that raised an alarm. Lower is better, because each one costs an analyst time.
- **F1** joins the two goals, catching attacks and avoiding false alarms, in one number from 0 to 1 that is high only when both are good. It is 2 × hits divided by (2 × hits + false alarms + missed attacks). Higher is better.
- **The paired test** says whether a difference between two detectors is real or could be luck. It looks only at the flows where the two disagree, the ones only one of them got right. If the two were equally good, those flows would split half and half, like a coin. The exact sign test gives p, the chance of a split at least as uneven as the one observed if both were equally good, and below 0.05 the difference counts as real. Holm's correction raises each p to account for the three comparisons made for each pair of detectors, on all flows, on known attacks and on zero-day attacks.

## Evidence and limits

The `paper-v2` split of CIC-IDS2017 holds 2,000 flows in the order they ended, 1,020 benign and 980 attacks, 293 of those zero-day. It was drawn from rows no earlier split held and read once. The runs of 2026-11-02 are in [`results/design-cicids2017/`](results/design-cicids2017), and [`docs/jevids-design.md`](docs/jevids-design.md) reads each one next to its stamp.

| D   | Jev IDS F1    | Random Forest F1 | kNN F1 | Isolation Forest F1 | Jev IDS zero-day recall | Random Forest zero-day recall | Jev IDS false alarms / 1,020 | Random Forest false alarms / 1,020 |
| --- | ------------- | ---------------- | ------ | ------------------- | ----------------------- | ----------------------------- | ---------------------------- | ---------------------------------- |
| 1   | 0.984 ± 0.001 | 0.988            | 0.983  | 0.495               | 0.953                   | 0.945                         | 1 to 2                       | 1                                  |
| 25  | 0.975 ± 0.002 | 0.961            | 0.951  | 0.494               | 0.883                   | 0.799                         | 2                            | 0                                  |
| 50  | 0.969 ± 0.001 | 0.947            | 0.934  | 0.494               | 0.861                   | 0.713                         | 3 to 6                       | 0                                  |
| 100 | 0.954 ± 0.004 | 0.906            | 0.898  | 0.495               | 0.721                   | 0.471                         | 2 to 4                       | 0                                  |
| 200 | 0.923 ± 0.001 | 0.873            | 0.869  | 0.495               | 0.540                   | 0.294                         | 3                            | 0                                  |

Each row is one delay D. The F1 of Jev IDS is the mean of its three runs followed by their standard deviation, and its false alarms are the range over the three runs. Each classical detector ran once.

With D = 1, Jev IDS and the Random Forest are level. Both learn almost at once from labels that come back one flow later, and the forest's slightly higher F1, 0.988 against 0.984, is a difference the paired test does not confirm. As D grows, the Random Forest falls fast, above all on zero-day attacks. Jev IDS falls more slowly, because Jev can judge an attack it has never seen from examples of the known ones. At D = 200 the F1 of Jev IDS is 0.050 above the forest's, and it catches 54% of the zero-day flows against 29%.

The Random Forest raises almost no false alarm, so the flows it loses are attacks it lets through. At D = 200 it misses all 87 flows of `SSH-Patator` and all 89 of `Infiltration - Portscan`, where the first run of Jev IDS catches 62 and 28. On `DoS Slowhttptest` at D = 200 the two forests do better than Jev IDS, with 96 of the 117 flows caught by the Isolation Forest, 86 by the Random Forest and 69 by the first run of Jev IDS. The Isolation Forest never uses the returning labels, so it stays the same at every D. It catches `DoS Slowhttptest` and neither of the other two zero-day attacks, finds about 35% of all attacks and raises 75 to 77 false alarms, which keeps its F1 near 0.49.

<img src="docs/results-cicids2017.svg" alt="F1 and zero-day recall by feedback delay D on the CIC-IDS2017 paper-v2 split. Jev IDS stays above the Random Forest and the kNN from D = 25 on and its lead grows with D, and the Isolation Forest stays flat near 0.49 F1" width="100%" />

Panel (a) shows F1 and panel (b) zero-day recall, both against the delay D, with one line per detector, and higher is better in both. The delays are evenly spaced along the horizontal axis, so the step from 100 to 200 takes the same width as the step from 1 to 25.

Flow by flow, Jev IDS beats the Random Forest on zero-day attacks in every run from D = 25 on (adjusted p ≤ 0.042) and on all flows in every run from D = 50 on (adjusted p ≤ 0.0014). At D = 25 the win on all flows holds in two runs of three (adjusted p = 0.0055 and 0.027, against 0.056). At D = 1 no run differs from the forest on all flows, and in one run the forest is better on known attacks (16 flows against 4, adjusted p = 0.035). Longer delays add nothing past D = 200. At D = 250 and 500 the first run of Jev IDS scores an F1 of 0.929 and 0.920 and the forest 0.872 and 0.873, so the gap stops growing once the delay outlasts the bursts.

### What each part adds

Each part of Jev IDS was removed or swapped in turn, one run each at D = 1, 50 and 200, and compared with the full system. This kind of test is called an ablation. The second column says what each line does differently.

| Line              | What changes                               | F1 at D = 1 / 50 / 200 | False alarms | Tokens per flow       |
| ----------------- | ------------------------------------------ | ---------------------- | ------------ | --------------------- |
| Full system       | nothing                                    | 0.985 / 0.970 / 0.925  | 2 / 5 / 3    | 3,029 / 2,984 / 3,096 |
| No Selector       | examples drawn at random from the memory   | 0.925 / 0.935 / 0.886  | 69 / 65 / 58 | 3,510 / 3,490 / 3,692 |
| Fixed k = 1       | no KController, one example per category   | 0.978 / 0.962 / 0.916  | 3 / 3 / 4    | 2,848 / 2,841 / 2,816 |
| Fixed k = 4       | no KController, four examples per category | 0.990 / 0.978 / 0.928  | 6 / 6 / 8    | 6,033 / 6,021 / 5,899 |
| Full record       | values as the CSV has them                 | 0.982 / 0.972 / 0.923  | 2 / 3 / 3    | 3,846 / 3,843 / 4,120 |
| Random, k = 4     | no Selector, no KController                | 0.957 / 0.955 / 0.927  | 75 / 73 / 69 | 5,410 / 5,388 / 5,322 |
| No nearest benign | the Selector without its benign anchor     | 0.979 / 0.971 / 0.929  | 27 / 29 / 22 | 3,300 / 3,339 / 3,351 |

The Selector matters most. Without it, Jev IDS loses on all flows at every D (adjusted p ≤ 8.7e-6) and raises 58 to 69 false alarms. With one example per category it loses on all flows at D = 1 (adjusted p = 0.007) and ties at D = 50 and 200, so the KController buys 0.7 to 0.8 points of F1 for 5% to 10% more tokens. Four examples per category tie with the full system at every D for twice the tokens. The full record ties at every D with 21% to 25% more tokens. Random examples lose at D = 1 and 50 and raise 69 to 75 false alarms. The nearest benign flow cuts the false alarms from 22 to 29 down to 2 to 5 and costs some zero-day flows at first contact. Jev itself adds something too. The kNN reads the same nearest flows without Jev, and in the first run the paired test finds no difference with it at D = 1 and a win for Jev IDS at every D from 25 on.

### Limits worth knowing

- One dataset carries the stream results. NSL-KDD has no timestamps, so it was measured as a k-shot benchmark only ([below](#earlier-benchmark-nsl-kdd)).
- The full system ran three times at each D, and every other line once. The F1 of the full system varies by up to 0.009 between runs at one D, so a smaller gap between two ablation lines may come from the run alone.
- The delays were chosen from the bursts of this same split.
- The cut of 0.58 sits on a thin margin. On the validation stream, the highest benign p_attack was 0.55 and the lowest attack p_attack 0.58.
- Every label comes back, missed attacks included. A real security team confirms only some of them.
- Jev's latency is the wall clock of one successful call to TypeSafe's API and leaves out the Selector's own time. Jev's cost is TypeSafe's list price, not what was billed.
- Jev's `noul` answer carries no confidence. Only the `choice` answer does.

## Why it is fast and cheap

- **One request, two answers.** Both questions run over the same state and come back as a probability, an option and a confidence. Nothing to parse, no schema to enforce.
- **Input only.** Jev charges $0.042 per million input tokens and nothing for output. At 2,900 to 3,100 tokens per flow, a million verdicts cost $121 to $131, and the median call took 0.22 to 0.24 s.
- **Few examples, chosen well.** The KController keeps k at 1 wherever Jev is right, and the Selector picks examples close to the flow. Drawing the examples at random instead raised the false alarms to 58 to 69 per 1,020 benign flows, against 2 to 5.
- **Fail open.** A failed call becomes a row with `error`, counted as no alert. Never a crash.

## Earlier benchmark: NSL-KDD

Before the stream, Jev IDS was measured on NSL-KDD as a k-shot detector, with k labeled examples per category drawn at random and no feedback, against Gemini 3.6 Flash on Vertex AI, a Random Forest and an Isolation Forest (2,000 flows, three seeds, runs of 2026-09-22). At k = 1 Jev was 5.4 times faster than the LLM, with a median of 0.31 s against 1.65 s per flow, and 22 times cheaper, with $74 against $1,651 per million flows. It was as precise (0.953 against 0.942) and lower on F1 (0.856 against 0.880). On zero-day attacks it caught 74.7% against 71.3%, a difference the paired test confirms only at k = 1 and 2. The tables, figures and tests are in [docs/results.md](docs/results.md) and the protocol in [docs/protocol.md](docs/protocol.md).

## Try it

```bash
git clone https://github.com/jev-sec/jev-ids.git
cd jev-ids
uv sync
# .env holds TYPESAFE_API_KEY for Jev. Gemini needs `gcloud auth application-default login` and GOOGLE_GENAI_USE_VERTEXAI=true,
# GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION=global in the environment. DEEPSEEK_API_KEY and CHATGPT_CLIENT_ID serve the other LLMs.
```

Download `CICIDS2017_improved.zip` from the [relabelled version of Liu et al.](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) into `data/raw/cicids2017/` and prepare it once. The committed splits need only the pool.

```bash
uv run python -m scripts.prepare_cicids2017
uv run jev-ids run --dataset data/cicids2017/dataset.json --detector jev --split smoke --delay 1 --k 1 --control aimd --selection score+nearest --seeds 0
```

The script drops the "Attempted" flows and the attacks with too few flows to measure (the web attacks, Heartbleed and the 36 flows labeled plain Infiltration), splits each attack's flows of each day in time between the pool and the test file, and holds three attack names out of the pool as zero-day attacks. Its docstring gives every decision and [`SOURCE.json`](data/cicids2017/splits/SOURCE.json) the counts.

The smoke split is five flows. The run writes `results/<timestamp>-cicids2017-jev-smoke/` with `config.json`, one JSON row per flow in `predictions.jsonl` (the verdict, the truth, p_attack, the category, the confidence, the k of every category, the latency and the gateway's token report) and the raw answers in `responses.jsonl`.

NSL-KDD has no timestamps, so it runs as a batch of k-shot requests with no stream. Download [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) into `data/raw/nsl-kdd/` and prepare it once.

```bash
uv run python -m scripts.prepare_nsl_kdd
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split smoke --k 0,1
```

## Compare detectors

```bash
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector jev --k 1 --control aimd --selection score+nearest --seeds 0,1,2
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector random_forest --k all --seeds 0
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector isolation_forest --k all --seeds 0
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector knn --neighbours 4 --k all --seeds 0
uv run jev-ids metrics --threshold 0.58 results/<jev_run> > results/jev.csv
uv run jev-ids metrics results/<rf_run> results/<if_run> results/<knn_run> > results/baselines.csv
uv run jev-ids compare --a results/<jev_run> --b results/<rf_run> --k-a 1 --k-b all --threshold-a 0.58 --subset novel  # novel = zero-day attacks
```

`--delay` streams the split with every label coming back D flows late. `--control aimd` hands k to the KController, starting from `--k 1`, and `--selection score+nearest` runs the Selector with the nearest benign flow. `--record compact` is the default. `metrics` prints one CSV row per run with F1, precision, recall, recall on zero-day attacks (`novel` in the code) at their first flows and after their labels came back, recall per category, false alarms, PR-AUC and ROC-AUC of p_attack, tokens, latency and cost, and `--threshold 0.58` reads Jev's verdicts at its cut. `compare` pairs two runs flow by flow and runs McNemar's exact test on the discordant pairs, because only the flows two detectors disagree on tell them apart. Cost is computed offline as tokens times the list prices in [`prices.json`](prices.json), for every detector alike.

## Reproduce the paper

Each CIC-IDS2017 run of the paper is a `make` target over the `paper-v2` split. A finished run with no failed call leaves a stamp in `results/design-cicids2017/v2-done/`, so `make -k` runs again only what is missing, and a Jev chain and a baseline chain can run in two terminals at once.

```bash
make v2-cut                  # the full system over the validation stream, then `jev-ids threshold` on its run gives the cut
make -k v2-d1                # D = 1, the full system at seeds 0 to 2 and the four baselines
make -k v2-paper-jev         # the full system at D = 25, 50, 100 and 200, then the ablations
make -k v2-paper-baselines   # the four baselines at D = 25, 50, 100 and 200
make -k results/design-cicids2017/v2-done/full-d{25,50,100,200}-s{1,2}   # seeds 1 and 2 of the full system
make -k v2-d500              # D = 500, past the longest burst, as for D = 1
make -k results/design-cicids2017/v2-done/{full-d250-s0,rf-d250,if-d250,knn4-d250,knnmatched-d250}   # D = 250, seed 0 alone
```

[`docs/jevids-design.md`](docs/jevids-design.md) fixes the split, the cut and the metrics before the runs, logs every change made after a result was seen, and reads each run next to its stamp. The NSL-KDD benchmark runs with `make paper`, as [`docs/protocol.md`](docs/protocol.md) describes.

## Small enough to read

| File                                                                   | Job                                                                                                         |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [cli.py](jev_ids/cli.py)                                               | `run`, `redo-errors`, `metrics`, `compare`, `sign-test` and `threshold`                                     |
| [dataset.py](jev_ids/dataset.py)                                       | The card, the pool, the splits, the k-shot example draw and the compact record                              |
| [stream.py](jev_ids/stream.py)                                         | The stream, the memory and the labels that come back D flows late                                           |
| [controller.py](jev_ids/controller.py)                                 | The KController, k per category by mirrored AIMD                                                            |
| [selector.py](jev_ids/selector.py)                                     | The Selector, examples by score and MMR plus the nearest benign flow                                        |
| [run.py](jev_ids/run.py)                                               | The loop, cell by cell and flow by flow, and the three files of a run                                       |
| [records.py](jev_ids/records.py)                                       | One prediction row and its JSONL                                                                            |
| [metrics.py](jev_ids/metrics.py)                                       | F1, recall per category, PR-AUC, tokens, cost, latency, the paired tests                                    |
| [detectors/jev.py](jev_ids/detectors/jev.py)                           | Jev through TypeSafe's API, one flow per request                                                            |
| [detectors/random_forest.py](jev_ids/detectors/random_forest.py)       | The classical baseline                                                                                      |
| [detectors/knn.py](jev_ids/detectors/knn.py)                           | The nearest-neighbour baseline, in the Selector's distance                                                  |
| [detectors/isolation_forest.py](jev_ids/detectors/isolation_forest.py) | The unsupervised baseline, fitted on benign traffic alone                                                   |
| [detectors/llm.py](jev_ids/detectors/llm.py)                           | The LLM baselines through Agno, used on NSL-KDD                                                             |
| [prompts/](prompts)                                                    | One folder per dataset, with `jev.json`, the whole request template, and `llm.md`, the agent's instructions |
| [scripts/](scripts)                                                    | One `prepare_<dataset>.py` per dataset, and `draw_split.py` for the splits                                  |

## Development

```bash
make check
```

Python 3.13+. The gate runs ruff with Google-style docstring rules, complexipy, pyright in strict mode, pytest with coverage, vulture, pip-audit and jscpd. Thresholds live in `pyproject.toml` and `.jscpd.json`. Runs make paid API calls and write only under `results/`.

## Bring your own flows

Jev IDS is an independent research prototype, not a product. Its numbers come from two benchmarks, CIC-IDS2017 and NSL-KDD, and the project is independent of TypeSafe. It can still sit inside a commercial solution, and this is how.

### Where Jev fits

A commercial IDS already has sensors, a flow exporter and a signature engine feeding a SIEM. Jev IDS replaces none of them. It sits beside the pipeline, off the packet path, and judges one flow record at a time.

- **A net behind the signatures.** Signatures miss what they have never seen. Sample the flows the engine passed as clean, or every flow to a critical asset, and let Jev judge them. On CIC-IDS2017, with labels 200 flows late, it caught 54% of the zero-day attacks where a Random Forest caught 29%.
- **Learning from the analysts.** Every alert an analyst confirms or dismisses goes back into the memory as a labeled flow, and the Selector and the KController use it from the next request on, with no retraining.
- **A category for the playbook.** The `choice` answer names the category with a confidence, so the SIEM routes DoS, PortScan and BruteForce, or your own taxonomy, to different runbooks with no parser in between.
- **Coverage from day one.** A new site or tenant has no training set. Jev starts from one labeled flow per category, so it covers the segment while a classical model is still collecting data.

A quarter of a second per verdict and a rate-limited API make this an asynchronous side channel, fed from the exporter (NetFlow, IPFIX, Zeek `conn.log`) through a queue, never an inline filter.

### Six steps

1. **Get a key.** Jev is served by TypeSafe. Set `TYPESAFE_API_KEY` in `.env`. Pricing and terms are TypeSafe's.
2. **Describe your flows.** Write a dataset card like [`data/cicids2017/dataset.json`](data/cicids2017/dataset.json), with the columns your flow exporter emits in order, which of them are symbolic, your categories and which one is benign.
3. **Write the request.** Copy [`prompts/cicids2017/jev.json`](prompts/cicids2017/jev.json), replace `columns` and the category descriptions with yours, and keep the two questions.
4. **Seed the memory.** One labeled flow per category from your own network is enough to start, because the KController begins at k = 1 and raises k only for the categories Jev gets wrong.
5. **Call the detector.** `JevDetector(load_prompt(path)).predict(flow, examples)` returns `p_attack`, `category_pred` and `confidence` for one flow in about a quarter of a second, and [`stream.py`](jev_ids/stream.py) shows how the memory, the Selector and the KController choose `examples` at each step. Route `p_attack` to your alerting with the cut your alarm budget allows. 0.58 was the benchmark's choice, not a rule.
6. **Measure before you trust.** Run `jev-ids run --delay` and `jev-ids metrics` on a labeled split of your own flows. The numbers above are CIC-IDS2017's, not yours.

Only flow features leave your network, never payloads, but they do leave it. Every request goes to TypeSafe's API.

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

[TypeSafe docs](https://docs.typesafe.ai/introduction) · [Jev models and pricing](https://docs.typesafe.ai/models) · [CIC-IDS2017, relabelled](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) · [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) · [Glossary](CONTEXT.md)
