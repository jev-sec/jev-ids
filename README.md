<img src="docs/banner.svg" alt="Jev IDS banner showing the jev_ids terminal lockup, the tagline &quot;Intrusion detection with a System One Model, benchmarked against an LLM and a Random Forest.&quot;, and the command that runs a detector over NSL-KDD" width="100%" />

# Jev IDS

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-0B6B3A?style=flat&labelColor=121917) ![Detector Jev, from TypeSafe](https://img.shields.io/badge/detector-Jev%20%28TypeSafe%29-0B6B3A?style=flat&labelColor=121917) ![Dataset NSL-KDD](https://img.shields.io/badge/dataset-NSL--KDD-0B6B3A?style=flat&labelColor=121917) ![License MIT](https://img.shields.io/badge/license-MIT-0B6B3A?style=flat&labelColor=121917)

**Intrusion detection in one request. Show [TypeSafe's Jev](https://docs.typesafe.ai/introduction) one network flow and five labeled examples. It answers whether the flow is an attack and which kind, in half a second, with no text to parse.**

Jev IDS was tested on NSL-KDD, a reference benchmark of the cybersecurity community, against a state-of-the-art LLM (Gemini 3.6 Flash on Vertex AI), a classic machine-learning model (Random Forest) and an unsupervised one (Isolation Forest): 2,000 flows, three seeds, k from 0 to 8 examples per category. Given the same five examples (k = 1), Jev IDS was:

- **7.7× faster** than the LLM: 0.32 s against 2.42 s per flow.
- **22× cheaper** than the LLM: $74 against $1,651 per million flows, at list prices.
- **As precise as the LLM**: 0.953 against 0.942.
- **18× fewer false alarms** than the Random Forest: 43 against 764 on the same 874 benign flows.

The LLM is the better detector on F1: 0.880 against Jev's 0.856 at k = 1, and ahead at every k (McNemar p < 0.001), because it catches more attacks of the kinds shown in the examples. Jev is the second best, and on zero-day attacks, kinds absent from the examples, it catches more than the LLM from k = 1 to k = 8 (0.747 against 0.713 at k = 1). The numbers, the figures and their limits are in [Evidence and limits](#evidence-and-limits) and [docs/results.md](docs/results.md).

[Read the loop](jev_ids/run.py) · [The request template](prompts/nsl-kdd/jev.json) · [Glossary](CONTEXT.md)

## How it works

Jev is a System One Model. Instead of writing text, it reads a `state` and answers typed questions about it with probabilities. Jev IDS puts one flow into the state, next to the instructions, the column names, the five category descriptions and the labeled examples, and asks two questions. `is_attack` comes back as a probability. `category` comes back as one of five options with a confidence. The verdict is attack when the probability reaches 0.5.

<img src="docs/verdict.svg" alt="One flow, two typed answers: is_attack, a noul question, returns 0.82, above the 0.5 cut, so the verdict is attack; category, a choice question, returns dos with confidence 0.84" width="100%" />

Every request follows the same path:

<img src="docs/request.svg" alt="The flow under test and the labeled examples go into one request to Jev, whose state holds instructions, columns, categories, examples and the flow, with two typed questions; the answers come back as p_attack 0.82, verdict attack, and category dos with confidence 0.84" width="100%" />

The whole request is one file, [`prompts/nsl-kdd/jev.json`](prompts/nsl-kdd/jev.json). Python adds only the flow and the examples, and the file's sha256 travels in every prediction row as `prompt_hash`, so runs that asked different things are never compared as equals. Examples are labeled by category only: attack names such as `neptune` never reach a model.

The same flows, examples and 0.5 cut go to two baselines: an LLM through an Agno agent with a JSON output schema (Gemini 3.6 Flash through Vertex AI in the paper; GPT-5.6 through the ChatGPT Codex backend or DeepSeek as alternatives) and a scikit-learn Random Forest trained on the same examples. A third baseline, an Isolation Forest fitted on the benign flows of the pool alone, never sees an example: it is the unsupervised reference, at k = all only.

## Try it

```bash
git clone https://github.com/jev-sec/jev-ids.git
cd jev-ids
uv sync
# .env: TYPESAFE_API_KEY for Jev. Gemini needs `gcloud auth application-default login` and GOOGLE_GENAI_USE_VERTEXAI=true,
# GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION=global in the environment; DEEPSEEK_API_KEY and CHATGPT_CLIENT_ID only for the other LLMs.
```

Download [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) into `data/raw/nsl-kdd/` and prepare it once:

```bash
uv run python -m scripts.prepare_nsl_kdd
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split smoke --k 0,1
```

The smoke split is five flows. The run writes `results/<timestamp>-nsl-kdd-jev-smoke/` with `config.json`, one JSON row per flow in `predictions.jsonl` (the verdict, the truth, p_attack, the category, the confidence, the latency and the gateway's token report) and the raw answers in `responses.jsonl`.

## Compare detectors

```bash
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split pilot --k 0,1,2,4,8 --seeds 0,1,2
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector llm:gemini --model gemini-3.6-flash --split pilot --k 0,1,2,4,8
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector random_forest --split pilot --k 1,2,4,8,all
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector isolation_forest --split pilot --k all
uv run jev-ids metrics results/<run_id> [results/<run_id> ...] > results/summary.csv
uv run jev-ids compare --a results/<jev_run> --b results/<rf_run> --subset novel --k-a 0 --k-b all  # novel = zero-day attacks
```

k is the number of labeled examples per category. k = 1 with five categories means five examples, and `all` means the whole pool. `metrics` prints one CSV row per detector and k with F1, recall on zero-day attacks (`novel` in the code) and per category, PR-AUC and ROC-AUC of p_attack, tokens, latency and cost. `compare` pairs two runs flow by flow and runs McNemar's test on the discordant pairs, because only the flows two detectors disagree on tell them apart. Cost is computed offline as tokens times the list prices in [`prices.json`](prices.json), for every detector alike.

## Reproduce the paper

[`docs/protocol.md`](docs/protocol.md) fixes the inputs (the 2,000-flow `paper` split, the prompts, the model ids, the prices) and `make paper` runs the four detectors over that split into `results/paper/` and writes `results/paper/summary.csv`. Each detector has its own target (`make paper-jev`, `make paper-llm`, `make paper-random-forest`, `make paper-isolation-forest`), so they can run in separate terminals; the LLM is the slow one. `make paper-llm` runs Gemini 3.6 Flash on Vertex AI as five parallel processes, one per k (`make -j5 paper-llm`); a quota error or a timeout is an error row, and `uv run jev-ids redo-errors results/paper/<run>` judges those flows again in place. The full tables and figures are in [`docs/results.md`](docs/results.md).

## Why it is fast and cheap

- **One request, two answers.** Both questions run over the same state and come back as a probability, an option and a confidence. Nothing to parse, no schema to enforce.
- **Input only.** Jev charges $0.042 per million input tokens and nothing for output. At about 1,800 tokens per flow, a million verdicts cost about $74.
- **The prompt is a file.** Its sha256 rides in every row, so runs with different prompts are never compared as equals.
- **Flows in the innermost loop.** The prompt prefix stays constant as long as possible, so provider caches get their best chance.
- **Fail open.** A failed call becomes a row with `error`, counted as no alert. Never a crash.
- **Same cut for everyone.** p_attack ≥ 0.5 decides for Jev, the LLM and the forest. No per-detector tuning.

## Small enough to read

| File                                                                   | Job                                                                           |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [cli.py](jev_ids/cli.py)                                               | `run`, `metrics` and `compare`                                                |
| [dataset.py](jev_ids/dataset.py)                                       | The card, the pool, the splits and the k-shot example draw                    |
| [run.py](jev_ids/run.py)                                               | The loop, cell by cell and flow by flow, and the three files of a run         |
| [records.py](jev_ids/records.py)                                       | One prediction row and its JSONL                                              |
| [metrics.py](jev_ids/metrics.py)                                       | F1, recall per category, PR-AUC, tokens, cost, latency, the paired comparison |
| [detectors/jev.py](jev_ids/detectors/jev.py)                           | Jev through TypeSafe's API, one flow per request                              |
| [detectors/llm.py](jev_ids/detectors/llm.py)                           | The LLM baselines through Agno                                                |
| [detectors/random_forest.py](jev_ids/detectors/random_forest.py)       | The classical baseline                                                        |
| [detectors/isolation_forest.py](jev_ids/detectors/isolation_forest.py) | The unsupervised baseline, fitted on benign traffic alone                     |
| [prompts/nsl-kdd/](prompts/nsl-kdd)                                    | `jev.json`, the whole request template; `llm.md`, the agent's instructions    |

## Evidence and limits

Paper split of NSL-KDD: 2,000 flows disjoint from the pilot, 1,126 of them attacks and 300 of those zero-day, of a kind absent from the example pool. Three seeds of examples, so 6,000 predictions per detector and k. Means over the three seeds, from the runs of 2026-09-22 in [`results/paper/`](results/paper), summarized in [`docs/results.md`](docs/results.md).

| Detector         | k   | F1    | Precision | Recall | Zero-day recall | False alarms / 874 normal | Latency | Cost per 1M flows |
| ---------------- | --- | ----- | --------- | ------ | --------------- | ------------------------- | ------- | ----------------- |
| Jev              | 1   | 0.856 | 0.953     | 0.778  | 0.747           | 43                        | 0.32 s  | $74               |
| Gemini 3.6 Flash | 1   | 0.880 | 0.942     | 0.826  | 0.713           | 57                        | 2.42 s  | $1,651            |
| Random Forest    | 1   | 0.748 | 0.598     | 1.000  | 1.000           | 764                       | 3 ms    | local             |
| Jev              | 8   | 0.854 | 0.942     | 0.783  | 0.721           | 56                        | 0.33 s  | $295              |
| Gemini 3.6 Flash | 8   | 0.881 | 0.949     | 0.823  | 0.702           | 50                        | 1.99 s  | $3,035            |
| Random Forest    | 8   | 0.865 | 0.794     | 0.950  | 0.912           | 278                       | 3 ms    | local             |
| Random Forest    | all | 0.765 | 0.971     | 0.631  | 0.263           | —                         | 3 ms    | local             |
| Isolation Forest | all | 0.761 | 0.974     | 0.624  | 0.573           | —                         | 3 ms    | local             |

Jev against Gemini over all 6,000 paired verdicts at k = 1: 508 differ, Jev is right in 195 and Gemini in 313 (McNemar p < 0.001); Gemini leads at every k. On the 900 zero-day attacks at k = 1: 118 differ, Jev is right in 74 and Gemini in 44 (p = 0.007); Jev also leads at k = 2, and the two are indistinguishable at k = 4 and 8. Jev against the Random Forest over all flows at k = 1: 2,909 differ, Jev is right in 2,161 (p < 0.001); the forest overtakes Jev only at k = 8 (0.865 against 0.854, p = 0.007). A forest trained on five rows calls almost everything an attack, which is why its recall is perfect and its precision is not.

<img src="docs/results-f1-three-sets.svg" alt="F1 by k for three attack sets, all with the normal flows: all attacks, known-type attacks and zero-day attacks; Gemini leads the first two, Jev leads zero-day from k = 1, the Random Forest is last on zero-day" width="100%" />

The multipliers at the top come from the k = 1 rows: 2,421 ms against 315 ms per flow, $1,651 against $74 per million flows, precision 0.942 against 0.953, and 764 against 43 false alarms on the same 874 benign flows.

Limits worth knowing:

- Gemini's cost is the list price through 2026-12-31 ($0.75 input, $3.75 output per million tokens); it doubles on 2027-01-01. Jev's is TypeSafe's list price. Neither is what was billed.
- Gemini's latency was measured with five processes in parallel on a congested day (transient 429, 500 and 504 answers, all repaired with `redo-errors`), so it is a real-day figure, not a floor. Jev's latency is the wall clock around one direct call to TypeSafe's API.
- Gemini 3.x cannot switch thinking off; it ran at `thinking_level="low"`, about 200 reasoning tokens per flow, billed as output.
- NF-UQ-NIDS-v2 has a card and a preparation script and no run yet. Every number here is NSL-KDD's.
- Jev's `noul` answer carries no confidence. Only the `choice` answer does.

## Development

```bash
make check
```

Python 3.13+. The gate runs ruff with Google-style docstring rules, complexipy, pyright in strict mode, pytest with coverage, vulture, pip-audit and jscpd. Thresholds live in `pyproject.toml` and `.jscpd.json`. Runs make paid API calls and write only under `results/`.

## Bring your own flows

Jev IDS is an independent research prototype, not a product. Its numbers come from one benchmark, NSL-KDD, and it is not affiliated with TypeSafe. It can still sit inside a commercial solution, and this is how.

### Where Jev fits

A commercial IDS already has sensors, a flow exporter and a signature engine feeding a SIEM. Jev IDS replaces none of them. It sits beside the pipeline, off the packet path, and judges one flow record at a time:

- **Second opinion on alerts.** Send Jev the flow behind each alert the signature engine raised. `p_attack` ranks the queue, and the SOC reads the top first. On the paper split at k = 1, Jev raised 43 false alarms on 874 benign flows where a Random Forest raised 764.
- **A net behind the signatures.** Signatures miss what they have never seen. Sample the flows the engine passed as clean, or every flow to a critical asset, and let Jev judge them: it caught 75% of the zero-day attacks at k = 1, where the LLM caught 71%.
- **A category for the playbook.** The `choice` answer names the category with a confidence, so the SIEM routes dos, probe, r2l and u2r, or your own taxonomy, to different runbooks with no parser in between.
- **Coverage from day one.** A new site or tenant has no training set. Jev needs one labeled flow per category, so it covers the segment while a classical model is still collecting data.

Half a second per verdict and a rate-limited API make this an asynchronous side channel, fed from the exporter (NetFlow, IPFIX, Zeek `conn.log`) through a queue, never an inline filter.

### Six steps

1. **Get a key.** Jev is served by TypeSafe; set `TYPESAFE_API_KEY` in `.env`. Pricing and terms are TypeSafe's.
2. **Describe your flows.** Write a dataset card like [`data/nsl-kdd/dataset.json`](data/nsl-kdd/dataset.json): the columns your flow exporter emits, in order, which of them are symbolic, your categories and which one is benign.
3. **Write the request.** Copy [`prompts/nsl-kdd/jev.json`](prompts/nsl-kdd/jev.json), replace `columns` and the category descriptions with yours, and keep the two questions.
4. **Pick examples.** One labeled flow per category from your own network is enough to start; k = 1 is where the benchmark's F1 reaches its plateau.
5. **Call the detector.** `JevDetector(load_prompt(path)).predict(flow, examples)` returns `p_attack`, `category_pred` and `confidence` for one flow in about half a second. Route `p_attack` to your alerting with the cut your alarm budget allows; 0.5 was the benchmark's choice, not a rule.
6. **Measure before you trust.** Run `jev-ids run` and `jev-ids metrics` on a labeled split of your own flows. The numbers above are NSL-KDD's, not yours.

Only flow features leave your network, never payloads, but they do leave it: every request goes to TypeSafe's API.

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

[TypeSafe docs](https://docs.typesafe.ai/introduction) · [Jev models and pricing](https://docs.typesafe.ai/models) · [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) · [Glossary](CONTEXT.md)
