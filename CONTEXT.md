# Jev IDS

Intrusion detection on network flow records with a System One Model (Jev),
compared with an LLM baseline, a Random Forest and an Isolation Forest on data
efficiency, cost and latency. NSL-KDD is the Dataset.

## Language

### Data

**Dataset**:
A source of Flows prepared once into a Card, a Pool and Splits: NSL-KDD. Every
Run names one.
_Avoid_: corpus, benchmark, source.

**Card**:
The description of a Dataset: its name, its features in column order, which of
them are symbolic, its Categories and which Category is benign.
_Avoid_: config, schema, manifest, metadata.

**Flow**:
One record of a Dataset: its features and its Category. In NSL-KDD, one
connection record with 41 attributes.
_Avoid_: row, line, record, connection.

**Category**:
The label every Detector works with, one per Flow, listed in the Card; one of
them is benign. NSL-KDD has `normal`, `dos`, `probe`, `r2l`, `u2r`. Attack
names such as `neptune` are never shown to a Detector.
_Avoid_: class, attack type (when the label is meant).

**Pool**:
The Flows of a Dataset that Examples are drawn from; KDDTrain+ in NSL-KDD.
k = all means the whole Pool.
_Avoid_: training set, train, corpus.

**Novel attack**:
An attack Flow whose kind is absent from the Pool. In NSL-KDD, a Flow whose
attack name occurs in KDDTest+ but never in KDDTrain+; seventeen such names
exist.
_Avoid_: unseen attack, zero-day, new attack.

**Example**:
A labeled Flow drawn from the Pool and shown to a Detector as a reference,
labeled by Category only.
_Avoid_: shot, demonstration, training row.

**k**:
The number of Examples per Category given to a Detector. k = 0 is zero-shot;
k = 4 with five Categories means twenty Examples.

**Split**:
A frozen, seeded sample of a Dataset's Flows outside the Pool, the Flows a Run
judges. In NSL-KDD, `internal` is for tuning, `paper` for reported results and
`smoke` for exercising the pipeline; these three are proportional, and `pilot`
is a further proportional sample used to rehearse the protocol and take design
decisions. `hard` and `mid` are diagnostic samples, half attacks and half
normals, of Flows inside a band of Difficulty. Splits are disjoint.

**Difficulty**:
NSL-KDD's per-record count of classic learners, out of 21, that classified the
record correctly. Low Difficulty means a hard Flow.

**Discordant pair**:
One Flow judged by two Detectors that gave different Verdicts. Only discordant
pairs tell two Detectors apart.
_Avoid_: subset, sample, test set.

### Detection

**Detector**:
Anything that turns a Flow plus Examples into a Prediction: Jev, an LLM
baseline, the Random Forest or the Isolation Forest.
_Avoid_: model (reserved for a provider's model id), classifier, algorithm.

**Prediction**:
The output of one Detector for one Flow: Verdict, Category, p_attack,
confidence, and the latency and provider usage (tokens) measured for it.
_Avoid_: record, result, answer.

**Verdict**:
The binary decision for a Flow, `attack` or `normal`, taken as p_attack ≥ 0.5
for every Detector.
_Avoid_: label, prediction (when only the binary decision is meant).

**p_attack**:
The probability that a Flow is an attack, as returned by the Detector: Jev's
`noul` answer, the number the LLM states, the Random Forest's class probability,
the Isolation Forest's anomaly score.
_Avoid_: score, confidence.

**confidence**:
Jev's per-question number for a `choice` question, derived from how spread out
the Category probabilities are. Only the Category question has one; `noul` has
none.
_Avoid_: certainty, probability.

**Batch (B)**:
The number of Flows judged in one request over a shared state. Fixed at 1 for
every Detector.

**Run**:
One execution of one Detector over one Split of one Dataset for a set of k
values, seeds and repetitions.
_Avoid_: experiment, job.

### Control loop

**Cascade**:
The three-zone control loop around Jev: block when p_attack ≥ τ_high, allow when
p_attack ≤ τ_low, escalate otherwise. Designed after the pilot.

**Escalation**:
Handing a Flow from the uncertain zone to the LLM agent for a second opinion.
