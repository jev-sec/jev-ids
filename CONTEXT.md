# Jev IDS

Intrusion detection on network flow records with a System One Model (Jev). On CIC-IDS2017, Jev judges a Stream whose labels come back late, against a Random Forest, a kNN and an Isolation Forest. On NSL-KDD, the first Dataset, it was compared as a k-shot Detector with an LLM baseline, a Random Forest and an Isolation Forest on data efficiency, cost and latency.

## Language

### Data

**Dataset**:
A source of Flows prepared once into a Card, a Pool and Splits: NSL-KDD or
CIC-IDS2017, in the relabelled version of Liu et al. (IEEE CNS 2022). Every
Run names one.
_Avoid_: corpus, benchmark, source.

**Card**:
The description of a Dataset: its name, its features in column order, which of
them are symbolic, its Categories and which Category is benign.
_Avoid_: config, schema, manifest, metadata.

**Flow**:
One record of a Dataset: its features and its Category. In NSL-KDD, one
connection record with 41 attributes; in CIC-IDS2017, one bidirectional flow
exported by CICFlowMeter, with 83 attributes.
_Avoid_: row, line, record, connection.

**Category**:
The label every Detector works with, one per Flow, listed in the Card; one of
them is benign. NSL-KDD has `normal`, `dos`, `probe`, `r2l`, `u2r`; CIC-IDS2017
has `BENIGN`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`. Attack names
such as `neptune` or `DoS Hulk` are never shown to a Detector.
_Avoid_: class, attack type (when the label is meant).

**Pool**:
The Flows of a Dataset that Examples are drawn from; KDDTrain+ in NSL-KDD. In
CIC-IDS2017, a capped, seeded sample of the earlier half in time of each attack
name's Flows on each day, the later half feeding the Splits.
k = all means the whole Pool, or the whole Memory in a Stream.
_Avoid_: training set, train, corpus.

**Novel attack**:
An attack Flow whose kind is absent from the Pool. In NSL-KDD, a Flow whose
attack name occurs in KDDTest+ but never in KDDTrain+; seventeen such names
exist. In CIC-IDS2017, a Flow of one of three attack names held out of the Pool
while their Category keeps another: `DoS Slowhttptest`, `SSH-Patator` and
`Infiltration - Portscan`.
Text written for readers outside the project, such as the README, calls it a zero-day attack.
_Avoid_: unseen attack, new attack.

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
normals, of Flows inside a band of Difficulty. CIC-IDS2017 has `smoke`,
`internal`, `pilot` and `paper`, all proportional, then `validation`, the Stream the Cut was taken on, `paper-v2`, the Stream the results are read on, and `selector-test`, a diagnostic sample. Splits are disjoint.

**Difficulty**:
NSL-KDD's per-record count of classic learners, out of 21, that classified the
record correctly. Low Difficulty means a hard Flow.
The Selector's own criterion is Jev's doubt about a judged Flow, a different quantity.

**Discordant pair**:
One Flow judged by two Detectors that gave different Verdicts. Only discordant
pairs tell two Detectors apart.
_Avoid_: subset, sample, test set.

### Detection

**Detector**:
Anything that turns a Flow plus Examples into a Prediction: Jev, an LLM
baseline, the Random Forest, the kNN or the Isolation Forest.
_Avoid_: model (reserved for a provider's model id), classifier, algorithm.

**Prediction**:
The output of one Detector for one Flow: Verdict, Category, p_attack,
confidence, and the latency and provider usage (tokens) measured for it.
_Avoid_: record, result, answer.

**Verdict**:
The binary decision for a Flow, `attack` or `normal`, taken as p_attack ≥ the Cut.
_Avoid_: label, prediction (when only the binary decision is meant).

**Cut**:
The p_attack at or above which a Verdict is `attack`. It is 0.5 for every Detector, except Jev on the CIC-IDS2017 Stream, whose Cut of 0.58 was taken on the `validation` Split before the test.
_Avoid_: threshold (except as the name of the command that computes it).

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
values, seeds and repetitions, and in a Stream for one Delay.
_Avoid_: experiment, job.

### Stream

**Stream**:
A Split judged one Flow per Step, in the order its Flows end, with a Memory that grows as labels come back. Only a Dataset with timestamps can be streamed.
_Avoid_: online mode, sequence.

**Step**:
The judgement of one Flow of a Stream. Step t judges the t-th Flow to end.

**Delay (D)**:
The number of Steps after which a judged Flow's true Category comes back. Every judged Flow comes back, missed attacks included.
_Avoid_: lag, latency (reserved for the time of one request).

**Memory**:
The labeled Flows a Step may draw Examples from, which are the Pool Flows that ended before the Flow under test and the judged Flows whose Category has come back.
_Avoid_: buffer, history, training set.

**First contact**:
A Novel attack Flow judged before any Flow of its attack name has come back.

**KController**:
The rule that sets k for each Category during a Stream by mirrored AIMD. Every Category starts at k = 1, and a returned Flow raises the k of its true Category when Jev named another Category and lowers it when Jev named the right one.
_Avoid_: adaptive k, k scheduler.

**Selector**:
The rule that chooses which Examples of each Category a Flow gets, ranking the Memory by similarity to the Flow, recency and Jev's doubt about each judged Flow, then picking by maximal marginal relevance.
_Avoid_: retriever, sampler.

**Nearest benign Flow**:
The benign Flow of the Memory closest to the Flow under test, added to the Selector's Examples when its pick left it out.
_Avoid_: anchor (the code's name for its Category).

**Record**:
The text of a Flow's values that a model reads, `full` as the CSV has them or `compact` with each decimal cut to 4 significant digits. A Record is never the Flow itself.

**Full system**:
Jev with the KController from k = 1, the Selector with the Nearest benign Flow and the compact Record, the configuration whose Stream results are reported.
_Avoid_: final model.

### Control loop

**Cascade**:
The three-zone control loop around Jev: block when p_attack ≥ τ_high, allow when
p_attack ≤ τ_low, escalate otherwise. Designed after the pilot.

**Escalation**:
Handing a Flow from the uncertain zone to the LLM agent for a second opinion.
