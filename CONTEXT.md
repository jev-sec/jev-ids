# JevIDS

Intrusion detection on network flow records with a System One Model (Jev). Jev judges a Stream whose labels come back late, on CIC-IDS2017 and TRUSTLab, against a Random Forest, two kNN, an Isolation Forest and Claude Sonnet 5.5.

## Language

### Data

**Dataset**:
A source of Flows prepared once into a Card, a Pool and Splits. The Datasets are CIC-IDS2017 in the relabelled version of Liu et al. (IEEE CNS 2022) and TRUSTLab (Cano Baños and Villafranca Albaladejo, Frontiers in Computer Science, 2026). A development Dataset (`cicids2017-dev`, `trustlab-dev`) is its Dataset with some attack names taken out of the Pool. Every Run names one.
_Avoid_: corpus, benchmark, source.

**Card**:
The description of a Dataset: its name, its features in column order, which of them are symbolic, its Categories, which Category is benign and the attack names of each Category.
_Avoid_: config, schema, manifest, metadata.

**Flow**:
One bidirectional flow exported by CICFlowMeter, holding its features and its Category. A CIC-IDS2017 Flow has 78 features and a TRUSTLab Flow 70.
_Avoid_: row, line, record, connection.

**Category**:
The label every Detector works with, one per Flow, listed in the Card, and one of them is benign. CIC-IDS2017 has `BENIGN`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`. TRUSTLab has `BENIGN` and its 15 attack families, each a Category with one attack name. Attack names such as `DoS Hulk` are never shown to a Detector.
_Avoid_: class, attack type (when the label is meant).

**Pool**:
The Flows of a Dataset that Examples are drawn from: a capped, seeded sample of the earlier half in time of each attack name's Flows on each day, the later half feeding the Splits.
_Avoid_: training set, train, corpus.

**Novel attack**:
An attack Flow whose attack name is absent from the Pool. In CIC-IDS2017, a Flow of `DoS Slowhttptest`, `SSH-Patator` or `Infiltration - Portscan`, whose Categories keep another name in the Pool. In TRUSTLab, a Flow of `C2Beaconing`, `DDoS`, `DoS`, `MITM` or `WebBased`, whose Categories have no Example until feedback brings one. Text written for readers outside the project, such as the README, calls it a zero-day attack.
_Avoid_: unseen attack, new attack.

**Example**:
A labeled Flow of the Memory shown to a Detector as a reference, labeled by Category only.
_Avoid_: shot, demonstration, training row.

**k**:
The number of Examples per Category given to a Detector. k = 4 with six Categories means 24 Examples.

**Split**:
A frozen, seeded sample of a Dataset's Flows, the Flows a Run judges. `paper-v3` of CIC-IDS2017 and `paper` of TRUSTLab are the test Splits, and `validation` of each development Dataset is the Stream the Cuts are taken on.
_Avoid_: subset, sample, test set.

**Discordant pair**:
One Flow judged by two Detectors that gave different Verdicts. Only discordant pairs tell two Detectors apart.

### Detection

**Detector**:
Anything that turns a Flow plus Examples into a Prediction. The Detectors are Jev, the Sonnet 5.5 baseline, the Random Forest, the kNN, the matched kNN and the Isolation Forest.
_Avoid_: model (reserved for a provider's model id), classifier, algorithm.

**Jev alone**:
Jev with the KController from k = 1, the Selector with the Nearest benign Flow and the compact Record.
_Avoid_: full system, final model.

**Matched kNN**:
A kNN that votes with as many neighbours as the Selector gives Jev at k = 4 for the same Memory.

**Full JevIDS**:
Jev alone and the matched kNN on the same Stream, joined by fusion. Each p_attack becomes its percentile among that Detector's p_attack on the `validation` Split, and the p_attack of the full JevIDS is the mean of the two percentiles. When Jev's call fails, the matched kNN's percentile stands alone.
_Avoid_: Fusion (as a name of the system), ensemble, cascade, stack.

**Prediction**:
The output of one Detector for one Flow: Verdict, Category, p_attack, confidence, and the latency and provider usage (tokens) measured for it.
_Avoid_: record, result, answer.

**Verdict**:
The binary decision for a Flow, `attack` or `normal`, taken as p_attack ≥ the Cut.
_Avoid_: label, prediction (when only the binary decision is meant).

**Cut**:
The p_attack at or above which a Verdict is `attack`, taken on the `validation` Split before the test. One Cut per Dataset, taken on the full JevIDS's fused p_attack and applied to every Detector, 0.2608 on CIC-IDS2017 and 0.377 on TRUSTLab.
_Avoid_: threshold (except as the name of the command that computes it).

**p_attack**:
The probability that a Flow is an attack, as returned by the Detector: Jev's `noul` answer, the number Sonnet states, the Random Forest's class probability, the kNN's share of attack neighbours, the Isolation Forest's anomaly score.
_Avoid_: score, confidence.

**confidence**:
Jev's per-question number for a `choice` question, derived from how spread out the Category probabilities are. Only the Category question has one, and `noul` has none.
_Avoid_: certainty, probability.

**Run**:
One execution of one Detector over one Split of one Dataset, for one k, one Delay and its seeds and repetitions.
_Avoid_: experiment, job.

### Stream

**Stream**:
A Split judged one Flow per Step, in the order its Flows end, with a Memory that grows as labels come back.
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
The Step that judges a Flow whose attack name is absent from the Pool before any Flow of that name has come back.

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
