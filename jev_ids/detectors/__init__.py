"""Detectors: Jev, the two LLM baselines, the Random Forest and the Isolation Forest.

Each detector is a class with `name`, `model`, `prompt_hash` and `predict(flow, examples) -> dict` returning what it measured for that
one Flow (`p_attack`, `category_pred`, `latency_ms`, ...) or an `error`. The run loop treats them alike without a shared base class.

Adding a Detector takes one module here and four lines elsewhere. The module holds a class with those four members.
`prompt_hash` is `None` when it reads no prompt, and `model` is the key it is priced by in prices.json when the Detector bills tokens.
Elsewhere, the class joins the `Detector` union of `run.py`, `run.build_detector` gets a branch that constructs it from the spec
and the card, the `--detector` help of `cli.py` names it, and `run.check_spec` gets a guard if it treats k unlike the others.
Whatever `predict` returns lands in the row as is (`raw` and `probabilities` go to responses.jsonl instead),
so a new measurement is a new key, and the metrics average every numeric `usage` field they find.
"""
