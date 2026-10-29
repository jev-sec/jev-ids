"""Builders shared by the test modules: a card, two prompt files, Flows, rows, files."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jev_ids.dataset import Config, Flow, split_header, write_split
from jev_ids.records import Prediction

# Defining a three-feature card with one symbolic feature and three Categories.
CONFIG: Config = {
    "name": "test",
    "features": ["a", "b", "c"],
    "symbolic": ["b"],
    "categories": ["normal", "dos", "probe"],
    "benign": "normal",
}
TASK = "You are given one record of a network connection."
CATEGORIES = {
    "normal": "legitimate traffic.",
    "dos": "denial of service.",
    "probe": "surveillance or scanning.",
}
# Mirroring what `run.load_prompt` returns for a `jev.json` and an `llm.md` written for `CONFIG`.
JEV_PROMPT: dict[str, Any] = {
    "text": json.dumps(
        {
            "model": "jev-1.13.0",
            "state": {
                "instructions": TASK,
                "columns": "a,b,c",
                "categories": CATEGORIES,
            },
            "questions": {
                "is_attack": {
                    "type": "noul",
                    "instructions": "Is `flows.under_test` bad?",
                },
                "category": {
                    "type": "choice",
                    "instructions": "Which category?",
                },
            },
        }
    ),
    "sha256": "h",
}
LLM_PROMPT: dict[str, Any] = {
    "text": (
        f"{TASK}\n\nCategories:\n\n"
        + "\n".join(f"- `{name}`: {text}" for name, text in CATEGORIES.items())
        + "\n\nColumns of a record, in order:\na,b,c\n{examples}\n"
        "Answer only with a JSON object.\n"
    ),
    "sha256": "h",
}


def make_flow(row_id: int, category: str, *, value: str = "0", novel_attack: bool = False) -> Flow:
    """A Flow of CONFIG whose three attributes all equal `value`."""
    return Flow(
        row_id=row_id,
        attributes_csv=",".join([value] * len(CONFIG["features"])),
        category=category,
        is_attack=category != CONFIG["benign"],
        novel_attack=novel_attack,
    )


def make_train(categories: Sequence[str]) -> list[Flow]:
    """One Flow per category given; row_id and every attribute equal the index."""
    return [make_flow(index, category, value=str(index)) for index, category in enumerate(categories)]


def write_dataset(root: Path, config: Config, splits: Mapping[str, Sequence[Flow]]) -> Path:
    """A dataset folder under `root` in the shared shape.

    Args:
        root: The folder that receives the dataset folder.
        config: The card, written as `dataset.json`.
        splits: The Flows of each split. `splits["pool"]` becomes `pool.csv`, and every other entry becomes `splits/<name>.csv`.

    Returns:
        The card's path.
    """
    folder = root / config["name"]
    folder.mkdir(parents=True, exist_ok=True)
    card = folder / "dataset.json"
    card.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    header = split_header(config)
    for name, flows in splits.items():
        path = folder / "pool.csv" if name == "pool" else folder / "splits" / f"{name}.csv"
        rows = [[flow.row_id, *flow.attribute_values, flow.category, int(flow.novel_attack)] for flow in flows]
        write_split(path, header, rows)
    return card


def make_prediction(row_id: int, is_attack: int, p_attack: float | None, **overrides: Any) -> Prediction:
    """A row as predictions.jsonl holds it, with plain defaults; `overrides` win."""
    prediction: Prediction = {
        "run_id": "r",
        "dataset": "test",
        "detector": "jev",
        "model": "m",
        "split": "internal",
        "prompt_hash": "h",
        "k": 1,
        "seed": 0,
        "repetition": 0,
        "n_examples": 3,
        "row_id": row_id,
        "is_attack": is_attack,
        "classification_verdict": None if p_attack is None else int(p_attack >= 0.5),
        "category_true": "dos" if is_attack else "normal",
        "novel_attack": False,
        "p_attack": p_attack,
        "latency_ms": 500.0,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 10,
        },
        "retries": 0,
        "error": None,
        "request_id": f"q{row_id}",
        "ts_utc": "t",
    }
    prediction.update(overrides)
    return prediction


class FakeResponse:
    """What `requests.post` returns, reduced to the attributes the code reads."""

    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        """Keep the status and the body; `ok` follows the 4xx boundary."""
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = json.dumps(body)
        self._body = body

    def json(self) -> dict[str, Any]:
        """The parsed body."""
        return self._body


def no_sleep(_seconds: float) -> None:
    """A backoff that does not wait, for the retry tests."""
    return None
