"""Dataset access shared by every dataset: the card, the CSV shape and the Flow.

In reading order:

- `Flow`: one record of a dataset, as its CSV row has it.
- `load_config`: the card `dataset.json` as a dict, hashed.
- `flow_from_row` and `load_split`: a CSV in the shared shape as Flows.
- `record_text` and `compact_value`: a Flow's values as the text a model reads, in full or compact (docs/jevids-design.md, D7).
- `category_by_name`, `split_header` and `write_split`: the card's label table and the same shape, for the preparation scripts.

A dataset lives in `data/<name>/`: `dataset.json` (the card), `pool.csv` (the Flows that Examples are drawn from) and `splits/<split>.csv`
(the Flows a run judges). The card names the dataset, lists its `features` in column order, the `symbolic` ones among them, the `categories`
every Detector works with and which category is `benign`. Every CSV has `row_id`, one column per feature, `category` and `novel_attack`
(0/1); a dataset with timestamps also has `end`, when the Flow ended, which orders the stream; extra columns are ignored. Nothing here knows
a dataset by name: `scripts/prepare_<name>.py` converts the raw download into this shape, once, outside the package.

Vocabulary follows CONTEXT.md: a Flow is one record of the dataset; an Example is a pool Flow shown to a Detector as reference, a role and
not a separate type, so Examples are plain Flows here.
"""

import csv
import hashlib
import json
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

# The dataset card as a dict; see `load_config`.
Config = dict[str, Any]


@dataclass(frozen=True)
class Flow:
    """One record of a dataset, as its CSV row has it.

    Frozen because the same Flow objects are shared by every cell of a run and cached by identity inside the detectors.

    Attributes:
        row_id: 0-based line index in the raw source file.
        attributes_csv: the feature values, comma separated, in card order.
        category: the Category label; an attack name never gets this far.
        is_attack: whether the category is not the card's benign one.
        novel_attack: whether the attack is absent from the pool (CONTEXT.md).
        end: when the Flow ended, the moment its record exists; None for a dataset without timestamps, such as NSL-KDD.
    """

    row_id: int
    attributes_csv: str
    category: str
    is_attack: bool
    novel_attack: bool = False
    end: datetime | None = None

    @property
    def attribute_values(self) -> tuple[str, ...]:
        """The feature values, split out of `attributes_csv`."""
        return tuple(self.attributes_csv.split(","))


def load_config(path: Path) -> Config:
    """The dataset card as a dict, plus `sha256` of its bytes and `dir`, its folder.

    The package reads `name`, `features`, `symbolic`, `categories` and `benign`; `source` and `attack_names` are for the preparation script
    and the reader. The hash goes into config.json so a run can be traced to the exact card it used.
    """
    raw_bytes = path.read_bytes()
    config: Config = json.loads(raw_bytes)
    config["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    config["dir"] = path.parent
    return config


def flow_from_row(row: dict[str, str], config: Config) -> Flow:
    """One Flow from one CSV row; a category outside the card raises.

    The features are joined in card order whatever the order of the file's columns, so every Detector sees the same `attributes_csv` for a
    Flow.
    """
    category = row["category"]
    if category not in config["categories"]:
        raise ValueError(f"row {row['row_id']}: category {category!r} is not in the card")
    return Flow(
        row_id=int(row["row_id"]),
        attributes_csv=",".join(row[name] for name in config["features"]),
        category=category,
        is_attack=category != config["benign"],
        novel_attack=row["novel_attack"] == "1",
        end=datetime.fromisoformat(row["end"]) if row.get("end") else None,
    )


def load_split(path: Path, config: Config) -> list[Flow]:
    """Every Flow of one CSV in the shared shape: a split file or the pool."""
    with path.open(encoding="utf-8", newline="") as handle:
        return [flow_from_row(row, config) for row in csv.DictReader(handle)]


# How a Flow's values are written in the text a model reads: `full` as the CSV has them, the protocol of the first paper and of line 0;
# `compact` with 4 significant digits (docs/jevids-design.md, D7). The forests always read the full values.
RECORDS = ("full", "compact")
SIGNIFICANT_DIGITS = 4
INTEGER = re.compile(r"-?\d+")


def record_text(flow: Flow, record: str) -> str:
    """The Flow's values as the comma-separated text a model reads; `record` is one of RECORDS."""
    if record == "full":
        return flow.attributes_csv
    if record == "compact":
        return ",".join(compact_value(value) for value in flow.attribute_values)
    raise ValueError(f"record {record!r} is not one of {RECORDS}")


def compact_value(value: str) -> str:
    """One value with 4 significant digits and no exponent, so `25160.418777440053` becomes `25160` and `168.86187098953056` `168.9`.

    An integer stays as it is, whatever its length: a port such as `44321` is a name more than a size, and rounding `20694308` to
    `20690000` would not shorten it. A value that is not a finite number (NSL-KDD's `tcp`, `inf`, `nan`) stays as it is too. A decimal
    with an integer value loses its `.0`: `0.0` becomes `0`.
    """
    if INTEGER.fullmatch(value):
        return value
    try:
        number = float(value)
    except ValueError:
        return value
    if not math.isfinite(number):
        return value
    return format(Decimal(f"{number:.{SIGNIFICANT_DIGITS}g}"), "f")


def category_by_name(config: Config) -> dict[str, str]:
    """Attack name -> category from the card's `attack_names`; the benign label maps to itself."""
    categories = {config["benign"]: config["benign"]}
    for category, names in config["attack_names"].items():
        for name in names:
            categories[name] = category
    return categories


def split_header(config: Config, *extra: str) -> list[str]:
    """The column names every split and pool file starts with, plus any trace column.

    The writers of this shape (the preparation scripts and the test builder) differ only in the trace columns they append, so the
    shared part is named here, beside the docstring that defines it.
    """
    return ["row_id", *config["features"], "category", "novel_attack", *extra]


def write_split(path: Path, header: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    """Write a CSV with a header row: the shape every split and pool file shares."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)
