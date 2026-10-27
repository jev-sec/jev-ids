"""Convert the improved CIC-IDS2017 into the shared CSV shape of `data/cicids2017/`.

Run once, from the repository root, after downloading `CICIDS2017_improved.zip` from
https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html into `data/raw/cicids2017/`, then draw the splits:

    uv run python -m scripts.prepare_cicids2017
    uv run python -m scripts.draw_split --dataset data/cicids2017 --name smoke --size 5 --seed 20261027
    uv run python -m scripts.draw_split --dataset data/cicids2017 --name internal --size 50 --seed 20261027
    uv run python -m scripts.draw_split --dataset data/cicids2017 --name pilot --size 300 --seed 20261027
    uv run python -m scripts.draw_split --dataset data/cicids2017 --name paper --size 2000 --seed 20261027 --min-novel 250
    uv run python -m scripts.draw_split --dataset data/cicids2017 --name validation --size 300 --seed 20261027 --source pool.csv

The zip is the relabelled CIC-IDS2017 of Liu et al., "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018",
IEEE CNS 2022, pp. 254-262, with one CSV per weekday of the capture (3 to 7 July 2017) and 91 columns. The labelling logic of every attack
is documented at https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html. Five decisions turn it into a Pool and a test
file:

1. Labels. A label ending in " - Attempted" marks attacker traffic in which the attack did not happen (no payload, closed port, a start-up
   artefact, an unresponsive target); it is neither an attack nor plainly benign, so it is dropped. Heartbleed (11 flows), the three web
   attacks (104) and Infiltration (36) are dropped too: too few flows for any per-Category metric. Every other label gets its Category from
   the card's `attack_names`; a label the card does not know raises.
2. Columns. The card keeps 83 of the 91: the flow id, both addresses, the ephemeral source port and the timestamp name the testbed, not the
   behaviour, so a Detector could learn them instead of the traffic. `id`, `Timestamp` and `Label` survive as trace columns.
3. Pool and test in time, per day. The flows of each label on each day are sorted by timestamp: the earlier half may become Examples,
   the later half may be judged. An Example is therefore never later than a judged Flow of the same attack on the same day, near-identical
   flows of one burst stay on one side, and BENIGN, the only label spanning several days, is judged on every day it occurs instead of only
   from Wednesday afternoon on (docs/jevids-design.md, D2).
4. Novel attacks. The labels in NOVEL_LABELS never reach the Pool; all their flows are test candidates with `novel_attack` = 1. Each holds
   out one variant of a Category that keeps another variant in the Pool, as NSL-KDD's test-only attack names do (CONTEXT.md, "Novel
   attack").
5. Caps. A seeded sample of at most POOL_CAPS (pool.csv) and TEST_CAPS (test.csv) flows per label, so no attack variant and no benign flood
   dominates, and the Pool stays near the size of NSL-KDD's.

`end`, the timestamp plus the Flow Duration in microseconds, is when the flow's record exists; it orders the stream (D3). `row_id` is the
0-based index of a flow over the five files read Monday to Friday, because each file's own `id` restarts at 1; the trace columns `day`,
`source_id`, `timestamp` and `raw_label` lead back to the raw line. `splits/SOURCE.json` records the zip's sha256, the seed, the caps, the
held-out and dropped labels and the rows per label on each side; `draw_split` adds the splits to it.
"""

import argparse
import csv
import hashlib
import io
import json
import random
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jev_ids.dataset import Config, category_by_name, load_config, split_header, write_split

ZIP_NAME = "CICIDS2017_improved.zip"
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
ATTEMPTED_SUFFIX = " - Attempted"
DROPPED_LABELS = frozenset({"Heartbleed", "Infiltration", "Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS"})
NOVEL_LABELS = frozenset({"DoS Slowhttptest", "Infiltration - Portscan", "SSH-Patator"})
# Kept after the shared columns so a row can be traced back to its raw line.
EXTRA_COLUMNS = ("day", "source_id", "timestamp", "raw_label")


@dataclass(frozen=True)
class Caps:
    """The most flows one label may keep in one file: the benign label and each attack label."""

    benign: int
    attack: int


POOL_CAPS = Caps(benign=50_000, attack=10_000)
TEST_CAPS = Caps(benign=10_000, attack=1_000)


@dataclass(frozen=True)
class RawFlow:
    """One line of a day file: its global `row_id`, its day and its fields by column name."""

    row_id: int
    day: str
    fields: dict[str, str]


def read_flows(raw: Path) -> Iterator[RawFlow]:
    """Every line of the five day files, Monday to Friday, numbered across files; a file with another header raises."""
    row_id = 0
    header: list[str] | None = None
    with zipfile.ZipFile(raw) as archive:
        for day in DAYS:
            with archive.open(f"{day}.csv") as binary:
                reader = csv.reader(io.TextIOWrapper(binary, encoding="utf-8", newline=""))
                day_header = next(reader)
                if header is not None and day_header != header:
                    raise ValueError(f"{day}.csv: header differs from monday.csv")
                header = day_header
                for values in reader:
                    yield RawFlow(row_id, day, dict(zip(header, values, strict=True)))
                    row_id += 1


def kept_label(label: str, categories: dict[str, str]) -> bool:
    """Whether a raw label stays in the dataset; a label neither dropped nor in the card raises."""
    if label.endswith(ATTEMPTED_SUFFIX) or label in DROPPED_LABELS:
        return False
    if label not in categories:
        raise ValueError(f"label {label!r} is neither in the card nor dropped")
    return True


def index_flows(raw: Path, config: Config) -> tuple[dict[str, list[tuple[str, str, int]]], Counter[str]]:
    """The (day, timestamp, row_id) of every kept flow by raw label, and the number of dropped flows by raw label."""
    categories = category_by_name(config)
    kept: dict[str, list[tuple[str, str, int]]] = {}
    dropped: Counter[str] = Counter()
    for flow in read_flows(raw):
        label = flow.fields["Label"]
        if kept_label(label, categories):
            kept.setdefault(label, []).append((flow.day, flow.fields["Timestamp"], flow.row_id))
        else:
            dropped[label] += 1
    return kept, dropped


def halves(flows: list[tuple[str, str, int]], novel: bool) -> tuple[list[int], list[int]]:
    """The row_ids that may go to the pool and to the test: the earlier and the later half in time of each day.

    A novel label has no pool half.
    """
    pool: list[int] = []
    test: list[int] = []
    for day in DAYS:
        in_time = [row_id for _, row_id in sorted((datetime.fromisoformat(ts), row_id) for d, ts, row_id in flows if d == day)]
        half = 0 if novel else len(in_time) // 2
        pool += in_time[:half]
        test += in_time[half:]
    return pool, test


def choose(kept: dict[str, list[tuple[str, str, int]]], config: Config, seed: int, caps: tuple[Caps, Caps]) -> dict[int, str]:
    """The side, "pool" or "test", of every chosen row_id: per day, the earlier half of a label may go to the pool, the later to the test.

    The caps then sample each side of a label over all its days.
    """
    rng = random.Random(seed)  # noqa: S311  seeded, reproducible sample
    side: dict[int, str] = {}
    for label in sorted(kept):
        pool, test = halves(kept[label], label in NOVEL_LABELS)
        for name, candidates, cap in (("pool", pool, caps[0]), ("test", test, caps[1])):
            limit = cap.benign if label == config["benign"] else cap.attack
            side.update(dict.fromkeys(rng.sample(candidates, min(limit, len(candidates))), name))
    return side


def end_time(fields: dict[str, str]) -> datetime:
    """When a flow ended: its timestamp plus its Flow Duration, in microseconds."""
    return datetime.fromisoformat(fields["Timestamp"]) + timedelta(microseconds=int(fields["Flow Duration"]))


def collect(raw: Path, config: Config, side: dict[int, str]) -> dict[str, list[list[object]]]:
    """The rows of pool.csv and test.csv in the shared shape, in row_id order."""
    categories = category_by_name(config)
    rows: dict[str, list[list[object]]] = {"pool": [], "test": []}
    for flow in read_flows(raw):
        if flow.row_id in side:
            label = flow.fields["Label"]
            rows[side[flow.row_id]].append(
                [
                    flow.row_id,
                    *(flow.fields[name] for name in config["features"]),
                    categories[label],
                    int(label in NOVEL_LABELS),
                    end_time(flow.fields).isoformat(),
                    flow.day,
                    flow.fields["id"],
                    flow.fields["Timestamp"],
                    label,
                ]
            )
    return rows


def manifest(
    raw: Path, seed: int, caps: tuple[Caps, Caps], dropped: Counter[str], rows: dict[str, list[list[object]]]
) -> dict[str, object]:
    """The preparation half of SOURCE.json: what was read, what was dropped and held out, and what each file holds."""
    with raw.open("rb") as handle:
        sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    return {
        "dataset": "CIC-IDS2017 improved, Liu et al., IEEE CNS 2022",
        "source_files": {raw.name: sha256},
        "seed": seed,
        "caps": {"pool": vars(caps[0]), "test": vars(caps[1])},
        "novel_labels": sorted(NOVEL_LABELS),
        "dropped_labels": sorted(DROPPED_LABELS) + [f"* {ATTEMPTED_SUFFIX.strip()}"],
        "dropped_rows": dict(sorted(dropped.items())),
        "rows_by_label": {name: dict(sorted(Counter(str(row[-1]) for row in side_rows).items())) for name, side_rows in rows.items()},
        "prepared_on": datetime.now(UTC).date().isoformat(),
    }


def prepare(raw: Path, out: Path, seed: int, caps: tuple[Caps, Caps] = (POOL_CAPS, TEST_CAPS)) -> None:
    """Write pool.csv, test.csv and splits/SOURCE.json next to the card in `out`; splits already drawn keep their entries."""
    config = load_config(out / "dataset.json")
    kept, dropped = index_flows(raw, config)
    rows = collect(raw, config, choose(kept, config, seed, caps))
    for name, side_rows in rows.items():
        write_split(out / f"{name}.csv", split_header(config, "end", *EXTRA_COLUMNS), side_rows)
        print(f"{out / name}.csv: {len(side_rows)} rows")
    source_path = out / "splits" / "SOURCE.json"
    source: dict[str, object] = {"sizes": {}, "novel_attack_rows": {}}
    if source_path.exists():
        source = json.loads(source_path.read_text(encoding="utf-8"))
    source.update(manifest(raw, seed, caps, dropped, rows))
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Parse the command line and prepare the dataset."""
    parser = argparse.ArgumentParser(description="prepare CIC-IDS2017 (improved) for Jev IDS")
    parser.add_argument("--raw", type=Path, default=Path("data/raw/cicids2017") / ZIP_NAME, help="the downloaded zip")
    parser.add_argument("--out", type=Path, default=Path("data/cicids2017"), help="folder holding dataset.json")
    parser.add_argument("--seed", type=int, default=20261027, help="seed of the capped samples")
    args = parser.parse_args()
    prepare(args.raw, args.out, args.seed)


if __name__ == "__main__":
    main()
