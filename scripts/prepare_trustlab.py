"""Convert the per-family CSV files of TRUSTLab into the shared CSV shape of `data/trustlab/`.

Run once, from the repository root, after downloading the dataset of https://doi.org/10.82432/10317/21203 and joining its split parts
(`cat Benign.csv.gz.0* > Benign.csv.gz`, and the same for API, TLSSSL and WebBased) into one folder, then draw the splits:

    uv run python -m scripts.prepare_trustlab --raw <folder holding the 16 *.csv.gz>
    uv run python -m scripts.draw_split --dataset data/trustlab --name paper --size 2000 --seed 20261116

TRUSTLab is the testbed of Villafranca, Tasic and Cano, Frontiers in Computer Science, 2026, doi 10.3389/fcomp.2026.1803271.
Each file holds the CICFlowMeter 4.0 flows of benign sessions or of one attack family, captured apart from all others. The decisions
below were taken on 2026-11-16 (docs/jevids-design.md, D1):

1. Categories. Each of the 15 families is a Category with one attack name, its own, since the files carry no finer label. The label of a
   flow is the family of its file, and a written label that names another family raises.
2. Columns. The card keeps 70 of the 78 columns of the other cards, renamed to their names. TRUSTLab has no per-direction RST flags,
   no per-direction packet rates, no `Fwd Act Data Pkts`, no ICMP columns, no `Total TCP Flow Time` and no `Fwd Seg Size Min`. The
   four TCP-stack columns it has leave, as on the other cards. `CWR Flag Count` takes `CWR Flag Cnt` or the misnamed `CWE Flag Count`,
   whichever the row fills.
3. Repairs. A flow of zero duration gets -1 per second, and a NaN inter-arrival time gets 0. A flow still
   holding a value that is not finite, or cut short by the truncated end of `PortScan.csv.gz`, is dropped and counted.
4. Pool and test in time, per UTC day and family, with the caps and the rule of `prepare_cicids2017` (docs/jevids-design.md, D2).
5. Novel attacks. The families in `NOVEL_LABELS` never reach the pool. They were drawn by `novel_families` before any stream run.

`end`, the timestamp plus the Flow Duration in microseconds, orders the stream. `row_id` numbers the flows over the files in `FILES`
order. The trace columns `file`, `line` and `timestamp` lead back to the line of the downloaded file.
"""

import argparse
import csv
import gzip
import math
import random
import zlib
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jev_ids.dataset import Config, category_by_name, load_config
from scripts.prepare_cicids2017 import POOL_CAPS, TEST_CAPS, Caps, choose, write_prepared

FAMILIES = (
    "API",
    "Bruteforce",
    "BufferOverflow",
    "C2Beaconing",
    "DDoS",
    "DNS",
    "DoS",
    "Evasion",
    "Exfiltration",
    "Exploitation",
    "MITM",
    "PortScan",
    "Slowloris",
    "TLSSSL",
    "WebBased",
)
FILES = ("Benign", *FAMILIES)
BENIGN = "BENIGN"
DRAW_SEED = 20261116
NOVEL_COUNT = 4
TWINS = frozenset({"DoS", "DDoS"})
# Naming the family of each label as the files write it, in lower case.
WRITTEN_LABELS = {
    "benign": BENIGN,
    "c2beac": "C2Beaconing",
    "exfiltracion": "Exfiltration",
    "explotacion": "Exploitation",
} | {family.lower(): family for family in FAMILIES}
# Naming each kept column of TRUSTLab after the column of the other cards; the CWR flag is coalesced in `fields_of`.
RENAMED = {
    "Dst Port": "Dst Port",
    "Protocol": "Protocol",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packet",
    "Tot Bwd Pkts": "Total Bwd packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packet",
    "TotLen Bwd Pkts": "Total Length of Bwd Packet",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Fwd Segment Size Avg",
    "Bwd Seg Size Avg": "Bwd Segment Size Avg",
    "Fwd Byts/b Avg": "Fwd Bytes/Bulk Avg",
    "Fwd Pkts/b Avg": "Fwd Packet/Bulk Avg",
    "Fwd Blk Rate Avg": "Fwd Bulk Rate Avg",
    "Bwd Byts/b Avg": "Bwd Bytes/Bulk Avg",
    "Bwd Pkts/b Avg": "Bwd Packet/Bulk Avg",
    "Bwd Blk Rate Avg": "Bwd Bulk Rate Avg",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
}
CWR_COLUMNS = ("CWR Flag Cnt", "CWE Flag Count")
FLOW_IAT = ("Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min")
EXTRA_COLUMNS = ("day", "file", "line", "timestamp", "raw_label")


def twin_closed(families: list[str]) -> list[str]:
    """The families with DoS and DDoS together, as the twin rule of `scripts/draw_dev.py` keeps them, sorted."""
    chosen = set(families)
    if chosen & TWINS:
        chosen |= TWINS
    return sorted(chosen)


def novel_families(families: tuple[str, ...] = FAMILIES, count: int = NOVEL_COUNT, seed: int = DRAW_SEED) -> list[str]:
    """The families held out of the pool: `count` drawn with `seed` from the sorted families, then closed under the twin rule."""
    return twin_closed(random.Random(seed).sample(sorted(families), count))  # noqa: S311  seeded, reproducible draw


NOVEL_LABELS = frozenset(novel_families())


def fields_of(raw: dict[str, str]) -> dict[str, str] | None:
    """The card's columns of one written row with the repairs of decision 3, or None when a value is missing or not finite."""
    fields = {name: raw.get(column) or "" for column, name in RENAMED.items()}
    fields["CWR Flag Count"] = next((raw[column] for column in CWR_COLUMNS if raw.get(column)), "")
    if fields["Flow Duration"] in ("0", "0.0"):
        fields["Flow Bytes/s"] = fields["Flow Packets/s"] = "-1"
    for name in FLOW_IAT:
        fields[name] = "0" if fields[name].lower() == "nan" else fields[name]
    try:
        finite = all(math.isfinite(float(value)) for value in fields.values())
    except ValueError:
        return None
    return fields if finite else None


def read_rows(raw: Path) -> Iterator[tuple[int, str, int, dict[str, str]]]:
    """The (row_id, file, line, written row) of every line of every file, stopping a file quietly at a truncated end."""
    row_id = 0
    for name in FILES:
        with gzip.open(raw / f"{name}.csv.gz", "rt", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            line = 1
            try:
                for written in reader:
                    line += 1
                    yield row_id, name, line, written
                    row_id += 1
            except (EOFError, zlib.error):
                print(f"{name}.csv.gz ends early after line {line}")


def label_of(name: str, written: dict[str, str]) -> str | None:
    """The family of a written row, None for a row cut short, and an error when the written label names another family."""
    label = (written.get("Label") or "").strip().lower()
    if not label or None in written.values():
        return None
    family = WRITTEN_LABELS.get(label)
    expected = BENIGN if name == "Benign" else name
    if family != expected:
        raise ValueError(f"{name}.csv.gz writes the label {label!r}")
    return family


def started(written: dict[str, str]) -> datetime:
    """When a flow started, from its Unix timestamp, in UTC."""
    return datetime.fromtimestamp(float(written["Timestamp"]), tz=UTC)


def index_rows(raw: Path) -> tuple[dict[str, list[tuple[str, str, int]]], Counter[str]]:
    """The (day, timestamp, row_id) of every kept flow by family, and the number of dropped rows by file."""
    kept: dict[str, list[tuple[str, str, int]]] = {}
    dropped: Counter[str] = Counter()
    for row_id, name, _, written in read_rows(raw):
        label = label_of(name, written)
        if label is None or fields_of(written) is None:
            dropped[name] += 1
            continue
        start = started(written)
        kept.setdefault(label, []).append((start.date().isoformat(), start.isoformat(), row_id))
    return kept, dropped


def collect(raw: Path, config: Config, side: dict[int, str]) -> dict[str, list[list[object]]]:
    """The rows of pool.csv and test.csv in the shared shape, in row_id order."""
    categories = category_by_name(config)
    rows: dict[str, list[list[object]]] = {side_name: [] for side_name in ("pool", "test")}
    for row_id, name, line, written in read_rows(raw):
        if row_id in side:
            label = str(label_of(name, written))
            fields = fields_of(written) or {}
            start = started(written)
            end = (start + timedelta(microseconds=float(fields["Flow Duration"]))).isoformat()
            extra = (start.date().isoformat(), name, line, start.isoformat(), label)
            values = [fields[feature] for feature in config["features"]]
            rows[side[row_id]].append([row_id, *values, categories[label], int(label in NOVEL_LABELS), end, *extra])
    return rows


def prepare(raw: Path, out: Path, seed: int, caps: tuple[Caps, Caps] = (POOL_CAPS, TEST_CAPS)) -> None:
    """Write pool.csv, test.csv and a splits/SOURCE.json that records the novel draw next to the TRUSTLab card in `out`.

    The entries of the splits already drawn stay in SOURCE.json.
    """
    config = load_config(out / "dataset.json")
    kept, dropped = index_rows(raw)
    rows = collect(raw, config, choose(kept, config, seed, caps, NOVEL_LABELS))
    facts: dict[str, object] = {
        "dataset": "TRUSTLab, Villafranca, Tasic and Cano, Frontiers in Computer Science, 2026",
        "flow_meter": "CICFlowMeter 4.0, as published",
        "seed": seed,
        "caps": {
            "pool": vars(caps[0]),
            "test": vars(caps[1]),
        },
        "novel_labels": sorted(NOVEL_LABELS),
        "novel_draw": {
            "seed": DRAW_SEED,
            "count": NOVEL_COUNT,
            "twins": sorted(TWINS),
        },
        "dropped_rows": dict(sorted(dropped.items())),
        "days": {label: [min(day for day, _, _ in flows), max(day for day, _, _ in flows)] for label, flows in sorted(kept.items())},
    }
    write_prepared(out, config, rows, EXTRA_COLUMNS, facts)


def main() -> None:
    """Parse the command line, then prepare the dataset."""
    parser = argparse.ArgumentParser(description="prepare TRUSTLab for JevIDS")
    parser.add_argument("--raw", type=Path, required=True, help="folder holding the 16 joined *.csv.gz files")
    parser.add_argument("--out", type=Path, default=Path("data/trustlab"), help="folder holding dataset.json")
    parser.add_argument("--seed", type=int, default=DRAW_SEED, help="seed of the capped samples")
    args = parser.parse_args()
    prepare(args.raw, args.out, args.seed)


if __name__ == "__main__":
    main()
