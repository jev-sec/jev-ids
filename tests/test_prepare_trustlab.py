"""The TRUSTLab preparation script, on family files small enough to read."""

import csv
import gzip
import io
import json
from pathlib import Path

import pytest

from scripts import prepare_trustlab as prepare
from scripts.prepare_cicids2017 import Caps

FEATURES = ["Dst Port", "Flow Duration", "Total Fwd Packet", "Flow Bytes/s", "Flow IAT Mean", "CWR Flag Count"]
HEADER = ["Src IP", *prepare.RENAMED, "CWE Flag Count", "Timestamp", "Label"]
WRITTEN = {
    "Benign": "benign",
    "C2Beaconing": "C2Beac",
    "Exfiltration": "Exfiltracion",
    "Exploitation": "Explotacion",
}


def family_file(folder: Path, name: str, rows: list[dict[str, str]], truncated: bool = False) -> None:
    """Write one gzipped family file with the TRUSTLab header, cutting its compressed bytes short when `truncated`."""
    text = io.StringIO()
    writer = csv.DictWriter(text, HEADER, restval="1")
    writer.writeheader()
    writer.writerows(rows)
    data = gzip.compress(text.getvalue().encode())
    (folder / f"{name}.csv.gz").write_bytes(data[:-12] if truncated else data)


def flows(name: str, count: int, **values: str) -> list[dict[str, str]]:
    """`count` rows of one family one second apart from 2025-06-01 00:00 UTC, with the label its file writes."""
    label = WRITTEN.get(name, name.lower())
    return [{"Timestamp": str(1748736000 + second), "Label": label, **values} for second in range(count)]


@pytest.fixture
def prepared(tmp_path: Path) -> Path:
    """A raw folder of 16 family files and the folder `prepare` wrote from it."""
    raw, out = tmp_path / "raw", tmp_path / "trustlab"
    raw.mkdir()
    (out / "splits").mkdir(parents=True)
    card = {
        "name": "trustlab",
        "features": FEATURES,
        "symbolic": [],
        "categories": ["BENIGN", *prepare.FAMILIES],
        "benign": "BENIGN",
        "attack_names": {family: [family] for family in prepare.FAMILIES},
    }
    (out / "dataset.json").write_text(json.dumps(card), encoding="utf-8")

    # Writing 4 benign rows, one of zero duration with an infinite rate and one with a value that is not finite, and 4 rows per family.
    benign = [*flows("Benign", 2), *flows("Benign", 1, **{"Flow Duration": "0", "Flow Byts/s": "inf", "Flow IAT Mean": "NaN"})]
    family_file(raw, "Benign", [*benign, *flows("Benign", 1, **{"Tot Fwd Pkts": "inf"})])
    for family in prepare.FAMILIES:
        family_file(raw, family, flows(family, 4, **{"CWE Flag Count": "7"}), truncated=family == "PortScan")
    prepare.prepare(raw, out, seed=0, caps=(Caps(benign=10, attack=10), Caps(benign=10, attack=10)))
    return out


def test_novel_families_reach_the_test_alone_and_known_ones_split_in_time(prepared: Path) -> None:
    sides = {name: list(csv.DictReader((prepared / f"{name}.csv").read_text(encoding="utf-8").splitlines())) for name in ("pool", "test")}
    pool_labels = {row["raw_label"] for row in sides["pool"]}
    assert not pool_labels & prepare.NOVEL_LABELS
    assert {row["raw_label"] for row in sides["test"] if row["novel_attack"] == "1"} == prepare.NOVEL_LABELS
    # Checking the earlier half of a known family goes to the pool and the later half to the test.
    api = {name: sorted(row["timestamp"] for row in rows if row["raw_label"] == "API") for name, rows in sides.items()}
    assert len(api["pool"]) == len(api["test"]) == 2
    assert api["pool"][-1] < api["test"][0]


def test_rows_are_renamed_repaired_and_dropped_as_the_decisions_say(prepared: Path) -> None:
    rows = [row for name in ("pool", "test") for row in csv.DictReader((prepared / f"{name}.csv").read_text(encoding="utf-8").splitlines())]
    benign = [row for row in rows if row["category"] == "BENIGN"]
    assert len(benign) == 3
    assert {row["Flow Bytes/s"] for row in benign if row["Flow Duration"] == "0"} == {"-1"}
    assert {row["Flow IAT Mean"] for row in benign if row["Flow Duration"] == "0"} == {"0"}
    assert {row["CWR Flag Count"] for row in rows if row["category"] == "API"} == {"7"}
    source = json.loads((prepared / "splits" / "SOURCE.json").read_text(encoding="utf-8"))
    assert source["dropped_rows"] == {"Benign": 1}
    assert source["novel_labels"] == sorted(prepare.NOVEL_LABELS)


def test_a_label_of_another_family_raises() -> None:
    with pytest.raises(ValueError, match="writes the label"):
        prepare.label_of("DNS", {"Label": "dos", "Timestamp": "1"})
