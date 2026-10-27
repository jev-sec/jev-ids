"""The CIC-IDS2017 preparation script, on a five-day zip small enough to read."""

import csv
import json
import zipfile
from pathlib import Path

import pytest

from jev_ids import ROOT, dataset
from scripts import prepare_cicids2017 as prepare

HEADER = ["id", "Src IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label", "Attempted Category"]
CARD = {
    "name": "cic",
    "features": ["Dst Port", "Protocol", "Flow Duration"],
    "symbolic": ["Protocol"],
    "categories": ["BENIGN", "DoS", "BruteForce"],
    "benign": "BENIGN",
    "attack_names": {"DoS": ["DoS Hulk", "DoS Slowhttptest"], "BruteForce": ["FTP-Patator"]},
}
# Per day, the labels of its lines in file order; line i of a day has timestamp 2017-07-0d 10:00:i and Flow Duration i.
DAYS = {
    "monday": ["BENIGN"] * 4,
    "tuesday": ["FTP-Patator", "BENIGN", "FTP-Patator", "FTP-Patator - Attempted", "FTP-Patator", "BENIGN"],
    "wednesday": ["DoS Hulk"] * 6 + ["DoS Slowhttptest"] * 3 + ["Heartbleed", "DoS Hulk - Attempted"],
    "thursday": ["Web Attack - XSS", "BENIGN"],
    "friday": ["BENIGN"],
}
SMALL = (prepare.Caps(benign=2, attack=2), prepare.Caps(benign=3, attack=2))


def write_raw(tmp_path: Path, days: dict[str, list[str]]) -> tuple[Path, Path]:
    """The zip in `raw/` and a folder holding the card, as the script expects them."""
    raw = tmp_path / "raw" / prepare.ZIP_NAME
    raw.parent.mkdir()
    with zipfile.ZipFile(raw, "w") as archive:
        for number, (day, labels) in enumerate(days.items(), start=3):
            lines = [",".join(HEADER)]
            lines += [f"{i + 1},10.0.0.1,80,6,2017-07-0{number} 10:00:{i:02d}.5,{i},{label},-1" for i, label in enumerate(labels)]
            archive.writestr(f"{day}.csv", "\n".join(lines) + "\n")
    out = tmp_path / "cic"
    out.mkdir()
    (out / "dataset.json").write_text(json.dumps(CARD), encoding="utf-8")
    return raw, out


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_prepare_keeps_the_card_labels_and_holds_out_the_novel_ones(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, DAYS)
    prepare.prepare(raw, out, seed=1, caps=SMALL)
    pool, test = read_rows(out / "pool.csv"), read_rows(out / "test.csv")
    assert list(pool[0]) == dataset.split_header(CARD, "end", *prepare.EXTRA_COLUMNS)
    labels = {row["raw_label"] for row in pool + test}
    assert labels == {"BENIGN", "FTP-Patator", "DoS Hulk", "DoS Slowhttptest"}
    assert {row["raw_label"] for row in pool} == {"BENIGN", "FTP-Patator", "DoS Hulk"}
    assert all(row["novel_attack"] == str(int(row["raw_label"] == "DoS Slowhttptest")) for row in pool + test)
    assert not {row["row_id"] for row in pool} & {row["row_id"] for row in test}
    config = dataset.load_config(out / "dataset.json")
    assert [flow.category for flow in dataset.load_split(out / "test.csv", config)].count("DoS") == 4


def test_prepare_puts_the_earlier_half_of_each_day_in_the_pool_and_respects_the_caps(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, DAYS)
    prepare.prepare(raw, out, seed=1, caps=SMALL)
    pool, test = read_rows(out / "pool.csv"), read_rows(out / "test.csv")
    latest_pool: dict[tuple[str, str], str] = {}
    for row in pool:
        group = (row["raw_label"], row["day"])
        latest_pool[group] = max(latest_pool.get(group, ""), row["timestamp"])
    assert all(row["timestamp"] > latest_pool.get((row["raw_label"], row["day"]), "") for row in test)
    for label in ("BENIGN", "FTP-Patator", "DoS Hulk"):
        assert sum(row["raw_label"] == label for row in pool) <= 2
        assert sum(row["raw_label"] == label for row in test) <= (3 if label == "BENIGN" else 2)
    # Six DoS Hulk flows: three may become Examples, the cap keeps two.
    assert sum(row["raw_label"] == "DoS Hulk" for row in pool) == 2


def test_prepare_judges_benign_flows_on_every_day_they_occur(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, DAYS)
    prepare.prepare(raw, out, seed=1, caps=(prepare.Caps(9, 9), prepare.Caps(9, 9)))
    pool, test = read_rows(out / "pool.csv"), read_rows(out / "test.csv")
    # One cut over all eight BENIGN flows would put Monday's four in the pool and judge none of them.
    assert {row["day"] for row in pool if row["raw_label"] == "BENIGN"} == {"monday", "tuesday"}
    assert {row["day"] for row in test if row["raw_label"] == "BENIGN"} == {"monday", "tuesday", "thursday", "friday"}


def test_prepare_numbers_flows_across_days_and_keeps_the_trace(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, DAYS)
    prepare.prepare(raw, out, seed=1, caps=(prepare.Caps(9, 9), prepare.Caps(9, 9)))
    rows = read_rows(out / "pool.csv") + read_rows(out / "test.csv")
    by_id = {int(row["row_id"]): row for row in rows}
    # Tuesday's line 1 (BENIGN) comes after Monday's four lines.
    assert by_id[5]["day"] == "tuesday"
    assert by_id[5]["source_id"] == "2"
    assert by_id[5]["Flow Duration"] == "1"
    # 10:00:01.5 plus a Flow Duration of 1 microsecond.
    assert by_id[5]["end"] == "2017-07-04T10:00:01.500001"
    assert "Src IP" not in by_id[5]
    source = json.loads((out / "splits" / "SOURCE.json").read_text(encoding="utf-8"))
    assert source["dropped_rows"] == {
        "DoS Hulk - Attempted": 1,
        "FTP-Patator - Attempted": 1,
        "Heartbleed": 1,
        "Web Attack - XSS": 1,
    }
    assert sum(source["rows_by_label"]["pool"].values()) + sum(source["rows_by_label"]["test"].values()) == len(rows)


def test_prepare_is_reproducible_and_keeps_the_drawn_splits(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, DAYS)
    prepare.prepare(raw, out, seed=1, caps=SMALL)
    first = (out / "pool.csv").read_bytes(), (out / "test.csv").read_bytes()
    source_path = out / "splits" / "SOURCE.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["sizes"]["smoke"] = 5
    source_path.write_text(json.dumps(source), encoding="utf-8")
    prepare.prepare(raw, out, seed=1, caps=SMALL)
    assert ((out / "pool.csv").read_bytes(), (out / "test.csv").read_bytes()) == first
    assert json.loads(source_path.read_text(encoding="utf-8"))["sizes"] == {"smoke": 5}


def test_prepare_rejects_an_unknown_label_and_a_changed_header(tmp_path: Path) -> None:
    raw, out = write_raw(tmp_path, {**DAYS, "friday": ["Ransomware"]})
    with pytest.raises(ValueError, match="'Ransomware' is neither in the card nor dropped"):
        prepare.prepare(raw, out, seed=1)
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("monday.csv", ",".join(HEADER) + "\n")
        archive.writestr("tuesday.csv", "id,Label\n1,BENIGN\n")
    with pytest.raises(ValueError, match="tuesday.csv: header differs"):
        list(prepare.read_flows(raw))


def test_the_committed_card_lists_every_label_the_script_keeps() -> None:
    config = dataset.load_config(ROOT / "data" / "cicids2017" / "dataset.json")
    names = {name for names in config["attack_names"].values() for name in names}
    assert names >= prepare.NOVEL_LABELS
    assert not prepare.DROPPED_LABELS & names
    assert not {"Flow ID", "Src IP", "Dst IP", "Src Port", "Timestamp"} & set(config["features"])
