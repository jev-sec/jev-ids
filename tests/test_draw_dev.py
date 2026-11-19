"""The development stream with pseudo-novel attacks, on a pool small enough to read."""

import argparse
import csv
from collections import Counter
from pathlib import Path

import pytest

from scripts import draw_dev

HEADER = ["row_id", "category", "novel_attack", "raw_label"]
POOL = (
    [["BENIGN", "BENIGN"]] * 6
    + [["DoS", "DoS flood"]] * 4
    + [["DoS", "DoS slow"]] * 4
    + [["DDoS", "DDoS flood"]] * 2
    + [["DDoS", "DDoS slow"]] * 3
    + [["Web", "Web xss"]] * 3
)


def test_the_largest_name_of_each_category_and_its_twin_leave_the_memory() -> None:
    names = Counter((category, name) for category, name in POOL)
    # Checking the tie in DoS goes to the first name in alphabetical order, its DDoS twin joins it, the larger DDoS name is held
    # out too, and Web, with one name, keeps it.
    assert draw_dev.held_out_names(names, "BENIGN") == ["DDoS flood", "DDoS slow", "DoS flood", "DoS slow"]


def test_the_stream_holds_the_asked_mix_and_the_pool_keeps_neither_it_nor_the_held_out_names() -> None:
    rows = [[str(index), category, "0", name] for index, (category, name) in enumerate(POOL)]
    args = argparse.Namespace(size=8, benign=3, novel=4, seed=0, held_out=None)
    held, stream, pool = draw_dev.draw(rows, HEADER, "BENIGN", args)
    assert Counter(row[1] for row in stream if row[2] == "0") == {"BENIGN": 3, "Web": 1}
    assert Counter(row[3] for row in stream if row[2] == "1") == dict.fromkeys(held, 1)
    assert not {row[0] for row in stream} & {row[0] for row in pool}
    assert {row[3] for row in pool} == {"BENIGN", "Web xss"}


def test_asked_names_replace_the_rule_on_a_card_of_one_name_per_category() -> None:
    rows = [[str(index), category, "0", name] for index, (category, name) in enumerate(POOL)]
    args = argparse.Namespace(size=8, benign=3, novel=3, seed=0, held_out=["Web xss"])
    held, stream, pool = draw_dev.draw(rows, HEADER, "BENIGN", args)
    assert held == ["Web xss"]
    assert Counter(row[3] for row in stream if row[2] == "1") == {"Web xss": 3}
    assert "Web xss" not in {row[3] for row in pool}


def test_main_writes_a_dataset_folder_with_the_stream_as_its_validation_split(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "toy"
    source.mkdir()
    (source / "dataset.json").write_text('{"benign": "BENIGN"}', encoding="utf-8")
    with (source / "pool.csv").open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows([HEADER, *([str(index), category, "0", name] for index, (category, name) in enumerate(POOL))])
    monkeypatch.setattr("sys.argv", ["draw_dev", "--dataset", str(source), "--size", "8", "--benign", "3", "--novel", "4"])
    draw_dev.main()
    with (tmp_path / "toy-dev" / "splits" / "validation.csv").open(encoding="utf-8", newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 8
    assert (tmp_path / "toy-dev" / "pool.csv").exists()
