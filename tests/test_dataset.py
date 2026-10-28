"""The card, the shared CSV shape and the Flow."""

import hashlib
from datetime import datetime
from pathlib import Path

import pytest

from jev_ids import ROOT, dataset
from tests.helpers import CONFIG, make_flow, write_dataset

SHARED_HEADER = ["row_id", "a", "b", "c", "category", "novel_attack"]


def test_load_config_adds_the_hash_and_the_folder(tmp_path: Path) -> None:
    card = write_dataset(tmp_path, CONFIG, {})
    config = dataset.load_config(card)
    assert config["name"] == "test"
    assert config["features"] == ["a", "b", "c"]
    assert config["sha256"] == hashlib.sha256(card.read_bytes()).hexdigest()
    assert config["dir"] == tmp_path / "test"


def test_load_split_round_trips_flows_in_card_order(tmp_path: Path) -> None:
    flows = [make_flow(0, "normal"), make_flow(7, "dos", value="3", novel_attack=True)]
    config = dataset.load_config(write_dataset(tmp_path, CONFIG, {"pool": flows}))
    assert dataset.load_split(config["dir"] / "pool.csv", config) == flows
    # Columns are read by name and joined in card order; extra ones are ignored.
    path = tmp_path / "shuffled.csv"
    header = ["c", "novel_attack", "row_id", "b", "category", "a", "difficulty"]
    dataset.write_split(path, header, [["z", "1", "4", "y", "probe", "x", "21"]])
    (flow,) = dataset.load_split(path, config)
    assert flow == dataset.Flow(4, "x,y,z", "probe", is_attack=True, novel_attack=True)
    assert flow.attribute_values == ("x", "y", "z")
    # A dataset with timestamps adds `end`, when the Flow ended.
    dataset.write_split(path, [*SHARED_HEADER, "end"], [[5, "x", "y", "z", "normal", "0", "2017-07-04T10:00:01.500001"]])
    (flow,) = dataset.load_split(path, config)
    assert flow.end == datetime(2017, 7, 4, 10, 0, 1, 500001)


def test_load_split_rejects_unknown_categories_and_missing_features(
    tmp_path: Path,
) -> None:
    config = dataset.load_config(write_dataset(tmp_path, CONFIG, {}))
    path = tmp_path / "bad.csv"
    dataset.write_split(path, SHARED_HEADER, [[1, 0, 0, 0, "u2r", 0]])
    with pytest.raises(ValueError, match="row 1: category 'u2r' is not in the card"):
        dataset.load_split(path, config)
    dataset.write_split(path, SHARED_HEADER[:3] + SHARED_HEADER[4:], [[1, 0, 0, "dos", 0]])
    with pytest.raises(KeyError, match="c"):
        dataset.load_split(path, config)


@pytest.mark.parametrize(("name", "features", "categories"), [("nsl-kdd", 41, 5), ("cicids2017", 83, 6)])
def test_each_committed_card_is_consistent(name: str, features: int, categories: int) -> None:
    config = dataset.load_config(ROOT / "data" / name / "dataset.json")
    assert config["name"] == name
    assert len(config["features"]) == features
    assert len(set(config["features"])) == features
    assert set(config["symbolic"]) <= set(config["features"])
    assert len(config["categories"]) == categories
    assert config["benign"] in config["categories"]
    assert set(config["attack_names"]) == set(config["categories"]) - {config["benign"]}


def test_the_nsl_kdd_card_maps_every_attack_name() -> None:
    config = dataset.load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
    assert sum(len(names) for names in config["attack_names"].values()) == 39


def test_compact_value_keeps_four_significant_digits_and_the_order_of_magnitude() -> None:
    # Large and small values keep their order of magnitude, the proof of stage 2 (docs/jevids-design.md, D7), and never get an exponent.
    cases = {
        "25160.418777440053": "25160",
        "168.86187098953056": "168.9",
        "520518.0347826088": "520500",
        "1.9295159033373677": "1.93",
        "0.0000123456": "0.00001235",
        "1.5e-07": "0.00000015",
        "-3.14159": "-3.142",
    }
    for value, compact in cases.items():
        assert dataset.compact_value(value) == compact
        assert abs(float(compact) - float(value)) <= 5e-4 * abs(float(value))
    for value in ("123456789.123", "0.000987654", "4.2e-05", "98765.4321"):
        assert "e" not in dataset.compact_value(value)


def test_compact_value_leaves_integers_and_non_numbers_and_drops_a_bare_point_zero() -> None:
    for value in ("44321", "119719148", "-1", "0", "tcp", "REJ", "inf", "nan", ""):
        assert dataset.compact_value(value) == value
    assert [dataset.compact_value(value) for value in ("0.0", "37.0", "-1.0")] == ["0", "37", "-1"]


def test_record_text_is_full_or_compact_and_never_changes_the_flow() -> None:
    flow = dataset.Flow(row_id=1, attributes_csv="53,tcp,25160.418777440053,0.0", category="normal", is_attack=False)
    assert dataset.record_text(flow, "full") == flow.attributes_csv
    assert dataset.record_text(flow, "compact") == "53,tcp,25160,0"
    assert flow.attribute_values == ("53", "tcp", "25160.418777440053", "0.0")
    with pytest.raises(ValueError, match="record"):
        dataset.record_text(flow, "short")
