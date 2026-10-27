"""The card, the shared CSV shape and the Flow."""

import hashlib
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
