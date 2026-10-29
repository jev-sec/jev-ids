"""Draw one proportional split from a dataset's test file (or its pool), disjoint from every split already on disk.

Run from the repository root. The `paper` split of NSL-KDD was drawn with:

    uv run python -m scripts.draw_split --dataset data/nsl-kdd --name paper --size 2000 --min-novel 300

The rows of `test.csv` are shuffled once with the seed and the first `--size` rows whose `row_id` no other split file holds are taken: a
uniform sample keeps the file's mix of Categories and of novel attacks, so the split is proportional, and skipping the taken rows keeps it
disjoint from the splits it leaves in place. A split of the same name is replaced and does not count as taken. Rows are copied verbatim
from the test file, header included, so the split keeps its trace columns. `SOURCE.json` gets the new size, the novel count and the draw.

`--source pool.csv` draws from the pool instead: the validation stream that tunes a choice without reading the test file
(docs/jevids-design.md, D9). Its Flows stay in the pool, so a run over it must not offer a Flow as its own Example.
"""

import argparse
import csv
import json
import random
from datetime import UTC, datetime
from pathlib import Path

from jev_ids.dataset import write_split


def parse_args() -> argparse.Namespace:
    """The command line: the dataset folder, the split's name and size, the seed and the novel floor."""
    parser = argparse.ArgumentParser(description="draw one split from a dataset's test file")
    parser.add_argument("--dataset", type=Path, required=True, help="folder holding test.csv and splits/")
    parser.add_argument("--name", required=True, help="the split to write, splits/<name>.csv")
    parser.add_argument("--size", type=int, required=True, help="rows to draw")
    parser.add_argument("--seed", type=int, default=20260920, help="the seed the other NSL-KDD splits were drawn with")
    parser.add_argument("--min-novel", type=int, default=0, help="refuse a draw with fewer novel-attack rows than this")
    parser.add_argument("--source", default="test.csv", help="the file to draw from, in the dataset folder: test.csv or pool.csv")
    return parser.parse_args()


def taken_row_ids(splits_dir: Path, name: str) -> tuple[list[str], set[str]]:
    """The names of the other split files and every row_id they hold."""
    others = sorted(path.stem for path in splits_dir.glob("*.csv") if path.stem != name)
    taken: set[str] = set()
    for other in others:
        with (splits_dir / f"{other}.csv").open(encoding="utf-8", newline="") as handle:
            taken.update(row["row_id"] for row in csv.DictReader(handle))
    return others, taken


def main() -> None:
    """Draw the split, write it next to the others and record it in SOURCE.json."""
    args = parse_args()
    with (args.dataset / args.source).open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        rows = list(reader)
    row_id, novel = header.index("row_id"), header.index("novel_attack")
    others, taken = taken_row_ids(args.dataset / "splits", args.name)
    random.Random(args.seed).shuffle(rows)  # noqa: S311  seeded, reproducible draw
    drawn = [row for row in rows if row[row_id] not in taken][: args.size]
    novel_rows = sum(row[novel] == "1" for row in drawn)
    if len(drawn) < args.size or novel_rows < args.min_novel:
        raise ValueError(f"{len(drawn)} rows drawn, {novel_rows} novel attacks; asked {args.size} with at least {args.min_novel} novel")
    write_split(args.dataset / "splits" / f"{args.name}.csv", header, drawn)

    # Keeping in the manifest the sizes and novel counts of every split,
    # plus how this one was drawn, so the draw can be audited and repeated.
    manifest_path = args.dataset / "splits" / "SOURCE.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sizes"][args.name] = len(drawn)
    manifest["novel_attack_rows"][args.name] = novel_rows
    manifest.setdefault("draws", {})[args.name] = {
        "seed": args.seed,
        "source": args.source,
        "disjoint_from": others,
        "drawn_on": datetime.now(UTC).date().isoformat(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{args.name}: {len(drawn)} rows, {novel_rows} novel attacks, disjoint from {', '.join(others)}")


if __name__ == "__main__":
    main()
