"""Draw a development stream from a dataset's pool, with pseudo-novel attacks, into a dataset folder of its own.

Run from the repository root:

    uv run python -m scripts.draw_dev --dataset data/cicids2017
    uv run python -m scripts.draw_dev --dataset data/trustlab --held-out DNS Exploitation TLSSSL --seed 20261116

The validation stream holds no novel attack, so a cut chosen on it never sees one (docs/jevids-design.md,
D9). Here, in each Category with at least two attack names in `pool.csv`, the name with the most pool Flows
leaves the memory and plays a novel attack, ties broken by alphabetical order, and its twin in DoS or DDoS leaves with it. The stream
draws `--benign` BENIGN Flows, `--novel` Flows of the held-out names in equal shares and the other attacks from the pool. The new folder,
`<dataset>-dev` by default, gets the same card, a pool without the held-out names and without the stream's Flows, which enter the memory
through feedback only, and the stream as its split `validation`, so `jev-ids threshold` takes the cut from its runs.
"""

import argparse
import csv
import json
import random
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jev_ids.dataset import write_split

TWINS = ("DoS ", "DDoS ")


def parse_args() -> argparse.Namespace:
    """The command line: the source folder, the target folder, the sizes and the seed."""
    parser = argparse.ArgumentParser(description="draw a development stream with pseudo-novel attacks from a dataset's pool")
    parser.add_argument("--dataset", type=Path, required=True, help="folder holding dataset.json and pool.csv")
    parser.add_argument("--out", type=Path, help="folder to write, <dataset>-dev by default")
    parser.add_argument("--size", type=int, default=1000, help="Flows in the stream")
    parser.add_argument("--benign", type=int, default=300, help="BENIGN Flows in the stream")
    parser.add_argument("--novel", type=int, default=150, help="Flows of the held-out names in the stream")
    parser.add_argument("--seed", type=int, default=20261115, help="seed of the draw")
    parser.add_argument("--held-out", nargs="+", help="attack names to hold out instead of the rule's, for a card of one name per Category")
    return parser.parse_args()


def held_out_names(names: Counter[tuple[str, str]], benign: str) -> list[str]:
    """The attack name with the most pool Flows in each Category that has two or more, plus its DoS or DDoS twin, sorted.

    Args:
        names: the pool Flows per (Category, attack name).
        benign: the benign Category, which holds no attack name.

    Returns:
        The held-out attack names.
    """
    by_category: dict[str, list[tuple[int, str]]] = {}
    for (category, name), count in names.items():
        if category != benign:
            by_category.setdefault(category, []).append((-count, name))
    chosen = {min(options)[1] for options in by_category.values() if len(options) >= 2}  # noqa: PLR2004  two names make one held out
    present = {name for _, name in names}
    for name in list(chosen):
        for prefix, other in zip(TWINS, reversed(TWINS), strict=True):
            twin = other + name.removeprefix(prefix)
            if name.startswith(prefix) and twin in present:
                chosen.add(twin)
    return sorted(chosen)


def draw(
    rows: list[list[str]], header: list[str], benign: str, args: argparse.Namespace
) -> tuple[list[str], list[list[str]], list[list[str]]]:
    """The held-out names, the stream's rows with their novel flag set, and the pool left for the memory."""
    category, label, novel = header.index("category"), header.index("raw_label"), header.index("novel_attack")
    held = sorted(args.held_out or held_out_names(Counter((row[category], row[label]) for row in rows), benign))
    order = list(range(len(rows)))
    random.Random(args.seed).shuffle(order)  # noqa: S311  seeded, reproducible draw

    # Taking the first rows of the shuffled order in three groups: BENIGN, each held-out name with an equal share (the first names
    # take the remainder), and the attacks of the names that stay in the memory.
    shares = [args.novel // len(held) + (index < args.novel % len(held)) for index in range(len(held))]
    picked = [index for index in order if rows[index][category] == benign][: args.benign]
    for name, share in zip(held, shares, strict=True):
        picked += [index for index in order if rows[index][label] == name][:share]
    others = args.size - args.benign - args.novel
    picked += [index for index in order if rows[index][category] != benign and rows[index][label] not in held][:others]
    if len(picked) != args.size:
        raise ValueError(f"{len(picked)} Flows drawn, {args.size} asked")

    # Marking the held-out Flows as novel attacks, so the runs report first contact for them, and keeping the pool free of the
    # held-out names and of the stream's own Flows.
    stream = [[*rows[index][:novel], str(int(rows[index][label] in held)), *rows[index][novel + 1 :]] for index in sorted(picked)]
    taken = set(picked)
    pool = [row for index, row in enumerate(rows) if index not in taken and row[label] not in held]
    return held, stream, pool


def main() -> None:
    """Draw the stream and write the new dataset folder with its card, pool, split and manifest."""
    args = parse_args()
    out = args.out or args.dataset.with_name(f"{args.dataset.name}-dev")
    card = json.loads((args.dataset / "dataset.json").read_text(encoding="utf-8"))
    with (args.dataset / "pool.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        rows = list(reader)
    held, stream, pool = draw(rows, header, card["benign"], args)
    (out / "splits").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.dataset / "dataset.json", out / "dataset.json")
    write_split(out / "pool.csv", header, pool)
    write_split(out / "splits" / "validation.csv", header, stream)
    category = header.index("category")
    manifest = {
        "source": str(args.dataset),
        "seed": args.seed,
        "held_out": held,
        "stream": dict(sorted(Counter(row[category] for row in stream).items())),
        "novel_attack_rows": sum(row[header.index("novel_attack")] == "1" for row in stream),
        "pool_rows": len(pool),
        "drawn_on": datetime.now(UTC).date().isoformat(),
    }
    (out / "splits" / "SOURCE.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
