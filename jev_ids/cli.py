"""The command line: `jev-ids run|redo-errors|metrics|compare|sign-test`, also reachable as `python -m jev_ids`.

In reading order:

- `parse_k` and `parse_list`: the list arguments (`--k 0,1,all`).
- `build_parser`: the five subcommands and their arguments.
- `run_command`, `redo_command`, `metrics_command`, `compare_command`, `sign_test_command`: one handler per subcommand, each turning
  the parsed arguments into calls of `run` or `metrics`.
- `print_csv`: a table as CSV on stdout.
- `main`: parse, dispatch, return the exit code.

Nothing here knows how a Detector or a metric works, and no dataset is named here: `run` takes the card of the dataset as `--dataset`.
"""

import argparse
import csv
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from jev_ids import ROOT, metrics, run
from jev_ids.records import read_predictions


def parse_k(text: str) -> int | None:
    """One k: an integer, or `all` for the whole pool (Random Forest only)."""
    return None if text.strip() == "all" else int(text)


def parse_list(text: str) -> tuple[int | None, ...]:
    """A comma-separated list of integers: `--k 0,1,2,all` and `--seeds 0,1,2`.

    Both arguments are read the same way, so `all` is accepted for `--seeds` too, where it means nothing; nobody writes it and one parser is
    worth that much looseness.
    """
    return tuple(parse_k(part) for part in text.split(","))


def build_parser() -> argparse.ArgumentParser:
    """The five subcommands; each one carries the function that handles it."""
    parser = argparse.ArgumentParser(prog="jev-ids")
    commands = parser.add_subparsers(dest="command", required=True)

    runner = commands.add_parser("run", help="run one detector over one split")
    runner.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    runner.add_argument("--detector", required=True, help="jev, llm:deepseek, llm:openai, llm:gemini, random_forest or isolation_forest")
    runner.add_argument("--split", required=True, help="internal, pilot, smoke, ...")
    runner.add_argument(
        "--k",
        type=parse_list,
        default=(0, 1, 2, 4, 8),
        help="examples per category, comma separated; `all` for the forests",
    )
    runner.add_argument("--seeds", type=parse_list, default=(0, 1, 2), help="seeds of the example draws")
    runner.add_argument("--reps", type=int, default=1, help="repetitions of each (k, seed) cell")
    runner.add_argument("--model", help="provider model id, for the LLM detectors")
    runner.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the run directory is created")
    runner.set_defaults(handler=run_command)

    redoer = commands.add_parser("redo-errors", help="complete a run in place: its error rows again, its missing flows for the first time")
    redoer.add_argument("run_dir", type=Path, help="results/<run_id> directory")
    redoer.set_defaults(handler=redo_command)

    reporter = commands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories")
    reporter.set_defaults(handler=metrics_command)

    comparer = commands.add_parser("compare", help="paired comparison of two detectors over the same split")
    comparer.add_argument("--a", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector A")
    comparer.add_argument("--b", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector B")
    comparer.add_argument(
        "--subset",
        choices=("all", "novel", "known"),
        default="all",
        help="every flow, only novel attacks or only known attacks",
    )
    comparer.add_argument("--k-a", help="cut run A to this k or `all`")
    comparer.add_argument("--k-b", help="cut run B to this k or `all`")
    comparer.set_defaults(handler=compare_command)

    signer = commands.add_parser("sign-test", help="flow-level sign test of two detectors on every subset and k, Holm-adjusted")
    signer.add_argument("--a", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector A")
    signer.add_argument("--b", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector B")
    signer.set_defaults(handler=sign_test_command)
    return parser


def run_command(args: argparse.Namespace) -> None:
    """`run`: one detector over one split; argparse already converted the types."""
    spec = run.RunSpec(
        detector=args.detector,
        dataset=args.dataset,
        split=args.split,
        k_values=args.k,
        seeds=args.seeds,
        reps=args.reps,
        model_id=args.model,
        results_dir=args.results_dir,
    )
    run.run_from_spec(spec)


def redo_command(args: argparse.Namespace) -> None:
    """`redo-errors`: complete the run directory given, in place."""
    run.redo_errors(args.run_dir)


def metrics_command(args: argparse.Namespace) -> None:
    """`metrics`: one CSV row per group over every run given, on stdout."""
    predictions = [p for run_dir in args.run_dirs for p in read_predictions(run_dir)]
    print_csv(metrics.summarize(predictions))


def compare_command(args: argparse.Namespace) -> None:
    """`compare`: the paired comparison of two detectors, optionally across k, as CSV."""
    if (args.k_a is None) != (args.k_b is None):
        raise SystemExit("--k-a and --k-b come together")
    across_k = None if args.k_a is None else (parse_k(args.k_a), parse_k(args.k_b))
    # A detector may be spread over several run directories (one k each, run in parallel); each side is the union of its rows.
    run_a = metrics.only_subset([p for run_dir in args.a for p in read_predictions(run_dir)], args.subset)
    run_b = metrics.only_subset([p for run_dir in args.b for p in read_predictions(run_dir)], args.subset)
    print_csv(metrics.compare(run_a, run_b, across_k))


def sign_test_command(args: argparse.Namespace) -> None:
    """`sign-test`: the flow-level sign test on all flows, known and novel attacks, with Holm's adjustment across every row, as CSV."""
    run_a = [p for run_dir in args.a for p in read_predictions(run_dir)]
    run_b = [p for run_dir in args.b for p in read_predictions(run_dir)]
    table = [
        {"subset": subset, **row}
        for subset in ("all", "known", "novel")
        for row in metrics.sign_test(metrics.only_subset(run_a, subset), metrics.only_subset(run_b, subset))
    ]
    # Adjusting the family of every subset and k together, the 15 comparisons of the paper's Table 4.
    for row, adjusted in zip(table, metrics.holm([float(row["sign_p"]) for row in table]), strict=True):
        row["holm_p"] = adjusted
    print_csv(table)


def print_csv(rows: Sequence[dict[str, Any]]) -> None:
    """The rows as CSV on stdout, header first; nothing at all when there are none.

    The header is every key any row has, in order of first appearance: the usage columns of a summary follow the Detectors present. CSV on
    stdout: the user redirects it when a file is wanted.
    """
    if not rows:
        return
    header = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(sys.stdout, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """Load the secrets of `.env`, parse the command line and call the subcommand's handler."""
    # The API keys live in `.env` and never in git (README); the console script and `python -m jev_ids` both pass through here.
    load_dotenv(ROOT / ".env")
    args = build_parser().parse_args(argv)
    args.handler(args)
    return 0
