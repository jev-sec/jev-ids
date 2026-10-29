"""The `jev-ids` command line run as its user runs it, on a small validation run, against reference outputs."""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPOSITORY = HERE.parents[1]
RUN = "tests/e2e/fixtures/validation-run"
# Naming each reference file with the arguments that produce it, recorded at commit 1539fbe.
REFERENCES = {
    "metrics.csv": ["metrics", RUN],
    "metrics-at-0.3.csv": ["metrics", RUN, "--threshold", "0.3"],
    "threshold.csv": ["threshold", RUN],
}


def test_every_command_prints_its_reference_output() -> None:
    for reference, arguments in REFERENCES.items():
        # Running the command line as its own process from the repository root, the way its user runs it.
        completed = subprocess.run(  # noqa: S603  runs this repository's own command line with fixed arguments
            [sys.executable, "-m", "jev_ids", *arguments],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPOSITORY,
        )
        assert completed.stdout == (HERE / "expected" / reference).read_text(encoding="utf-8"), reference
