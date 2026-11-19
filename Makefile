# The virtual environment lives outside the repository unless the shell says otherwise: this folder may sit on a synced volume (iCloud
# Drive evicts files of .venv and hides its .pth files, so `uv run` hangs or cannot import the package). `?=` keeps any value the shell
# already exported.
UV_PROJECT_ENVIRONMENT ?= $(HOME)/.venvs/jev-ids
export UV_PROJECT_ENVIRONMENT

# Running the quality gate (added by /code-quality:setup), whose thresholds live in pyproject.toml / eslint.config.mjs
# Each check is one target. `make list` shows them by moment.
# To skip one, add `name = "reason"` under [tool.code-quality.skip] in pyproject.toml.
SHELL := bash

# Pinning the tools that run outside the lock file, so a new release never changes the gate by surprise
RUFF := uvx ruff@0.17.5
COMPLEXIPY := uvx complexipy@9.0.0
PIP_AUDIT := uvx pip-audit@2.10.1
JSCPD := npx jscpd@5.4.3

# Checking the edited file when the hook passes FILE, and the whole project otherwise
TARGET := $(or $(FILE),.)
PYFILES = $$(git ls-files -co --exclude-standard '*.py') /dev/null
READ_SKIPS = python3 -c 'import sys, tomllib; skips = tomllib.load(open("pyproject.toml", "rb")).get("tool", {}).get("code-quality", {}).get("skip", {}); print(*(skips if sys.argv[1] == "names" else [f"skipped {name}: {reason}" for name, reason in skips.items()]), sep=" " if sys.argv[1] == "names" else "\n")'
SKIP := $(shell [ ! -f pyproject.toml ] || $(READ_SKIPS) names)

# Listing the checks of each moment, by language
PY := $(wildcard pyproject.toml)
TS := $(wildcard package.json)
EDIT := format lint complexity
TURN := $(if $(PY),format lint complexity types tests dead-code class-size file-length suppressions lock) $(if $(TS),ts-fast) duplication
COMMIT := $(if $(PY),audit) $(if $(TS),ts-audit) test-guard
EXTRA := $(if $(PY),e2e imports) $(if $(TS),ts-check)
active = $(filter-out $(SKIP),$(1))
# Ending a failed check with one line that says how to fix it
fix = || { echo "FIX $@: $(1)" >&2; exit 1; }

.PHONY: check turn commit edit list skipped report mutation run-check run-turn \
  format lint complexity types tests dead-code class-size file-length suppressions lock \
  duplication audit test-guard e2e imports ts-fast ts-check ts-audit

# Saving the output of the last run with its commit, so a report can quote it.
# Running every check even after one fails (-k), so one run shows all the failures
check turn:
	@mkdir -p .quality && bash -o pipefail -c '{ git rev-parse HEAD 2>/dev/null; $(MAKE) -s -k run-$@; } 2>&1 | tee .quality/last-$@.txt'

run-turn: skipped $(call active,$(TURN)) report
run-check: skipped $(call active,$(TURN) $(COMMIT) $(EXTRA)) report
commit: skipped $(call active,$(COMMIT))
edit: $(call active,$(EDIT))

list:
	@printf 'edit    %s\nturn    %s\ncommit  %s\ncheck   adds %s\nskipped %s\n' "$(EDIT)" "$(strip $(TURN))" "$(strip $(COMMIT))" "$(strip $(EXTRA))" "$(or $(SKIP),none)"

skipped:
	@[ ! -f pyproject.toml ] || $(READ_SKIPS) reasons

format:
	@$(if $(FILE),$(RUFF) format -q "$(FILE)",$(RUFF) format --check .) $(call fix,run: $(RUFF) format .)

lint:
	@$(RUFF) check $(TARGET) $(call fix,refactor the code. A suppression is the last resort and names the rule and its reason)

complexity:
	@$(COMPLEXIPY) -q $(TARGET) $(call fix,simplify or inline before splitting the function)

types:
	@uv run pyright $(call fix,correct the types. cast and Any hide the error)

tests:
	@uv run pytest -q $(call fix,fix the code under test. Weakening a test or the coverage threshold is silencing)

dead-code:
	@uv run vulture $(call fix,delete the unused code)

# Counting instance attributes and public methods per class, and attributes first set outside __init__
class-size:
	@uv run pylint $(PYFILES) $(call fix,split the class by responsibility or group related attributes into one value)

# Counting lines without blanks and comments, the same way the TypeScript limit does
file-length:
	@awk 'FNR==1{n=0} NF && !/^[[:space:]]*#/{n++} n==401{print FILENAME ": more than 400 code lines"; bad=1} END{exit bad}' $(PYFILES) $(call fix,split the module by feature)

# Requiring a reason after the rule code of every suppression
suppressions:
	@! grep -nE '#[[:space:]]*(noqa|type: ignore|pyright: ignore)(:[[:space:]]*[A-Z0-9, ]+|\[[^]]*\])?[[:space:]]*$$' $(PYFILES) $(call fix,write the rule code and then the reason on the same line)

lock:
	@uv lock --check -q $(call fix,run: uv lock)

duplication:
	@$(JSCPD) . $(call fix,merge the repeated code into one place)

audit:
	@bash -o pipefail -c 'uv export --format requirements-txt --no-hashes -q | $(PIP_AUDIT) --no-deps --disable-pip -r /dev/stdin' $(call fix,upgrade the dependency or ignore the advisory by ID with a dated reason)

# Comparing the staged change with the last commit, so no test or threshold gets weaker unnoticed
test-guard:
	@python3 "$$(git rev-parse --git-path hooks)/code-quality-test-guard.py" $(call fix,restore the tests. When the expected behavior really changed then ask the user before committing with --no-verify)

e2e:
	@find tests/e2e -name 'test_*.py' 2>/dev/null | grep -q . $(call fix,add an end-to-end test under tests/e2e that runs the program the way its user does)

# Failing on import cycles between features when [tool.importlinter] is configured
imports:
	@! grep -q '^\[tool.importlinter\]' pyproject.toml || uv run lint-imports $(call fix,remove the import cycle)

ts-fast:
	@npx eslint . && npx prettier --check .

ts-check:
	@npx tsc --noEmit \
	  && (find tests/e2e -name '*.test.*' 2>/dev/null | grep -q . || (echo "tests/e2e has no end-to-end test" >&2; exit 1)) \
	  && npx vitest run --coverage && npx knip \
	  && npx madge --circular --extensions ts,tsx --exclude 'node_modules|\.next|dist' .

ts-audit:
	@npm audit --audit-level=high

# Reporting counts that inform a review and never fail the gate
report:
	@[ ! -f pyproject.toml ] || echo "report: cast=$$(grep -hoE '\bcast\(' $(PYFILES) | wc -l | tr -d ' ') suppressions=$$(grep -hoE '#[[:space:]]*(noqa|type: ignore|pyright: ignore)' $(PYFILES) | wc -l | tr -d ' ')"

# Running mutation testing, which is slow, so it stays outside `check` and runs before a release
mutation:
	@[ ! -f pyproject.toml ] || uv run mutmut run
	@[ ! -f package.json ] || npx stryker run


# The zero-day battery of docs/jevids-design.md, on the split `paper`. DATASET picks CIC-IDS2017 or TRUSTLab, as in
# `make -k zeroday-jev DATASET=trustlab`. A run that ends with no error row leaves a stamp in results/zeroday-<dataset>/v2-done/ holding
# the name of its directory, and make skips every run whose stamp exists, so the same command resumes a chain that was cut. Each stamp
# names the directory its own run printed, so `make -j` may run several runs at the same time. caffeinate keeps the Mac awake meanwhile.
DATASET ?= cicids2017
RESULTS = results/zeroday-$(DATASET)
DONE = $(RESULTS)/v2-done
KEEP_AWAKE = $(if $(shell command -v caffeinate),caffeinate -i)
RUN = $(KEEP_AWAKE) uv run jev-ids run --dataset data/$(DATASET)/dataset.json --split paper --results-dir $(RESULTS) --delay
# The Examples of Jev alone: the `Selector`'s choice plus the nearest benign Flow.
ANCHOR = --selection score+nearest
# Reading D and the seed from the stem of a stamp, `200-s2` for `full-d200-s2`.
SEEDED = $(firstword $(subst -s, ,$*)) --seeds $(lastword $(subst -s, ,$*))
JEV = $(SEEDED) --detector jev
ONCE = --k all --seeds 0
# The stamps of the Jev lines in $(1) at the delay $(2), one per seed in $(3).
jev_stamps = $(foreach line,$(1),$(foreach seed,$(3),$(DONE)/$(line)-d$(2)-s$(seed)))
# Running one battery run with the arguments $(1) and stamping it with the directory its own `done:` line names.
# The stamp is withheld when the run wrote no row or any row holds an error, so the next call runs it again.
stamped_run = set -o pipefail && run=$$(PYTHONUNBUFFERED=1 $(RUN) $(1) | tee /dev/stderr | sed -n 's/^done: //p') \
  && [ -s "$$run/predictions.jsonl" ] && ! grep -q '"error"' $$run/predictions.jsonl && mkdir -p $(@D) && basename $$run > $@
.PHONY: zeroday-cut zeroday-knn-cut zeroday-jev zeroday-baselines zeroday-sonnet paper-numbers

# Running Jev alone over the development stream of data/<dataset>-dev at D = 200, seeds 0 to 2, for the cut (D9).
zeroday-cut:
	$(KEEP_AWAKE) uv run jev-ids run --dataset data/$(DATASET)-dev/dataset.json --split validation \
	  --results-dir $(RESULTS)-dev --delay 200 --detector jev --k 1 --seeds 0,1,2 --control aimd $(ANCHOR)
# Running the matched kNN over the same stream, whose scores give the fusion its percentiles and its cut.
# It is deterministic and free, so one seed suffices.
zeroday-knn-cut:
	uv run jev-ids run --dataset data/$(DATASET)-dev/dataset.json --split validation \
	  --results-dir $(RESULTS)-dev-knn --delay 200 --detector knn --k all --seeds 0 --neighbours matched:4
# The Jev runs of the paper, Jev alone at D = 200 first: 17 on CIC-IDS2017, which repeats D = 50 and D = 1 over three seeds,
# and 13 on TRUSTLab, which runs them with seed 0. Then the 12 baseline runs and the 3 Sonnet 5.5 runs at D = 200.
JEV_DELAYS_cicids2017 = $(call jev_stamps,full,50,0 1 2) $(call jev_stamps,full,1,0 1 2)
JEV_DELAYS_trustlab = $(call jev_stamps,full,50,0) $(call jev_stamps,full,1,0)
zeroday-jev: $(call jev_stamps,full,200,0 1 2) $(JEV_DELAYS_$(DATASET)) \
  $(call jev_stamps,fixedk1 noctl,200,0 1 2) $(call jev_stamps,nosel randomk4,200,0)
zeroday-baselines: $(foreach d,200 50 1,$(addprefix $(DONE)/,$(addsuffix -d$(d),rf if knn4 knnmatched)))
zeroday-sonnet: $(call jev_stamps,sonnet,200,0 1 2)
# Writing results/paper/numbers.json from every stamped run of both datasets, the numbers of the paper.
paper-numbers:
	uv run python scripts/paper_numbers.py

$(DONE)/full-d%:
	$(call stamped_run,$(JEV) --k 1 --control aimd $(ANCHOR))
$(DONE)/fixedk1-d%:
	$(call stamped_run,$(JEV) --k 1 $(ANCHOR))
$(DONE)/randomk4-d%:
	$(call stamped_run,$(JEV) --k 4 --selection random)
$(DONE)/noctl-d%:
	$(call stamped_run,$(JEV) --k 4 $(ANCHOR))
$(DONE)/nosel-d%:
	$(call stamped_run,$(JEV) --k 1 --selection random --control aimd)
$(DONE)/sonnet-d%:
	$(call stamped_run,$(SEEDED) --detector llm:sonnet --k 1 --control aimd $(ANCHOR))
$(DONE)/rf-d%:
	$(call stamped_run,$* $(ONCE) --detector random_forest)
$(DONE)/if-d%:
	$(call stamped_run,$* $(ONCE) --detector isolation_forest)
$(DONE)/knn4-d%:
	$(call stamped_run,$* $(ONCE) --detector knn --neighbours 4)
$(DONE)/knnmatched-d%:
	$(call stamped_run,$* $(ONCE) --detector knn --neighbours matched:4)
