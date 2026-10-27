# The virtual environment lives outside the repository unless the shell says otherwise: this folder may sit on a synced volume (iCloud
# Drive evicts files of .venv and hides its .pth files, so `uv run` hangs or cannot import the package). `?=` keeps any value the shell
# already exported.
UV_PROJECT_ENVIRONMENT ?= $(HOME)/.venvs/jev-ids
export UV_PROJECT_ENVIRONMENT

# Quality gate (added by /quality-init). Thresholds live in pyproject.toml / eslint.config.mjs.
.PHONY: check fast check-py check-ts check-dup

check: check-py check-ts check-dup

fast:
	@[ ! -f pyproject.toml ] || (uvx ruff check . && uvx ruff format --check . && uvx complexipy -q --max-complexity-allowed 15 .)
	@[ ! -f package.json ] || (npx eslint . && npx prettier --check .)

check-py:
	@[ ! -f pyproject.toml ] || (uvx ruff check . && uvx ruff format --check . \
	  && uvx complexipy -q --max-complexity-allowed 15 . \
	  && uv run pyright && uv run pytest && uv run vulture \
	  && uv export --format requirements-txt --no-hashes -q | uvx pip-audit --no-deps --disable-pip -r /dev/stdin)

check-ts:
	@[ ! -f package.json ] || (npx tsc --noEmit && npx eslint . && npx prettier --check . \
	  && npx vitest run --coverage && npx knip \
	  && npx madge --circular --extensions ts,tsx --exclude 'node_modules|\.next|dist' . \
	  && npm audit --audit-level=high)

check-dup:
	@npx jscpd .

# Paper protocol (docs/protocol.md): the four detectors over the `paper` split of NSL-KDD into results/paper/, then the summary;
# `make paper DATASET=cicids2017` does the same over CIC-IDS2017 into results/paper-cicids2017/, apart from the published runs. Each
# detector is its own target so they can run in separate terminals; `paper` runs them one after the other. The LLM is the slow one, about
# 1.7 s per flow, so it is split into one target per k, each its own run directory: `make -j5 paper-llm` runs the five at once;
# `metrics` and `compare --b` take the five directories together. k stops at 8 since 2026-09-22 (docs/protocol.md).
DATASET ?= nsl-kdd
PAPER_DIR = results/paper$(if $(filter-out nsl-kdd,$(DATASET)),-$(DATASET))
PAPER_RUN = uv run jev-ids run --dataset data/$(DATASET)/dataset.json --split paper --results-dir $(PAPER_DIR) --seeds 0,1,2
LLM_KS = 0 1 2 4 8
# The LLM baseline of the paper: override with `make paper-llm LLM=openai LLM_MODEL=gpt-5.6-luna`.
LLM ?= gemini
LLM_MODEL ?= gemini-3.6-flash
.PHONY: paper paper-jev paper-llm paper-random-forest paper-isolation-forest paper-summary

paper: paper-jev paper-llm paper-random-forest paper-isolation-forest paper-summary

paper-jev:
	$(PAPER_RUN) --detector jev --k 0,1,2,4,8

paper-llm: $(addprefix paper-llm-k,$(LLM_KS))

paper-llm-k%:
	$(PAPER_RUN) --detector llm:$(LLM) --model $(LLM_MODEL) --k $*

paper-random-forest:
	$(PAPER_RUN) --detector random_forest --k 1,2,4,8,all

paper-isolation-forest:
	$(PAPER_RUN) --detector isolation_forest --k all

# The tables of the paper: the summary (Tables 2, 3 and 5), the flow-level sign tests (Table 4 and Jev against the Random Forest) and the
# McNemar test per seed.
paper-summary:
	uv run jev-ids metrics $(PAPER_DIR)/*/ > $(PAPER_DIR)/summary.csv
	uv run jev-ids sign-test --a $(PAPER_DIR)/*-jev-paper/ --b $(PAPER_DIR)/*-llm-gemini-paper/ > $(PAPER_DIR)/sign-test-jev-gemini.csv
	uv run jev-ids sign-test --a $(PAPER_DIR)/*-jev-paper/ --b $(PAPER_DIR)/*-random_forest-paper/ > $(PAPER_DIR)/sign-test-jev-random_forest.csv
	for subset in all known novel; do \
	  uv run jev-ids compare --a $(PAPER_DIR)/*-jev-paper/ --b $(PAPER_DIR)/*-llm-gemini-paper/ --subset $$subset \
	    > $(PAPER_DIR)/compare-jev-gemini-$$subset.csv; \
	done
