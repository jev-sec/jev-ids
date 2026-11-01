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

# Paper protocol (docs/protocol.md): the four detectors over the `paper` split of CIC-IDS2017 into results/paper-cicids2017/, then the
# summary; NSL-KDD is frozen (docs/jevids-design.md, D1), and `make paper DATASET=nsl-kdd` writes into results/paper/, the published
# runs. Each detector is its own target so they can run in separate terminals; `paper` runs them one after the other. The LLM is the slow
# one, about 1.7 s per flow, so it is split into one target per k, each its own run directory: `make -j5 paper-llm` runs the five at
# once; `metrics` and `compare --b` take the five directories together. k stops at 8 since 2026-09-22 (docs/protocol.md).
DATASET ?= cicids2017
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

# Stage 6 (docs/jevids-design.md, "Stage 6 in slots"): the paper split of CIC-IDS2017 read once, in 15 slots of 60 to 90 minutes,
# each a chain of whole runs that needs nobody at the keyboard. A stream run cannot be redone (`redo-errors` refuses it), so a slot cut
# midway loses the run it was in and keeps the finished ones. `make -k stage6-N` goes on to the next run when one fails, `make -k stage6`
# runs every slot in order, and caffeinate keeps the Mac awake while a run lasts. A run that ends well leaves a stamp holding the name of
# its directory in results/design-cicids2017/stage6-done/, and make skips every run whose stamp exists, so the same command resumes a cut
# chain at the run that was cut.
#
# Each Jev run holds one seed and its stamp is `<line>-d<D>-s<seed>`. Since 2026-11-01, to fit the TypeSafe credits left ("Changes after
# results"), the full system and Jev at a fixed k = 1 run STAGE6_SEEDS and every other Jev line runs STAGE6_FEW_SEEDS. Setting either on
# the command line, as in `make -k stage6 STAGE6_FEW_SEEDS="0 1 2"`, runs only the seeds still without a stamp.
KEEP_AWAKE = $(if $(shell command -v caffeinate),caffeinate -i)
STAGE6_RUN = $(KEEP_AWAKE) uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper \
  --results-dir results/design-cicids2017 --delay
STAGE6_SEEDS = 0 1 2
STAGE6_FEW_SEEDS = 0
# Reading D and the seed from the stem of a Jev stamp, `500-s2` for `full-d500-s2`.
stage6_d = $(firstword $(subst -s, ,$*))
stage6_seed = $(lastword $(subst -s, ,$*))
STAGE6_JEV = $(stage6_d) --detector jev --seeds $(stage6_seed)
STAGE6_ONCE = --k all --seeds 0
STAGE6_DONE = results/design-cicids2017/stage6-done
# The stamps of the Jev lines in $(1) at the delay $(2), one per seed in $(3).
stage6_jev = $(foreach line,$(1),$(foreach seed,$(3),$(STAGE6_DONE)/$(line)-d$(2)-s$(seed)))
# Withholding the stamp when any row of the run just made, the newest directory, holds an error, so the next `make -k stage6` runs it
# again. Added on 2026-11-01, after the TypeSafe credits ran out in slot 7 and six runs of nothing but HTTP 402 rows were stamped.
STAGE6_STAMP = run=$$(ls -td results/design-cicids2017/*-paper | head -1) && ! grep -q '"error"' $$run/predictions.jsonl \
  && mkdir -p $(@D) && basename $$run > $@
STAGE6_SLOTS = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
.PHONY: stage6 $(addprefix stage6-,$(STAGE6_SLOTS))

stage6: $(addprefix stage6-,$(STAGE6_SLOTS))

# Slots 1 to 4 at D = 1, 5 to 8 at D = 100, 9 to 12 at D = 500, then the β check at each D.
stage6-1: $(call stage6_jev,full,1,$(STAGE6_SEEDS)) $(addprefix $(STAGE6_DONE)/,if-d1 knn4-d1 knnmatched-d1)
stage6-2: $(call stage6_jev,fixedk1,1,$(STAGE6_SEEDS)) $(STAGE6_DONE)/rf-d1
stage6-3: $(call stage6_jev,randomk4 noctl,1,$(STAGE6_FEW_SEEDS))
stage6-4: $(call stage6_jev,nosel nocompact,1,$(STAGE6_FEW_SEEDS))
stage6-5: $(call stage6_jev,full,100,$(STAGE6_SEEDS)) $(addprefix $(STAGE6_DONE)/,if-d100 knn4-d100 knnmatched-d100)
stage6-6: $(call stage6_jev,fixedk1,100,$(STAGE6_SEEDS)) $(STAGE6_DONE)/rf-d100
stage6-7: $(call stage6_jev,randomk4 noctl,100,$(STAGE6_FEW_SEEDS))
stage6-8: $(call stage6_jev,nosel nocompact,100,$(STAGE6_FEW_SEEDS))
stage6-9: $(call stage6_jev,full,500,$(STAGE6_SEEDS)) $(addprefix $(STAGE6_DONE)/,if-d500 knn4-d500 knnmatched-d500)
stage6-10: $(call stage6_jev,fixedk1,500,$(STAGE6_SEEDS)) $(STAGE6_DONE)/rf-d500
stage6-11: $(call stage6_jev,randomk4 noctl,500,$(STAGE6_FEW_SEEDS))
stage6-12: $(call stage6_jev,nosel nocompact,500,$(STAGE6_FEW_SEEDS))
stage6-13: $(call stage6_jev,beta1.5 beta3,1,$(STAGE6_FEW_SEEDS))
stage6-14: $(call stage6_jev,beta1.5 beta3,100,$(STAGE6_FEW_SEEDS))
stage6-15: $(call stage6_jev,beta1.5 beta3,500,$(STAGE6_FEW_SEEDS))

$(STAGE6_DONE)/full-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1 --control aimd
	$(STAGE6_STAMP)
$(STAGE6_DONE)/fixedk1-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1
	$(STAGE6_STAMP)
$(STAGE6_DONE)/randomk4-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 4 --selection random
	$(STAGE6_STAMP)
$(STAGE6_DONE)/noctl-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 4
	$(STAGE6_STAMP)
$(STAGE6_DONE)/nosel-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1 --selection random --control aimd
	$(STAGE6_STAMP)
$(STAGE6_DONE)/nocompact-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1 --control aimd --record full
	$(STAGE6_STAMP)
$(STAGE6_DONE)/beta1.5-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1 --control aimd --beta 1.5
	$(STAGE6_STAMP)
$(STAGE6_DONE)/beta3-d%:
	$(STAGE6_RUN) $(STAGE6_JEV) --k 1 --control aimd --beta 3
	$(STAGE6_STAMP)
$(STAGE6_DONE)/rf-d%:
	$(STAGE6_RUN) $* $(STAGE6_ONCE) --detector random_forest
	$(STAGE6_STAMP)
$(STAGE6_DONE)/if-d%:
	$(STAGE6_RUN) $* $(STAGE6_ONCE) --detector isolation_forest
	$(STAGE6_STAMP)
$(STAGE6_DONE)/knn4-d%:
	$(STAGE6_RUN) $* $(STAGE6_ONCE) --detector knn --neighbours 4
	$(STAGE6_STAMP)
$(STAGE6_DONE)/knnmatched-d%:
	$(STAGE6_RUN) $* $(STAGE6_ONCE) --detector knn --neighbours matched:4
	$(STAGE6_STAMP)
