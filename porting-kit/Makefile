# Porting Kit — self-check.
#
# `check-kit` is referenced by README.md, CLAUDE.md, PLAYBOOK.md, OPERATING-GUIDE.md,
# every PROMPTS/ file and all six skills as THE way to prove the kit is internally
# consistent. It did not exist until the M5 retrospective (nmap) found sixteen live
# references to a make target with no Makefile behind them — the kit's own
# "a delegated control that nothing enforces is not a control" (LESSONS #003),
# turned on itself.
#
# Deliberately python3 + bash only: no Rust toolchain, no network. It must run in
# any repo that vendors the kit, or it will be skipped, and a skipped control is a
# broken control.

PY ?= python3
SH ?= bash

PY_HARNESSES := \
	harnesses/unsafe-audit/audit_unsafe.py \
	harnesses/differential/diff_run.py \
	harnesses/differential/normalize.py \
	harnesses/golden/golden.py \
	harnesses/c-flaw-scan/scan_c_flaws.py \
	harnesses/progress/progress.py \
	harnesses/scaling/scale_check.py \
	harnesses/ci/ci_local.py

SH_HARNESSES := \
	harnesses/fuzz/gen_fuzz_target.sh \
	harnesses/sanitizers/run_sanitizers.sh \
	harnesses/supply-chain/run_supply_chain.sh

# `ci-local` runs every job of the port's CI workflows on this machine, unscoped,
# and prints a summary to paste into the PR. No check run on the head SHA means no
# gate ran (LESSONS #042): nmap's whole M6.6 merged with zero CI runs while the
# local stand-ins were scoped (#030's trap). It needs the port's toolchains, so it
# is deliberately NOT part of check-kit. WORKFLOWS defaults to every workflow in the
# repository that vendors this kit; set it to name fewer *workflows*, never fewer jobs.
WORKFLOWS ?= $(wildcard ../.github/workflows/*.yml ../.github/workflows/*.yaml)

.PHONY: check-kit check-harnesses check-skills check-shell ci-local help

help:
	@echo "make check-kit         smoke-test every harness + the skills-integrity check"
	@echo "make check-harnesses   python harness self-tests only"
	@echo "make check-shell       shell harness syntax check only"
	@echo "make check-skills      skills-integrity check only"
	@echo "make ci-local          run every CI job locally when CI did not run (WORKFLOWS=...)"

check-kit: check-harnesses check-shell check-skills
	@echo "check-kit: OK"

# Every python harness ships a --self-test. A harness without one is a harness
# nobody can trust after an edit, so a missing flag is a failure, not a skip.
check-harnesses:
	@for h in $(PY_HARNESSES); do \
		printf '%-46s ' "$$h"; \
		$(PY) "$$h" --self-test >/dev/null 2>&1 \
			&& echo "self-test OK" \
			|| { echo "SELF-TEST FAILED"; exit 1; }; \
	done

# The shell harnesses drive external toolchains (cargo-fuzz, the sanitizers,
# cargo-audit) that are deliberately not required here, so they are syntax-checked
# rather than executed.
check-shell:
	@for h in $(SH_HARNESSES); do \
		printf '%-46s ' "$$h"; \
		$(SH) -n "$$h" && echo "syntax OK" \
			|| { echo "SYNTAX ERROR"; exit 1; }; \
	done

check-skills:
	@$(PY) skills/check_skills.py

ci-local:
	@test -n "$(WORKFLOWS)" || { echo "ci-local: no workflow found; pass WORKFLOWS=path/to/ci.yml"; exit 2; }
	@$(PY) harnesses/ci/ci_local.py $(WORKFLOWS)
