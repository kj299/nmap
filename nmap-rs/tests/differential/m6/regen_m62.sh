#!/usr/bin/env bash
# Re-derive the M6.2 corpus with nmap's OWN Lua and OWN LPeg, and compare it
# with what is committed.
#
#   ./regen_m62.sh           regenerate corpus, goldens and fixtures in place
#   ./regen_m62.sh --check   FAIL if any of the six differs
#
# The oracle is `liblua/` plus `lpeg.c`, both compiled from this repository,
# running the `--script` selection grammar sliced verbatim out of
# `nse_main.lua` and `nselib/lpeg-utility.lua` (see oracle/extract_nse_main.py).
# Nothing about how a selection expression parses or evaluates is restated in
# the harness; it is pasted in, and generation fails loudly if upstream moves
# an anchor.
#
# LPeg is what makes this oracle worth building. The grammar's observable
# behaviour — ordered choice that commits, possessive repetition, capture
# functions that run only over the surviving parse tree, and a backtrack stack
# that gives out at fifteen nested parentheses — belongs to that engine, not to
# PEGs in general. A hand-written oracle would encode what a PEG "should" do and
# bless the same wrong answers as the port.
#
# Six files are derived, and all six are checked:
#   m62_cases.txt         the edge-case corpus (rule x script entry)
#   m62_golden.txt        LPeg's verdict and the verdict this port must reach
#   m62_norm_cases.txt    the rule-normalisation corpus
#   m62_norm_golden.txt   Lua's verdict and the verdict this port must reach
#   m62_fixtures.rs       the same inputs as Rust consts, `include!`d by the
#                         unit tests in `core::nse::selection` (which run under
#                         Miri, where there is no filesystem)
#   m62_sweep_golden.txt  45 realistic rules x all 611 shipped scripts
# Checking the fixtures here is what stops the Miri-visible tests from drifting
# away from the corpus.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMES=(m62_cases.txt m62_golden.txt m62_norm_cases.txt m62_norm_golden.txt m62_fixtures.rs m62_sweep_golden.txt)

bash "$HERE/oracle/build_lua_oracle.sh" >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/oracle/gen_m62_cases.py" "$WORK" >/dev/null
python3 "$HERE/oracle/gen_m62_sweep.py" "$WORK" >/dev/null

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  for name in "${NAMES[@]}"; do
    diff -u "$HERE/$name" "$WORK/$name" || rc=1
  done
  if [[ $rc -ne 0 ]]; then
    echo "M6.2 corpus is stale: re-run tests/differential/m6/regen_m62.sh" >&2
    exit 1
  fi
  echo "M6.2 corpus matches the oracle."
  exit 0
fi

for name in "${NAMES[@]}"; do cp "$WORK/$name" "$HERE/$name"; done
echo "M6.2 corpus regenerated."
