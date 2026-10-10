#!/usr/bin/env bash
# Re-derive the M6.6 step b LPeg tree corpus with the tree's own Lua and LPeg,
# and compare it with what is committed.
#
#   ./regen_m66b_trees.sh           regenerate cases and golden in place
#   ./regen_m66b_trees.sh --check   FAIL if either differs
#
# Gates `core::nse::lpeg` at step b: pattern construction — every constructor
# and operator, the grammar builder and its verifier, `type`, `version`,
# `setmaxstack`, `locale`, the `ptree`/`pcode` stubs and the metatable —
# through crates/core/tests/lpeg_tree_differential.rs. No case calls `match`.
#
# The oracle is `liblua/` plus `lpeg.c` from this repository, built by
# oracle/build_lua_oracle.sh. Each case is a Lua chunk; oracle/m66b_tree_core.lua
# runs and renders it on BOTH sides, so only LPeg itself can differ. Error
# messages are compared byte for byte; the one masked class is the rule name
# four grammar errors take from the grammar table's traversal order, which is
# salted per process ("hashorder"), and the two runs below are how a row that
# depends on it unmasked would be caught.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m66b_tree_cases.txt m66b_tree_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m66b_trees.py > "$WORK/m66b_tree_cases.txt"
./oracle/lua oracle/m66b_tree_driver.lua oracle/m66b_tree_core.lua "$WORK/m66b_tree_cases.txt" \
  > "$WORK/m66b_tree_golden.txt"

# Determinism is asserted, not assumed: the generator twice, and the oracle
# twice (each run of the oracle salts its string hashes afresh).
python3 oracle/gen_m66b_trees.py > "$WORK/cases_again.txt"
./oracle/lua oracle/m66b_tree_driver.lua oracle/m66b_tree_core.lua "$WORK/m66b_tree_cases.txt" \
  > "$WORK/second_run.txt"
for pair in "m66b_tree_cases.txt cases_again.txt" "m66b_tree_golden.txt second_run.txt"; do
  set -- $pair
  if ! diff -q "$WORK/$1" "$WORK/$2" >/dev/null; then
    echo "FAIL: $1 is not deterministic across two runs" >&2
    diff -u "$WORK/$1" "$WORK/$2" | head -40 >&2 || true
    exit 1
  fi
done

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m66b_trees.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m66b_tree_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m66b trees: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m66b trees: regenerated ($total cases)"
