#!/usr/bin/env bash
# Re-derive the corpus for the tail of the standard library with nmap's OWN
# Lua and compare it with what is committed.
#
#   ./regen_m6_tail.sh           regenerate cases and golden in place
#   ./regen_m6_tail.sh --check   FAIL if either differs
#
# Gates `core::nse::stdlib::base` (`_G`, `rawequal`, `xpcall`, `load`,
# `coroutine.wrap`) and `core::nse::stdlib::strrep` (`string.rep`). The oracle
# is `liblua/` from this repository, built by oracle/build_lua_oracle.sh. It
# reuses the pattern corpus's driver, oracle/m6_pattern_driver.lua, which
# keeps error messages.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m6_tail_cases.txt m6_tail_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m6_tail.py > "$WORK/m6_tail_cases.txt"
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m6_tail_cases.txt" \
  > "$WORK/m6_tail_golden.txt"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m6_tail_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m6_tail_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m6_tail_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m6_tail.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m6_tail_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6 tail: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6 tail: regenerated ($total cases)"
