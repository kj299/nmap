#!/usr/bin/env bash
# Re-derive the Lua-pattern corpus (`string.find` / `match` / `gmatch` /
# `gsub`) with nmap's OWN Lua and compare it with what is committed.
#
#   ./regen_m6_pattern.sh           regenerate cases and golden in place
#   ./regen_m6_pattern.sh --check   FAIL if either differs
#
# Gates `core::nse::stdlib::pattern`, the first-party port of
# `liblua/lstrlib.c:347-947`. The oracle is `liblua/` from this repository,
# built by oracle/build_lua_oracle.sh, and each case is a Lua chunk it evaluates.
#
# The generator reads every `.lua` and `.nse` file under nselib/ and scripts/
# for the patterns NSE actually uses (section J), so a change to those trees
# changes the corpus -- which is what --check is for.
#
# The driver is oracle/m6_pattern_driver.lua, not the coercion driver the
# strpack corpus shares: it keeps error MESSAGES, hex-encoded, because for the
# matcher the message is the behaviour.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m6_pattern_cases.txt m6_pattern_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m6_pattern.py > "$WORK/m6_pattern_cases.txt"
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m6_pattern_cases.txt" \
  > "$WORK/m6_pattern_golden.txt"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m6_pattern_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m6_pattern_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m6_pattern_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m6_pattern.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m6_pattern_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6 pattern: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6 pattern: regenerated ($total cases)"
