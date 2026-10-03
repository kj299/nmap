#!/usr/bin/env bash
# Re-derive the M6.3 `--script-args` corpus with nmap's OWN Lua and LPeg, and
# compare it with what is committed.
#
#   ./regen_m63.sh           regenerate cases and golden in place
#   ./regen_m63.sh --check   FAIL if either differs
#
# The oracle is `liblua/` plus `lpeg.c`, compiled from this repository, running
# the argument-joining code and the grammar sliced verbatim out of
# `nse_main.lua:1245-1291` and `nselib/lpeg-utility.lua` (see
# oracle/extract_nse_main.py). Section B of the generator reads every
# `--script-args` example in scripts/ and nselib/, so --check also fails when
# those trees change.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMES=(m63_args_cases.txt m63_args_golden.txt)

bash "$HERE/oracle/build_lua_oracle.sh" >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/oracle/gen_m63_args.py" "$WORK" >/dev/null

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  for name in "${NAMES[@]}"; do
    diff -q "$HERE/$name" "$WORK/$name" >/dev/null || { echo "stale: $name" >&2; rc=1; }
  done
  if [[ $rc -ne 0 ]]; then
    echo "M6.3 corpus is stale: re-run tests/differential/m6/regen_m63.sh" >&2
    exit 1
  fi
  echo "M6.3 corpus matches the oracle ($(grep -cv '^#' "$HERE/m63_args_cases.txt") cases)."
  exit 0
fi

for name in "${NAMES[@]}"; do cp "$WORK/$name" "$HERE/$name"; done
echo "M6.3 corpus regenerated ($(grep -cv '^#' "$HERE/m63_args_cases.txt") cases)."
