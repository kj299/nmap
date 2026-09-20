#!/usr/bin/env bash
# Re-derive the M6.0 Lua-semantics corpus with nmap's OWN Lua and compare it
# with what is committed.
#
#   ./regen_m60.sh           regenerate corpus and golden in place
#   ./regen_m60.sh --check   FAIL if either differs
#
# M6.1 and M6.2 gated parsers. M6.0 gates the *interpreter*, so the oracle is
# used differently: each case is a Lua chunk, and the golden is what `liblua/`
# — compiled from this repository by oracle/build_lua_oracle.sh — evaluates it
# to. Nothing about Lua's semantics is restated in the harness; it is executed.
#
# Two files are derived, and both are checked:
#   m60_semantics_cases.txt   the chunks, hex-encoded (they contain NUL and
#                             non-UTF-8 bytes, and the file is TSV)
#   m60_semantics_golden.txt  nmap's Lua's verdict for each
#
# The golden is portable by construction: NaN's printed sign is canonicalized
# (glibc prints "-nan"), pcall cases keep only the boolean rather than
# implementation-specific message text, and every value carries its `math.type`
# because NSE's binary libraries branch on integer-vs-float.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m60_semantics_cases.txt m60_semantics_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m60_cases.py > "$WORK/m60_semantics_cases.txt"
./oracle/lua oracle/m60_driver.lua "$WORK/m60_semantics_cases.txt" \
  > "$WORK/m60_semantics_golden.txt"

# Determinism is a property worth asserting rather than assuming: a golden that
# differs run to run silently turns this gate into noise, and the failure mode
# (a table iterated in hash order, an address in a tostring) is exactly the kind
# that survives a single manual eyeball.
./oracle/lua oracle/m60_driver.lua "$WORK/m60_semantics_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m60_semantics_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m60_semantics_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -u "$n" "$WORK/$n"; then
      echo "FAIL: $n is stale — run ./regen_m60.sh" >&2
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

if (( CHECK )); then
  (( rc == 0 )) && echo "m60: cases and golden are current ($(grep -cv '^#' m60_semantics_cases.txt) cases)"
  exit $rc
fi
echo "m60: regenerated ($(grep -cv '^#' m60_semantics_cases.txt) cases)"
